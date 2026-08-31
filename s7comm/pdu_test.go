package s7comm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseS7HeaderRoundTripJob(t *testing.T) {
	param := []byte{0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0}
	pdu := buildS7Header(rosctrJob, 0x0042, 0, 0, param, nil)

	hdr, body, err := parseS7Header(pdu)
	if err != nil {
		t.Fatalf("parseS7Header: %v", err)
	}
	if hdr.rosctr != rosctrJob {
		t.Errorf("rosctr = 0x%02x, want 0x%02x", hdr.rosctr, rosctrJob)
	}
	if hdr.pduRef != 0x0042 {
		t.Errorf("pduRef = 0x%04x, want 0x0042", hdr.pduRef)
	}
	if int(hdr.parLen) != len(param) {
		t.Errorf("parLen = %d, want %d", hdr.parLen, len(param))
	}
	if !bytes.Equal(body[:hdr.parLen], param) {
		t.Errorf("body param section = % x, want % x", body[:hdr.parLen], param)
	}
}

func TestParseS7HeaderRoundTripAckData(t *testing.T) {
	param := []byte{0x04, 0x01}
	data := []byte{0xFF, 0x04, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8}
	pdu := buildS7Header(rosctrAckData, 0x0007, errclsNone, 0x00, param, data)

	if len(pdu) < s7HeaderLenLong {
		t.Fatalf("Ack_Data PDU too short: %d bytes", len(pdu))
	}
	hdr, body, err := parseS7Header(pdu)
	if err != nil {
		t.Fatalf("parseS7Header: %v", err)
	}
	if hdr.rosctr != rosctrAckData {
		t.Errorf("rosctr = 0x%02x, want 0x%02x", hdr.rosctr, rosctrAckData)
	}
	gotData := body[hdr.parLen : hdr.parLen+hdr.datLen]
	if !bytes.Equal(gotData, data) {
		t.Errorf("data section = % x, want % x", gotData, data)
	}
}

func TestParseS7HeaderRejectsBadProtocolID(t *testing.T) {
	pdu := buildS7Header(rosctrJob, 1, 0, 0, []byte{0xF0}, nil)
	pdu[0] = 0x33 // corrupt the protocol-id byte
	if _, _, err := parseS7Header(pdu); err == nil {
		t.Fatal("expected an error for a bad protocol id, got nil")
	}
}

func TestParseS7HeaderRejectsBadROSCTR(t *testing.T) {
	pdu := buildS7Header(rosctrJob, 1, 0, 0, []byte{0xF0}, nil)
	pdu[1] = 0x05 // not one of 1/2/3/7
	if _, _, err := parseS7Header(pdu); err == nil {
		t.Fatal("expected an error for an invalid ROSCTR, got nil")
	}
}

func TestParseS7HeaderRejectsTruncatedInput(t *testing.T) {
	for n := 0; n < s7HeaderLenShort; n++ {
		buf := make([]byte, n)
		if _, _, err := parseS7Header(buf); err == nil {
			t.Errorf("parseS7Header accepted a %d-byte buffer (< %d)", n, s7HeaderLenShort)
		}
	}
}

func TestParseS7HeaderRejectsLengthsThatOverrunBuffer(t *testing.T) {
	pdu := buildS7Header(rosctrJob, 1, 0, 0, []byte{0xF0, 0x00}, nil)
	// Claim a much larger parameter length than the buffer actually has.
	binary.BigEndian.PutUint16(pdu[6:8], 0xFFFF)
	if _, _, err := parseS7Header(pdu); err == nil {
		t.Fatal("expected an error when declared parLen+datLen exceeds the buffer, got nil")
	}
}

func TestParseS7HeaderDoesNotPanicOnRandomShortBuffers(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseS7Header panicked: %v", r)
		}
	}()
	for n := 0; n < 15; n++ {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(0x30 + i)
		}
		_, _, _ = parseS7Header(buf)
	}
}

// buildJobPDU is a small helper for constructing request PDUs the way a real
// S7 client would, for feeding into handlePDU in tests below.
func buildJobPDU(pduRef uint16, param, data []byte) []byte {
	return buildS7Header(rosctrJob, pduRef, 0, 0, param, data)
}

func TestHandleSetupCommUsesPersonaValues(t *testing.T) {
	// Request body content is irrelevant (see handleSetupComm's doc comment)
	// but must be shaped like a real one.
	reqParam := []byte{fnSetupComm, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0}
	pdu := buildJobPDU(0x0001, reqParam, nil)

	resp, ok := handlePDU(pdu, "198.51.100.1", newSession())
	if !ok || resp == nil {
		t.Fatalf("handlePDU(SetupComm) = (%v, %v), want a non-nil response", resp, ok)
	}

	hdr, body, err := parseS7Header(resp)
	if err != nil {
		t.Fatalf("parseS7Header(response): %v", err)
	}
	if hdr.rosctr != rosctrAckData {
		t.Errorf("response ROSCTR = 0x%02x, want Ack_Data", hdr.rosctr)
	}
	if hdr.pduRef != 0x0001 {
		t.Errorf("response pduRef = 0x%04x, want echoed 0x0001", hdr.pduRef)
	}
	param := body[:hdr.parLen]
	if len(param) != 8 || param[0] != fnSetupComm {
		t.Fatalf("response param = % x, want an 8-byte Setup Communication ack", param)
	}
	gotAMQCalling := binary.BigEndian.Uint16(param[2:4])
	gotAMQCalled := binary.BigEndian.Uint16(param[4:6])
	gotPDULen := binary.BigEndian.Uint16(param[6:8])
	if gotAMQCalling != MaxAMQCalling || gotAMQCalled != MaxAMQCalled || gotPDULen != NegotiatedPDULength {
		t.Errorf("negotiated (AMQcalling=%d, AMQcalled=%d, pduLen=%d), want (%d, %d, %d)",
			gotAMQCalling, gotAMQCalled, gotPDULen, MaxAMQCalling, MaxAMQCalled, NegotiatedPDULength)
	}
}

// buildS7AnyItem builds one 12-byte S7ANY item spec.
func buildS7AnyItem(transportSize byte, length uint16, db uint16, area byte, bitAddress uint32) []byte {
	item := make([]byte, s7AnyItemLen)
	item[0] = varSpecType
	item[1] = 10
	item[2] = syntaxIDS7Any
	item[3] = transportSize
	binary.BigEndian.PutUint16(item[4:6], length)
	binary.BigEndian.PutUint16(item[6:8], db)
	item[8] = area
	item[9] = byte(bitAddress >> 16)
	item[10] = byte(bitAddress >> 8)
	item[11] = byte(bitAddress)
	return item
}

func TestHandleWriteThenReadVarPerIPIsolationThroughFullDispatch(t *testing.T) {
	const area = 0x84 // DB
	const db = 5
	const byteOffset = 200
	item := buildS7AnyItem(2 /* BYTE */, 4, db, area, byteOffset*8)
	writeSess := newSession()

	writeParam := append([]byte{fnWriteVar, 0x01}, item...)
	sentinel := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	writeData := make([]byte, 4+len(sentinel))
	writeData[0] = 0x00
	writeData[1] = dataTransportBByte
	binary.BigEndian.PutUint16(writeData[2:4], uint16(len(sentinel)*8)) // length in BITS
	copy(writeData[4:], sentinel)

	writePDU := buildJobPDU(0x0010, writeParam, writeData)
	writeResp, ok := handlePDU(writePDU, "203.0.113.10", writeSess)
	if !ok || writeResp == nil {
		t.Fatalf("handlePDU(WriteVar) = (%v, %v)", writeResp, ok)
	}
	whdr, wbody, err := parseS7Header(writeResp)
	if err != nil {
		t.Fatalf("parseS7Header(write response): %v", err)
	}
	wdata := wbody[whdr.parLen : whdr.parLen+whdr.datLen]
	if len(wdata) != 1 || wdata[0] != itemRetvalOK {
		t.Fatalf("write return codes = % x, want a single 0xFF (success)", wdata)
	}

	readParam := append([]byte{fnReadVar, 0x01}, item...)
	readPDU := buildJobPDU(0x0011, readParam, nil)

	// The SAME attacker reads back its own write.
	sameIPResp, ok := handlePDU(readPDU, "203.0.113.10", writeSess)
	if !ok || sameIPResp == nil {
		t.Fatalf("handlePDU(ReadVar, same IP) = (%v, %v)", sameIPResp, ok)
	}
	rhdr, rbody, err := parseS7Header(sameIPResp)
	if err != nil {
		t.Fatalf("parseS7Header(read response): %v", err)
	}
	rdata := rbody[rhdr.parLen : rhdr.parLen+rhdr.datLen]
	if len(rdata) < 4 || rdata[0] != itemRetvalOK {
		t.Fatalf("read data header = % x, want return code 0xFF", rdata)
	}
	gotPayload := rdata[4 : 4+len(sentinel)]
	if !bytes.Equal(gotPayload, sentinel) {
		t.Errorf("same-IP read = % x, want its own sentinel write % x back", gotPayload, sentinel)
	}

	// A DIFFERENT attacker reading the exact same address must NOT see it.
	otherIPResp, ok := handlePDU(readPDU, "203.0.113.99", newSession())
	if !ok || otherIPResp == nil {
		t.Fatalf("handlePDU(ReadVar, other IP) = (%v, %v)", otherIPResp, ok)
	}
	_, obody, err := parseS7Header(otherIPResp)
	if err != nil {
		t.Fatalf("parseS7Header(other IP read response): %v", err)
	}
	ohdr, _, _ := parseS7Header(otherIPResp)
	odata := obody[ohdr.parLen : ohdr.parLen+ohdr.datLen]
	otherPayload := odata[4 : 4+len(sentinel)]
	if bytes.Equal(otherPayload, sentinel) {
		t.Fatalf("a different attacker IP observed the first attacker's write % x -- writes are not IP-scoped", sentinel)
	}
}

func TestHandlePLCStopPerIPIsolationThroughFullDispatch(t *testing.T) {
	stopParam := append([]byte{fnPLCStop}, []byte{0, 0, 0, 0, 0, 7, 'P', 'L', 'C', 'S', 'T', 'O', 'P'}...)
	stopPDU := buildJobPDU(0x0020, stopParam, nil)

	resp, ok := handlePDU(stopPDU, "198.51.100.55", newSession())
	if !ok || resp == nil {
		t.Fatalf("handlePDU(PLCStop) = (%v, %v)", resp, ok)
	}
	hdr, body, err := parseS7Header(resp)
	if err != nil {
		t.Fatalf("parseS7Header: %v", err)
	}
	if hdr.rosctr != rosctrAckData {
		t.Errorf("STOP ack ROSCTR = 0x%02x, want Ack_Data", hdr.rosctr)
	}
	param := body[:hdr.parLen]
	if len(param) < 1 || param[0] != fnPLCStop {
		t.Errorf("STOP ack param = % x, want it to start with the echoed function byte 0x29", param)
	}

	if globalState.Get("198.51.100.55").getMode() != modeStop {
		t.Error("attacker that sent PLC Stop is not recorded as stopped")
	}
	if globalState.Get("198.51.100.200").getMode() != modeRun {
		t.Error("a different attacker IP was affected by another attacker's PLC Stop")
	}
}

func TestHandleUnknownJobFunctionReturnsHeaderLevelError(t *testing.T) {
	pdu := buildJobPDU(0x0030, []byte{0x77}, nil) // 0x77 is not a function this honeypot implements
	resp, ok := handlePDU(pdu, "192.0.2.1", newSession())
	if !ok || resp == nil {
		t.Fatalf("handlePDU(unknown function) = (%v, %v)", resp, ok)
	}
	hdr, _, err := parseS7Header(resp)
	if err != nil {
		t.Fatalf("parseS7Header: %v", err)
	}
	if hdr.rosctr != rosctrAckData {
		t.Fatalf("rosctr = 0x%02x, want Ack_Data", hdr.rosctr)
	}
	if len(resp) < s7HeaderLenLong {
		t.Fatalf("response is only %d bytes, too short to carry the 12-byte Ack_Data header (errcls/errcod)", len(resp))
	}
	// errcls/errcod live in the fixed 12-byte Ack_Data header, at offsets 10
	// and 11 -- not inside the parameter/data sections parseS7Header splits
	// out, so check the raw response bytes directly.
	if resp[10] != errclsApplication {
		t.Errorf("errcls = 0x%02x, want 0x%02x (application error)", resp[10], errclsApplication)
	}
}
