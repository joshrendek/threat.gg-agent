package s7comm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildReadSZLRequest builds a Read SZL Userdata request PDU the way a real
// S7 client sends one: standard (non-extended) parameter part, then an
// 8-byte data part carrying the SZL-ID and Index.
func buildReadSZLRequest(pduRef uint16, szlID, szlIdx uint16) []byte {
	param := []byte{
		fnCPUServices, 0x01,
		varSpecType, 0x04, syntaxIDShort,
		(udTypeReq << 6) | udFuncGroupCPU,
		udSubfReadSZL,
		0x55, // sequence number, echoed back
	}
	data := make([]byte, 8)
	data[0] = 0x00
	data[1] = dataTransportBStr
	binary.BigEndian.PutUint16(data[2:4], 4)
	binary.BigEndian.PutUint16(data[4:6], szlID)
	binary.BigEndian.PutUint16(data[6:8], szlIdx)

	return buildS7Header(rosctrUserdata, pduRef, 0, 0, param, data)
}

// parseSZLResponse decodes the extended Userdata param + SZL data section of
// a response built by buildSZLSuccessResponse/buildSZLNotAvailableResponse,
// for test assertions.
type szlResponse struct {
	seqNum       byte
	errorcode    uint16
	dataPresent  bool
	retVal       byte
	szlID, szlIx uint16
	listLen      uint16
	listCount    uint16
	records      [][]byte
}

func parseSZLResponse(t *testing.T, pdu []byte) szlResponse {
	t.Helper()
	hdr, body, err := parseS7Header(pdu)
	if err != nil {
		t.Fatalf("parseS7Header: %v", err)
	}
	if hdr.rosctr != rosctrUserdata {
		t.Fatalf("rosctr = 0x%02x, want Userdata (0x07)", hdr.rosctr)
	}
	param := body[:hdr.parLen]
	if len(param) != 12 {
		t.Fatalf("param length = %d, want 12 (extended)", len(param))
	}
	if param[4] != syntaxIDExt {
		t.Fatalf("syntax id = 0x%02x, want extended 0x%02x", param[4], syntaxIDExt)
	}

	var resp szlResponse
	resp.seqNum = param[7]
	resp.errorcode = binary.BigEndian.Uint16(param[10:12])

	data := body[hdr.parLen : hdr.parLen+hdr.datLen]
	if len(data) == 0 {
		return resp
	}
	resp.dataPresent = true
	if len(data) < 4 {
		t.Fatalf("data section too short: %d bytes", len(data))
	}
	resp.retVal = data[0]
	if resp.retVal != itemRetvalOK {
		return resp
	}
	payload := data[4:]
	if len(payload) < 8 {
		t.Fatalf("SZL success payload too short: %d bytes", len(payload))
	}
	resp.szlID = binary.BigEndian.Uint16(payload[0:2])
	resp.szlIx = binary.BigEndian.Uint16(payload[2:4])
	resp.listLen = binary.BigEndian.Uint16(payload[4:6])
	resp.listCount = binary.BigEndian.Uint16(payload[6:8])
	records := payload[8:]
	for i := 0; i < int(resp.listCount); i++ {
		start := i * int(resp.listLen)
		resp.records = append(resp.records, records[start:start+int(resp.listLen)])
	}
	return resp
}

func TestReadSZLModuleIdentification(t *testing.T) {
	pdu := buildReadSZLRequest(1, szlModuleIdentification, 0x0001)
	respBytes, ok := handlePDU(pdu, "192.0.2.10")
	if !ok || respBytes == nil {
		t.Fatalf("handlePDU = (%v, %v)", respBytes, ok)
	}
	resp := parseSZLResponse(t, respBytes)

	if resp.seqNum != 0x55 {
		t.Errorf("seqNum = 0x%02x, want echoed 0x55", resp.seqNum)
	}
	if resp.errorcode != 0 {
		t.Fatalf("errorcode = 0x%04x, want 0 (success)", resp.errorcode)
	}
	if resp.retVal != itemRetvalOK {
		t.Fatalf("data retVal = 0x%02x, want 0xFF", resp.retVal)
	}
	if resp.szlID != szlModuleIdentification || resp.szlIx != 0x0001 {
		t.Errorf("echoed SZL-ID/Index = 0x%04x/0x%04x, want 0x0011/0x0001", resp.szlID, resp.szlIx)
	}
	if resp.listLen != szlModuleIdentRecordLen || resp.listCount != 1 {
		t.Fatalf("listLen/listCount = %d/%d, want %d/1", resp.listLen, resp.listCount, szlModuleIdentRecordLen)
	}

	rec := resp.records[0]
	gotIdx := binary.BigEndian.Uint16(rec[0:2])
	if gotIdx != 0x0001 {
		t.Errorf("record index = 0x%04x, want 0x0001", gotIdx)
	}
	gotMLFB := string(rec[2:22])
	wantMLFB := string(padASCII(OrderNumber, 20))
	if gotMLFB != wantMLFB {
		t.Errorf("MlfB field = %q, want %q", gotMLFB, wantMLFB)
	}
}

func TestReadSZLComponentIdentIndividualIndexes(t *testing.T) {
	// fieldWidth is the ASCII field's own width within the 32-byte body;
	// whatever remains up to 32 bytes is a reserved, zero-filled tail (see
	// s7comm_decode_szl_id_xy1c_idx_000x -- e.g. index 0x0001 is name(24) +
	// reserved(8), not a 32-byte padded name).
	cases := []struct {
		idx        uint16
		want       string
		fieldWidth int
	}{
		{0x0001, SystemName, 24},
		{0x0002, ModuleName, 24},
		{0x0003, PlantIdentification, 32},
		{0x0004, Copyright, 26},
		{0x0005, SerialNumber, 24},
		{0x0007, ModuleTypeName, 32},
		{0x0008, MemoryCardSerial, 32},
	}
	for _, c := range cases {
		pdu := buildReadSZLRequest(1, szlComponentIdent, c.idx)
		respBytes, ok := handlePDU(pdu, "192.0.2.11")
		if !ok || respBytes == nil {
			t.Fatalf("index 0x%04x: handlePDU = (%v, %v)", c.idx, respBytes, ok)
		}
		resp := parseSZLResponse(t, respBytes)
		if resp.retVal != itemRetvalOK {
			t.Fatalf("index 0x%04x: retVal = 0x%02x, want success", c.idx, resp.retVal)
		}
		if resp.listCount != 1 || resp.listLen != szlComponentRecordLen {
			t.Fatalf("index 0x%04x: listLen/listCount = %d/%d, want %d/1", c.idx, resp.listLen, resp.listCount, szlComponentRecordLen)
		}
		rec := resp.records[0]
		if gotIdx := binary.BigEndian.Uint16(rec[0:2]); gotIdx != c.idx {
			t.Errorf("index 0x%04x: record index field = 0x%04x", c.idx, gotIdx)
		}
		body := rec[2:]
		gotField := string(body[:c.fieldWidth])
		wantField := string(padASCII(c.want, c.fieldWidth))
		if gotField != wantField {
			t.Errorf("index 0x%04x field = %q, want %q", c.idx, gotField, wantField)
		}
		for i, b := range body[c.fieldWidth:] {
			if b != 0 {
				t.Errorf("index 0x%04x reserved tail byte %d = 0x%02x, want 0x00", c.idx, i, b)
			}
		}
	}
}

// TestReadSZLComponentIdentIndex0009NotAnswered is the brief's explicit
// requirement: SZL 0x001C index 0x0009 must return the "not available"
// error, never a value -- the manufacturer/profile IDs in persona.go are
// unverified and a wrong-but-plausible value is a worse tell than an
// ordinary unsupported-index response.
func TestReadSZLComponentIdentIndex0009NotAnswered(t *testing.T) {
	pdu := buildReadSZLRequest(1, szlComponentIdent, 0x0009)
	respBytes, ok := handlePDU(pdu, "192.0.2.12")
	if !ok || respBytes == nil {
		t.Fatalf("handlePDU = (%v, %v)", respBytes, ok)
	}
	resp := parseSZLResponse(t, respBytes)

	if resp.dataPresent {
		t.Fatalf("index 0x0009 returned a data section (% v), want none (error is param-level only)", resp)
	}
	if resp.errorcode != paramErrSZLNotAvailable {
		t.Fatalf("errorcode = 0x%04x, want 0x%04x (SZL not available)", resp.errorcode, paramErrSZLNotAvailable)
	}
}

func TestReadSZLUnsupportedIDReturnsSameErrorAs0009(t *testing.T) {
	// Any SZL-ID/Index this honeypot doesn't implement should look exactly
	// like an unsupported list to a scanner probing broadly, not crash and
	// not silently succeed with fabricated data.
	pdu := buildReadSZLRequest(1, 0x9999, 0x0000)
	respBytes, ok := handlePDU(pdu, "192.0.2.13")
	if !ok || respBytes == nil {
		t.Fatalf("handlePDU = (%v, %v)", respBytes, ok)
	}
	resp := parseSZLResponse(t, respBytes)
	if resp.dataPresent {
		t.Error("unsupported SZL-ID returned a data section, want none")
	}
	if resp.errorcode != paramErrSZLNotAvailable {
		t.Errorf("errorcode = 0x%04x, want 0x%04x", resp.errorcode, paramErrSZLNotAvailable)
	}
}

func TestReadSZLComponentIdentIndexZeroReturnsAllExceptWithheld(t *testing.T) {
	pdu := buildReadSZLRequest(1, szlComponentIdent, 0x0000)
	respBytes, ok := handlePDU(pdu, "192.0.2.14")
	if !ok || respBytes == nil {
		t.Fatalf("handlePDU = (%v, %v)", respBytes, ok)
	}
	resp := parseSZLResponse(t, respBytes)
	if resp.retVal != itemRetvalOK {
		t.Fatalf("retVal = 0x%02x, want success", resp.retVal)
	}

	seen := map[uint16]bool{}
	for _, rec := range resp.records {
		idx := binary.BigEndian.Uint16(rec[0:2])
		if idx == 0x0009 {
			t.Fatal("index 0x0000 (\"all\") included the withheld 0x0009 record")
		}
		seen[idx] = true
	}
	for _, want := range []uint16{0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0007, 0x0008} {
		if !seen[want] {
			t.Errorf("index 0x0000 response is missing sub-index 0x%04x", want)
		}
	}
}

func TestSZLLookupUnknownReturnsNotOK(t *testing.T) {
	if _, _, ok := szlLookup(0x001C, 0x0009); ok {
		t.Error("szlLookup(0x001C, 0x0009) = ok, want it excluded")
	}
	if _, _, ok := szlLookup(0x001C, 0x0006); ok {
		t.Error("szlLookup(0x001C, 0x0006) = ok, want unimplemented index to report not-ok")
	}
	if _, _, ok := szlLookup(0xABCD, 0x0000); ok {
		t.Error("szlLookup for an entirely unimplemented SZL-ID = ok, want not-ok")
	}
}

func TestPadASCIITruncatesAndPads(t *testing.T) {
	got := padASCII("hi", 5)
	if !bytes.Equal(got, []byte("hi   ")) {
		t.Errorf("padASCII(\"hi\", 5) = %q, want \"hi   \"", got)
	}
	got = padASCII("toolong", 3)
	if !bytes.Equal(got, []byte("too")) {
		t.Errorf("padASCII(\"toolong\", 3) = %q, want \"too\"", got)
	}
}
