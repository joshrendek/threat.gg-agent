package modbus

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func encodeMBAP(transactionID, protoID, length uint16, unitID byte, pdu []byte) []byte {
	buf := make([]byte, 7+len(pdu))
	binary.BigEndian.PutUint16(buf[0:2], transactionID)
	binary.BigEndian.PutUint16(buf[2:4], protoID)
	binary.BigEndian.PutUint16(buf[4:6], length)
	buf[6] = unitID
	copy(buf[7:], pdu)
	return buf
}

func TestReadMBAPParsesAValidFrame(t *testing.T) {
	raw := encodeMBAP(0xABCD, 0x0000, 3, 0x11, []byte{0x03, 0x00})
	hdr, pdu, err := readMBAP(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("readMBAP: %v", err)
	}
	if hdr.transactionID != 0xABCD {
		t.Errorf("transactionID = 0x%04X, want 0xABCD", hdr.transactionID)
	}
	if hdr.unitID != 0x11 {
		t.Errorf("unitID = 0x%02X, want 0x11", hdr.unitID)
	}
	if !bytes.Equal(pdu, []byte{0x03, 0x00}) {
		t.Errorf("pdu = % x, want 03 00", pdu)
	}
}

func TestReadMBAPRejectsNonZeroProtocolID(t *testing.T) {
	raw := encodeMBAP(1, 0x0001, 2, 0x00, []byte{0x03})
	_, _, err := readMBAP(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Error("expected an error for a non-zero protocol identifier")
	}
}

func TestReadMBAPRejectsLengthBelowMinimum(t *testing.T) {
	// length=1 means only the unit id byte, no PDU at all -- below the
	// documented minimum of 2 (ei_mbtcp_invalid_length).
	raw := encodeMBAP(1, 0x0000, 1, 0x00, nil)
	_, _, err := readMBAP(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Error("expected an error for length < 2")
	}
}

func TestReadMBAPRejectsLengthAboveMaximum(t *testing.T) {
	raw := encodeMBAP(1, 0x0000, 0xFFFF, 0x00, nil)
	_, _, err := readMBAP(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Error("expected an error for length > 254")
	}
}

func TestReadMBAPDoesNotAllocateHugeBufferForOversizedLength(t *testing.T) {
	// Only the 7-byte header is present -- no PDU bytes at all -- so if
	// readMBAP tried to read length-1 bytes before validating length, this
	// would hang/fail on a short read rather than failing fast on the
	// length check itself.
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint16(hdr[4:6], 0xFFFF)
	_, _, err := readMBAP(bufio.NewReader(bytes.NewReader(hdr)))
	if err == nil {
		t.Error("expected an error; the oversized length must be rejected before reading PDU bytes")
	}
}

func TestReadMBAPReturnsErrorOnShortRead(t *testing.T) {
	// Header claims 5 PDU bytes but only 2 are present.
	raw := encodeMBAP(1, 0x0000, 6, 0x00, []byte{0x03, 0x00})
	_, _, err := readMBAP(bufio.NewReader(bytes.NewReader(raw)))
	if err == nil {
		t.Error("expected an error for a truncated PDU")
	}
}

func TestWriteMBAPEchoesTransactionAndUnitID(t *testing.T) {
	var buf bytes.Buffer
	hdr := mbapHeader{transactionID: 0x1234, unitID: 0x05}
	if err := writeMBAP(&buf, hdr, []byte{0x03, 0x02, 0xAA, 0xBB}); err != nil {
		t.Fatalf("writeMBAP: %v", err)
	}

	gotHdr, pdu, err := readMBAP(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("readMBAP(round-trip): %v", err)
	}
	if gotHdr.transactionID != 0x1234 || gotHdr.unitID != 0x05 {
		t.Errorf("round-tripped header = %+v, want transactionID=0x1234 unitID=0x05", gotHdr)
	}
	if !bytes.Equal(pdu, []byte{0x03, 0x02, 0xAA, 0xBB}) {
		t.Errorf("round-tripped pdu = % x, want 03 02 aa bb", pdu)
	}
}
