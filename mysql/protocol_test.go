package mysql

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestWriteAndReadPacket(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello world")
	if err := writePacket(&buf, 1, payload); err != nil {
		t.Fatalf("writePacket failed: %v", err)
	}

	got, seqID, err := readPacket(&buf)
	if err != nil {
		t.Fatalf("readPacket failed: %v", err)
	}
	if seqID != 1 {
		t.Fatalf("expected seqID=1, got %d", seqID)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("expected %q, got %q", payload, got)
	}
}

func TestWritePacketHeader(t *testing.T) {
	var buf bytes.Buffer
	payload := make([]byte, 300)
	writePacket(&buf, 5, payload)

	header := buf.Bytes()[:4]
	length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if length != 300 {
		t.Fatalf("expected length=300, got %d", length)
	}
	if header[3] != 5 {
		t.Fatalf("expected seqID=5, got %d", header[3])
	}
}

func TestEncodeLengthEncodedInt_Small(t *testing.T) {
	buf := appendLengthEncodedInt(nil, 42)
	if len(buf) != 1 || buf[0] != 42 {
		t.Fatalf("expected [42], got %v", buf)
	}
}

func TestEncodeLengthEncodedInt_TwoByte(t *testing.T) {
	buf := appendLengthEncodedInt(nil, 1000)
	if len(buf) != 3 || buf[0] != 0xFC {
		t.Fatalf("expected 3-byte encoding with 0xFC prefix, got %v", buf)
	}
	val := binary.LittleEndian.Uint16(buf[1:])
	if val != 1000 {
		t.Fatalf("expected 1000, got %d", val)
	}
}

func TestEncodeLengthEncodedInt_ThreeByte(t *testing.T) {
	buf := appendLengthEncodedInt(nil, 100000)
	if len(buf) != 4 || buf[0] != 0xFD {
		t.Fatalf("expected 4-byte encoding with 0xFD prefix, got %v", buf)
	}
}

func TestEncodeLengthEncodedInt_EightByte(t *testing.T) {
	buf := appendLengthEncodedInt(nil, 1<<24)
	if len(buf) != 9 || buf[0] != 0xFE {
		t.Fatalf("expected 9-byte encoding with 0xFE prefix, got %v", buf)
	}
}

func TestDecodeLengthEncodedInt_Small(t *testing.T) {
	data := []byte{42}
	val, offset := decodeLengthEncodedInt(data, 0)
	if val != 42 || offset != 1 {
		t.Fatalf("expected val=42, offset=1; got val=%d, offset=%d", val, offset)
	}
}

func TestDecodeLengthEncodedInt_TwoByte(t *testing.T) {
	data := appendLengthEncodedInt(nil, 1000)
	val, offset := decodeLengthEncodedInt(data, 0)
	if val != 1000 || offset != 3 {
		t.Fatalf("expected val=1000, offset=3; got val=%d, offset=%d", val, offset)
	}
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	values := []uint64{0, 1, 250, 251, 1000, 65535, 65536, 100000, 1 << 24, 1 << 48}
	for _, v := range values {
		buf := appendLengthEncodedInt(nil, v)
		got, _ := decodeLengthEncodedInt(buf, 0)
		if got != v {
			t.Errorf("round-trip failed for %d: got %d", v, got)
		}
	}
}

func TestWriteOKPacket(t *testing.T) {
	var buf bytes.Buffer
	writeOKPacket(&buf, 1, 0, 0)

	data := buf.Bytes()
	// Should start with 4-byte header
	if len(data) < 5 {
		t.Fatalf("packet too short: %d bytes", len(data))
	}
	// Payload starts at byte 4, first byte should be 0x00 (OK marker)
	if data[4] != 0x00 {
		t.Fatalf("expected OK marker 0x00, got 0x%02x", data[4])
	}
}

func TestWriteERRPacket(t *testing.T) {
	var buf bytes.Buffer
	writeERRPacket(&buf, 1, 1045, "28000", "Access denied")

	data := buf.Bytes()
	if len(data) < 5 {
		t.Fatalf("packet too short: %d bytes", len(data))
	}
	// Payload first byte should be 0xFF (ERR marker)
	if data[4] != 0xFF {
		t.Fatalf("expected ERR marker 0xFF, got 0x%02x", data[4])
	}
	// Error code at bytes 5-6
	code := binary.LittleEndian.Uint16(data[5:7])
	if code != 1045 {
		t.Fatalf("expected error code 1045, got %d", code)
	}
}

func TestWriteResultSet(t *testing.T) {
	var buf bytes.Buffer
	cols := []columnDef{
		{Name: "name", ColType: 0xFD, MaxLen: 255},
		{Name: "age", ColType: 0xFD, MaxLen: 255},
	}
	rows := [][]string{
		{"Alice", "30"},
		{"Bob", "25"},
	}
	_, err := writeResultSet(&buf, 1, cols, rows)
	if err != nil {
		t.Fatalf("writeResultSet failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty result set output")
	}
}

func TestWriteEmptyResultSet(t *testing.T) {
	var buf bytes.Buffer
	cols := []columnDef{{Name: "result", ColType: 0xFD}}
	_, err := writeResultSet(&buf, 1, cols, nil)
	if err != nil {
		t.Fatalf("writeResultSet failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty output for empty result set")
	}
}

func TestLengthEncodedString_RoundTrip(t *testing.T) {
	s := "hello world"
	buf := appendLengthEncodedString(nil, s)
	got, offset := decodeLengthEncodedString(buf, 0)
	if got != s {
		t.Fatalf("expected %q, got %q", s, got)
	}
	if offset != len(buf) {
		t.Fatalf("expected offset=%d, got %d", len(buf), offset)
	}
}
