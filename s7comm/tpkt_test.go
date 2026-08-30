package s7comm

import (
	"bufio"
	"bytes"
	"testing"
)

func TestTPKTRoundTrip(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	var buf bytes.Buffer
	if err := writeTPKT(&buf, payload); err != nil {
		t.Fatalf("writeTPKT: %v", err)
	}

	want := []byte{0x03, 0x00, 0x00, 0x09} // version=3, reserved=0, length=4+5=9
	got := buf.Bytes()[:4]
	if !bytes.Equal(got, want) {
		t.Fatalf("TPKT header = % x, want % x", got, want)
	}

	out, err := readTPKT(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("readTPKT: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("readTPKT payload = % x, want % x", out, payload)
	}
}

func TestReadTPKTRejectsBadVersion(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x02, 0x00, 0x00, 0x04})
	if _, err := readTPKT(bufio.NewReader(buf)); err == nil {
		t.Fatal("expected an error for a non-3 TPKT version, got nil")
	}
}

func TestReadTPKTRejectsLengthBelowHeader(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x03, 0x00, 0x00, 0x02}) // declares 2 bytes total, less than the 4-byte header
	if _, err := readTPKT(bufio.NewReader(buf)); err == nil {
		t.Fatal("expected an error for a declared length shorter than the TPKT header, got nil")
	}
}

func TestReadTPKTRejectsOversizedLength(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x03, 0x00, 0xFF, 0xFF}) // declares 65535 bytes, over maxTPKTLength
	if _, err := readTPKT(bufio.NewReader(buf)); err == nil {
		t.Fatal("expected an error for a declared length over maxTPKTLength, got nil")
	}
}

func TestReadTPKTRejectsTruncatedPayload(t *testing.T) {
	// Declares 20 bytes total but only supplies the 4-byte header.
	buf := bytes.NewBuffer([]byte{0x03, 0x00, 0x00, 0x14})
	if _, err := readTPKT(bufio.NewReader(buf)); err == nil {
		t.Fatal("expected an error for a truncated TPKT payload, got nil")
	}
}

func TestReadTPKTDoesNotPanicOnEmptyInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("readTPKT panicked on empty input: %v", r)
		}
	}()
	buf := bytes.NewBuffer(nil)
	if _, err := readTPKT(bufio.NewReader(buf)); err == nil {
		t.Fatal("expected an error for empty input, got nil")
	}
}
