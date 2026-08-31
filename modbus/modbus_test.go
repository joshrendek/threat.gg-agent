package modbus

import (
	"bufio"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// startTestHoneypot binds an ephemeral (":0") listener and serves it in the
// background, returning the address to dial. Mirrors s7comm's
// startTestHoneypot.
func startTestHoneypot(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	hp := New().(*honeypot)
	go hp.serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr()
}

func dialTest(t *testing.T, addr net.Addr) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

// buildRequest wraps pdu in an MBAP header with the given transaction id
// and unit id -- the request-side counterpart to writeMBAP, built directly
// from the wire format rather than reusing writeMBAP so a test failure in
// framing can't hide behind the same code it's testing.
func buildRequest(transactionID uint16, unitID byte, pdu []byte) []byte {
	buf := make([]byte, mbapHeaderLen+len(pdu))
	binary.BigEndian.PutUint16(buf[0:2], transactionID)
	binary.BigEndian.PutUint16(buf[2:4], 0x0000)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(pdu)+1))
	buf[6] = unitID
	copy(buf[7:], pdu)
	return buf
}

// exchange writes a full MBAP+PDU request and reads back exactly one
// MBAP+PDU response, returning the parsed header and PDU.
func exchange(t *testing.T, conn net.Conn, req []byte) (mbapHeader, []byte) {
	t.Helper()
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	hdr, pdu, err := readMBAP(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("readMBAP: %v", err)
	}
	return hdr, pdu
}

// TestFullSessionOverRealTCP drives a realistic exchange over an actual TCP
// connection: a holding-register read, a holding-register write, and Read
// Device Identification, asserting byte-level correctness of each response
// -- exactly the sequence a real Modbus master (or a scanner like
// mbtget/nmap's modbus-discover) performs against a live device.
func TestFullSessionOverRealTCP(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	// --- Read Holding Registers: addr=10, qty=2 ---
	readReq := buildRequest(0x0001, 0xFF, []byte{fnReadHoldingRegs, 0x00, 0x0A, 0x00, 0x02})
	hdr, respPDU := exchange(t, conn, readReq)

	if hdr.transactionID != 0x0001 {
		t.Errorf("transaction id = 0x%04X, want 0x0001 (must echo the request)", hdr.transactionID)
	}
	if hdr.unitID != 0xFF {
		t.Errorf("unit id = 0x%02X, want 0xFF (must echo the request)", hdr.unitID)
	}
	if len(respPDU) != 6 || respPDU[0] != fnReadHoldingRegs || respPDU[1] != 4 {
		t.Fatalf("read holding regs response = % x, want function=0x03 byteCount=4 + 4 bytes", respPDU)
	}

	// --- Write Single Register: addr=10, value=0x1234 ---
	writeReq := buildRequest(0x0002, 0xFF, []byte{fnWriteSingleReg, 0x00, 0x0A, 0x12, 0x34})
	_, writeResp := exchange(t, conn, writeReq)
	if len(writeResp) != 5 || writeResp[0] != fnWriteSingleReg {
		t.Fatalf("write single reg response = % x, want the echoed request", writeResp)
	}
	wantWriteResp := []byte{fnWriteSingleReg, 0x00, 0x0A, 0x12, 0x34}
	for i := range wantWriteResp {
		if writeResp[i] != wantWriteResp[i] {
			t.Fatalf("write single reg response = % x, want % x (echoed)", writeResp, wantWriteResp)
		}
	}

	// --- Read back the same register: must now return what was just written ---
	readBackReq := buildRequest(0x0003, 0xFF, []byte{fnReadHoldingRegs, 0x00, 0x0A, 0x00, 0x01})
	_, readBackResp := exchange(t, conn, readBackReq)
	if len(readBackResp) != 4 {
		t.Fatalf("read-back response = % x, want 4 bytes (function+byteCount+1 register)", readBackResp)
	}
	gotValue := binary.BigEndian.Uint16(readBackResp[2:4])
	if gotValue != 0x1234 {
		t.Errorf("read-back value = 0x%04X, want 0x1234 (the value just written)", gotValue)
	}

	// --- Read Device Identification: Basic (code 1) ---
	deviceIDReq := buildRequest(0x0004, 0xFF, []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDBasic, 0x00})
	_, deviceIDResp := exchange(t, conn, deviceIDReq)

	if deviceIDResp[0] != fnReadDeviceID {
		t.Fatalf("read device id response function = 0x%02X, want 0x2B", deviceIDResp[0])
	}
	if deviceIDResp[1] != meiTypeReadDeviceID {
		t.Errorf("MEI type = 0x%02X, want 0x0E", deviceIDResp[1])
	}
	if deviceIDResp[2] != readDeviceIDBasic {
		t.Errorf("read device id code echoed = 0x%02X, want 0x01 (Basic)", deviceIDResp[2])
	}
	if deviceIDResp[3] != conformityRegularIndividual {
		t.Errorf("conformity level = 0x%02X, want 0x%02X", deviceIDResp[3], conformityRegularIndividual)
	}
	numObjects := deviceIDResp[6]
	if numObjects != 3 {
		t.Fatalf("Basic response numObjects = %d, want 3", numObjects)
	}
	offset := 7
	objID, objLen := deviceIDResp[offset], int(deviceIDResp[offset+1])
	gotVendor := string(deviceIDResp[offset+2 : offset+2+objLen])
	if objID != objVendorName || gotVendor != VendorName {
		t.Errorf("first object = id=0x%02X value=%q, want id=0x00 value=%q", objID, gotVendor, VendorName)
	}
}

// TestMalformedMBAPLayerClosesConnection sends a byte stream with an
// invalid protocol identifier and confirms the honeypot neither panics nor
// hangs: the connection closes.
func TestMalformedMBAPLayerClosesConnection(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	hdr := make([]byte, 7)
	binary.BigEndian.PutUint16(hdr[0:2], 1)
	binary.BigEndian.PutUint16(hdr[2:4], 0x1234) // invalid protocol id, must not be accepted
	binary.BigEndian.PutUint16(hdr[4:6], 2)
	hdr[6] = 0xFF
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertConnectionCloses(t, conn)
}

// TestOversizedLengthClosesConnectionNotPanics sends an MBAP header
// claiming a length far larger than maxLength allows.
func TestOversizedLengthClosesConnectionNotPanics(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	hdr := make([]byte, 7)
	binary.BigEndian.PutUint16(hdr[0:2], 1)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0000)
	binary.BigEndian.PutUint16(hdr[4:6], 0xFFFF)
	hdr[6] = 0xFF
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertConnectionCloses(t, conn)
}

// TestTruncatedFrameClosesConnectionNotPanics sends a syntactically valid
// MBAP header promising more PDU bytes than are ever sent, then half-closes
// its write side so the honeypot's blocked read sees EOF immediately rather
// than waiting out the idle deadline -- confirming truncated input at the
// MBAP/PDU boundary closes the connection rather than hanging or panicking.
func TestTruncatedFrameClosesConnectionNotPanics(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	hdr := make([]byte, 7)
	binary.BigEndian.PutUint16(hdr[0:2], 1)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0000)
	binary.BigEndian.PutUint16(hdr[4:6], 10) // promises 9 more PDU bytes
	hdr[6] = 0xFF
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := conn.Write([]byte{fnReadHoldingRegs}); err != nil { // only 1 of the promised 9 bytes
		t.Fatalf("write: %v", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}

	assertConnectionCloses(t, conn)
}

func assertConnectionCloses(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected the connection to close or the read to fail after malformed/truncated input, but the read succeeded")
	}
}
