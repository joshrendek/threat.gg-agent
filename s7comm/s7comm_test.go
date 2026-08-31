package s7comm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// startTestHoneypot binds an ephemeral (":0") listener and serves it in the
// background, returning the address to dial and a cleanup func.
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

// exchange writes a TPKT frame and reads back exactly one TPKT frame's
// payload.
func exchange(t *testing.T, conn net.Conn, out []byte) []byte {
	t.Helper()
	if err := writeTPKT(conn, out); err != nil {
		t.Fatalf("writeTPKT: %v", err)
	}
	in, err := readTPKT(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("readTPKT: %v", err)
	}
	return in
}

// TestFullSessionOverRealTCP drives an entire realistic exchange over an
// actual TCP connection: COTP CR -> CC, S7 Setup Communication, and Read SZL
// 0x001C (component identification), asserting byte-level correctness of
// each response -- exactly the sequence a real S7 client (or nmap's
// s7-info/plcscan) performs against a live device.
func TestFullSessionOverRealTCP(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	// --- COTP Connect Request -> Connect Confirm ---
	srcTSAP := []byte{0x01, 0x00}
	dstTSAP := []byte{0x03, 0x02} // rack 0, slot 2 -- the conventional PLC CPU slot
	cr := buildTestCR(0xAAAA, srcTSAP, dstTSAP, 0x0A)
	ccBytes := exchange(t, conn, cr)

	if len(ccBytes) < 7 || ccBytes[1] != cotpCC {
		t.Fatalf("expected a COTP CC TPDU, got % x", ccBytes)
	}
	dstRef := uint16(ccBytes[2])<<8 | uint16(ccBytes[3])
	if dstRef != 0xAAAA {
		t.Errorf("CC dst-ref = 0x%04x, want the CR's src-ref 0xAAAA", dstRef)
	}

	// --- S7 Setup Communication ---
	setupParam := []byte{fnSetupComm, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0}
	setupDT := buildDT(buildS7Header(rosctrJob, 0x0001, 0, 0, setupParam, nil))
	setupRespDT := exchange(t, conn, setupDT)

	s7Resp, err := parseDT(setupRespDT)
	if err != nil {
		t.Fatalf("parseDT(setup response): %v", err)
	}
	hdr, body, err := parseS7Header(s7Resp)
	if err != nil {
		t.Fatalf("parseS7Header(setup response): %v", err)
	}
	if hdr.rosctr != rosctrAckData || hdr.pduRef != 0x0001 {
		t.Fatalf("setup response header = %+v, want Ack_Data/pduRef=1", hdr)
	}
	param := body[:hdr.parLen]
	wantParam := []byte{
		fnSetupComm, 0x00,
		0x00, byte(MaxAMQCalling),
		0x00, byte(MaxAMQCalled),
		byte(NegotiatedPDULength >> 8), byte(NegotiatedPDULength),
	}
	if !bytes.Equal(param, wantParam) {
		t.Errorf("setup communication response param = % x, want % x", param, wantParam)
	}

	// --- Read SZL 0x001C index 0x0001 (automation system name) ---
	szlReq := buildReadSZLRequest(0x0002, szlComponentIdent, 0x0001)
	szlReqDT := buildDT(szlReq)
	szlRespDT := exchange(t, conn, szlReqDT)

	szlS7Resp, err := parseDT(szlRespDT)
	if err != nil {
		t.Fatalf("parseDT(SZL response): %v", err)
	}
	resp := parseSZLResponse(t, szlS7Resp)
	if resp.retVal != itemRetvalOK {
		t.Fatalf("SZL response retVal = 0x%02x, want success", resp.retVal)
	}
	if resp.szlID != szlComponentIdent || resp.szlIx != 0x0001 {
		t.Errorf("echoed SZL-ID/Index = 0x%04x/0x%04x, want 0x001c/0x0001", resp.szlID, resp.szlIx)
	}
	gotName := string(resp.records[0][2 : 2+24])
	wantName := string(padASCII(SystemName, 24))
	if gotName != wantName {
		t.Errorf("SZL 0x001C/0x0001 name = %q, want %q", gotName, wantName)
	}
}

// TestMalformedTPKTLayerClosesConnection sends a byte stream that never
// forms a valid TPKT frame and confirms the honeypot neither panics nor
// hangs: the connection is closed (reads return EOF/error).
func TestMalformedTPKTLayerClosesConnection(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	// Version byte 0x99 is not a valid TPKT version.
	if _, err := conn.Write([]byte{0x99, 0x00, 0x00, 0x04}); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertConnectionCloses(t, conn)
}

// TestMalformedCOTPLayerClosesConnection sends a syntactically valid TPKT
// frame wrapping a COTP TPDU with an invalid type byte, and confirms the
// connection is closed rather than hanging or the process panicking.
func TestMalformedCOTPLayerClosesConnection(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	garbage := []byte{0x02, 0x77, 0x00} // LI=2, type=0x77 (not CR/CC/DT), pad
	if err := writeTPKT(conn, garbage); err != nil {
		t.Fatalf("writeTPKT: %v", err)
	}
	assertConnectionCloses(t, conn)
}

// TestMalformedS7HeaderLayerClosesConnection completes a real COTP handshake
// (so the S7 layer is actually reached) and then sends a COTP DT TPDU
// carrying garbage that isn't a valid S7 header, confirming the connection
// closes rather than hanging or crashing the process.
func TestMalformedS7HeaderLayerClosesConnection(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	cr := buildTestCR(1, []byte{0x01, 0x00}, []byte{0x03, 0x02}, 0x0A)
	if _, err := exchangeExpectOK(t, conn, cr); err != nil {
		t.Fatalf("COTP handshake failed: %v", err)
	}

	garbageS7 := bytes.Repeat([]byte{0xFF}, 6) // not even long enough for a minimal S7 header, and 0xFF != 0x32
	if err := writeTPKT(conn, buildDT(garbageS7)); err != nil {
		t.Fatalf("writeTPKT: %v", err)
	}
	assertConnectionCloses(t, conn)
}

// TestOversizedTPKTLengthClosesConnectionNotPanics sends a TPKT header
// claiming a length far larger than maxTPKTLength allows.
func TestOversizedTPKTLengthClosesConnectionNotPanics(t *testing.T) {
	addr := startTestHoneypot(t)
	conn := dialTest(t, addr)

	hdr := make([]byte, 4)
	hdr[0] = 0x03
	binary.BigEndian.PutUint16(hdr[2:4], 0xFFFF)
	if _, err := conn.Write(hdr); err != nil {
		t.Fatalf("write: %v", err)
	}
	assertConnectionCloses(t, conn)
}

// exchangeExpectOK writes out and reads back one TPKT frame's payload,
// returning any I/O error instead of failing the test (used where the
// caller wants to assert success itself).
func exchangeExpectOK(t *testing.T, conn net.Conn, out []byte) ([]byte, error) {
	t.Helper()
	if err := writeTPKT(conn, out); err != nil {
		return nil, err
	}
	return readTPKT(bufio.NewReader(conn))
}

// assertConnectionCloses confirms that reading from conn eventually returns
// an error (closed/reset/timeout) rather than hanging or panicking the
// honeypot process. It does not care WHICH error, only that the connection
// does not stay silently open forever.
func assertConnectionCloses(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected the connection to close or the read to fail after malformed input, but the read succeeded")
	}
}
