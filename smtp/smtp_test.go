package smtp

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func startTestServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func dial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	// Read banner
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("expected 220 banner, got: %s", line)
	}
	return conn, reader
}

func send(t *testing.T, conn net.Conn, reader *bufio.Reader, cmd string) string {
	t.Helper()
	fmt.Fprintf(conn, "%s\r\n", cmd)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("error reading after %q: %v", cmd, err)
	}
	return strings.TrimRight(line, "\r\n")
}

func sendRaw(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	fmt.Fprint(conn, data)
}

func readLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(line, "\r\n")
}

func readMultiLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		trimmed := strings.TrimRight(line, "\r\n")
		lines = append(lines, trimmed)
		// Multi-line responses have "-" after code; last line has space
		if len(trimmed) >= 4 && trimmed[3] == ' ' {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func TestFullEmailLifecycle(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	// EHLO
	fmt.Fprintf(conn, "EHLO test.example.com\r\n")
	ehlo := readMultiLine(t, reader)
	if !strings.Contains(ehlo, "250") {
		t.Fatalf("expected 250 in EHLO response, got: %s", ehlo)
	}
	if !strings.Contains(ehlo, "AUTH LOGIN PLAIN") {
		t.Fatalf("expected AUTH LOGIN PLAIN in EHLO response, got: %s", ehlo)
	}

	// AUTH LOGIN
	resp := send(t, conn, reader, "AUTH LOGIN")
	if !strings.HasPrefix(resp, "334") {
		t.Fatalf("expected 334 for AUTH LOGIN, got: %s", resp)
	}

	// Username
	resp = send(t, conn, reader, base64.StdEncoding.EncodeToString([]byte("admin")))
	if !strings.HasPrefix(resp, "334") {
		t.Fatalf("expected 334 for password prompt, got: %s", resp)
	}

	// Password
	resp = send(t, conn, reader, base64.StdEncoding.EncodeToString([]byte("secret")))
	if !strings.HasPrefix(resp, "235") {
		t.Fatalf("expected 235 auth success, got: %s", resp)
	}

	// MAIL FROM
	resp = send(t, conn, reader, "MAIL FROM:<attacker@evil.com>")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250 for MAIL FROM, got: %s", resp)
	}

	// RCPT TO
	resp = send(t, conn, reader, "RCPT TO:<victim@corp.com>")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250 for RCPT TO, got: %s", resp)
	}

	// DATA
	resp = send(t, conn, reader, "DATA")
	if !strings.HasPrefix(resp, "354") {
		t.Fatalf("expected 354 for DATA, got: %s", resp)
	}

	// Message body
	sendRaw(t, conn, "Subject: Test Phish\r\nFrom: attacker@evil.com\r\n\r\nClick here for free stuff\r\n.\r\n")
	resp = readLine(t, reader)
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250 after DATA, got: %s", resp)
	}

	// QUIT
	resp = send(t, conn, reader, "QUIT")
	if !strings.HasPrefix(resp, "221") {
		t.Fatalf("expected 221 for QUIT, got: %s", resp)
	}
}

func TestOpenRelayAttempt(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	// Skip AUTH, go straight to MAIL FROM
	fmt.Fprintf(conn, "EHLO scanner.net\r\n")
	readMultiLine(t, reader)

	resp := send(t, conn, reader, "MAIL FROM:<spam@evil.com>")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250, got: %s", resp)
	}

	resp = send(t, conn, reader, "RCPT TO:<victim@target.com>")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250, got: %s", resp)
	}

	resp = send(t, conn, reader, "DATA")
	if !strings.HasPrefix(resp, "354") {
		t.Fatalf("expected 354, got: %s", resp)
	}

	sendRaw(t, conn, "Subject: Buy stuff\r\n\r\nSpam body\r\n.\r\n")
	resp = readLine(t, reader)
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250, got: %s", resp)
	}

	send(t, conn, reader, "QUIT")
}

func TestCredentialBruteForce(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	fmt.Fprintf(conn, "EHLO brute.net\r\n")
	readMultiLine(t, reader)

	for i := 0; i < 3; i++ {
		resp := send(t, conn, reader, "AUTH LOGIN")
		if !strings.HasPrefix(resp, "334") {
			t.Fatalf("attempt %d: expected 334, got: %s", i, resp)
		}

		resp = send(t, conn, reader, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("user%d", i))))
		if !strings.HasPrefix(resp, "334") {
			t.Fatalf("attempt %d: expected 334 password prompt, got: %s", i, resp)
		}

		resp = send(t, conn, reader, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pass%d", i))))
		if !strings.HasPrefix(resp, "235") {
			t.Fatalf("attempt %d: expected 235, got: %s", i, resp)
		}
	}

	send(t, conn, reader, "QUIT")
}

func TestMaxRecipients(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	fmt.Fprintf(conn, "EHLO test.com\r\n")
	readMultiLine(t, reader)

	send(t, conn, reader, "MAIL FROM:<sender@test.com>")

	for i := 0; i < maxRecipients; i++ {
		resp := send(t, conn, reader, fmt.Sprintf("RCPT TO:<user%d@test.com>", i))
		if !strings.HasPrefix(resp, "250") {
			t.Fatalf("rcpt %d: expected 250, got: %s", i, resp)
		}
	}

	// The 51st should be rejected
	resp := send(t, conn, reader, "RCPT TO:<overflow@test.com>")
	if !strings.HasPrefix(resp, "452") {
		t.Fatalf("expected 452 too many recipients, got: %s", resp)
	}

	send(t, conn, reader, "QUIT")
}

func TestIdleTimeout(t *testing.T) {
	// Override idle timeout for test
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Set a very short timeout for testing
				c.SetDeadline(time.Now().Add(200 * time.Millisecond))
				writer := bufio.NewWriter(c)
				reader := bufio.NewReader(c)
				writeLine(writer, banner)

				for {
					c.SetDeadline(time.Now().Add(200 * time.Millisecond))
					_, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					writeLine(writer, "250 OK")
				}
			}(c)
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	readLine(t, reader) // banner

	// Wait longer than the timeout
	time.Sleep(500 * time.Millisecond)

	_, writeErr := fmt.Fprintf(conn, "EHLO test.com\r\n")
	if writeErr != nil {
		return // connection closed as expected
	}

	_, readErr := reader.ReadString('\n')
	if readErr == nil {
		t.Fatal("expected connection to be closed after idle timeout")
	}
}

func TestRSET(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	fmt.Fprintf(conn, "EHLO test.com\r\n")
	readMultiLine(t, reader)

	send(t, conn, reader, "MAIL FROM:<a@b.com>")
	send(t, conn, reader, "RCPT TO:<c@d.com>")

	resp := send(t, conn, reader, "RSET")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250 for RSET, got: %s", resp)
	}

	// After RSET, we should be able to start a new envelope
	resp = send(t, conn, reader, "MAIL FROM:<new@sender.com>")
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("expected 250 for new MAIL FROM after RSET, got: %s", resp)
	}

	send(t, conn, reader, "QUIT")
}

func TestSTARTTLS(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	fmt.Fprintf(conn, "EHLO test.com\r\n")
	readMultiLine(t, reader)

	resp := send(t, conn, reader, "STARTTLS")
	if !strings.HasPrefix(resp, "220") {
		t.Fatalf("expected 220 for STARTTLS, got: %s", resp)
	}

	// Connection should close after STARTTLS (no real TLS)
	_, err := reader.ReadString('\n')
	if err == nil {
		t.Fatal("expected connection to close after STARTTLS")
	}
}

func TestVRFY(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	fmt.Fprintf(conn, "EHLO test.com\r\n")
	readMultiLine(t, reader)

	resp := send(t, conn, reader, "VRFY root")
	if !strings.HasPrefix(resp, "252") {
		t.Fatalf("expected 252 for VRFY, got: %s", resp)
	}

	resp = send(t, conn, reader, "EXPN admins")
	if !strings.HasPrefix(resp, "252") {
		t.Fatalf("expected 252 for EXPN, got: %s", resp)
	}

	send(t, conn, reader, "QUIT")
}

func TestAuthPlain(t *testing.T) {
	addr, cleanup := startTestServer(t)
	defer cleanup()

	conn, reader := dial(t, addr)
	defer conn.Close()

	fmt.Fprintf(conn, "EHLO test.com\r\n")
	readMultiLine(t, reader)

	cred := base64.StdEncoding.EncodeToString([]byte("\x00admin\x00password123"))
	resp := send(t, conn, reader, "AUTH PLAIN "+cred)
	if !strings.HasPrefix(resp, "235") {
		t.Fatalf("expected 235 for AUTH PLAIN, got: %s", resp)
	}

	send(t, conn, reader, "QUIT")
}

func TestDualPortListening(t *testing.T) {
	// Start two listeners on random ports to simulate dual-port
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	handler := func(ln net.Listener) {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConnection(c)
		}
	}
	go handler(ln1)
	go handler(ln2)

	// Verify both accept connections
	for _, addr := range []string{ln1.Addr().String(), ln2.Addr().String()} {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to connect to %s: %v", addr, err)
		}
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			t.Fatalf("failed to read banner from %s: %v", addr, err)
		}
		if !strings.HasPrefix(line, "220") {
			conn.Close()
			t.Fatalf("expected 220 banner from %s, got: %s", addr, line)
		}
		conn.Close()
	}
}
