package mysql

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// threat_gg-cb0 follow-up. The unit tests in capture_test.go build a session by hand, so
// they prove persistSession's behaviour but NOT the wiring that fills it in: if
// handleConnection stopped assigning sess.scramble or sess.authData, every one of them
// would still pass while production captured nothing again -- the exact failure this issue
// exists to fix.
//
// This drives a real connection end to end over net.Pipe and asserts that the scramble the
// server actually put on the wire, and the auth reply the client actually sent, are the
// two halves of the stored credential.
func TestConnectionCapturesCredentialAndQuery(t *testing.T) {
	rec := withRecorder(t)
	done := make(chan struct{})

	server, client := net.Pipe()
	h := &honeypot{logger: zerolog.Nop()}
	go func() {
		h.handleConnection(server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(client)

	greeting, _, err := readPacket(reader)
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	advertised := scrambleFromGreeting(t, greeting)

	authData := make([]byte, 20)
	for i := range authData {
		authData[i] = byte(0xA0 + i)
	}
	if err := writePacket(client, 1, buildClientAuthPacket("root", authData)); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	if _, _, err := readPacket(reader); err != nil { // server OK
		t.Fatalf("read auth OK: %v", err)
	}

	const query = "CREATE USER 'evil'@'%' IDENTIFIED BY 'hunter2'"
	if err := writePacket(client, 0, append([]byte{comQuery}, query...)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	if _, _, err := readPacket(reader); err != nil {
		t.Fatalf("read query response: %v", err)
	}
	if err := writePacket(client, 0, []byte{comQuit}); err != nil {
		t.Fatalf("write quit: %v", err)
	}

	<-done
	client.Close()
	waitFor(t, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.logins) == 1 && len(rec.queries) == 1
	}, "login and query to be persisted")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	login := rec.logins[0]
	if login.Username != "root" {
		t.Errorf("username = %q, want root", login.Username)
	}
	if !strings.HasPrefix(login.Password, "$mysqlna$") {
		t.Fatalf("password = %q, want a $mysqlna$ artifact", login.Password)
	}
	// The stored artifact must be the full 20-byte scramble this connection advertised
	// paired with the exact reply the client sent. Asserting the whole value rather than a
	// prefix matters: a regression that kept the first 8 bytes but corrupted bytes 9-20
	// would still yield an uncrackable credential.
	want := "$mysqlna$" + hex.EncodeToString(advertised) + "*" + hex.EncodeToString(authData)
	if login.Password != want {
		t.Errorf("password = %q, want %q", login.Password, want)
	}
	if got := rec.queries[0]; got.Query != query || got.CommandType != "mysql" || got.Guid != login.Guid {
		t.Errorf("query captured as %+v, want %q/mysql sharing the login guid", got, query)
	}
}

// TestConnectionCapturesCredentialWhenClientHangsUpAfterAuth covers the case worth the
// most: a credential-spraying scanner sends its auth response and closes without waiting
// for the reply. Writing the OK packet then fails, and the bare return that used to follow
// skipped persistence entirely -- losing the credential precisely where we most want it.
func TestConnectionCapturesCredentialWhenClientHangsUpAfterAuth(t *testing.T) {
	rec := withRecorder(t)
	done := make(chan struct{})

	server, client := net.Pipe()
	h := &honeypot{logger: zerolog.Nop()}
	go func() {
		h.handleConnection(server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	greeting, _, err := readPacket(bufio.NewReader(client))
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	advertised := scrambleFromGreeting(t, greeting)

	authData := make([]byte, 20)
	for i := range authData {
		authData[i] = byte(i + 3)
	}
	if err := writePacket(client, 1, buildClientAuthPacket("admin", authData)); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	// Hang up without reading the OK packet.
	client.Close()
	<-done

	waitFor(t, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.logins) == 1
	}, "the credential to be persisted despite the client hanging up")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	want := "$mysqlna$" + hex.EncodeToString(advertised) + "*" + hex.EncodeToString(authData)
	if got := rec.logins[0].Password; got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
	if rec.logins[0].Username != "admin" {
		t.Errorf("username = %q, want admin", rec.logins[0].Username)
	}
}

// A connection that opens and disconnects without authenticating must still persist
// nothing, so ordinary port scans do not manufacture attacker rows.
func TestConnectionWithoutAuthPersistsNothing(t *testing.T) {
	rec := withRecorder(t)
	done := make(chan struct{})

	server, client := net.Pipe()
	h := &honeypot{logger: zerolog.Nop()}
	go func() {
		h.handleConnection(server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := readPacket(bufio.NewReader(client)); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	client.Close()
	<-done

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.logins) != 0 || len(rec.queries) != 0 {
		t.Errorf("bare scan persisted %d logins, %d queries", len(rec.logins), len(rec.queries))
	}
}

// scrambleFromGreeting reassembles the full 20-byte scramble a HandshakeV10 greeting
// advertises. MySQL splits it: 8 bytes early, the remaining 12 after the status and
// capability fields, which is why a test that reads only the first fragment can miss a
// corrupted tail.
func scrambleFromGreeting(t *testing.T, greeting []byte) []byte {
	t.Helper()
	// part 1: protocol version (1) + server version + NUL + connection id (4)
	p1 := 1 + len(serverVersion) + 1 + 4
	// part 2: part 1 (8) + filler (1) + capability low (2) + charset (1) +
	//         status (2) + capability high (2) + auth data length (1) + reserved (10)
	p2 := p1 + 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
	if len(greeting) < p2+12 {
		t.Fatalf("greeting too short to hold a scramble: %d bytes", len(greeting))
	}
	full := make([]byte, 0, 20)
	full = append(full, greeting[p1:p1+8]...)
	full = append(full, greeting[p2:p2+12]...)
	return full
}

// buildClientAuthPacket assembles the HandshakeResponse41 layout parseHandshakeResponse
// expects: 4 capability bytes, 4 max-packet bytes, 1 charset byte, 23 reserved, the
// null-terminated username, then a length-prefixed auth response.
func buildClientAuthPacket(username string, authData []byte) []byte {
	buf := make([]byte, 0, 64)
	caps := make([]byte, 4)
	binary.LittleEndian.PutUint32(caps, clientProtocol41|clientSecureConn|clientPluginAuth)
	buf = append(buf, caps...)
	buf = append(buf, make([]byte, 4)...) // max packet size
	buf = append(buf, charsetUTF8MB4)
	buf = append(buf, make([]byte, 23)...) // reserved
	buf = append(buf, username...)
	buf = append(buf, 0x00)
	buf = append(buf, byte(len(authData)))
	buf = append(buf, authData...)
	return buf
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
