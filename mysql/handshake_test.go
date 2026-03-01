package mysql

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildHandshakeV10(t *testing.T) {
	pkt, err := buildHandshakeV10(42)
	if err != nil {
		t.Fatalf("buildHandshakeV10 failed: %v", err)
	}

	// Protocol version
	if pkt[0] != 10 {
		t.Fatalf("expected protocol version 10, got %d", pkt[0])
	}

	// Server version (null-terminated)
	verEnd := bytes.IndexByte(pkt[1:], 0x00)
	if verEnd < 0 {
		t.Fatal("server version not null-terminated")
	}
	ver := string(pkt[1 : 1+verEnd])
	if ver != "8.0.35-0ubuntu0.24.04.1" {
		t.Fatalf("expected server version '8.0.35-0ubuntu0.24.04.1', got %q", ver)
	}

	// Connection ID
	connIDOffset := 1 + verEnd + 1
	connID := binary.LittleEndian.Uint32(pkt[connIDOffset:])
	if connID != 42 {
		t.Fatalf("expected connection ID 42, got %d", connID)
	}
}

func TestBuildHandshakeV10_ScrambleLength(t *testing.T) {
	pkt1, _ := buildHandshakeV10(1)
	pkt2, _ := buildHandshakeV10(2)

	// Two calls should produce different scramble data (random)
	// Find scramble part 1 location (after connID, 4 bytes)
	verEnd := bytes.IndexByte(pkt1[1:], 0x00) + 1
	scramble1Start := 1 + verEnd + 4
	scramble1 := pkt1[scramble1Start : scramble1Start+8]

	verEnd2 := bytes.IndexByte(pkt2[1:], 0x00) + 1
	scramble2Start := 1 + verEnd2 + 4
	scramble2 := pkt2[scramble2Start : scramble2Start+8]

	if bytes.Equal(scramble1, scramble2) {
		t.Fatal("expected different scramble data for different calls")
	}
}

func TestParseHandshakeResponse(t *testing.T) {
	// Construct a minimal HandshakeResponse41
	buf := make([]byte, 0, 128)

	// Capability flags (4 bytes)
	caps := make([]byte, 4)
	binary.LittleEndian.PutUint32(caps, clientProtocol41|clientConnectWithDB)
	buf = append(buf, caps...)

	// Max packet size (4 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)

	// Character set (1 byte)
	buf = append(buf, charsetUTF8MB4)

	// Reserved (23 bytes)
	buf = append(buf, make([]byte, 23)...)

	// Username (null-terminated)
	buf = append(buf, []byte("admin")...)
	buf = append(buf, 0x00)

	// Auth data (length-encoded)
	authData := []byte{0x01, 0x02, 0x03, 0x04}
	buf = append(buf, byte(len(authData)))
	buf = append(buf, authData...)

	// Database (null-terminated)
	buf = append(buf, []byte("production")...)
	buf = append(buf, 0x00)

	creds := parseHandshakeResponse(buf)

	if creds.username != "admin" {
		t.Fatalf("expected username 'admin', got %q", creds.username)
	}
	if creds.database != "production" {
		t.Fatalf("expected database 'production', got %q", creds.database)
	}
	if len(creds.authData) != 4 {
		t.Fatalf("expected 4 bytes auth data, got %d", len(creds.authData))
	}
}

func TestParseHandshakeResponse_NoDatabase(t *testing.T) {
	buf := make([]byte, 0, 64)

	// Capability flags
	caps := make([]byte, 4)
	binary.LittleEndian.PutUint32(caps, clientProtocol41)
	buf = append(buf, caps...)

	// Max packet size
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)

	// Character set
	buf = append(buf, charsetUTF8MB4)

	// Reserved
	buf = append(buf, make([]byte, 23)...)

	// Username
	buf = append(buf, []byte("root")...)
	buf = append(buf, 0x00)

	// Auth data (empty)
	buf = append(buf, 0x00)

	creds := parseHandshakeResponse(buf)

	if creds.username != "root" {
		t.Fatalf("expected username 'root', got %q", creds.username)
	}
	if creds.database != "" {
		t.Fatalf("expected empty database, got %q", creds.database)
	}
}

func TestSendHandshake(t *testing.T) {
	var buf bytes.Buffer
	err := sendHandshake(&buf, 100)
	if err != nil {
		t.Fatalf("sendHandshake failed: %v", err)
	}
	if buf.Len() < 4 {
		t.Fatal("handshake packet too short")
	}

	// Read the packet back
	payload, seqID, err := readPacket(&buf)
	if err != nil {
		t.Fatalf("readPacket failed: %v", err)
	}
	if seqID != 0 {
		t.Fatalf("expected seqID=0, got %d", seqID)
	}
	if payload[0] != protocolVersion {
		t.Fatalf("expected protocol version %d, got %d", protocolVersion, payload[0])
	}
}
