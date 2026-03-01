package mysql

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

const (
	protocolVersion = 10
	serverVersion   = "8.0.35-0ubuntu0.24.04.1"

	// Capability flags
	clientProtocol41    uint32 = 0x00000200
	clientSecureConn    uint32 = 0x00008000
	clientPluginAuth    uint32 = 0x00080000
	clientConnectWithDB uint32 = 0x00000008

	// Status flags
	serverStatusAutocommit uint16 = 0x0002

	// Character set
	charsetUTF8MB4 byte = 0x2D // 45

	authPluginName = "mysql_native_password"
)

// credentials holds parsed auth data from the client handshake response.
type credentials struct {
	username string
	database string
	authData []byte
}

// buildHandshakeV10 constructs the server greeting packet.
func buildHandshakeV10(connID uint32) ([]byte, error) {
	scramble := make([]byte, 20)
	if _, err := rand.Read(scramble); err != nil {
		return nil, err
	}

	capabilities := clientProtocol41 | clientSecureConn | clientPluginAuth | clientConnectWithDB
	capLow := uint16(capabilities & 0xFFFF)
	capHigh := uint16((capabilities >> 16) & 0xFFFF)

	buf := make([]byte, 0, 128)

	// Protocol version
	buf = append(buf, protocolVersion)

	// Server version (null-terminated)
	buf = append(buf, serverVersion...)
	buf = append(buf, 0x00)

	// Connection ID
	connIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(connIDBytes, connID)
	buf = append(buf, connIDBytes...)

	// Auth plugin data part 1 (8 bytes)
	buf = append(buf, scramble[:8]...)

	// Filler
	buf = append(buf, 0x00)

	// Capability flags (lower 2 bytes)
	buf = append(buf, byte(capLow), byte(capLow>>8))

	// Character set
	buf = append(buf, charsetUTF8MB4)

	// Status flags
	buf = append(buf, byte(serverStatusAutocommit), byte(serverStatusAutocommit>>8))

	// Capability flags (upper 2 bytes)
	buf = append(buf, byte(capHigh), byte(capHigh>>8))

	// Auth plugin data length (total = 20 + 1 null)
	buf = append(buf, 21)

	// Reserved (10 bytes of zeros)
	buf = append(buf, make([]byte, 10)...)

	// Auth plugin data part 2 (12 bytes + null terminator)
	buf = append(buf, scramble[8:20]...)
	buf = append(buf, 0x00)

	// Auth plugin name (null-terminated)
	buf = append(buf, authPluginName...)
	buf = append(buf, 0x00)

	return buf, nil
}

// parseHandshakeResponse extracts credentials from the client's auth packet.
func parseHandshakeResponse(payload []byte) credentials {
	creds := credentials{}
	if len(payload) < 32 {
		return creds
	}

	offset := 0

	// Capability flags (4 bytes)
	_ = binary.LittleEndian.Uint32(payload[offset:])
	offset += 4

	// Max packet size (4 bytes)
	offset += 4

	// Character set (1 byte)
	offset += 1

	// Reserved (23 bytes)
	offset += 23

	// Username (null-terminated)
	usernameEnd := offset
	for usernameEnd < len(payload) && payload[usernameEnd] != 0x00 {
		usernameEnd++
	}
	if usernameEnd > offset {
		creds.username = string(payload[offset:usernameEnd])
	}
	offset = usernameEnd + 1

	if offset >= len(payload) {
		return creds
	}

	// Auth data (length-encoded)
	authLen := int(payload[offset])
	offset++
	if offset+authLen <= len(payload) {
		creds.authData = payload[offset : offset+authLen]
		offset += authLen
	}

	// Database (null-terminated, optional)
	if offset < len(payload) {
		dbEnd := offset
		for dbEnd < len(payload) && payload[dbEnd] != 0x00 {
			dbEnd++
		}
		if dbEnd > offset {
			creds.database = string(payload[offset:dbEnd])
		}
	}

	return creds
}

// sendHandshake writes the HandshakeV10 greeting to the connection.
func sendHandshake(w io.Writer, connID uint32) error {
	greeting, err := buildHandshakeV10(connID)
	if err != nil {
		return err
	}
	return writePacket(w, 0, greeting)
}
