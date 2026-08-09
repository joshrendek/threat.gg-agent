package mysql

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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
	// authPlugin is the plugin the client says it used, when it advertised
	// CLIENT_PLUGIN_AUTH. Empty means it named none. It decides whether authData may be
	// labelled a mysql_native_password hash: a 20-byte reply proves nothing on its own,
	// and a mysql_clear_password reply of that length is a plaintext password that must
	// never be stored as though it were a digest.
	authPlugin string
}

// buildHandshakeV10 constructs the server greeting packet and returns the per-connection
// scramble it embedded. The scramble is returned rather than kept internal because the
// client's auth reply is only meaningful when paired with it: mysql_native_password sends
// SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw))), so the reply alone cannot be cracked.
// See nativePasswordArtifact (threat_gg-cb0).
func buildHandshakeV10(connID uint32) ([]byte, []byte, error) {
	scramble := make([]byte, 20)
	if _, err := rand.Read(scramble); err != nil {
		return nil, nil, err
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

	return buf, scramble, nil
}

// parseHandshakeResponse extracts credentials from the client's auth packet.
func parseHandshakeResponse(payload []byte) credentials {
	creds := credentials{}
	if len(payload) < 32 {
		return creds
	}

	offset := 0

	// Capability flags (4 bytes)
	capFlags := binary.LittleEndian.Uint32(payload[offset:])
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

	// Database (null-terminated, present only when the client asked to connect with one).
	// The flag is honoured rather than assumed because the auth plugin name follows, and
	// reading the database when there is none would consume it.
	if capFlags&clientConnectWithDB != 0 && offset < len(payload) {
		dbEnd := offset
		for dbEnd < len(payload) && payload[dbEnd] != 0x00 {
			dbEnd++
		}
		if dbEnd > offset {
			creds.database = string(payload[offset:dbEnd])
		}
		offset = dbEnd + 1
	}

	// Auth plugin name (null-terminated, present only when the client advertised
	// CLIENT_PLUGIN_AUTH).
	if capFlags&clientPluginAuth != 0 && offset < len(payload) {
		pluginEnd := offset
		for pluginEnd < len(payload) && payload[pluginEnd] != 0x00 {
			pluginEnd++
		}
		if pluginEnd > offset {
			creds.authPlugin = string(payload[offset:pluginEnd])
		}
	}

	return creds
}

// sendHandshake writes the HandshakeV10 greeting and returns the scramble it advertised,
// which the caller must retain to make sense of the client's auth reply.
func sendHandshake(w io.Writer, connID uint32) ([]byte, error) {
	greeting, scramble, err := buildHandshakeV10(connID)
	if err != nil {
		return nil, err
	}
	if err := writePacket(w, 0, greeting); err != nil {
		return nil, err
	}
	return scramble, nil
}

// nativePasswordArtifact renders a captured mysql_native_password exchange in hashcat's
// -m 11200 format ("$mysqlna$<scramble>*<response>").
//
// The tagged format is deliberate. This value lands in attackers.password, a column that
// holds plaintext for ssh/telnet/postgres, so an untagged 40-hex blob would eventually be
// read as a password someone actually typed. The $mysqlna$ prefix says what it is, and it
// is the format a cracker consumes without conversion.
//
// Returns empty unless both halves are exactly 20 bytes AND the client either named
// mysql_native_password or named no plugin at all. Length alone is not proof: a
// mysql_clear_password reply that happens to be 20 bytes is a plaintext password, and
// hex-encoding it under a $mysqlna$ label would both misdescribe it and bury it.
func nativePasswordArtifact(scramble, authData []byte, authPlugin string) string {
	if len(scramble) != 20 || len(authData) != 20 {
		return ""
	}
	// An empty plugin name means the client named none, which under the protocol means it
	// used the plugin the server advertised -- and the greeting only ever advertises
	// mysql_native_password. Treating it as native is therefore the protocol-correct read,
	// not a permissive fallback. It does mean a client that omits CLIENT_PLUGIN_AUTH and
	// sends 20 bytes of something else is taken at its word, which is the same trust any
	// real server extends; if the advertised plugin ever changes (threat_gg-dpk), this
	// default must change with it.
	if authPlugin != "" && authPlugin != authPluginName {
		return ""
	}
	return "$mysqlna$" + hex.EncodeToString(scramble) + "*" + hex.EncodeToString(authData)
}
