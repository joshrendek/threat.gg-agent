package mysql

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type packet struct {
	seq     uint8
	payload []byte
}

// splitPackets cuts a byte stream into MySQL packets, failing on a torn one.
func splitPackets(t *testing.T, b []byte) []packet {
	t.Helper()
	var out []packet
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		p, seq, err := readPacket(r)
		require.NoError(t, err)
		out = append(out, packet{seq, p})
	}
	return out
}

func strp(s string) *string { return &s }

func isEOF(p []byte) bool { return len(p) == 5 && p[0] == 0xFE }

// isOKAsEOF is the OK packet that ends a row stream under CLIENT_DEPRECATE_EOF:
// header 0xFE, affected rows, last insert id, status, warnings (7 bytes with
// both counts zero). Length < 9 is how a client tells it from a row whose
// first cell is a 0xFE length-encoded integer.
func isOKAsEOF(p []byte) bool { return len(p) >= 7 && len(p) < 9 && p[0] == 0xFE }

func requireConsecutive(t *testing.T, pkts []packet, first uint8) {
	t.Helper()
	for i, p := range pkts {
		require.Equal(t, first+uint8(i), p.seq, "packet %d sequence id", i)
	}
}

func TestResultSetDeprecateEOFFraming(t *testing.T) {
	cols := []columnDef{{Name: "name", ColType: 0xFD}}
	b, next, ok := encodeResultSet(1, cols, [][]*string{{strp("alice")}, {strp("bob")}}, true)
	require.True(t, ok)
	pkts := splitPackets(t, b)
	// count, column, row, row, terminator: no EOF between columns and rows.
	require.Len(t, pkts, 5)
	requireConsecutive(t, pkts, 1)
	require.Equal(t, uint8(6), next)
	require.Equal(t, []byte{0x01}, pkts[0].payload)
	require.Equal(t, append([]byte{5}, "alice"...), pkts[2].payload, "the first row follows the column definitions directly")
	require.Equal(t, append([]byte{3}, "bob"...), pkts[3].payload)
	require.True(t, isOKAsEOF(pkts[4].payload), "row stream ends with an OK packet carrying the 0xFE header: % x", pkts[4].payload)
	require.Equal(t, []byte{0xFE, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, pkts[4].payload, "0 affected, 0 insert id, AUTOCOMMIT, 0 warnings")
}

func TestResultSetClassicEOFFraming(t *testing.T) {
	cols := []columnDef{{Name: "name", ColType: 0xFD}}
	b, next, ok := encodeResultSet(1, cols, [][]*string{{strp("alice")}}, false)
	require.True(t, ok)
	pkts := splitPackets(t, b)
	// count, column, EOF, row, EOF.
	require.Len(t, pkts, 5)
	requireConsecutive(t, pkts, 1)
	require.Equal(t, uint8(6), next)
	require.True(t, isEOF(pkts[2].payload), "classic framing: EOF after the column definitions: % x", pkts[2].payload)
	require.Equal(t, append([]byte{5}, "alice"...), pkts[3].payload)
	require.Equal(t, []byte{0xFE, 0x00, 0x00, 0x02, 0x00}, pkts[4].payload, "EOF: 0 warnings, AUTOCOMMIT")
}

func TestResultSetEmptyFraming(t *testing.T) {
	cols := []columnDef{{Name: "id", ColType: 0x03}}
	b, _, ok := encodeResultSet(1, cols, nil, true)
	require.True(t, ok)
	pkts := splitPackets(t, b)
	require.Len(t, pkts, 3, "count, column, terminator")
	require.True(t, isOKAsEOF(pkts[2].payload))

	b, _, ok = encodeResultSet(1, cols, nil, false)
	require.True(t, ok)
	pkts = splitPackets(t, b)
	require.Len(t, pkts, 4, "count, column, EOF, EOF")
	require.True(t, isEOF(pkts[2].payload))
	require.True(t, isEOF(pkts[3].payload))
}

func TestResultSetNullCellIsFB(t *testing.T) {
	cols := []columnDef{{Name: "a", ColType: 0xFD}, {Name: "b", ColType: 0xFD}, {Name: "c", ColType: 0xFD}}
	b, _, ok := encodeResultSet(1, cols, [][]*string{{strp("x"), nil, strp("")}}, true)
	require.True(t, ok)
	pkts := splitPackets(t, b)
	require.Equal(t, []byte{0x01, 'x', 0xFB, 0x00}, pkts[4].payload, "NULL is 0xFB; an empty string is a zero length")
}

func TestColumnDefinitionCarriesTypeCharsetFlags(t *testing.T) {
	def := buildColumnDef(columnDef{Name: "id", ColType: 0x08, MaxLen: 20, Charset: charsetBinary, Flags: flagBinary | flagUnsigned, Decimals: 3})
	off := 0
	var s string
	for _, want := range []string{"def", "", "", "", "id", "id"} {
		s, off = decodeLengthEncodedString(def, off)
		require.Equal(t, want, s)
	}
	require.Equal(t, byte(0x0c), def[off])
	off++
	require.Equal(t, uint16(63), binary.LittleEndian.Uint16(def[off:]), "charset")
	require.Equal(t, uint32(20), binary.LittleEndian.Uint32(def[off+2:]), "column length")
	require.Equal(t, byte(0x08), def[off+6], "type")
	require.Equal(t, flagBinary|flagUnsigned, binary.LittleEndian.Uint16(def[off+7:]), "flags")
	require.Equal(t, byte(3), def[off+9], "decimals")
	require.Len(t, def, off+12)
}

// A column with no charset set is a string column in the connection's
// utf8mb4 collation, the one the handshake advertises.
func TestColumnDefinitionDefaultsToUTF8MB4(t *testing.T) {
	def := buildColumnDef(columnDef{Name: "v", ColType: 0xFD})
	off := len(def) - 12 // charset opens the 12 fixed bytes
	require.Equal(t, uint16(charsetUTF8MB4), binary.LittleEndian.Uint16(def[off:]))
}

// buildClientAuthPacketCaps is buildClientAuthPacket with chosen capability flags.
func buildClientAuthPacketCaps(caps uint32, username string, authData []byte) []byte {
	pkt := buildClientAuthPacket(username, authData)
	binary.LittleEndian.PutUint32(pkt, caps)
	return pkt
}

// The framing a session uses is the one both sides agreed on: the server
// advertises CLIENT_DEPRECATE_EOF, so it is in force exactly when the client
// asked for it too.
func TestSessionFramingFollowsNegotiatedDeprecateEOF(t *testing.T) {
	for _, tc := range []struct {
		name      string
		clientCap uint32
		wantEOF   bool
	}{
		{"client sets DEPRECATE_EOF", clientProtocol41 | clientSecureConn | clientPluginAuth | clientDeprecateEOF, false},
		{"client omits DEPRECATE_EOF", clientProtocol41 | clientSecureConn | clientPluginAuth, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubLookup(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) { return &proto.CommandResponse{}, nil })
			server, client := net.Pipe()
			h := &honeypot{logger: zerolog.Nop(), generate: noAI}
			record(h)
			done := make(chan struct{})
			go func() { h.handleConnection(server); close(done) }()
			defer func() { client.Close(); <-done }()
			_ = client.SetDeadline(time.Now().Add(5 * time.Second))
			r := bufio.NewReader(client)
			_, _, err := readPacket(r)
			require.NoError(t, err)
			require.NoError(t, writePacket(client, 1, buildClientAuthPacketCaps(tc.clientCap, "root", make([]byte, 20))))
			_, _, err = readPacket(r) // OK
			require.NoError(t, err)
			require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, "show databases"...)))
			// count, 1 column, [EOF], 6 rows, terminator
			n := 9
			if tc.wantEOF {
				n = 10
			}
			var pkts []packet
			for i := 0; i < n; i++ {
				p, seq, err := readPacket(r)
				require.NoError(t, err)
				pkts = append(pkts, packet{seq, p})
			}
			requireConsecutive(t, pkts, 1)
			require.Equal(t, tc.wantEOF, isEOF(pkts[2].payload), "packet after the column definition: % x", pkts[2].payload)
			last := pkts[len(pkts)-1].payload
			if tc.wantEOF {
				require.True(t, isEOF(last))
			} else {
				require.True(t, isOKAsEOF(last))
			}
			require.NoError(t, writePacket(client, 0, []byte{comQuit}))
		})
	}
}

// Everything the server advertises must be something this honeypot speaks.
// CLIENT_QUERY_ATTRIBUTES would prefix every COM_QUERY with parameters,
// CLIENT_OPTIONAL_RESULTSET_METADATA would allow result sets with no column
// definitions, and CLIENT_SSL would invite a TLS upgrade the honeypot does not
// perform; none may be advertised.
func TestAdvertisedCapabilitiesAreImplemented(t *testing.T) {
	require.NotZero(t, serverCapabilities&clientDeprecateEOF)
	const (
		clientSSL                       uint32 = 0x00000800
		clientOptionalResultsetMetadata uint32 = 0x02000000
		clientQueryAttributes           uint32 = 0x08000000
	)
	require.Zero(t, serverCapabilities&(clientSSL|clientOptionalResultsetMetadata|clientQueryAttributes))
}
