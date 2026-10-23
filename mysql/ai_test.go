package mysql

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// noAI is a generate call that is never answered: the server has no AI.
var noAI sqlai.Generate = func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
	return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil
}

func aiResult(rs *proto.ResultSet) sqlai.Generate {
	return func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI, GenerationId: "gen-1",
			Body: &proto.GenerateReply_ResultSet{ResultSet: rs}}, nil
	}
}

// The server pins the same literal (internal/ai/validate SQLColumnTypes).
func TestMySQLAITypesMatchServer(t *testing.T) {
	types := make([]string, 0, len(mysqlTypes))
	for k := range mysqlTypes {
		types = append(types, k)
	}
	sort.Strings(types)
	require.Equal(t, []string{"bool", "date", "float4", "float8", "int2", "int4", "int8", "json", "jsonb", "name", "numeric", "oid", "text", "timestamp", "timestamptz", "varchar"}, types)
}

// columnFields decodes the fixed part of a column definition.
type columnFields struct {
	name     string
	charset  uint16
	length   uint32
	typ      byte
	flags    uint16
	decimals byte
}

func parseColumnDef(t *testing.T, def []byte) columnFields {
	t.Helper()
	off := 0
	var name string
	for i := 0; i < 6; i++ {
		var s string
		s, off = decodeLengthEncodedString(def, off)
		if i == 4 {
			name = s
		}
	}
	require.Equal(t, byte(0x0c), def[off])
	off++
	return columnFields{name, binary.LittleEndian.Uint16(def[off:]), binary.LittleEndian.Uint32(def[off+2:]),
		def[off+6], binary.LittleEndian.Uint16(def[off+7:]), def[off+9]}
}

// parseRow decodes a text-protocol row; nil is NULL.
func parseRow(t *testing.T, p []byte) []*string {
	t.Helper()
	var out []*string
	for off := 0; off < len(p); {
		if p[off] == 0xFB {
			out = append(out, nil)
			off++
			continue
		}
		var s string
		s, off = decodeLengthEncodedString(p, off)
		out = append(out, &s)
	}
	return out
}

func TestMySQLAITypedResult(t *testing.T) {
	rs := &proto.ResultSet{
		Columns: []*proto.Column{
			{Name: "i2", Type: "int2"}, {Name: "i4", Type: "int4"}, {Name: "i8", Type: "int8"}, {Name: "u", Type: "oid"},
			{Name: "ok", Type: "bool"}, {Name: "f4", Type: "float4"}, {Name: "f8", Type: "float8"}, {Name: "amount", Type: "numeric"},
			{Name: "s", Type: "varchar"}, {Name: "n", Type: "name"}, {Name: "body", Type: "text"}, {Name: "doc", Type: "json"},
			{Name: "d", Type: "date"}, {Name: "ts", Type: "timestamp"}, {Name: "tz", Type: "timestamptz"}, {Name: "missing", Type: "text"},
		},
		Rows: []*proto.Row{{
			Values: []string{"-7", "2147483647", "9000000000", "4000000000", "true", "1.5", "-2.25", "12.50",
				"alice", "users", "line1\nline2", `{"a": 1}`, "2026-01-02", "2026-01-02 15:04:05", "2026-01-02T15:04:05+02:00", ""},
			Nulls: []bool{false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true},
		}},
		CommandTag: "SELECT 1",
	}
	b, discarded := mysqlAIResponse(rs, 1, true)
	require.Empty(t, discarded)
	pkts := splitPackets(t, b)
	requireConsecutive(t, pkts, 1)
	require.Equal(t, []byte{16}, pkts[0].payload)
	require.Len(t, pkts, 1+16+1+1, "count, 16 columns, 1 row, terminator (DEPRECATE_EOF)")

	want := map[string]columnFields{}
	for name, typ := range map[string]string{"i2": "int2", "i4": "int4", "i8": "int8", "u": "oid", "ok": "bool", "f4": "float4", "f8": "float8",
		"amount": "numeric", "s": "varchar", "n": "name", "body": "text", "doc": "json", "d": "date", "ts": "timestamp", "tz": "timestamptz", "missing": "text"} {
		m := mysqlTypes[typ]
		want[name] = columnFields{name, m.charset, m.length, m.id, m.flags, m.decimals}
	}
	// numeric's precision and scale follow the values, as decimal(p,s) would.
	// "12.50" is decimal(4,2): length is precision + point + sign.
	want["amount"] = columnFields{"amount", charsetBinary, 4 + 2, 0xF6, 0, 2}
	for i, c := range rs.Columns {
		require.Equal(t, want[c.Name], parseColumnDef(t, pkts[1+i].payload), c.Name)
	}

	row := parseRow(t, pkts[17].payload)
	got := make([]any, len(row))
	for i, v := range row {
		if v != nil {
			got[i] = *v
		}
	}
	require.Equal(t, []any{"-7", "2147483647", "9000000000", "4000000000", "1", "1.5", "-2.25", "12.50",
		"alice", "users", "line1\nline2", `{"a": 1}`, "2026-01-02", "2026-01-02 15:04:05", "2026-01-02 13:04:05", nil}, got,
		"bool is tinyint(1) 1/0; timestamptz is a TIMESTAMP shown in the session's UTC")
	require.True(t, isOKAsEOF(pkts[18].payload))
}

// The type table is what a real MySQL 8.0 server sends for a table column of
// each canonical type's MySQL counterpart (persona.mysqlTypeNames on the
// server), captured with `mysql --column-type-info` against mysqld 8.0.46.
// The client adds NUM itself, so it is not on the wire; table numeric columns
// carry no BINARY flag (only expressions do).
func TestMySQLTypeTable(t *testing.T) {
	type w struct {
		id       byte
		length   uint32
		charset  uint16
		flags    uint16
		decimals byte
	}
	want := map[string]w{
		"bool":        {0x01, 1, 63, 0, 0},                              // TINY, tinyint(1)
		"int2":        {0x02, 6, 63, 0, 0},                              // SHORT, smallint
		"int4":        {0x03, 11, 63, 0, 0},                             // LONG, int
		"int8":        {0x08, 20, 63, 0, 0},                             // LONGLONG, bigint
		"oid":         {0x03, 10, 63, flagUnsigned, 0},                  // LONG, int unsigned
		"float4":      {0x04, 12, 63, 0, 31},                            // FLOAT
		"float8":      {0x05, 22, 63, 0, 31},                            // DOUBLE
		"numeric":     {0xF6, 12, 63, 0, 2},                             // NEWDECIMAL, decimal(10,2)
		"varchar":     {0xFD, 1020, 255, 0, 0},                          // VAR_STRING, varchar(255)
		"name":        {0xFD, 256, 255, 0, 0},                           // VAR_STRING, varchar(64)
		"text":        {0xFC, 262140, 255, flagBlob, 0},                 // BLOB, text
		"json":        {0xF5, 4294967295, 63, flagBlob | flagBinary, 0}, // JSON
		"jsonb":       {0xF5, 4294967295, 63, flagBlob | flagBinary, 0}, // JSON
		"date":        {0x0A, 10, 63, flagBinary, 0},                    // DATE
		"timestamp":   {0x0C, 19, 63, flagBinary, 0},                    // DATETIME
		"timestamptz": {0x07, 19, 63, flagBinary, 0},                    // TIMESTAMP
	}
	for typ, m := range mysqlTypes {
		require.Equal(t, want[typ], w{m.id, m.length, m.charset, m.flags, m.decimals}, typ)
	}
}

func TestMySQLAIClassicFraming(t *testing.T) {
	b, discarded := mysqlAIResponse(&proto.ResultSet{
		Columns: []*proto.Column{{Name: "id", Type: "int4"}},
		Rows:    []*proto.Row{{Values: []string{"1"}}, {Values: []string{"2"}}},
	}, 1, false)
	require.Empty(t, discarded)
	pkts := splitPackets(t, b)
	require.Len(t, pkts, 6, "count, column, EOF, 2 rows, EOF")
	require.True(t, isEOF(pkts[2].payload))
	require.True(t, isEOF(pkts[5].payload))
}

func TestMySQLAIError(t *testing.T) {
	b, discarded := mysqlAIResponse(&proto.ResultSet{Error: &proto.SqlError{Code: "undefined_table", Message: "Table 'production.accounts' doesn't exist"}}, 1, true)
	require.Empty(t, discarded)
	pkts := splitPackets(t, b)
	require.Len(t, pkts, 1)
	require.Equal(t, uint8(1), pkts[0].seq)
	want := []byte{0xFF, 0x7A, 0x04, '#', '4', '2', 'S', '0', '2'} // 1146 = 0x047A
	require.Equal(t, append(want, "Table 'production.accounts' doesn't exist"...), pkts[0].payload)
}

func TestMySQLAIErrorEveryCodeIsMapped(t *testing.T) {
	for code, m := range sqlai.Errors {
		b, discarded := mysqlAIResponse(&proto.ResultSet{Error: &proto.SqlError{Code: code, Message: "x"}}, 1, true)
		require.Empty(t, discarded, code)
		p := splitPackets(t, b)[0].payload
		require.Equal(t, m.MySQLNumber, binary.LittleEndian.Uint16(p[1:]), code)
		require.Equal(t, "#"+m.MySQLState, string(p[3:9]), code)
	}
}

// MySQL cuts an error message at MYSQL_ERRMSG_SIZE-1 bytes; so does the
// honeypot, on a rune boundary, and control characters never reach the wire.
func TestMySQLAIErrorMessageCleanedAndCut(t *testing.T) {
	long := strings.Repeat("é", 400) // 800 bytes
	b, discarded := mysqlAIResponse(&proto.ResultSet{Error: &proto.SqlError{Code: "syntax_error", Message: "bad\x1b[31m " + long}}, 1, true)
	require.Empty(t, discarded)
	msg := string(splitPackets(t, b)[0].payload[9:])
	require.True(t, strings.HasPrefix(msg, "bad[31m "), msg[:12])
	require.LessOrEqual(t, len(msg), maxErrorMessageBytes)
	require.True(t, strings.HasSuffix(msg, "é"), "cut on a rune boundary")
}

func TestMySQLAIDiscards(t *testing.T) {
	for name, rs := range map[string]*proto.ResultSet{
		"unknown error code":   {Error: &proto.SqlError{Code: "made_up", Message: "x"}},
		"empty error message":  {Error: &proto.SqlError{Code: "syntax_error", Message: "\x1b"}},
		"rows without columns": {Rows: []*proto.Row{{Values: []string{"1"}}}},
		"unknown column type":  {Columns: []*proto.Column{{Name: "a", Type: "uuid"}}},
		"short row":            {Columns: []*proto.Column{{Name: "a", Type: "int4"}, {Name: "b", Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"1"}}}},
		"nulls length":         {Columns: []*proto.Column{{Name: "a", Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"1"}, Nulls: []bool{false, true}}}},
		"bad int":              {Columns: []*proto.Column{{Name: "a", Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"abc"}}}},
		"int out of range":     {Columns: []*proto.Column{{Name: "a", Type: "int2"}}, Rows: []*proto.Row{{Values: []string{"70000"}}}},
		"bad bool":             {Columns: []*proto.Column{{Name: "a", Type: "bool"}}, Rows: []*proto.Row{{Values: []string{"yes"}}}},
		"bad float":            {Columns: []*proto.Column{{Name: "a", Type: "float8"}}, Rows: []*proto.Row{{Values: []string{"NaN"}}}},
		"bad numeric":          {Columns: []*proto.Column{{Name: "a", Type: "numeric"}}, Rows: []*proto.Row{{Values: []string{"1e5"}}}},
		"bad date":             {Columns: []*proto.Column{{Name: "a", Type: "date"}}, Rows: []*proto.Row{{Values: []string{"2026-13-01"}}}},
		"bad timestamp":        {Columns: []*proto.Column{{Name: "a", Type: "timestamp"}}, Rows: []*proto.Row{{Values: []string{"2026-01-01T00:00:00"}}}},
		"bad timestamptz":      {Columns: []*proto.Column{{Name: "a", Type: "timestamptz"}}, Rows: []*proto.Row{{Values: []string{"2026-01-01 00:00:00"}}}},
		"bad json":             {Columns: []*proto.Column{{Name: "a", Type: "json"}}, Rows: []*proto.Row{{Values: []string{"{"}}}},
		"too many columns":     {Columns: make([]*proto.Column, 65)},
		"long column name":     {Columns: []*proto.Column{{Name: strings.Repeat("a", 257), Type: "text"}}},
	} {
		b, discarded := mysqlAIResponse(rs, 1, true)
		require.Nil(t, b, name)
		require.NotEmpty(t, discarded, name)
	}
}

func TestMySQLAINoReply(t *testing.T) {
	b, discarded := mysqlAIResponse(nil, 1, true)
	require.Nil(t, b)
	require.Empty(t, discarded)
}

func TestMySQLAIStatementWithoutRows(t *testing.T) {
	for tag, affected := range map[string]byte{"INSERT 3": 3, "UPDATE 2": 2, "DELETE 0": 0, "REPLACE 4": 4, "INSERT 0 1": 1, "OK": 0, "": 0, "CREATE TABLE": 0, "SELECT 5": 0} {
		b, discarded := mysqlAIResponse(&proto.ResultSet{CommandTag: tag}, 1, true)
		require.Empty(t, discarded, tag)
		pkts := splitPackets(t, b)
		require.Len(t, pkts, 1, tag)
		require.Equal(t, []byte{0x00, affected, 0x00, 0x02, 0x00, 0x00, 0x00}, pkts[0].payload, tag)
	}
}

// record sends h's persistence to a recorder of its own, so no package state is
// swapped under a connection goroutine.
func record(h *honeypot) *recorder {
	rec := &recorder{}
	h.loginSaver, h.querySaver = rec.login, rec.query
	return rec
}

// startAIConn drives handleConnection over a pipe up to the command phase.
func startAIConn(t *testing.T, h *honeypot, caps uint32) (net.Conn, *bufio.Reader) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { h.handleConnection(server); close(done) }()
	t.Cleanup(func() { client.Close(); <-done })
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(client)
	_, _, err := readPacket(r)
	require.NoError(t, err)
	require.NoError(t, writePacket(client, 1, buildClientAuthPacketCaps(caps, "root", make([]byte, 20))))
	_, _, err = readPacket(r)
	require.NoError(t, err)
	return client, r
}

// readReply reads one full COM_QUERY reply: an OK or ERR, or a result set
// through its terminator.
func readReply(t *testing.T, r *bufio.Reader, deprecateEOF bool) []byte {
	t.Helper()
	var out bytes.Buffer
	read := func() []byte {
		p, seq, err := readPacket(r)
		require.NoError(t, err)
		require.NoError(t, writePacket(&out, seq, p))
		return p
	}
	first := read()
	if first[0] == 0x00 || first[0] == 0xFF {
		return out.Bytes()
	}
	n, _ := decodeLengthEncodedInt(first, 0)
	for i := uint64(0); i < n; i++ {
		read()
	}
	if !deprecateEOF {
		require.True(t, isEOF(read()))
	}
	for {
		p := read()
		if (deprecateEOF && isOKAsEOF(p)) || (!deprecateEOF && isEOF(p)) {
			return out.Bytes()
		}
	}
}

const clientCaps = clientProtocol41 | clientSecureConn | clientPluginAuth | clientDeprecateEOF

// lookupStub replaces the cmdresp seams for one test. calls counts lookups;
// within records each lookup's deadline (3 s for the default lookup).
type lookupStub struct {
	mu     sync.Mutex
	calls  int
	saves  int
	within []time.Duration
}

func (s *lookupStub) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }

func stubLookup(t *testing.T, fn func(*proto.CommandRequest) (*proto.CommandResponse, error)) *lookupStub {
	t.Helper()
	s := &lookupStub{}
	origGet, origWithin, origSave := cmdresp.GetCommandResponse, cmdresp.GetCommandResponseWithin, cmdresp.SaveResponseLookup
	lookup := func(in *proto.CommandRequest, d time.Duration) (*proto.CommandResponse, error) {
		s.mu.Lock()
		s.calls++
		s.within = append(s.within, d)
		s.mu.Unlock()
		return fn(in)
	}
	cmdresp.GetCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) { return lookup(in, 3*time.Second) }
	cmdresp.GetCommandResponseWithin = lookup
	cmdresp.SaveResponseLookup = func(*proto.ResponseLookupRequest) error {
		s.mu.Lock()
		s.saves++
		s.mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		// Every lookup with a guid records its key from a goroutine of its own, which
		// reads SaveResponseLookup; restore only after each has run.
		waitFor(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.saves >= s.calls }, "lookup telemetry goroutines")
		cmdresp.GetCommandResponse, cmdresp.GetCommandResponseWithin, cmdresp.SaveResponseLookup = origGet, origWithin, origSave
	})
	return s
}

// AI first: an answered reply goes on the wire and the authored lookup is not
// consulted. The request names protocol "mysql", the session's guid (the one
// its login is filed under) and the query exactly as the client sent it.
func TestMySQLAIAnswersBeforeAuthoredLookup(t *testing.T) {
	calls := stubLookup(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "AUTHORED", Matched: true}, nil
	})
	var mu sync.Mutex
	var reqs []*proto.GenerateRequest
	h := &honeypot{logger: zerolog.Nop(), generate: func(in *proto.GenerateRequest, d time.Duration) (*proto.GenerateReply, error) {
		mu.Lock()
		reqs = append(reqs, in)
		mu.Unlock()
		return aiResult(&proto.ResultSet{Columns: []*proto.Column{{Name: "id", Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"42"}}}})(in, d)
	}}
	rec := record(h)
	client, r := startAIConn(t, h, clientCaps)
	require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, "SELECT id FROM Users"...)))
	reply := readReply(t, r, true)
	require.True(t, bytes.Contains(reply, []byte{0x02, '4', '2'}), "the AI row reached the wire: % x", reply)
	require.NotContains(t, string(reply), "AUTHORED")
	require.Zero(t, calls.count(), "the authored lookup is not consulted when the AI answered")
	require.NoError(t, writePacket(client, 0, []byte{comQuit}))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, reqs, 1)
	require.Equal(t, "mysql", reqs[0].Protocol)
	require.Equal(t, "SELECT id FROM Users", reqs[0].Input)
	waitFor(t, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.logins) == 1 }, "login")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Equal(t, rec.logins[0].Guid, reqs[0].Guid)
}

// Unanswered (NONE, an RPC error, AI off): the reply is byte for byte what the
// honeypot sends with no AI at all, authored response or built-in default.
func TestMySQLAIFallbackIsTodaysReply(t *testing.T) {
	stubLookup(t, func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.Command == "select authored()" {
			return &proto.CommandResponse{Response: "AUTHORED", Matched: true}, nil
		}
		return &proto.CommandResponse{}, nil
	})
	queries := []string{"select authored()", "SHOW DATABASES", "select 1", "INSERT INTO t VALUES (1)", "garbage here"}
	replies := func(gen sqlai.Generate) [][]byte {
		h := &honeypot{logger: zerolog.Nop(), generate: gen}
		record(h)
		client, r := startAIConn(t, h, clientCaps)
		var out [][]byte
		for _, q := range queries {
			require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, q...)))
			out = append(out, readReply(t, r, true))
		}
		require.NoError(t, writePacket(client, 0, []byte{comQuit}))
		return out
	}
	today := replies(nil)
	require.Contains(t, string(today[0]), "AUTHORED")
	off := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		return nil, status.Error(codes.Unimplemented, "no")
	}
	live := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "g"}, nil
	}
	unencodable := aiResult(&proto.ResultSet{Error: &proto.SqlError{Code: "made_up", Message: "x"}})
	for name, gen := range map[string]sqlai.Generate{"none": noAI, "unimplemented": off, "none with ledger id": live, "unencodable": unencodable} {
		require.Equal(t, today, replies(gen), name)
	}
}

func TestMySQLAIErrorReachesClient(t *testing.T) {
	stubLookup(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) { return &proto.CommandResponse{}, nil })
	h := &honeypot{logger: zerolog.Nop(), generate: aiResult(&proto.ResultSet{Error: &proto.SqlError{Code: "undefined_database", Message: "Unknown database 'hr'"}})}
	record(h)
	client, r := startAIConn(t, h, clientCaps)
	require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, "USE hr"...)))
	reply := readReply(t, r, true)
	require.Equal(t, byte(0xFF), reply[4])
	require.Equal(t, uint16(1049), binary.LittleEndian.Uint16(reply[5:]))
	require.Equal(t, "#42000Unknown database 'hr'", string(reply[7:]))
	require.NoError(t, writePacket(client, 0, []byte{comQuit}))
}

// After a slow generate call the authored lookup gets sqlai.DegradedLookup,
// not its usual 3 s, so one query never costs the generate budget plus the
// full lookup.
func TestMySQLAISlowGenerateShortensLookup(t *testing.T) {
	stub := stubLookup(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) { return &proto.CommandResponse{}, nil })
	h := &honeypot{logger: zerolog.Nop(), generate: func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		return nil, context.DeadlineExceeded
	}}
	record(h)
	client, r := startAIConn(t, h, clientCaps)
	require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, "select 1"...)))
	readReply(t, r, true)
	require.NoError(t, writePacket(client, 0, []byte{comQuit}))
	stub.mu.Lock()
	defer stub.mu.Unlock()
	require.Equal(t, []time.Duration{sqlai.DegradedLookup}, stub.within)
}

// The AI session state is per connection: a session the server answered asks
// again with the live budget.
func TestMySQLAISessionGoesLive(t *testing.T) {
	stubLookup(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) { return &proto.CommandResponse{}, nil })
	var mu sync.Mutex
	var budgets []time.Duration
	h := &honeypot{logger: zerolog.Nop(), generate: func(in *proto.GenerateRequest, d time.Duration) (*proto.GenerateReply, error) {
		mu.Lock()
		budgets = append(budgets, d)
		mu.Unlock()
		return aiResult(&proto.ResultSet{CommandTag: "OK"})(in, d)
	}}
	record(h)
	client, r := startAIConn(t, h, clientCaps)
	for i := 0; i < 2; i++ {
		require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, "SET autocommit=1"...)))
		readReply(t, r, true)
	}
	require.NoError(t, writePacket(client, 0, []byte{comQuit}))
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []time.Duration{sqlai.FirstBudget, sqlai.LiveBudget}, budgets)
}

// The login is filed when the client authenticates, not when the session
// ends, so the server can tie the session's AI requests to the attacker from
// the first query. It is still filed exactly once.
func TestMySQLLoginSavedAtAuth(t *testing.T) {
	h := &honeypot{logger: zerolog.Nop(), generate: noAI}
	rec := record(h)
	client, r := startAIConn(t, h, clientCaps)
	waitFor(t, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.logins) == 1 }, "login saved while the session is still open")
	rec.mu.Lock()
	require.Equal(t, "root", rec.logins[0].Username)
	require.True(t, strings.HasPrefix(rec.logins[0].Password, "$mysqlna$"))
	rec.mu.Unlock()
	require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, "select 1"...)))
	readReply(t, r, true)
	require.NoError(t, writePacket(client, 0, []byte{comQuit}))
	waitFor(t, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.queries) == 1 }, "query saved")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Len(t, rec.logins, 1, "the login is saved once")
}

// A login that failed to save still keeps the session's queries out of the
// backend, as before: they would point at a guid with no attacker row.
func TestMySQLLoginFailureAtAuthStillGatesQueries(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	h := &honeypot{logger: zerolog.Nop(), generate: noAI}
	rec := record(h)
	h.loginSaver = func(*proto.MysqlRequest) error {
		mu.Lock()
		attempts++
		mu.Unlock()
		return errors.New("backend down")
	}
	client, r := startAIConn(t, h, clientCaps)
	require.NoError(t, writePacket(client, 0, append([]byte{comQuery}, "select 1"...)))
	readReply(t, r, true)
	require.NoError(t, writePacket(client, 0, []byte{comQuit}))
	time.Sleep(100 * time.Millisecond)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Empty(t, rec.queries)
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, attempts)
}
