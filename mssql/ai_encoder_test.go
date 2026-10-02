package mssql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// The tests in this file pin the TDS encoder's hardening paths with a real
// go-mssqldb client (fix wave items 4 and 6) and the discarded-reply warning
// (item 5).

// byQuery answers each query with the result set of the first key its text
// contains; any other query gets the fallback. Contains, not equality:
// go-mssqldb prefixes each batch with the TDS ALL_HEADERS block, which
// parseSQLBatch does not strip today.
func byQuery(fallback *proto.ResultSet, answers map[string]*proto.ResultSet) sqlai.Generate {
	return func(in *proto.GenerateRequest, _ time.Duration) (*proto.GenerateReply, error) {
		rs := fallback
		for k, a := range answers {
			if strings.Contains(in.Input, k) {
				rs = a
				break
			}
		}
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI, GenerationId: "gen-1",
			Body: &proto.GenerateReply_ResultSet{ResultSet: rs}}, nil
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

var syncProbe = &proto.ResultSet{Columns: []*proto.Column{{Name: "probe", Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"42"}}}, CommandTag: "SELECT 1"}

// requireInSync runs a follow-up query on the same connection and checks the
// AI answer to it, proving the previous response left the stream in sync.
func requireInSync(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var probe int64
	require.NoError(t, db.QueryRowContext(ctx, "SELECT probe FROM dbo.sync").Scan(&probe), "the stream is still in sync")
	require.Equal(t, int64(42), probe)
}

// requireLegacyAnswer checks the built-in answer to SELECT @@VERSION: one
// column holding the canned version string.
func requireLegacyAnswer(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	rows, err := db.QueryContext(ctx, "SELECT @@VERSION")
	require.NoError(t, err)
	defer rows.Close()
	cols, err := rows.Columns()
	require.NoError(t, err)
	require.Len(t, cols, 1, "the legacy answer has one column")
	require.True(t, rows.Next())
	var v string
	require.NoError(t, rows.Scan(&v))
	require.Contains(t, v, "Microsoft SQL Server 2022", "the legacy answer ran")
	require.False(t, rows.Next())
	require.NoError(t, rows.Err())
}

func TestMSSQLAINullInEveryFixedLengthType(t *testing.T) {
	nulls := &proto.ResultSet{
		Columns: []*proto.Column{{Name: "i", Type: "int4"}, {Name: "b", Type: "bool"}, {Name: "f", Type: "float8"},
			{Name: "d", Type: "date"}, {Name: "ts", Type: "timestamp"}, {Name: "tz", Type: "timestamptz"}},
		Rows:       []*proto.Row{{Values: []string{"", "", "", "", "", ""}, Nulls: []bool{true, true, true, true, true, true}}},
		CommandTag: "SELECT 1",
	}
	db := startAIMSSQL(t, byQuery(syncProbe, map[string]*proto.ResultSet{"SELECT * FROM dbo.blank": nulls}))
	ctx := testCtx(t)
	var (
		i     sql.NullInt64
		b     sql.NullBool
		f     sql.NullFloat64
		d, ts sql.NullTime
		tz    sql.NullTime
	)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT * FROM dbo.blank").Scan(&i, &b, &f, &d, &ts, &tz))
	require.False(t, i.Valid, "INTN NULL")
	require.False(t, b.Valid, "BITN NULL")
	require.False(t, f.Valid, "FLTN NULL")
	require.False(t, d.Valid, "DATEN NULL")
	require.False(t, ts.Valid, "DATETIME2N NULL")
	require.False(t, tz.Valid, "DATETIMEOFFSETN NULL")
	requireInSync(t, ctx, db)
}

func TestMSSQLAIMultiRowResult(t *testing.T) {
	multi := &proto.ResultSet{
		Columns: []*proto.Column{{Name: "id", Type: "int4"}, {Name: "name", Type: "text"}},
		Rows: []*proto.Row{
			{Values: []string{"1", "alice"}}, {Values: []string{"2", "bob"}},
			{Values: []string{"3", ""}, Nulls: []bool{false, true}}, {Values: []string{"4", "dave"}},
		},
		CommandTag: "SELECT 4",
	}
	db := startAIMSSQL(t, byQuery(syncProbe, map[string]*proto.ResultSet{"SELECT id, name FROM dbo.users": multi}))
	ctx := testCtx(t)
	rows, err := db.QueryContext(ctx, "SELECT id, name FROM dbo.users")
	require.NoError(t, err)
	type rec struct {
		id   int64
		name sql.NullString
	}
	var got []rec
	for rows.Next() {
		var r rec
		require.NoError(t, rows.Scan(&r.id, &r.name))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.Equal(t, []rec{
		{1, sql.NullString{String: "alice", Valid: true}}, {2, sql.NullString{String: "bob", Valid: true}},
		{3, sql.NullString{}}, {4, sql.NullString{String: "dave", Valid: true}},
	}, got)
	requireInSync(t, ctx, db)
}

// days3 must floor, not truncate, before 1970.
func TestMSSQLAIDatesBefore1970And1900RoundTrip(t *testing.T) {
	old := &proto.ResultSet{
		Columns: []*proto.Column{{Name: "landing", Type: "timestamp"}, {Name: "landing_tz", Type: "timestamptz"},
			{Name: "founded", Type: "date"}, {Name: "evening", Type: "timestamp"}},
		Rows:       []*proto.Row{{Values: []string{"1969-07-20 20:17:40", "1969-07-20T20:17:40-05:00", "1899-12-31", "1850-03-04 23:59:59"}}},
		CommandTag: "SELECT 1",
	}
	db := startAIMSSQL(t, byQuery(syncProbe, map[string]*proto.ResultSet{"SELECT * FROM dbo.history": old}))
	ctx := testCtx(t)
	var landing, landingTZ, founded, evening time.Time
	require.NoError(t, db.QueryRowContext(ctx, "SELECT * FROM dbo.history").Scan(&landing, &landingTZ, &founded, &evening))
	require.True(t, landing.Equal(time.Date(1969, 7, 20, 20, 17, 40, 0, time.UTC)), landing.String())
	require.True(t, landingTZ.Equal(time.Date(1969, 7, 21, 1, 17, 40, 0, time.UTC)), landingTZ.String())
	_, offset := landingTZ.Zone()
	require.Equal(t, -5*3600, offset)
	require.True(t, founded.Equal(time.Date(1899, 12, 31, 0, 0, 0, 0, time.UTC)), founded.String())
	require.True(t, evening.Equal(time.Date(1850, 3, 4, 23, 59, 59, 0, time.UTC)), evening.String())
	requireInSync(t, ctx, db)
}

func intColumns(n int) []*proto.Column {
	cols := make([]*proto.Column, n)
	for i := range cols {
		cols[i] = &proto.Column{Name: fmt.Sprintf("c%d", i), Type: "int4"}
	}
	return cols
}

// Each oversized or out-of-range reply falls back to the built-in answer.
func TestMSSQLAIUnencodableRepliesFallBackToLegacy(t *testing.T) {
	wide := &proto.ResultSet{Columns: intColumns(65), Rows: []*proto.Row{{Values: make([]string, 65)}}, CommandTag: "SELECT 1"}
	for i := range wide.Rows[0].Values {
		wide.Rows[0].Values[i] = "1"
	}
	long := &proto.ResultSet{Columns: intColumns(1), CommandTag: "SELECT 1001"}
	for i := 0; i < 1001; i++ {
		long.Rows = append(long.Rows, &proto.Row{Values: []string{"1"}})
	}
	big := &proto.ResultSet{Columns: make([]*proto.Column, 64), CommandTag: "SELECT 3"}
	for i := range big.Columns {
		big.Columns[i] = &proto.Column{Name: fmt.Sprintf("c%d", i), Type: "text"}
	}
	for r := 0; r < 3; r++ {
		row := &proto.Row{Values: make([]string, 64)}
		for i := range row.Values {
			row.Values[i] = strings.Repeat("a", 4000) // 8000 bytes as UTF-16
		}
		big.Rows = append(big.Rows, row)
	}
	offset := func(v string) *proto.ResultSet {
		return &proto.ResultSet{Columns: []*proto.Column{{Name: "at", Type: "timestamptz"}}, Rows: []*proto.Row{{Values: []string{v}}}, CommandTag: "SELECT 1"}
	}
	for name, rs := range map[string]*proto.ResultSet{
		"65 columns":     wide,
		"1001 rows":      long,
		"over 1 MiB":     big,
		"offset +14:01":  offset("2026-01-02T15:04:05+14:01"),
		"offset -14:01":  offset("2026-01-02T15:04:05-14:01"),
		"emoji col name": {Columns: []*proto.Column{{Name: strings.Repeat("🐘", 128), Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"7"}}}, CommandTag: "SELECT 1"},
	} {
		t.Run(name, func(t *testing.T) {
			db := startAIMSSQL(t, byQuery(rs, nil))
			ctx := testCtx(t)
			requireLegacyAnswer(t, ctx, db)
			requireLegacyAnswer(t, ctx, db)
		})
	}
	// The boundaries themselves still encode.
	for name, rs := range map[string]*proto.ResultSet{
		"offset +14:00":      offset("2026-01-02T15:04:05+14:00"),
		"offset -14:00":      offset("2026-01-02T15:04:05-14:00"),
		"64 emoji col name":  {Columns: []*proto.Column{{Name: strings.Repeat("🐘", 64), Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"7"}}}, CommandTag: "SELECT 1"},
		"128 ascii col name": {Columns: []*proto.Column{{Name: strings.Repeat("n", 128), Type: "int4"}}, Rows: []*proto.Row{{Values: []string{"7"}}}, CommandTag: "SELECT 1"},
	} {
		payload, discarded := mssqlAIResponse(rs)
		require.NotNil(t, payload, name)
		require.Empty(t, discarded, name)
	}
}

// The per-row size check stops encoding as soon as the payload outgrows one
// TDS message, rather than building every row first.
func TestTDSResultSetBailsOnOversizedRows(t *testing.T) {
	cols := []*proto.Column{{Name: "a", Type: "text"}}
	var rows []*proto.Row
	for i := 0; i < 200; i++ {
		rows = append(rows, &proto.Row{Values: []string{strings.Repeat("a", 4000)}})
	}
	payload, ok := tdsResultSet(cols, rows)
	require.False(t, ok, "200 rows of 8000 bytes outgrow 1 MiB")
	require.Nil(t, payload)
}

// Item 4: the column-name cap counts UTF-16 units, which is what B_VARCHAR
// writes; 128 non-BMP characters are 256 units and fall back.
func TestTDSColumnNameCapCountsUTF16Units(t *testing.T) {
	one := []*proto.Row{{Values: []string{"7"}}}
	_, ok := tdsResultSet([]*proto.Column{{Name: strings.Repeat("🐘", 128), Type: "int4"}}, one)
	require.False(t, ok, "256 UTF-16 units")
	_, ok = tdsResultSet([]*proto.Column{{Name: strings.Repeat("🐘", 64), Type: "int4"}}, one)
	require.True(t, ok, "128 UTF-16 units")
	_, ok = tdsResultSet([]*proto.Column{{Name: strings.Repeat("🐘", 64) + "x", Type: "int4"}}, one)
	require.False(t, ok, "129 UTF-16 units")
}

func TestMSSQLGenerateErrorsAnswerWithLegacy(t *testing.T) {
	for name, err := range map[string]error{
		"unimplemented": persistence.ErrUnimplemented,
		"other error":   errors.New("boom"),
	} {
		t.Run(name, func(t *testing.T) {
			err := err
			db := startAIMSSQL(t, func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) { return nil, err })
			ctx := testCtx(t)
			requireLegacyAnswer(t, ctx, db)
			requireLegacyAnswer(t, ctx, db)
		})
	}
}

// lockedBuffer lets the connection goroutine log while the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Item 5: a discarded reply logs one warning with the generation id, protocol
// and reason, never the query or the model's text; the legacy path answers.
func TestMSSQLDiscardedAIReplyLogsOneWarning(t *testing.T) {
	logs := &lockedBuffer{}
	client, _ := startLoggedInPipe(t, &honeypot{logger: zerolog.New(logs), queryLimit: 2,
		lookup: func(string, string) (string, bool) { return "", false },
		generate: byQuery(&proto.ResultSet{Error: &proto.SqlError{Code: "not_a_code", Message: "secret model text"}},
			map[string]*proto.ResultSet{"dbo.sync": syncProbe}),
	})
	require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2("select secret_column from dbo.secret_table")))
	_, reply, err := readMessage(client)
	require.NoError(t, err)
	require.Contains(t, string(reply), string(encodeUCS2("1")), "the built-in answer ran")
	require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2("SELECT probe FROM dbo.sync")))
	_, _, err = readMessage(client)
	require.NoError(t, err)

	out := logs.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 1, "only the discarded reply logs: %s", out)
	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
	require.Equal(t, "warn", entry["level"])
	require.Equal(t, "gen-1", entry["generation_id"])
	require.Equal(t, "mssql", entry["protocol"])
	require.Equal(t, "error_not_mapped", entry["reason"])
	require.NotContains(t, out, "secret")
}
