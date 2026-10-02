package mssql

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	mssqldb "github.com/denisenkom/go-mssqldb"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func aiResult(rs *proto.ResultSet) sqlai.Generate {
	return func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI, GenerationId: "gen-1",
			Body: &proto.GenerateReply_ResultSet{ResultSet: rs}}, nil
	}
}

func startAIMSSQL(t *testing.T, gen sqlai.Generate) *sql.DB {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h := &honeypot{
		logger:    zerolog.Nop(),
		saveLogin: func(*proto.MssqlRequest) error { return nil },
		saveQuery: func(*proto.QueryRequest) error { return nil },
		lookup:    func(string, string) (string, bool) { return "", false },
		generate:  gen,
	}
	serveDone := make(chan struct{})
	go func() { h.serve(listener); close(serveDone) }()
	t.Cleanup(func() { listener.Close(); <-serveDone })
	db, err := sql.Open("sqlserver", fmt.Sprintf("sqlserver://sa:probe@%s?database=master&encrypt=disable", listener.Addr()))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

// The server pins the same literal (internal/ai/validate SQLColumnTypes).
func TestMSSQLAITypesMatchServer(t *testing.T) {
	types := make([]string, 0, len(tdsTypes))
	for k := range tdsTypes {
		types = append(types, k)
	}
	sort.Strings(types)
	require.Equal(t, []string{"bool", "date", "float4", "float8", "int2", "int4", "int8", "json", "jsonb", "name", "numeric", "oid", "text", "timestamp", "timestamptz", "varchar"}, types)
	require.Equal(t, "SQLSERVER01", tdsServerName, "the server prompt states the same @@SERVERNAME (prompt.MSSQLServerName)")
}

func TestMSSQLAITypedResultReachesRealClient(t *testing.T) {
	db := startAIMSSQL(t, aiResult(&proto.ResultSet{
		Columns: []*proto.Column{{Name: "i2", Type: "int2"}, {Name: "i4", Type: "int4"}, {Name: "i8", Type: "int8"}, {Name: "ok", Type: "bool"},
			{Name: "f4", Type: "float4"}, {Name: "f8", Type: "float8"}, {Name: "s", Type: "varchar"}, {Name: "amount", Type: "numeric"},
			{Name: "d", Type: "date"}, {Name: "ts", Type: "timestamp"}, {Name: "tz", Type: "timestamptz"}, {Name: "missing", Type: "text"}},
		Rows: []*proto.Row{{
			Values: []string{"-7", "2147483647", "9000000000", "true", "1.5", "-2.25", "alice", "12.50", "2026-01-02", "2026-01-02 15:04:05", "2026-01-02T15:04:05+02:00", ""},
			Nulls:  []bool{false, false, false, false, false, false, false, false, false, false, false, true},
		}},
		CommandTag: "SELECT 1",
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var (
		i2, i4, i8 int64
		ok         bool
		f4, f8     float64
		s, amount  string
		d, ts, tz  time.Time
		missing    sql.NullString
	)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT * FROM dbo.accounts").Scan(&i2, &i4, &i8, &ok, &f4, &f8, &s, &amount, &d, &ts, &tz, &missing))
	require.Equal(t, int64(-7), i2)
	require.Equal(t, int64(2147483647), i4)
	require.Equal(t, int64(9000000000), i8)
	require.True(t, ok)
	require.Equal(t, 1.5, f4)
	require.Equal(t, -2.25, f8)
	require.Equal(t, "alice", s)
	require.Equal(t, "12.50", amount)
	require.True(t, d.Equal(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)))
	require.True(t, ts.Equal(time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)))
	require.True(t, tz.Equal(time.Date(2026, 1, 2, 13, 4, 5, 0, time.UTC)), "same instant")
	_, offset := tz.Zone()
	require.Equal(t, 2*3600, offset, "the offset survives")
	require.False(t, missing.Valid)
}

func TestMSSQLAIErrorNumberClassState(t *testing.T) {
	db := startAIMSSQL(t, aiResult(&proto.ResultSet{Error: &proto.SqlError{Code: "undefined_table", Message: "Invalid object name 'dbo.missing'."}}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, "SELECT * FROM dbo.missing")
	var merr mssqldb.Error
	require.ErrorAs(t, err, &merr)
	require.Equal(t, int32(208), merr.Number)
	require.Equal(t, uint8(16), merr.Class)
	require.Equal(t, uint8(1), merr.State)
	require.Equal(t, "Invalid object name 'dbo.missing'.", merr.Message)
	require.Equal(t, tdsServerName, merr.ServerName)
}

// Review Focus 4.
func TestMSSQLNonBMPTextKeepsStreamInSync(t *testing.T) {
	var mu sync.Mutex
	n := 0
	db := startAIMSSQL(t, func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		mu.Lock()
		n++
		call := n
		mu.Unlock()
		rs := &proto.ResultSet{Columns: []*proto.Column{{Name: "note🐘", Type: "text"}}, Rows: []*proto.Row{{Values: []string{"🐘 elephant"}}}, CommandTag: "SELECT 1"}
		if call == 2 {
			rs = &proto.ResultSet{Error: &proto.SqlError{Code: "undefined_table", Message: "Invalid object name 'dbo.🐘'."}}
		}
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI, GenerationId: "g", Body: &proto.GenerateReply_ResultSet{ResultSet: rs}}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, "SELECT note FROM dbo.notes")
	require.NoError(t, err)
	names, err := rows.Columns()
	require.NoError(t, err)
	require.Equal(t, []string{"note🐘"}, names, "B_VARCHAR column names count UTF-16 units too")
	require.True(t, rows.Next())
	var note string
	require.NoError(t, rows.Scan(&note))
	require.Equal(t, "🐘 elephant", note)
	require.NoError(t, rows.Close())
	_, err = db.ExecContext(ctx, "SELECT * FROM dbo.🐘")
	var merr mssqldb.Error
	require.ErrorAs(t, err, &merr)
	require.Equal(t, "Invalid object name 'dbo.🐘'.", merr.Message)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT note FROM dbo.notes").Scan(&note), "the stream is still in sync")
}

func TestMSSQLRowsAffectedFromTag(t *testing.T) {
	db := startAIMSSQL(t, aiResult(&proto.ResultSet{CommandTag: "INSERT 3"}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := db.ExecContext(ctx, "INSERT INTO dbo.t VALUES (1),(2),(3)")
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(3), n)
}

// P8: an authored override and a built-in answer both exist for this query,
// and the AI reply must still win (spec §2 precedence: AI first). The lookup
// hook runs on the connection goroutine, so it only records; assertions
// happen on the test goroutine.
func TestMSSQLAIReplyWinsOverAuthoredAndBuiltIn(t *testing.T) {
	var mu sync.Mutex
	lookups := 0
	client, _ := startLoggedInPipe(t, &honeypot{logger: zerolog.Nop(), queryLimit: 1,
		saveQuery: func(*proto.QueryRequest) error { return nil },
		lookup: func(string, string) (string, bool) {
			mu.Lock()
			lookups++
			mu.Unlock()
			return "authored-version", true
		},
		generate: aiResult(&proto.ResultSet{Columns: []*proto.Column{{Name: "v", Type: "text"}},
			Rows: []*proto.Row{{Values: []string{"generated-version"}}}, CommandTag: "SELECT 1"}),
	})
	require.True(t, bytes.Contains(responseForQuery("SELECT @@VERSION"), encodeUCS2("Microsoft SQL Server 2022")), "a built-in answer exists")
	require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2("SELECT @@VERSION")))
	_, reply, err := readMessage(client)
	require.NoError(t, err)
	require.True(t, bytes.Contains(reply, encodeUCS2("generated-version")), "the AI reply went out")
	require.False(t, bytes.Contains(reply, encodeUCS2("authored-version")), "not the authored override")
	require.False(t, bytes.Contains(reply, encodeUCS2("Microsoft SQL Server 2022")), "not the built-in answer")
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 0, lookups, "an answered query never consults the legacy lookup")
}

// The generate hook runs on the connection goroutine, so it only records;
// assertions happen on the test goroutine.
func TestMSSQLFirstQueryShortBudgetThenLiveAndLegacyFallback(t *testing.T) {
	var mu sync.Mutex
	var budgets []time.Duration
	var protocols []string
	client, _ := startLoggedInPipe(t, &honeypot{logger: zerolog.Nop(), queryLimit: 3,
		lookup: func(string, string) (string, bool) { return "", false },
		generate: func(in *proto.GenerateRequest, within time.Duration) (*proto.GenerateReply, error) {
			mu.Lock()
			budgets = append(budgets, within)
			protocols = append(protocols, in.Protocol)
			mu.Unlock()
			return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "row"}, nil
		},
	})
	for _, q := range []string{"SELECT @@VERSION", "SELECT 1"} {
		require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2(q)))
		_, reply, err := readMessage(client)
		require.NoError(t, err)
		require.NotEmpty(t, reply, "NONE falls back to the built-in answer")
	}
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []time.Duration{500 * time.Millisecond, 3 * time.Second}, budgets)
	require.Equal(t, []string{"mssql", "mssql"}, protocols)
}

func TestMSSQLNoneWithoutIDStopsAsking(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	client, _ := startLoggedInPipe(t, &honeypot{logger: zerolog.Nop(), queryLimit: 3,
		lookup: func(string, string) (string, bool) { return "", false },
		generate: func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil
		},
	})
	for _, q := range []string{"SELECT 1", "SELECT 2"} {
		require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2(q)))
		_, _, err := readMessage(client)
		require.NoError(t, err)
	}
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, calls)
}

func TestMSSQLUnusableAIReplyFallsBack(t *testing.T) {
	for name, rs := range map[string]*proto.ResultSet{
		"unknown code": {Error: &proto.SqlError{Code: "208", Message: "x"}},
		"unknown type": {Columns: []*proto.Column{{Name: "id", Type: "uuid"}}},
		"bad date":     {Columns: []*proto.Column{{Name: "d", Type: "date"}}, Rows: []*proto.Row{{Values: []string{"0000-01-01"}}}},
		"short row":    {Columns: []*proto.Column{{Name: "a", Type: "text"}, {Name: "b", Type: "text"}}, Rows: []*proto.Row{{Values: []string{"x"}}}},
	} {
		require.Nil(t, mssqlAIResponse(rs), name)
	}
	require.Nil(t, mssqlAIResponse(nil))
	client, _ := startLoggedInPipe(t, &honeypot{logger: zerolog.Nop(), queryLimit: 1,
		lookup:   func(string, string) (string, bool) { return "", false },
		generate: aiResult(&proto.ResultSet{Error: &proto.SqlError{Code: "nope", Message: "x"}}),
	})
	require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2("select @@version")))
	_, reply, err := readMessage(client)
	require.NoError(t, err)
	require.Contains(t, string(reply), string(encodeUCS2("Microsoft SQL Server 2022")), "the built-in answer ran")
}

func TestMSSQLAICleansServerText(t *testing.T) {
	payload := mssqlAIResponse(&proto.ResultSet{Columns: []*proto.Column{{Name: "n\x1bame", Type: "text"}}, Rows: []*proto.Row{{Values: []string{"red\x1b[31m"}}}})
	require.NotNil(t, payload)
	require.NotContains(t, string(payload), string(encodeUCS2("\x1b")))
	require.Contains(t, string(payload), string(encodeUCS2("red[31m")))
}

// TestLiveMSSQLProbe runs only for the deploy check (Task 12):
// MSSQL_PROBE_ADDR=<honeypot-ip>:1433 go test ./mssql -run TestLiveMSSQLProbe -v -count=1
func TestLiveMSSQLProbe(t *testing.T) {
	addr := os.Getenv("MSSQL_PROBE_ADDR")
	if addr == "" {
		t.Skip("MSSQL_PROBE_ADDR not set")
	}
	db, err := sql.Open("sqlserver", fmt.Sprintf("sqlserver://sa:probe@%s?database=master&encrypt=disable", addr))
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var version string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT @@VERSION").Scan(&version))
	t.Logf("@@VERSION: %s", version)
	rows, err := db.QueryContext(ctx, "SELECT name FROM sys.databases")
	require.NoError(t, err)
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		t.Logf("database: %s", name)
	}
	rows.Close()
	_, err = db.ExecContext(ctx, "SELECT * FROM dbo.table_that_does_not_exist")
	t.Logf("missing table answer: %v", err)
}
