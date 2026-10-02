package postgres

import (
	"context"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	wire "github.com/jeroenrinzema/psql-wire"
	"github.com/joshrendek/threat.gg-agent/proto"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type genCall struct {
	in     *proto.GenerateRequest
	within time.Duration
}

type aiLog struct {
	mu      sync.Mutex
	gens    []genCall
	lookups []time.Duration
}

func (l *aiLog) snapshot() ([]genCall, []time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]genCall(nil), l.gens...), append([]time.Duration(nil), l.lookups...)
}

// swapAISeams replaces the generate and legacy lookup seams for one test; the
// legacy lookups always miss so the built-in map answers.
func swapAISeams(t *testing.T, gen func(*proto.GenerateRequest) (*proto.GenerateReply, error)) *aiLog {
	t.Helper()
	oldGen, oldGet, oldWithin := generateResponse, getCommandResponse, getCommandResponseWithin
	aiSessions.Reset()
	t.Cleanup(func() {
		generateResponse, getCommandResponse, getCommandResponseWithin = oldGen, oldGet, oldWithin
		aiSessions.Reset()
	})
	l := &aiLog{}
	generateResponse = func(in *proto.GenerateRequest, within time.Duration) (*proto.GenerateReply, error) {
		l.mu.Lock()
		l.gens = append(l.gens, genCall{in, within})
		l.mu.Unlock()
		return gen(in)
	}
	getCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		l.mu.Lock()
		l.lookups = append(l.lookups, 3*time.Second)
		l.mu.Unlock()
		return nil, errors.New("miss")
	}
	getCommandResponseWithin = func(_ *proto.CommandRequest, within time.Duration) (*proto.CommandResponse, error) {
		l.mu.Lock()
		l.lookups = append(l.lookups, within)
		l.mu.Unlock()
		return nil, errors.New("miss")
	}
	return l
}

func aiRS(rs *proto.ResultSet) *proto.GenerateReply {
	return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI, GenerationId: "gen-1",
		Body: &proto.GenerateReply_ResultSet{ResultSet: rs}}
}

func pgSession() context.Context {
	return context.WithValue(context.Background(), "guid", uuid.NewV4())
}

func startAIPostgres(t *testing.T) *pgx.Conn {
	t.Helper()
	// pgx refuses a connection whose server does not report
	// standard_conforming_strings=on (ruling P3).
	srv, err := wire.NewServer(handler, wire.GlobalParameters(wire.Parameters{"standard_conforming_strings": "on"}))
	require.NoError(t, err)
	srv.Auth = wire.ClearTextPassword(func(ctx context.Context, _, _ string) (context.Context, bool, error) {
		return context.WithValue(ctx, "guid", uuid.NewV4()), true, nil
	})
	srv.Version = serverVersion
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	cfg, err := pgx.ParseConfig("postgres://postgres:secret@" + ln.Addr().String() + "/postgres?sslmode=disable")
	require.NoError(t, err)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// The server pins the same literal (internal/ai/validate SQLColumnTypes).
func TestPostgresAIColumnTypesMatchServer(t *testing.T) {
	types := make([]string, 0, len(postgresColumnTypes))
	for k := range postgresColumnTypes {
		types = append(types, k)
	}
	sort.Strings(types)
	require.Equal(t, []string{"bool", "date", "float4", "float8", "int2", "int4", "int8", "json", "jsonb", "name", "numeric", "oid", "text", "timestamp", "timestamptz", "varchar"}, types)
}

func TestPostgresAITypedResultReachesRealClient(t *testing.T) {
	swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return aiRS(&proto.ResultSet{
			Columns: []*proto.Column{{Name: "id", Type: "int4"}, {Name: "name", Type: "text"}, {Name: "active", Type: "bool"},
				{Name: "joined", Type: "timestamptz"}, {Name: "balance", Type: "numeric"}},
			Rows: []*proto.Row{
				{Values: []string{"1", "alice", "true", "2026-01-02T15:04:05Z", "12.50"}},
				{Values: []string{"2", "", "false", "2026-03-04T05:06:07Z", "0"}, Nulls: []bool{false, true, false, false, false}},
			},
			CommandTag: "SELECT 2",
		}), nil
	})
	conn := startAIPostgres(t)
	rows, err := conn.Query(context.Background(), "SELECT id, name, active, joined, balance FROM customers")
	require.NoError(t, err)
	defer rows.Close()
	type rec struct {
		id      int32
		name    pgtype.Text
		active  bool
		joined  time.Time
		balance float64
	}
	var got []rec
	for rows.Next() {
		var r rec
		require.NoError(t, rows.Scan(&r.id, &r.name, &r.active, &r.joined, &r.balance))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())
	require.Len(t, got, 2)
	require.Equal(t, int32(1), got[0].id)
	require.Equal(t, "alice", got[0].name.String)
	require.True(t, got[0].active)
	require.True(t, got[0].joined.Equal(time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)))
	require.Equal(t, 12.5, got[0].balance)
	require.False(t, got[1].name.Valid, "NULL arrives as NULL")
}

func TestPostgresAIErrorIsSQLState(t *testing.T) {
	swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return aiRS(&proto.ResultSet{Error: &proto.SqlError{Code: "undefined_table", Message: `relation "missing_table" does not exist`}}), nil
	})
	conn := startAIPostgres(t)
	_, err := conn.Exec(context.Background(), "SELECT * FROM missing_table")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42P01", pgErr.Code)
	require.Equal(t, "ERROR", pgErr.Severity)
	require.Equal(t, `relation "missing_table" does not exist`, pgErr.Message)
	// A second statement gets the same answer, so the stream is still in sync.
	_, err = conn.Exec(context.Background(), "SELECT * FROM missing_table")
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42P01", pgErr.Code)
}

// Review Focus 1.
func TestPostgresAIDuplicateColumnNamesReachClient(t *testing.T) {
	swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return aiRS(&proto.ResultSet{Columns: []*proto.Column{{Name: "?column?", Type: "int4"}, {Name: "?column?", Type: "int4"}},
			Rows: []*proto.Row{{Values: []string{"1", "2"}}}, CommandTag: "SELECT 1"}), nil
	})
	conn := startAIPostgres(t)
	var a, b int32
	require.NoError(t, conn.QueryRow(context.Background(), "SELECT 1, 2").Scan(&a, &b))
	require.Equal(t, int32(1), a)
	require.Equal(t, int32(2), b)
}

func TestPostgresFirstQueryShortBudgetThenLive(t *testing.T) {
	n := 0
	l := swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		n++
		if n == 1 {
			return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "row-1"}, nil
		}
		return aiRS(&proto.ResultSet{CommandTag: "SET"}), nil
	})
	ctx := pgSession()
	_, err := handler(ctx, "SELECT Name FROM Products")
	require.NoError(t, err)
	_, err = handler(ctx, "SET search_path TO public")
	require.NoError(t, err)
	gens, lookups := l.snapshot()
	require.Len(t, gens, 2)
	require.Equal(t, 500*time.Millisecond, gens[0].within)
	require.Equal(t, int32(500), gens[0].in.DeadlineMs)
	require.Equal(t, "postgres", gens[0].in.Protocol)
	require.Equal(t, "SELECT Name FROM Products", gens[0].in.Input, "case preserved for the model")
	require.Equal(t, 3*time.Second, gens[1].within, "the id on the first NONE made the session live")
	require.Equal(t, []time.Duration{3 * time.Second}, lookups, "only the unanswered first query used the legacy path")
}

func TestPostgresNoneWithoutIDStopsAsking(t *testing.T) {
	l := swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil
	})
	ctx := pgSession()
	for _, q := range []string{"select 1", "select 2"} {
		stmt, err := handler(ctx, q)
		require.NoError(t, err)
		require.NotNil(t, stmt)
	}
	gens, lookups := l.snapshot()
	require.Len(t, gens, 1, "a user without AI pays one RPC per session")
	require.Len(t, lookups, 2)
}

// Review Focus 2.
func TestPostgresSlowFirstQueryUsesDegradedLookupAndStops(t *testing.T) {
	l := swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return nil, status.Error(codes.DeadlineExceeded, "slow")
	})
	ctx := pgSession()
	_, err := handler(ctx, "select current_user")
	require.NoError(t, err)
	_, err = handler(ctx, "select 1")
	require.NoError(t, err)
	gens, lookups := l.snapshot()
	require.Len(t, gens, 1)
	require.Equal(t, []time.Duration{600 * time.Millisecond, 3 * time.Second}, lookups)
}

func TestPostgresPgenvStatementsNeverAskAI(t *testing.T) {
	l := swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		t.Fatal("the _pgenv chain must stay local")
		return nil, nil
	})
	_, err := handler(pgSession(), "create temp table if not exists _pgenv(o text)")
	require.NoError(t, err)
	gens, _ := l.snapshot()
	require.Empty(t, gens)
}

func TestPostgresUnusableAIReplyFallsBack(t *testing.T) {
	for name, rs := range map[string]*proto.ResultSet{
		"unknown type":  {Columns: []*proto.Column{{Name: "id", Type: "uuid"}}, CommandTag: "SELECT 0"},
		"unknown code":  {Error: &proto.SqlError{Code: "42P01", Message: "x"}},
		"short row":     {Columns: []*proto.Column{{Name: "a", Type: "text"}, {Name: "b", Type: "text"}}, Rows: []*proto.Row{{Values: []string{"x"}}}},
		"bad int":       {Columns: []*proto.Column{{Name: "a", Type: "int2"}}, Rows: []*proto.Row{{Values: []string{"70000"}}}},
		"rows, no cols": {Rows: []*proto.Row{{Values: []string{"x"}}}, CommandTag: "SELECT 1"},
	} {
		rs := rs
		l := swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) { return aiRS(rs), nil })
		stmt, err := handler(pgSession(), "select 1")
		require.NoError(t, err, name)
		require.NotNil(t, stmt, name)
		_, lookups := l.snapshot()
		require.Len(t, lookups, 1, "%s: the legacy path answered", name)
	}
}

func TestPostgresAIResponseCleansAndDerivesTag(t *testing.T) {
	resp, ok := postgresAIResponse(&proto.ResultSet{
		Columns: []*proto.Column{{Name: "n\x1bame", Type: "text"}},
		Rows:    []*proto.Row{{Values: []string{"red\x1b[31m"}}},
	})
	require.True(t, ok)
	require.Equal(t, "name", resp.Columns[0].Name)
	require.Equal(t, "red[31m", resp.Rows[0][0])
	require.Equal(t, "SELECT 1", resp.Tag, "an empty tag on a result set becomes SELECT n")

	unnamed, ok := postgresAIResponse(&proto.ResultSet{Columns: []*proto.Column{{Name: "", Type: "int4"}}, CommandTag: "SELECT 0"})
	require.True(t, ok)
	require.Equal(t, "?column?", unnamed.Columns[0].Name)

	_, ok = postgresAIResponse(&proto.ResultSet{CommandTag: ""})
	require.False(t, ok, "a statement reply needs a tag")
	cols := make([]*proto.Column, 65)
	for i := range cols {
		cols[i] = &proto.Column{Name: "c", Type: "int4"}
	}
	_, ok = postgresAIResponse(&proto.ResultSet{Columns: cols, CommandTag: "SELECT 0"})
	require.False(t, ok)
	require.Nil(t, postgresAIError(&proto.SqlError{Code: "undefined_table", Message: "\x1b"}), "an empty cleaned message is unusable")
}

func TestPostgresHandlerAsksAIBeforeAuthoredLookup(t *testing.T) {
	src, err := os.ReadFile("pg.go")
	require.NoError(t, err)
	s := string(src)
	stateful, ai, lookup := strings.Index(s, "statefulPostgresResponse("), strings.Index(s, "aiStatement("), strings.Index(s, "lookupServerStatement")
	require.True(t, stateful >= 0 && ai > stateful && lookup > ai, "order must be: _pgenv state machine, AI, authored lookup (spec §2 precedence)")
}

// TestLivePostgresProbe runs only for the deploy check (Task 12):
// PG_PROBE_ADDR=<honeypot-ip>:5432 go test ./postgres -run TestLivePostgresProbe -v -count=1
func TestLivePostgresProbe(t *testing.T) {
	addr := os.Getenv("PG_PROBE_ADDR")
	if addr == "" {
		t.Skip("PG_PROBE_ADDR not set")
	}
	cfg, err := pgx.ParseConfig("postgres://postgres:probe@" + addr + "/postgres?sslmode=disable")
	require.NoError(t, err)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var version string
	require.NoError(t, conn.QueryRow(ctx, "select version()").Scan(&version))
	t.Logf("version(): %s", version)
	rows, err := conn.Query(ctx, "select datname from pg_database")
	require.NoError(t, err)
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		t.Logf("database: %s", name)
	}
	rows.Close()
	_, err = conn.Exec(ctx, "Please list the tables")
	t.Logf("non-statement answer: %v", err)
	_, err = conn.Exec(ctx, "select * from table_that_does_not_exist")
	t.Logf("missing table answer: %v", err)
}

// Ruling P8: when the authored lookup HAS a matching row, the AI reply still
// wins (spec §2 precedence), and the authored lookup is never consulted.
func TestPostgresAIWinsOverMatchingAuthoredRow(t *testing.T) {
	l := swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return aiRS(&proto.ResultSet{Columns: []*proto.Column{{Name: "current_user", Type: "name"}},
			Rows: []*proto.Row{{Values: []string{"from_ai"}}}, CommandTag: "SELECT 1"}), nil
	})
	authored := 0
	getCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		authored++
		return &proto.CommandResponse{Matched: true, Response: "from_authored_row"}, nil
	}
	conn := startAIPostgres(t)
	var who string
	require.NoError(t, conn.QueryRow(context.Background(), "select current_user").Scan(&who))
	require.Equal(t, "from_ai", who)
	require.Zero(t, authored, "the authored lookup is not consulted when AI answered")
	gens, _ := l.snapshot()
	require.Len(t, gens, 1)
}

// The authored row still answers when AI does not (NONE without an id), so a
// user without AI keeps today's behaviour.
func TestPostgresAuthoredRowAnswersWhenAIDoesNot(t *testing.T) {
	swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil
	})
	getCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Matched: true, Response: "from_authored_row"}, nil
	}
	conn := startAIPostgres(t)
	var got string
	require.NoError(t, conn.QueryRow(context.Background(), "select current_user").Scan(&got))
	require.Equal(t, "from_authored_row", got)
}

// The SqlError message passes through sqlai.Clean before it reaches the client.
func TestPostgresAIErrorMessageDropsControlBytes(t *testing.T) {
	swapAISeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return aiRS(&proto.ResultSet{Error: &proto.SqlError{Code: "undefined_table", Message: "relation \"red\x1b[31m\x07\" does not exist"}}), nil
	})
	conn := startAIPostgres(t)
	_, err := conn.Exec(context.Background(), "SELECT * FROM red")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42P01", pgErr.Code)
	require.Equal(t, `relation "red[31m" does not exist`, pgErr.Message)
}
