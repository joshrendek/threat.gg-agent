package mysql

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// realClient is how to run the official mysql 8 command-line client against a
// listener on port: natively (MYSQL_CLIENT, or mysql on PATH), or in the
// mysql:8.0 image when docker is up. host is what the client dials and bind is
// the address the listener must use for the client to reach it.
type realClient struct {
	bind, host string
	command    func(port int, args ...string) *exec.Cmd
}

func findRealClient(t *testing.T) realClient {
	t.Helper()
	if path := os.Getenv("MYSQL_CLIENT"); path != "" {
		return nativeClient(path)
	}
	if exec.Command("docker", "info").Run() == nil {
		// Docker Desktop and colima route host.docker.internal to the host; a
		// listener on loopback only is unreachable from the container.
		return realClient{bind: "0.0.0.0", host: "host.docker.internal", command: func(port int, args ...string) *exec.Cmd {
			return exec.Command("docker", append([]string{"run", "--rm", "--add-host=host.docker.internal:host-gateway", "mysql:8.0", "mysql",
				"-h", "host.docker.internal", "-P", strconv.Itoa(port)}, args...)...)
		}}
	}
	if path, err := exec.LookPath("mysql"); err == nil {
		return nativeClient(path)
	}
	t.Skip("no mysql client: set MYSQL_CLIENT, put mysql on PATH, or start docker")
	return realClient{}
}

func nativeClient(path string) realClient {
	return realClient{bind: "127.0.0.1", host: "127.0.0.1", command: func(port int, args ...string) *exec.Cmd {
		return exec.Command(path, append([]string{"--no-defaults", "--protocol=TCP", "-h", "127.0.0.1", "-P", strconv.Itoa(port)}, args...)...)
	}}
}

func s(v string) *string { return &v }

// realClientReplies is what the fake AI answers, per query.
var realClientReplies = map[string]*proto.ResultSet{
	// typed columns and a NULL cell
	"SELECT id, email, balance, active, created_at, deleted_at FROM accounts WHERE id = 1": {
		Columns: []*proto.Column{{Name: "id", Type: "int4"}, {Name: "email", Type: "varchar"}, {Name: "balance", Type: "numeric"},
			{Name: "active", Type: "int2"}, {Name: "created_at", Type: "timestamp"}, {Name: "deleted_at", Type: "timestamp"}},
		Rows: []*proto.Row{{Values: []string{"1", "alice@example.com", "1520.75", "1", "2024-03-11 09:15:02", ""},
			Nulls: []bool{false, false, false, false, false, true}}},
		CommandTag: "SELECT 1",
	},
	// an empty result
	"SELECT token FROM api_keys WHERE revoked = 0": {
		Columns: []*proto.Column{{Name: "token", Type: "varchar"}}, CommandTag: "SELECT 0",
	},
	// an error
	"SELECT * FROM payroll": {Error: &proto.SqlError{Code: "undefined_table", Message: "Table 'production.payroll' doesn't exist"}},
	// several rows
	"SELECT user, host FROM mysql.user": {
		Columns: []*proto.Column{{Name: "user", Type: "name"}, {Name: "host", Type: "name"}},
		Rows: []*proto.Row{{Values: []string{"root", "%"}}, {Values: []string{"debian-sys-maint", "localhost"}},
			{Values: []string{"mysql.infoschema", "localhost"}}, {Values: []string{"mysql.session", "localhost"}}},
		CommandTag: "SELECT 4",
	},
	// rows affected
	"UPDATE accounts SET balance = 0": {CommandTag: "UPDATE 3"},
	// a JSON document and a float after all of the above: the stream is still in sync
	"SELECT JSON_OBJECT('ok', true) AS doc, 0.5 AS ratio": {
		Columns:    []*proto.Column{{Name: "doc", Type: "json"}, {Name: "ratio", Type: "float8"}},
		Rows:       []*proto.Row{{Values: []string{`{"ok": true}`, "0.5"}}},
		CommandTag: "SELECT 1",
	},
}

// TestRealMySQLClient runs the official mysql 8 client (which always negotiates
// CLIENT_DEPRECATE_EOF) against the honeypot with a fake AI, and checks what
// the client prints. Classic EOF framing is covered at the packet level
// (TestResultSetClassicEOFFraming, TestSessionFramingFollowsNegotiatedDeprecateEOF).
func TestRealMySQLClient(t *testing.T) {
	if testing.Short() {
		t.Skip("runs an external mysql client")
	}
	client := findRealClient(t)
	stubLookup(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) { return &proto.CommandResponse{}, nil })

	var mu sync.Mutex
	var asked []*proto.GenerateRequest
	h := &honeypot{logger: zerolog.Nop(), generate: func(in *proto.GenerateRequest, d time.Duration) (*proto.GenerateReply, error) {
		mu.Lock()
		asked = append(asked, in)
		mu.Unlock()
		rs, ok := realClientReplies[in.Input]
		if !ok {
			// What a server with AI on sends for a statement it does not answer: a NONE
			// carrying a ledger id, which keeps the session live.
			return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "gen-none"}, nil
		}
		return aiResult(rs)(in, d)
	}}
	rec := record(h)
	listener, err := net.Listen("tcp", net.JoinHostPort(client.bind, "0"))
	require.NoError(t, err)
	served := make(chan struct{})
	go func() { h.serve(listener); close(served) }()
	t.Cleanup(func() { listener.Close(); <-served })
	port := listener.Addr().(*net.TCPAddr).Port

	run := func(sql string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		// --force must follow -e, which turns it off.
		cmd := client.command(port, "-uroot", "-pS3cret!", "--table", "-vvv", "-e", sql, "--force")
		cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	sql := strings.Join([]string{
		"SELECT id, email, balance, active, created_at, deleted_at FROM accounts WHERE id = 1",
		"SELECT token FROM api_keys WHERE revoked = 0",
		"SELECT * FROM payroll",
		"SELECT user, host FROM mysql.user",
		"UPDATE accounts SET balance = 0",
		"SELECT JSON_OBJECT('ok', true) AS doc, 0.5 AS ratio",
	}, ";\n") + ";"
	out, err := run(sql)
	t.Logf("mysql client output (exit: %v):\n%s", err, out)

	for _, want := range []string{
		// typed result with a NULL cell; numeric columns right-aligned, and nullable
		// columns at least as wide as NULL, as the client does for a real server
		"| id   | email             | balance | active | created_at          | deleted_at |",
		"|    1 | alice@example.com | 1520.75 |      1 | 2024-03-11 09:15:02 | NULL       |",
		"1 row in set",
		// empty result
		"Empty set",
		// mapped error
		"ERROR 1146 (42S02) at line 3: Table 'production.payroll' doesn't exist",
		// several rows
		"| debian-sys-maint | localhost |",
		"| mysql.session    | localhost |",
		"4 rows in set",
		// OK with rows affected
		"Query OK, 3 rows affected",
		// still in sync at the end
		`| {"ok": true} |   0.5 |`,
	} {
		require.Contains(t, out, want)
	}
	require.NotContains(t, out, "Lost connection")
	require.NotContains(t, out, "Malformed")

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, asked)
	for _, a := range asked {
		t.Logf("asked the server: %q", a.Input)
		require.Equal(t, "mysql", a.Protocol)
	}
	waitFor(t, func() bool { rec.mu.Lock(); defer rec.mu.Unlock(); return len(rec.logins) == 1 }, "login")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Equal(t, "root", rec.logins[0].Username)
	require.True(t, strings.HasPrefix(rec.logins[0].Password, "$mysqlcaching$"), "the mysql 8 client authenticates with caching_sha2_password")
	require.Equal(t, rec.logins[0].Guid, asked[0].Guid)
}
