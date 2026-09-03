package mssql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRealGoMSSQLClientCanLoginAndQuery(t *testing.T) {
	saved := make(chan struct{}, 2)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h := &honeypot{
		logger:    zerolog.Nop(),
		saveLogin: func(*proto.MssqlRequest) error { saved <- struct{}{}; return nil },
		saveQuery: func(*proto.QueryRequest) error { saved <- struct{}{}; return nil },
		lookup:    func(string, string) (string, bool) { return "", false },
	}
	serveDone := make(chan struct{})
	go func() { h.serve(listener); close(serveDone) }()
	t.Cleanup(func() { listener.Close(); <-serveDone })

	dsn := fmt.Sprintf("sqlserver://svc-sql:S3cret%%21@%s?database=Finance&encrypt=disable", listener.Addr())
	db, err := sql.Open("sqlserver", dsn)
	require.NoError(t, err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var version string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT @@VERSION").Scan(&version))
	require.Contains(t, version, "Microsoft SQL Server 2022")
	for i := 0; i < 2; i++ {
		select {
		case <-saved:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for asynchronous persistence")
		}
	}
}

func TestParseLogin7CapturesClientMetadataAndPassword(t *testing.T) {
	payload := login7Fixture(map[int]string{
		36: "WS-042", 40: "svc-sql", 44: "S3cret!", 48: "sqlcmd",
		52: "sqlserver01.corp.com", 60: "ODBC", 68: "Finance",
	})
	got, err := parseLogin7(payload)
	require.NoError(t, err)
	require.Equal(t, "WS-042", got.hostname)
	require.Equal(t, "svc-sql", got.username)
	require.Equal(t, "S3cret!", got.password)
	require.Equal(t, "sqlcmd", got.appName)
	require.Equal(t, "sqlserver01.corp.com", got.serverName)
	require.Equal(t, "ODBC", got.library)
	require.Equal(t, "Finance", got.database)
	require.Equal(t, uint32(0x74000004), got.tdsVersion)
}

func TestParseLogin7RejectsOutOfBoundsFields(t *testing.T) {
	payload := login7Fixture(map[int]string{40: "user"})
	binary.LittleEndian.PutUint16(payload[40:42], uint16(len(payload)-1))
	binary.LittleEndian.PutUint16(payload[42:44], 2)
	_, err := parseLogin7(payload)
	require.ErrorContains(t, err, "bounds")
}

func TestReadMessageAggregatesPacketsAndEnforcesLimit(t *testing.T) {
	packet := func(status byte, body string) []byte {
		h := []byte{packetSQLBatch, status, 0, 0, 0, 0, 1, 0}
		binary.BigEndian.PutUint16(h[2:4], uint16(len(body)+8))
		return append(h, body...)
	}
	typeID, payload, err := readMessage(bytes.NewReader(append(packet(0, "abc"), packet(statusEOM, "def")...)))
	require.NoError(t, err)
	require.Equal(t, byte(packetSQLBatch), typeID)
	require.Equal(t, []byte("abcdef"), payload)

	bad := []byte{packetSQLBatch, statusEOM, 0, 7, 0, 0, 1, 0}
	_, _, err = readMessage(bytes.NewReader(bad))
	require.ErrorContains(t, err, "length")
}

func TestSessionCompletesLoginPersistsAndAnswersQuery(t *testing.T) {
	var mu sync.Mutex
	var login *proto.MssqlRequest
	var query *proto.QueryRequest
	saved := make(chan struct{}, 2)

	server, client := net.Pipe()
	h := &honeypot{
		logger: zerolog.Nop(),
		saveLogin: func(in *proto.MssqlRequest) error {
			mu.Lock()
			login = in
			mu.Unlock()
			saved <- struct{}{}
			return nil
		},
		saveQuery: func(in *proto.QueryRequest) error {
			mu.Lock()
			query = in
			mu.Unlock()
			saved <- struct{}{}
			return nil
		},
		lookup: func(commandType, command string) (string, bool) {
			require.Equal(t, "mssql", commandType)
			require.Equal(t, "select @@version", command)
			return "authored-version", true
		},
	}
	done := make(chan struct{})
	go func() { h.handleConnection(server); close(done) }()
	t.Cleanup(func() { client.Close(); <-done })

	require.NoError(t, writeMessage(client, packetPrelogin, []byte{0xff}))
	typeID, prelogin, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, byte(packetReply), typeID)
	require.True(t, bytes.Contains(prelogin, []byte{0x10, 0x00, 0x03, 0xe8}))

	require.NoError(t, writeMessage(client, packetLogin7, login7Fixture(map[int]string{
		36: "WS-042", 40: "svc-sql", 44: "S3cret!", 48: "sqlcmd", 52: "sqlserver01.corp.com", 60: "ODBC", 68: "Finance",
	})))
	_, loginReply, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, byte(0xad), loginReply[0])

	require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2("SELECT @@VERSION")))
	_, queryReply, err := readMessage(client)
	require.NoError(t, err)
	require.True(t, bytes.Contains(queryReply, encodeUCS2("authored-version")))

	for i := 0; i < 2; i++ {
		select {
		case <-saved:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for persistence")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, "svc-sql", login.Username)
	require.Equal(t, "S3cret!", login.Password)
	require.NotEmpty(t, login.Guid)
	require.Equal(t, login.Guid, query.Guid)
	require.Equal(t, "mssql", query.CommandType)
}

func TestResponseForQueryHasPlausibleRecon(t *testing.T) {
	for query, want := range map[string]string{
		"select @@version":               "Microsoft SQL Server 2022",
		"SELECT DB_NAME()":               "master",
		"select name from sys.databases": "Finance",
		"select system_user":             `CORP\svc-sql`,
	} {
		require.True(t, bytes.Contains(responseForQuery(query), encodeUCS2(want)), query)
	}
	require.Equal(t, byte(0xaa), responseForQuery("nonsense")[0])
}

func TestPersistenceQueueDropsInsteadOfBlocking(t *testing.T) {
	full := make(chan struct{}, 1)
	full <- struct{}{}
	h := &honeypot{logger: zerolog.Nop(), persistSlots: full}
	called := false
	start := time.Now()
	h.persist(func() error { called = true; return errors.New("should not run") })
	require.Less(t, time.Since(start), 100*time.Millisecond)
	require.False(t, called)
}

func TestConnectionAdmissionRejectsWhenCapacityIsFull(t *testing.T) {
	slots := make(chan struct{}, 1)
	slots <- struct{}{}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h := &honeypot{logger: zerolog.Nop(), connectionSlots: slots}
	done := make(chan struct{})
	go func() { h.serve(listener); close(done) }()
	t.Cleanup(func() { listener.Close(); <-done })

	client, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = client.Read(make([]byte, 1))
	require.Error(t, err)
}

func TestInitialReadAndSessionDurationAreBounded(t *testing.T) {
	server, client := net.Pipe()
	h := &honeypot{logger: zerolog.Nop(), idleTimeout: 20 * time.Millisecond}
	initialDone := make(chan struct{})
	go func() { h.handleConnection(server); close(initialDone) }()
	t.Cleanup(func() { client.Close() })
	select {
	case <-initialDone:
	case <-time.After(time.Second):
		t.Fatal("initial TDS read was not bounded by the idle deadline")
	}

	h = &honeypot{logger: zerolog.Nop(), idleTimeout: time.Second, sessionLimit: 30 * time.Millisecond}
	sessionClient, sessionDone := startLoggedInPipe(t, h)
	_ = sessionClient
	select {
	case <-sessionDone:
	case <-time.After(time.Second):
		t.Fatal("session did not stop at its duration limit")
	}
}

func TestSessionQueryCapStopsFurtherBatches(t *testing.T) {
	h := &honeypot{logger: zerolog.Nop(), queryLimit: 1, lookup: func(string, string) (string, bool) { return "", false }}
	require.Equal(t, maxQueries, (&honeypot{}).effectiveQueryLimit())
	client, done := startLoggedInPipe(t, h)
	require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2("SELECT 1")))
	_, _, err := readMessage(client)
	require.NoError(t, err)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop at query cap")
	}
	require.Error(t, writeMessage(client, packetSQLBatch, encodeUCS2("SELECT 2")))
}

func TestUnsupportedPacketKeepsSessionUsable(t *testing.T) {
	client, _ := startLoggedInPipe(t, &honeypot{logger: zerolog.Nop(), queryLimit: 2, lookup: func(string, string) (string, bool) { return "", false }})
	require.NoError(t, writeMessage(client, packetRPC, []byte{1, 2, 3}))
	_, unsupported, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, byte(0xaa), unsupported[0])

	require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2("SELECT 1")))
	_, reply, err := readMessage(client)
	require.NoError(t, err)
	require.True(t, bytes.Contains(reply, encodeUCS2("1")))
}

func TestOverrideLookupIsNormalizedAndCachedPerSession(t *testing.T) {
	calls := 0
	client, _ := startLoggedInPipe(t, &honeypot{
		logger:     zerolog.Nop(),
		queryLimit: 2,
		lookup: func(commandType, command string) (string, bool) {
			calls++
			require.Equal(t, "mssql", commandType)
			require.Equal(t, "select @@version", command)
			return "cached", true
		},
	})
	for _, query := range []string{"SELECT   @@VERSION", " select @@version "} {
		require.NoError(t, writeMessage(client, packetSQLBatch, encodeUCS2(query)))
		_, reply, err := readMessage(client)
		require.NoError(t, err)
		require.True(t, bytes.Contains(reply, encodeUCS2("cached")))
	}
	require.Equal(t, 1, calls)
}

func startLoggedInPipe(t *testing.T, h *honeypot) (net.Conn, <-chan struct{}) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { h.handleConnection(server); close(done) }()
	t.Cleanup(func() {
		client.Close()
		<-done
	})
	require.NoError(t, writeMessage(client, packetPrelogin, []byte{0xff}))
	_, _, err := readMessage(client)
	require.NoError(t, err)
	require.NoError(t, writeMessage(client, packetLogin7, login7Fixture(map[int]string{40: "svc-sql", 44: "secret"})))
	_, reply, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, byte(0xad), reply[0])
	return client, done
}

func login7Fixture(fields map[int]string) []byte {
	payload := make([]byte, 94)
	binary.LittleEndian.PutUint32(payload[4:8], 0x74000004)
	for _, pair := range []int{36, 40, 44, 48, 52, 60, 64, 68, 82, 86} {
		value := fields[pair]
		raw := encodeUCS2(value)
		if pair == 44 {
			for i := range raw {
				b := raw[i]
				raw[i] = (b<<4 | b>>4) ^ 0xa5
			}
		}
		binary.LittleEndian.PutUint16(payload[pair:pair+2], uint16(len(payload)))
		binary.LittleEndian.PutUint16(payload[pair+2:pair+4], uint16(len([]rune(value))))
		payload = append(payload, raw...)
	}
	binary.LittleEndian.PutUint32(payload[:4], uint32(len(payload)))
	return payload
}

func TestSQLBatchDecodeTrimsWhitespace(t *testing.T) {
	require.Equal(t, "SELECT 1", parseSQLBatch(encodeUCS2("  SELECT 1\r\n")))
	require.False(t, strings.Contains(parseSQLBatch(encodeUCS2("SELECT 1")), "\x00"))
}

// threat_gg-x59t was an intermittent -race failure: tests swapped package-level
// hooks in setup and restored them in t.Cleanup while connection goroutines
// from an earlier test -- which outlive both serve() and the test -- still
// read them. It reproduced at -count=30 once, then hid behind a partial
// mitigation for weeks, and an intermittent race cannot be pinned by running
// the suite and watching it pass. So this pins the STRUCTURE instead: the
// hooks live on the honeypot struct, and no test may assign to a package
// default. If this fails, the fix has been undone -- even if -race is green.
func TestNoTestReassignsPackageDefaults(t *testing.T) {
	src, err := os.ReadFile("mssql_test.go")
	require.NoError(t, err)
	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, name := range []string{"defaultSaveLogin", "defaultSaveQuery", "defaultLookup", "defaultPersistSlots", "defaultConnectionSlots"} {
			if strings.HasPrefix(trimmed, name+" =") || strings.HasPrefix(trimmed, name+"=") {
				t.Errorf("mssql_test.go:%d assigns to %s; set the field on the honeypot struct instead (threat_gg-x59t)", i+1, name)
			}
		}
	}
}
