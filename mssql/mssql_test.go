package mssql

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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
	origLogin, origQuery, origLookup := saveMssqlLogin, saveQuery, lookupResponse
	t.Cleanup(func() { saveMssqlLogin, saveQuery, lookupResponse = origLogin, origQuery, origLookup })
	saveMssqlLogin = func(*proto.MssqlRequest) error { return nil }
	saveQuery = func(*proto.QueryRequest) error { return nil }
	lookupResponse = func(string, string) (string, bool) { return "", false }

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h := &honeypot{logger: zerolog.Nop()}
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
	origLogin, origQuery, origLookup := saveMssqlLogin, saveQuery, lookupResponse
	t.Cleanup(func() { saveMssqlLogin, saveQuery, lookupResponse = origLogin, origQuery, origLookup })

	var mu sync.Mutex
	var login *proto.MssqlRequest
	var query *proto.QueryRequest
	saved := make(chan struct{}, 2)
	saveMssqlLogin = func(in *proto.MssqlRequest) error {
		mu.Lock()
		login = in
		mu.Unlock()
		saved <- struct{}{}
		return nil
	}
	saveQuery = func(in *proto.QueryRequest) error {
		mu.Lock()
		query = in
		mu.Unlock()
		saved <- struct{}{}
		return nil
	}
	lookupResponse = func(commandType, command string) (string, bool) {
		require.Equal(t, "mssql", commandType)
		require.Equal(t, "SELECT @@VERSION", command)
		return "authored-version", true
	}

	server, client := net.Pipe()
	h := &honeypot{logger: zerolog.Nop()}
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
	orig := persistSlots
	t.Cleanup(func() { persistSlots = orig })
	persistSlots = make(chan struct{}, 1)
	persistSlots <- struct{}{}
	h := &honeypot{logger: zerolog.Nop()}
	called := false
	start := time.Now()
	h.persist(func() error { called = true; return errors.New("should not run") })
	require.Less(t, time.Since(start), 100*time.Millisecond)
	require.False(t, called)
}

func login7Fixture(fields map[int]string) []byte {
	payload := make([]byte, 94)
	binary.BigEndian.PutUint32(payload[4:8], 0x74000004)
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
