package mssql

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// Item 7: TDS 7.2+ clients put an ALL_HEADERS block before the query text.
// It must be stripped before the saved query, the legacy rules and the AI
// request see the text.
func TestRealClientBatchHeadersAreStripped(t *testing.T) {
	var mu sync.Mutex
	var saved, asked []string
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h := &honeypot{
		logger:    zerolog.Nop(),
		saveLogin: func(*proto.MssqlRequest) error { return nil },
		saveQuery: func(q *proto.QueryRequest) error {
			mu.Lock()
			saved = append(saved, q.Query)
			mu.Unlock()
			return nil
		},
		lookup: func(string, string) (string, bool) { return "", false },
		generate: func(in *proto.GenerateRequest, _ time.Duration) (*proto.GenerateReply, error) {
			mu.Lock()
			asked = append(asked, in.Input)
			mu.Unlock()
			return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "row"}, nil
		},
	}
	serveDone := make(chan struct{})
	go func() { h.serve(listener); close(serveDone) }()
	t.Cleanup(func() { listener.Close(); <-serveDone })
	db, err := sql.Open("sqlserver", fmt.Sprintf("sqlserver://sa:probe@%s?database=master&encrypt=disable", listener.Addr()))
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	ctx := testCtx(t)

	var one, version string
	oneErr := db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
	_, useErr := db.ExecContext(ctx, "USE master")
	versionErr := db.QueryRowContext(ctx, "SELECT @@VERSION").Scan(&version)

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(saved) == 3
	}, 2*time.Second, 10*time.Millisecond, "persistence is asynchronous")
	mu.Lock()
	require.Equal(t, []string{"SELECT 1", "USE master", "SELECT @@VERSION"}, saved, "saved queries carry no header bytes")
	require.Equal(t, []string{"SELECT 1", "USE master", "SELECT @@VERSION"}, asked, "the AI request carries no header bytes")
	mu.Unlock()

	// Legacy rules keyed on the start of the query now match a real client;
	// before, the header bytes made them "Incorrect syntax".
	require.NoError(t, oneErr)
	require.Equal(t, "1", one)
	require.NoError(t, useErr, "the legacy USE rule matches")
	require.NoError(t, versionErr)
	require.Contains(t, version, "Microsoft SQL Server 2022")
}

// allHeaders builds an ALL_HEADERS block holding one transaction descriptor
// header (type 2), as go-mssqldb sends it.
func allHeaders() []byte {
	b := binary.LittleEndian.AppendUint32(nil, 22) // TotalLength
	b = binary.LittleEndian.AppendUint32(b, 18)    // HeaderLength
	b = binary.LittleEndian.AppendUint16(b, 2)     // HeaderType
	b = binary.LittleEndian.AppendUint64(b, 0)     // TransactionDescriptor
	return binary.LittleEndian.AppendUint32(b, 1)  // OutstandingRequestCount
}

func TestParseSQLBatchHeaders(t *testing.T) {
	require.Equal(t, "SELECT 1", parseSQLBatch(append(allHeaders(), encodeUCS2("SELECT 1")...)), "TDS 7.2+ batch")
	require.Equal(t, "SELECT 1", parseSQLBatch(encodeUCS2("SELECT 1")), "a bare TDS 7.1 batch")
	require.Equal(t, "", parseSQLBatch(allHeaders()), "headers and no text")
	require.Equal(t, "", parseSQLBatch(nil))

	tooLong := allHeaders()
	binary.LittleEndian.PutUint32(tooLong[0:4], 1<<31) // TotalLength past the message
	got := parseSQLBatch(append(tooLong, encodeUCS2("SELECT 1")...))
	require.Equal(t, decodeUCS2(append(tooLong, encodeUCS2("SELECT 1")...)), got, "a malformed block is treated as bare text")

	unknownType := allHeaders()
	binary.LittleEndian.PutUint16(unknownType[8:10], 9)
	require.NotEqual(t, "SELECT 1", parseSQLBatch(append(unknownType, encodeUCS2("SELECT 1")...)), "an unknown header type is not a header")

	shortHeader := allHeaders()
	binary.LittleEndian.PutUint32(shortHeader[4:8], 5)
	require.NotEqual(t, "SELECT 1", parseSQLBatch(append(shortHeader, encodeUCS2("SELECT 1")...)), "HeaderLength under 6 is not a header")

	headerPastTotal := allHeaders()
	binary.LittleEndian.PutUint32(headerPastTotal[4:8], 40)
	require.NotEqual(t, "SELECT 1", parseSQLBatch(append(headerPastTotal, encodeUCS2("SELECT 1")...)), "a header longer than the block is not a header")
}
