package adb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/stretchr/testify/require"
)

func handshake(t *testing.T, conn net.Conn) {
	handshakeWithPayload(t, conn, advertisedPayload)
}

func handshakeWithPayload(t *testing.T, conn net.Conn, payload uint32) {
	t.Helper()
	require.NoError(t, writeMessage(conn, message{command: cmdCNXN, arg0: adbVersion, arg1: payload, data: []byte("host::features=cmd")}))
	auth, err := readMessage(conn)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdAUTH), auth.command)
	require.Equal(t, uint32(authToken), auth.arg0)
	require.Len(t, auth.data, 20)
	require.NoError(t, writeMessage(conn, message{command: cmdAUTH, arg0: authSignature, data: bytes.Repeat([]byte{0x42}, 256)}))
	connect, err := readMessage(conn)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdCNXN), connect.command)
	require.Contains(t, string(connect.data), "ro.product.model=Pixel_7")
}

func TestTransportAuthenticatesRunsShellAndCapturesSession(t *testing.T) {
	originalSave, originalLookup := saveSession, getCommandResponse
	t.Cleanup(func() { saveSession, getCommandResponse = originalSave, originalLookup })
	saved := make(chan *pb.AdbSessionRequest, 1)
	saveSession = func(in *pb.AdbSessionRequest) error { saved <- in; return nil }
	lookedUp := make(chan struct {
		request *pb.CommandRequest
		timeout time.Duration
	}, 1)
	const peerPayload = 4096
	longResponse := strings.Repeat("x", peerPayload+17)
	getCommandResponse = func(in *pb.CommandRequest, timeout time.Duration) (*pb.CommandResponse, error) {
		lookedUp <- struct {
			request *pb.CommandRequest
			timeout time.Duration
		}{in, timeout}
		return &pb.CommandResponse{Matched: true, Response: longResponse}, nil
	}

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { (&honeypot{}).handleConnection(server); close(done) }()
	handshakeWithPayload(t, client, peerPayload)
	require.NoError(t, writeMessage(client, message{command: cmdOPEN, arg0: 7, data: []byte("shell:id\x00")}))
	ok, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdOKAY), ok.command)
	output, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdWRTE), output.command)
	require.Len(t, output.data, peerPayload)
	require.Equal(t, strings.Repeat("x", peerPayload), string(output.data))
	require.NoError(t, writeMessage(client, message{command: cmdOKAY, arg0: 7, arg1: ok.arg0}))
	output, err = readMessage(client)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("x", 17)+"\n", string(output.data))
	require.NoError(t, writeMessage(client, message{command: cmdOKAY, arg0: 7, arg1: ok.arg0}))
	closed, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdCLSE), closed.command)
	require.NoError(t, client.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not stop")
	}
	select {
	case capture := <-saved:
		require.Equal(t, "host::features=cmd", capture.HostBanner)
		require.Equal(t, "signature", capture.AuthKind)
		sum := sha256.Sum256(bytes.Repeat([]byte{0x42}, 256))
		require.Equal(t, fmt.Sprintf("sha256:%x", sum[:]), capture.AuthFingerprint)
		require.Equal(t, []string{"shell:id"}, capture.Services)
		require.Equal(t, []string{"id"}, capture.Commands)
	case <-time.After(time.Second):
		t.Fatal("session was not persisted")
	}
	select {
	case lookup := <-lookedUp:
		require.Equal(t, "adb", lookup.request.CommandType)
		require.Equal(t, "id", lookup.request.Command)
		require.Equal(t, commandLookupLimit, lookup.timeout)
	case <-time.After(time.Second):
		t.Fatal("command lookup was not captured")
	}
}

func TestAuthenticationAndTextSafetyBoundaries(t *testing.T) {
	s := &session{channels: make(map[uint32]*channel)}
	require.True(t, s.handleMessage(nil, message{command: cmdAUTH, arg0: authSignature, data: []byte("unsolicited")}))
	require.False(t, s.authenticated)
	require.False(t, s.handleMessage(nil, message{command: cmdOPEN, arg0: 1, data: []byte("shell:id\x00")}))

	key := []byte("decoded-adb-public-key")
	encoded := base64.StdEncoding.EncodeToString(key) + " operator@host\x00"
	sum := sha256.Sum256(key)
	require.Equal(t, fmt.Sprintf("sha256:%x", sum[:]), fingerprintAuth([]byte(encoded), true))
	require.Equal(t, "adb-upload.bin", safeFilename("../.."))
	require.Equal(t, "a", boundedText([]byte{'a', 0xe2, 0x82, 0xac}, 2))
	require.Len(t, boundedText([]byte(strings.Repeat("x", maxCommandResponse+1)), maxCommandResponse), maxCommandResponse)
}

func TestConnectionDeadlineAndChannelControlAreBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	require.Equal(t, now.Add(idleTimeout), nextReadDeadline(now, now.Add(connectionTimeout)))
	require.Equal(t, now.Add(time.Second), nextReadDeadline(now, now.Add(time.Second)))

	ch := &channel{clientID: 7, deviceID: 11, pending: []byte("pending")}
	s := &session{channels: map[uint32]*channel{11: ch}}
	require.False(t, s.handleMessage(nil, message{command: cmdOKAY, arg0: 8, arg1: 11}))
	require.Equal(t, []byte("pending"), ch.pending)
	require.False(t, s.handleMessage(nil, message{command: cmdCLSE, arg0: 8, arg1: 11}))
	require.Same(t, ch, s.channels[11])
	require.True(t, s.handleMessage(nil, message{command: cmdCLSE, arg0: 7, arg1: 99}))
}

func TestGlobalUploadBudgetIsEnforced(t *testing.T) {
	original := bufferedUploadBytes.Load()
	t.Cleanup(func() { bufferedUploadBytes.Store(original) })
	bufferedUploadBytes.Store(maxBufferedUploads - 1)
	require.True(t, reserveUploadBytes(1))
	require.False(t, reserveUploadBytes(1))
	releaseUploadBytes(1)
	require.Equal(t, int64(maxBufferedUploads-1), bufferedUploadBytes.Load())
}

func TestSyncBudgetIsReleasedOnDropAndSessionTeardown(t *testing.T) {
	original := bufferedUploadBytes.Load()
	t.Cleanup(func() { bufferedUploadBytes.Store(original) })
	bufferedUploadBytes.Store(maxBufferedUploads)
	ch := &channel{sync: syncState{data: []byte("held"), reserved: 4}}
	payload := appendSyncRecord(nil, "DATA", []byte("x"))
	require.True(t, (&session{}).handleSync(nil, ch, payload))
	require.True(t, ch.sync.dropped)
	require.Nil(t, ch.sync.data)
	require.Zero(t, ch.sync.reserved)
	require.Equal(t, int64(maxBufferedUploads-4), bufferedUploadBytes.Load())

	bufferedUploadBytes.Store(7)
	first := &channel{sync: syncState{data: []byte("abc"), reserved: 3}}
	second := &channel{sync: syncState{data: []byte("defg"), reserved: 4}}
	s := &session{channels: map[uint32]*channel{1: first, 2: second}}
	s.releaseUploads()
	require.Zero(t, bufferedUploadBytes.Load())
	require.Nil(t, first.sync.data)
	require.Nil(t, second.sync.data)
}

func TestSyncPushIsBoundedAndSentToFilePipeline(t *testing.T) {
	originalSave, originalFile := saveSession, saveFile
	t.Cleanup(func() { saveSession, saveFile = originalSave, originalFile })
	sessionSaved := make(chan struct{}, 1)
	saveSession = func(*pb.AdbSessionRequest) error { sessionSaved <- struct{}{}; return nil }
	uploaded := make(chan struct {
		data, filename, guid, source string
	}, 1)
	saveFile = func(data []byte, filename, guid, source string) error {
		uploaded <- struct{ data, filename, guid, source string }{string(data), filename, guid, source}
		return nil
	}

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { (&honeypot{}).handleConnection(server); close(done) }()
	handshake(t, client)
	require.NoError(t, writeMessage(client, message{command: cmdOPEN, arg0: 9, data: []byte("sync:\x00")}))
	ok, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdOKAY), ok.command)

	var syncPayload []byte
	syncPayload = appendSyncRecord(syncPayload, "SEND", []byte("/data/local/tmp/payload.bin,33272"))
	syncPayload = appendSyncRecord(syncPayload, "DATA", []byte("malware-bytes"))
	syncPayload = append(syncPayload, []byte("DONE")...)
	var mtime [4]byte
	binary.LittleEndian.PutUint32(mtime[:], uint32(time.Now().Unix()))
	syncPayload = append(syncPayload, mtime[:]...)
	require.NoError(t, writeMessage(client, message{command: cmdWRTE, arg0: 9, arg1: ok.arg0, data: syncPayload}))
	transportAck, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdOKAY), transportAck.command)
	syncAck, err := readMessage(client)
	require.NoError(t, err)
	require.Equal(t, uint32(cmdWRTE), syncAck.command)
	require.Equal(t, "OKAY", string(syncAck.data[:4]))
	select {
	case upload := <-uploaded:
		require.Equal(t, "malware-bytes", upload.data)
		require.Equal(t, "payload.bin", upload.filename)
		require.Equal(t, "adb-sync", upload.source)
		require.NotEmpty(t, upload.guid)
	case <-time.After(time.Second):
		t.Fatal("sync upload was not persisted")
	}
	require.NoError(t, client.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not stop")
	}
	select {
	case <-sessionSaved:
	case <-time.After(time.Second):
		t.Fatal("session persistence did not finish")
	}
}

func TestMessageFramingRejectsMagicChecksumAndOversize(t *testing.T) {
	var encoded bytes.Buffer
	require.NoError(t, writeMessage(&encoded, message{command: cmdCNXN, arg0: 1, arg1: 2, data: []byte("host")}), "valid message")
	got, err := readMessage(&encoded)
	require.NoError(t, err)
	require.Equal(t, []byte("host"), got.data)

	badMagic := make([]byte, 24)
	binary.LittleEndian.PutUint32(badMagic[0:4], cmdCNXN)
	binary.LittleEndian.PutUint32(badMagic[20:24], 0)
	_, err = readMessage(bytes.NewReader(badMagic))
	require.ErrorContains(t, err, "magic")

	badChecksum := make([]byte, 25)
	binary.LittleEndian.PutUint32(badChecksum[0:4], cmdCNXN)
	binary.LittleEndian.PutUint32(badChecksum[12:16], 1)
	binary.LittleEndian.PutUint32(badChecksum[16:20], 2)
	binary.LittleEndian.PutUint32(badChecksum[20:24], cmdCNXN^0xffffffff)
	badChecksum[24] = 1
	_, err = readMessage(bytes.NewReader(badChecksum))
	require.ErrorContains(t, err, "checksum")

	oversize := make([]byte, 24)
	binary.LittleEndian.PutUint32(oversize[0:4], cmdWRTE)
	binary.LittleEndian.PutUint32(oversize[12:16], maxWirePayload+1)
	binary.LittleEndian.PutUint32(oversize[20:24], cmdWRTE^0xffffffff)
	_, err = readMessage(bytes.NewReader(oversize))
	require.ErrorContains(t, err, "too large")
}

func TestStockAdbClientConnectsAndRunsShell(t *testing.T) {
	if os.Getenv("ADB_STOCK_CLIENT_TEST") != "1" {
		t.Skip("set ADB_STOCK_CLIENT_TEST=1 to exercise the installed adb client")
	}
	adbPath, err := exec.LookPath("adb")
	require.NoError(t, err)
	originalFile := saveFile
	t.Cleanup(func() { saveFile = originalFile })
	uploaded := make(chan string, 1)
	saveFile = func(data []byte, filename, guid, source string) error {
		uploaded <- filename + ":" + string(data) + ":" + source
		return nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			(&honeypot{}).handleConnection(conn)
		}
	}()
	address := listener.Addr().String()
	connect := exec.Command(adbPath, "connect", address)
	output, err := connect.CombinedOutput()
	require.NoError(t, err, string(output))
	t.Cleanup(func() { _ = exec.Command(adbPath, "disconnect", address).Run() })
	shell := exec.Command(adbPath, "-s", address, "shell", "id")
	output, err = shell.CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "uid=2000(shell)")
	localFile := t.TempDir() + "/adb-stock-payload.bin"
	require.NoError(t, os.WriteFile(localFile, []byte("stock-adb-upload"), 0o600))
	pushCtx, cancelPush := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPush()
	push := exec.CommandContext(pushCtx, adbPath, "-s", address, "push", localFile, "/data/local/tmp/adb-stock-payload.bin")
	push.Env = append(os.Environ(), "ADB_TRACE=sync,packets")
	output, err = push.CombinedOutput()
	require.NoError(t, err, string(output))
	select {
	case capture := <-uploaded:
		require.Equal(t, "adb-stock-payload.bin:stock-adb-upload:adb-sync", capture)
	case <-time.After(3 * time.Second):
		t.Fatal("stock adb push did not reach the file pipeline")
	}
}

func appendSyncRecord(out []byte, id string, data []byte) []byte {
	out = append(out, id...)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(data)))
	out = append(out, n[:]...)
	return append(out, data...)
}
