package mongo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

// recorder captures persistence calls under a mutex.
type recorder struct {
	mu       sync.Mutex
	connects []*proto.MongoConnectRequest
	commands []*proto.MongoCommandRequest
}

func (r *recorder) addConnect(in *proto.MongoConnectRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connects = append(r.connects, in)
}

func (r *recorder) addCommand(in *proto.MongoCommandRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, in)
}

func (r *recorder) connectSnapshot() []*proto.MongoConnectRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*proto.MongoConnectRequest(nil), r.connects...)
}

func (r *recorder) commandSnapshot() []*proto.MongoCommandRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*proto.MongoCommandRequest(nil), r.commands...)
}

// testRec is the single persistence sink, installed once so background goroutines never
// race test teardown. Assertions key on unique per-test content.
var testRec = &recorder{}

func init() {
	saveMongoConnect = func(in *proto.MongoConnectRequest) error { testRec.addConnect(in); return nil }
	saveMongoCommand = func(in *proto.MongoCommandRequest) error { testRec.addCommand(in); return nil }
}

func startTestServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	h := &honeypot{logger: zerolog.Nop()}
	go h.serve(ln)
	return ln.Addr().String()
}

// buildClientOpMsg frames a full client OP_MSG (header + payload).
func buildClientOpMsg(requestID int32, body []byte) []byte {
	payload := buildOpMsgRequest(body)
	total := headerLen + len(payload)
	out := appendHeader(nil, int32(total), requestID, 0, opMsg)
	return append(out, payload...)
}

// buildClientOpQuery frames a full client OP_QUERY (header + payload).
func buildClientOpQuery(requestID int32, collection string, query []byte) []byte {
	payload := make([]byte, 4) // flags
	payload = append(payload, collection...)
	payload = append(payload, 0x00)
	payload = append(payload, make([]byte, 8)...) // skip + return
	payload = append(payload, query...)
	total := headerLen + len(payload)
	out := appendHeader(nil, int32(total), requestID, 0, opQuery)
	return append(out, payload...)
}

// readReply reads one full wire message from the connection.
func readReply(t *testing.T, conn net.Conn) (msgHeader, []byte) {
	t.Helper()
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	total := int(binary.LittleEndian.Uint32(lenBuf[:]))
	if total < headerLen || total > maxMessageLen {
		t.Fatalf("reply length %d out of range", total)
	}
	buf := make([]byte, total)
	copy(buf, lenBuf[:])
	if _, err := io.ReadFull(conn, buf[4:]); err != nil {
		t.Fatalf("read body: %v", err)
	}
	h, err := parseHeader(buf[:16])
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	return h, buf[16:]
}

func TestMongoOpMsgHello(t *testing.T) {
	addr := startTestServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var b bsonBuilder
	b.addInt32("hello", 1)
	b.addString("$db", "admin")
	if _, err := conn.Write(buildClientOpMsg(1, b.build())); err != nil {
		t.Fatalf("write: %v", err)
	}

	h, payload := readReply(t, conn)
	if h.opCode != opMsg {
		t.Fatalf("reply opCode = %d, want OP_MSG", h.opCode)
	}
	if h.responseTo != 1 {
		t.Fatalf("responseTo = %d, want 1", h.responseTo)
	}
	body, err := parseOpMsg(payload)
	if err != nil {
		t.Fatalf("parseOpMsg: %v", err)
	}
	doc, err := decodeDocument(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
		t.Fatalf("ok = %v, want 1.0", v.d)
	}
	if v, ok := doc.lookup("ismaster"); !ok || !v.b {
		t.Fatalf("ismaster = %v, want true", v.b)
	}
}

func TestMongoOpQueryIsMaster(t *testing.T) {
	addr := startTestServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var q bsonBuilder
	q.addInt32("isMaster", 1)
	if _, err := conn.Write(buildClientOpQuery(9, "admin.$cmd", q.build())); err != nil {
		t.Fatalf("write: %v", err)
	}

	h, payload := readReply(t, conn)
	if h.opCode != opReply {
		t.Fatalf("reply opCode = %d, want OP_REPLY", h.opCode)
	}
	if h.responseTo != 9 {
		t.Fatalf("responseTo = %d, want 9", h.responseTo)
	}
	// OP_REPLY body starts 20 bytes into the payload.
	doc, err := decodeDocument(payload[20:])
	if err != nil {
		t.Fatalf("decode OP_REPLY body: %v", err)
	}
	if v, ok := doc.lookup("ismaster"); !ok || !v.b {
		t.Fatalf("ismaster = %v, want true", v.b)
	}
}

// TestMongoNonStringDbIgnored checks the $db type guard: a $db field sent as a non-string
// must not be read as a namespace (it is simply ignored), and the command still succeeds.
func TestMongoNonStringDbIgnored(t *testing.T) {
	addr := startTestServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var b bsonBuilder
	b.addInt32("ping", 1)
	b.addInt32("$db", 123) // hostile: $db is not a string
	if _, err := conn.Write(buildClientOpMsg(42, b.build())); err != nil {
		t.Fatalf("write: %v", err)
	}

	h, payload := readReply(t, conn)
	if h.opCode != opMsg {
		t.Fatalf("reply opCode = %d, want OP_MSG", h.opCode)
	}
	body, err := parseOpMsg(payload)
	if err != nil {
		t.Fatalf("parseOpMsg: %v", err)
	}
	doc, err := decodeDocument(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, ok := doc.lookup("ok"); !ok || v.d != 1.0 {
		t.Fatalf("ok = %v, want 1.0", v.d)
	}
	conn.Close()

	// The recorded command must be the bare command name, with no namespace appended.
	waitFor(t, func() bool {
		for _, c := range testRec.commandSnapshot() {
			if c.Command == "ping" {
				return true
			}
		}
		return false
	})
}

func TestMongoCapturesPlainCredentials(t *testing.T) {
	addr := startTestServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var b bsonBuilder
	b.addInt32("saslStart", 1)
	b.addString("mechanism", "PLAIN")
	b.addBinary("payload", []byte("\x00sa\x00hunter2"))
	b.addString("$db", "admin")
	if _, err := conn.Write(buildClientOpMsg(3, b.build())); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Drain the auth-failed reply.
	readReply(t, conn)
	conn.Close()

	waitFor(t, func() bool {
		for _, c := range testRec.connectSnapshot() {
			if c.Username == "sa" && c.Password == "hunter2" {
				return true
			}
		}
		return false
	})
}

// TestMongoHandlerRecoversFromPanic is the regression for the recover backstop: a panic
// raised on a downstream path (here, persistence) must be caught by the handler's
// deferred recover rather than escaping the goroutine and crashing the whole agent
// process (an unrecovered goroutine panic terminates every honeypot on the node).
func TestMongoHandlerRecoversFromPanic(t *testing.T) {
	called := make(chan struct{}, 1)
	orig := saveMongoConnect
	saveMongoConnect = func(*proto.MongoConnectRequest) error {
		select {
		case called <- struct{}{}:
		default:
		}
		panic("boom from persistence")
	}
	t.Cleanup(func() { saveMongoConnect = orig })

	addr := startTestServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	var b bsonBuilder
	b.addInt32("hello", 1)
	if _, err := conn.Write(buildClientOpMsg(1, b.build())); err != nil {
		t.Fatalf("write: %v", err)
	}
	readReply(t, conn) // a valid reply is still served before the connection closes
	conn.Close()

	select {
	case <-called:
		// The panicking seam ran inside persistSession; without the handler's recover
		// this goroutine panic would have crashed the test binary.
	case <-time.After(2 * time.Second):
		t.Fatal("persistence seam was never invoked")
	}
	time.Sleep(50 * time.Millisecond) // let the deferred recover run
}

// TestMongoRejectsOversizedMessage is the regression for the up-front full-message
// allocation: a hostile 4-byte length prefix declaring a huge message must be rejected
// before any body read or `make([]byte, total)`, and the accepted cap must stay small so
// stalled connections can't each pin a large buffer.
func TestMongoRejectsOversizedMessage(t *testing.T) {
	if maxMessageLen > 2*1024*1024 {
		t.Fatalf("maxMessageLen = %d, want <= 2MiB to bound the up-front allocation", maxMessageLen)
	}

	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(maxMessageLen+1))
	// Only the length prefix is provided: if the cap were checked before the body read,
	// no body read is attempted and we get errWire — not a read error from a giant buffer.
	r := bufio.NewReader(bytes.NewReader(header))
	if _, _, err := readMessage(r); !errors.Is(err, errWire) {
		t.Fatalf("readMessage(oversized) err = %v, want errWire", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
