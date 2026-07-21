package mongo

import (
	"encoding/binary"
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
