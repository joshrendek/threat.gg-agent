package memcached

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

// recorder captures persistence calls under a mutex so tests can assert on them without
// racing the honeypot's background goroutines.
type recorder struct {
	mu       sync.Mutex
	connects []*proto.MemcachedConnectRequest
	commands []*proto.MemcachedCommandRequest
}

func (r *recorder) addConnect(in *proto.MemcachedConnectRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connects = append(r.connects, in)
}

func (r *recorder) addCommand(in *proto.MemcachedCommandRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, in)
}

func (r *recorder) connectSnapshot() []*proto.MemcachedConnectRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*proto.MemcachedConnectRequest(nil), r.connects...)
}

func (r *recorder) commandSnapshot() []*proto.MemcachedCommandRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*proto.MemcachedCommandRequest(nil), r.commands...)
}

// testRec is the single sink for persistence in tests. The seams are installed exactly
// once (below) and never reassigned, so the honeypot's background goroutines can read
// them without racing test teardown. Assertions are existence checks keyed on unique
// per-test content, so the shared sink does not couple tests.
var testRec = &recorder{}

func init() {
	saveMemcachedConnect = func(in *proto.MemcachedConnectRequest) error { testRec.addConnect(in); return nil }
	saveMemcachedCommand = func(in *proto.MemcachedCommandRequest) error { testRec.addCommand(in); return nil }
}

// startTestServer spins up the real listener on an ephemeral port and returns its address.
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

func TestMemcachedVersionAndGet(t *testing.T) {
	addr := startTestServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)

	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		t.Fatalf("write version: %v", err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read version reply: %v", err)
	}
	if len(line) < 8 || line[:8] != "VERSION " {
		t.Fatalf("version reply = %q, want VERSION prefix", line)
	}

	if _, err := conn.Write([]byte("get foo\r\n")); err != nil {
		t.Fatalf("write get: %v", err)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		t.Fatalf("read get reply: %v", err)
	}
	if line != "END\r\n" {
		t.Fatalf("get miss reply = %q, want END", line)
	}
}

func TestMemcachedStorageDataBlockConsumed(t *testing.T) {
	addr := startTestServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(conn)

	// A set carries a data block; the payload must NOT be parsed as the next command.
	if _, err := conn.Write([]byte("set greeting 0 0 5\r\nhello\r\nversion\r\n")); err != nil {
		t.Fatalf("write set: %v", err)
	}
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read stored: %v", err)
	}
	if line != "STORED\r\n" {
		t.Fatalf("set reply = %q, want STORED", line)
	}
	line, err = r.ReadString('\n')
	if err != nil {
		t.Fatalf("read version after set: %v", err)
	}
	if len(line) < 8 || line[:8] != "VERSION " {
		t.Fatalf("post-set reply = %q, want VERSION (data block leaked into parser)", line)
	}

	conn.Close()
	waitFor(t, func() bool {
		for _, c := range testRec.commandSnapshot() {
			if c.Command == "set greeting 0 0 5" {
				return true
			}
		}
		return false
	})
}

func TestMemcachedPersistsConnect(t *testing.T) {
	addr := startTestServer(t)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("version\r\n"))
	bufio.NewReader(conn).ReadString('\n')
	conn.Close()

	waitFor(t, func() bool {
		for _, c := range testRec.connectSnapshot() {
			if c.Protocol == "ascii" && c.Guid != "" {
				return true
			}
		}
		return false
	})
}

// countingReader records how many bytes were pulled from the underlying stream.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// TestReadLineRejectsOverlongLine is the regression for unbounded line buffering: a long
// newline-free flood must be rejected at the buffer bound, not accumulated. bufio's size
// alone does NOT bound ReadString, so this asserts on bytes actually consumed.
func TestReadLineRejectsOverlongLine(t *testing.T) {
	flood := bytes.Repeat([]byte{'A'}, maxLineLen*8)
	cr := &countingReader{r: bytes.NewReader(flood)}
	reader := bufio.NewReaderSize(cr, maxLineLen)

	if _, err := readLine(reader); err == nil {
		t.Fatal("readLine(overlong flood): err = nil, want an overlong-line error")
	}
	if cr.n > maxLineLen {
		t.Fatalf("readLine consumed %d bytes, want <= %d (it must not buffer the whole flood)", cr.n, maxLineLen)
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
