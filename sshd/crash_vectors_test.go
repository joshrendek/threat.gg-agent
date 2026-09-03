package sshd

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"golang.org/x/crypto/ssh"
)

// threat_gg-ith. Three one-request crash vectors in the SSH honeypot, each
// reachable by any attacker because auth accepts anything. A crashed agent
// takes down every honeypot on the node, captures nothing, and a port that
// vanishes right after a specific benign request is itself a fingerprint.
// The exec/scp paths were hardened against exactly this (parseExecCommand),
// so these were gaps, not a design stance.

// fakeChannel is a scriptable ssh.Channel: it serves one chunk of input then
// EOF, records what was written back, and can be told to panic on Write to
// exercise the recover() guard.
type fakeChannel struct {
	mu           sync.Mutex
	input        []byte
	served       bool
	written      []byte
	closed       bool
	panicOnWrite bool
}

func (c *fakeChannel) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.served {
		return 0, io.EOF
	}
	c.served = true
	return copy(p, c.input), nil
}
func (c *fakeChannel) Write(p []byte) (int, error) {
	if c.panicOnWrite {
		panic("simulated write failure")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, p...)
	return len(p), nil
}
func (c *fakeChannel) Close() error                                   { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *fakeChannel) CloseWrite() error                              { return nil }
func (c *fakeChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (c *fakeChannel) Stderr() io.ReadWriter                          { return nil }

func testPerms() *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{"guid": "test-guid"}}
}

// mustNotPanic converts a panic into a test failure so the exploit tests
// fail loudly against the unfixed code instead of taking the test binary
// down with them -- which is, of course, the exact production symptom.
func mustNotPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	fn()
}

// withCapturedSaves replaces the persistence hook with one that delivers each
// saved request on a channel. The real save is fire-and-forget (a goroutine,
// so a slow control plane never blocks the attacker's channel), which means a
// test has to WAIT for it rather than look immediately.
func withCapturedSaves(t *testing.T) <-chan *proto.HttpRequest {
	t.Helper()
	orig := saveHTTPRequest
	saved := make(chan *proto.HttpRequest, 8)
	saveHTTPRequest = func(in *proto.HttpRequest) error {
		saved <- in
		return nil
	}
	t.Cleanup(func() { saveHTTPRequest = orig })
	return saved
}

func awaitSave(t *testing.T, saved <-chan *proto.HttpRequest) *proto.HttpRequest {
	t.Helper()
	select {
	case in := <-saved:
		return in
	case <-time.After(2 * time.Second):
		t.Fatal("the proxied request was never persisted")
		return nil
	}
}

// --- vector 1: direct-tcpip with the default (tor disabled) config ---------

// httpClient is only assigned inside the torEnabled branch, so with
// TOR_ENABLED unset -- the default -- a direct-tcpip channel carrying one
// HTTP request line dereferenced a nil client and the process exited.
func TestDirectTCPIPWithoutTorDoesNotPanic(t *testing.T) {
	orig := httpClient
	httpClient = nil
	t.Cleanup(func() { httpClient = orig })
	saved := withCapturedSaves(t)

	ch := &fakeChannel{input: []byte("GET /probe HTTP/1.1\r\nHost: example.test\r\n\r\n")}
	mustNotPanic(t, "HandleTcpReading with nil httpClient", func() {
		HandleTcpReading(ch, nil, testPerms())
	})

	if !ch.closed {
		t.Error("channel must be closed after the request is handled")
	}
	// The request is the capture. Not being able to proxy it is no reason to
	// lose it -- before this fix we lost it AND the process.
	in := awaitSave(t, saved)
	if in.Url != "example.test/probe" {
		t.Fatalf("captured url = %q, want example.test/probe", in.Url)
	}
	if in.Response != "" {
		t.Error("no upstream was contacted, so no response body may be recorded")
	}
}

// --- vector 2: upstream failure in the proxy path ----------------------------

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated upstream failure")
}

// Both error branches called log.Fatalf, so even WITH tor enabled a proxied
// request to a dead host killed the agent.
func TestProxyUpstreamFailureDoesNotExit(t *testing.T) {
	orig := httpClient
	httpClient = &http.Client{Transport: failingTransport{}}
	t.Cleanup(func() { httpClient = orig })
	saved := withCapturedSaves(t)

	ch := &fakeChannel{input: []byte("GET / HTTP/1.1\r\nHost: dead.test\r\n\r\n")}
	mustNotPanic(t, "HandleTcpReading with a failing upstream", func() {
		HandleTcpReading(ch, nil, testPerms())
	})
	// log.Fatalf would have os.Exit'd before reaching here, so getting here at
	// all is the assertion -- but the capture must survive the failure too.
	in := awaitSave(t, saved)
	if in.Response != "" {
		t.Error("a failed proxy must not record a response body")
	}
}

// --- vector 3: pty-req payload parsing ----------------------------------------

func ptyPayload(term string) []byte {
	// RFC 4254 §6.2: string TERM, then four uint32s, then string modes.
	p := make([]byte, 4+len(term)+16+4)
	binary.BigEndian.PutUint32(p[:4], uint32(len(term)))
	copy(p[4:], term)
	return p
}

func TestParsePtyRequestAcceptsRealPayloads(t *testing.T) {
	for _, term := range []string{"xterm", "xterm-256color", "", strings.Repeat("t", 255), strings.Repeat("t", 300)} {
		got, err := parsePtyRequest(ptyPayload(term))
		if err != nil {
			t.Fatalf("parsePtyRequest(%q): %v", term, err)
		}
		if got != term {
			t.Fatalf("parsePtyRequest returned %q, want %q", got, term)
		}
	}
}

// The old code read Payload[3] as the length and sliced Payload[4:termLen+4]
// with no checks. Three ways that panicked, each a single request away.
func TestParsePtyRequestRejectsMalformedPayloads(t *testing.T) {
	tests := map[string][]byte{
		"empty":               {},
		"shorter than header": {0, 0, 0},
		"declared too long": func() []byte {
			p := ptyPayload("xterm")
			binary.BigEndian.PutUint32(p[:4], 5000)
			return p
		}(),
		"over limit": func() []byte {
			p := make([]byte, 4)
			binary.BigEndian.PutUint32(p, maxPtyTermLen+1)
			return p
		}(),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			mustNotPanic(t, "parsePtyRequest", func() {
				if _, err := parsePtyRequest(payload); err == nil {
					t.Fatal("parsePtyRequest returned nil error for a malformed payload")
				}
			})
		})
	}
}

// The original read the length as a single byte, so a TERM length of 253
// computed 253+4 = 1 in byte arithmetic and sliced Payload[4:1] -- a panic on
// a payload that is, read correctly, perfectly well-formed. Pin that it now
// parses rather than merely that it no longer panics: the fix is reading the
// four-byte length the protocol actually sends.
func TestParsePtyRequestSurvivesTheByteWrapThatPanicked(t *testing.T) {
	p := make([]byte, 4+300)
	p[3] = 253 // big-endian uint32 253; the old code's termLen+4 wrapped to 1
	var got string
	mustNotPanic(t, "parsePtyRequest", func() {
		var err error
		got, err = parsePtyRequest(p)
		if err != nil {
			t.Fatalf("a 253-byte TERM inside a 300-byte payload is valid: %v", err)
		}
	})
	if len(got) != 253 {
		t.Fatalf("parsed TERM length = %d, want 253", len(got))
	}
}

// --- defense in depth ----------------------------------------------------------

// Anything else that panics inside a per-channel goroutine must be contained
// to that channel. The process is 35 honeypots; one attacker's session is not
// allowed to end all of them.
func TestChannelPanicIsContained(t *testing.T) {
	orig := httpClient
	httpClient = nil
	t.Cleanup(func() { httpClient = orig })
	saved := withCapturedSaves(t)

	ch := &fakeChannel{
		input:        []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		panicOnWrite: true,
	}
	mustNotPanic(t, "HandleTcpReading with a panicking channel", func() {
		HandleTcpReading(ch, nil, testPerms())
	})
	if !ch.closed {
		t.Error("channel must still be closed after a contained panic")
	}
	// The save was dispatched before the write panicked; it must still land.
	awaitSave(t, saved)
}

// A hung upstream must release the channel rather than pin it open for as long
// as the far end cares to stall. The transport blocks until the request's
// context is cancelled, so the only way this test finishes is the timeout.
type hangingTransport struct{}

func (hangingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

func TestProxyUpstreamIsBoundedByTimeout(t *testing.T) {
	orig, origTimeout := httpClient, proxyUpstreamTimeout
	httpClient = &http.Client{Transport: hangingTransport{}}
	proxyUpstreamTimeout = 200 * time.Millisecond
	t.Cleanup(func() { httpClient, proxyUpstreamTimeout = orig, origTimeout })

	start := time.Now()
	body := proxyUpstream("hung.test/", http.Header{})
	elapsed := time.Since(start)

	if body != nil {
		t.Error("a timed-out fetch must yield no body")
	}
	if elapsed > proxyUpstreamTimeout+2*time.Second {
		t.Fatalf("proxyUpstream took %v against a hung upstream; the timeout is not being applied", elapsed)
	}
	if elapsed < proxyUpstreamTimeout-50*time.Millisecond {
		t.Fatalf("proxyUpstream returned after %v, before the %v timeout -- the transport should have been held", elapsed, proxyUpstreamTimeout)
	}
}
