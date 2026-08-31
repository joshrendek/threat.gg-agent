package icsprobe

import (
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// --- remote address correctness ----------------------------------------------
//
// The server calls normalizedRemoteIP() on remote_addr and, when it cannot
// parse the value, silently substitutes ::1. llmcore and etcd already suffer
// this (all their IPv6 attackers collapse into one ::1 bucket). These tests
// prove the exact strings icsprobe sends survive the server's parse logic,
// for IPv4, bare IPv6, and bracketed IPv6-with-port.

// serverParse mirrors the parsing normalizedRemoteIP performs server-side.
func serverParse(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.Trim(addr, "[]")
	}
	return net.ParseIP(host)
}

func TestRemoteAddrStringsSurviveServerParsing(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"ipv4 with port", "203.0.113.7:54321"},
		{"ipv6 bracketed with port", "[2001:db8::1]:54321"},
		{"ipv6 bare, no port", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := serverParse(tc.addr)
			require.NotNil(t, ip, "server-side parse of %q must yield a valid IP", tc.addr)
		})
	}
}

// TestServeSendsAParseableRemoteAddr drives a real TCP connection
// (not net.Pipe, whose addresses don't look like real ones) through
// handleConnection and confirms the exact string conn.RemoteAddr().String()
// produces -- and that icsprobe forwards unmodified -- round-trips through
// the server's parse logic. Runs over both tcp4 and IPv6 loopback.
func TestServeSendsAParseableRemoteAddr(t *testing.T) {
	restoreDeadline := shrinkReadDeadline(t, 300*time.Millisecond)
	defer restoreDeadline()

	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			loopback := "127.0.0.1:0"
			if network == "tcp6" {
				loopback = "[::1]:0"
			}

			listener, err := net.Listen(network, loopback)
			if err != nil {
				t.Skipf("%s loopback unavailable in this environment: %v", network, err)
			}
			defer listener.Close()

			captured := installFakeSave(t)

			h := &honeypot{logger: zerolog.Nop(), sem: make(chan struct{}, 4)}
			go h.serve(listener)

			conn, err := net.Dial(network, listener.Addr().String())
			require.NoError(t, err)
			defer conn.Close()

			req := waitForCapture(t, captured)

			ip := serverParse(req.RemoteAddr)
			require.NotNil(t, ip, "remote_addr %q sent by icsprobe must survive the server's parse logic", req.RemoteAddr)
		})
	}
}

// --- listener capture behaviour -----------------------------------------------

func TestServeCapturesBytesAndClosesPromptly(t *testing.T) {
	restoreDeadline := shrinkReadDeadline(t, 500*time.Millisecond)
	defer restoreDeadline()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	wantPort := listener.Addr().(*net.TCPAddr).Port
	captured := installFakeSave(t)

	h := &honeypot{logger: zerolog.Nop(), sem: make(chan struct{}, 4)}
	go h.serve(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	payload := []byte{0x03, 0x00, 0x00, 0x1f, 0xff, 0x01} // arbitrary opening bytes
	start := time.Now()
	_, err = conn.Write(payload)
	require.NoError(t, err)

	req := waitForCapture(t, captured)
	elapsed := time.Since(start)

	require.Less(t, elapsed, 2*time.Second, "connection should be closed promptly after data arrives, not held for the full deadline")
	require.Equal(t, uint32(wantPort), req.Port)
	require.Equal(t, uint32(len(payload)), req.ByteCount)
	require.True(t, reflect.DeepEqual(payload, req.FirstBytes), "first_bytes = %x, want %x", req.FirstBytes, payload)
	require.LessOrEqual(t, req.TtfbMs, uint32(readDeadline.Milliseconds()))
	require.NotEmpty(t, req.Guid)

	// The server should close its side promptly too.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	require.Equal(t, 0, n)
	require.Error(t, err)
}

// --- bare connect, no bytes sent ----------------------------------------------

func TestServeCapturesBareConnectWithNoBytesSent(t *testing.T) {
	restoreDeadline := shrinkReadDeadline(t, 200*time.Millisecond)
	defer restoreDeadline()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	captured := installFakeSave(t)

	h := &honeypot{logger: zerolog.Nop(), sem: make(chan struct{}, 4)}
	go h.serve(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	// Send nothing. A bare connect is itself the signal -- the most common
	// scanner case -- and must still produce a record once the read deadline
	// elapses.

	req := waitForCapture(t, captured)

	require.Equal(t, uint32(0), req.ByteCount)
	require.Equal(t, uint32(0), req.TtfbMs)
	require.Empty(t, req.FirstBytes)
	require.NotEmpty(t, req.Guid)
}

// --- ICS_PROBE_PORTS parsing ---------------------------------------------------

func TestParsePorts(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		got := parsePorts("")
		require.Equal(t, []int{2404, 20000, 44818, 4840}, got) // 102/502 belong to the s7comm/modbus honeypots
	})

	t.Run("blank/whitespace-only also defaults", func(t *testing.T) {
		got := parsePorts("   ")
		require.Equal(t, []int{2404, 20000, 44818, 4840}, got) // 102/502 belong to the s7comm/modbus honeypots
	})

	t.Run("override when set", func(t *testing.T) {
		got := parsePorts("2404, 20000")
		require.Equal(t, []int{2404, 20000}, got)
	})

	t.Run("an explicitly configured owned port is still dropped", func(t *testing.T) {
		got := parsePorts("502, 2404")
		require.Equal(t, []int{2404}, got, "502 belongs to the modbus honeypot even when explicitly configured")
	})

	t.Run("malformed entries are skipped without panicking", func(t *testing.T) {
		var got []int
		require.NotPanics(t, func() {
			got = parsePorts("abc,,502,99999,-1,0,2404,")
		})
		require.Equal(t, []int{2404}, got)
	})

	t.Run("entirely malformed yields no ports rather than falling back to defaults", func(t *testing.T) {
		got := parsePorts("abc,xyz")
		require.Empty(t, got)
	})
}

// --- test helpers ------------------------------------------------------------

// installFakeSave swaps in a fake saveIcsProbe that forwards each captured
// request on a channel, and restores the real one on test cleanup.
func installFakeSave(t *testing.T) chan *proto.IcsProbeRequest {
	t.Helper()
	original := saveIcsProbe
	captured := make(chan *proto.IcsProbeRequest, 4)
	saveIcsProbe = func(in *proto.IcsProbeRequest) error {
		captured <- in
		return nil
	}
	t.Cleanup(func() { saveIcsProbe = original })
	return captured
}

func waitForCapture(t *testing.T, captured chan *proto.IcsProbeRequest) *proto.IcsProbeRequest {
	t.Helper()
	select {
	case req := <-captured:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("expected a captured icsprobe record")
		return nil
	}
}

// shrinkReadDeadline overrides the package's readDeadline for a test and
// returns a func to restore it, avoiding real multi-second sleeps.
func shrinkReadDeadline(t *testing.T, d time.Duration) func() {
	t.Helper()
	original := readDeadline
	readDeadline = d
	return func() { readDeadline = original }
}

// A fully-malformed ICS_PROBE_PORTS must fall back to the defaults, not start
// nothing.
//
// Starting nothing yields zero rows, and for a measurement instrument zero rows
// reads exactly like "no ICS scanning reaches us" -- the conclusion that would
// cancel the whole ICS programme. A typo in an env var must not be able to
// manufacture that answer. Partly-valid lists are unaffected: good entries are
// kept and typos dropped.
func TestPortsForStartFallsBackToDefaultsWhenNothingParses(t *testing.T) {
	// The decision Start actually makes. Exercising it through Start would mean
	// binding the real default ports, one of which (102) is privileged and all
	// of which would collide with a running agent, so the decision is split out.
	ports, fellBack := portsForStart("nonsense,also-bad,-1,99999")
	require.True(t, fellBack, "an all-invalid list must report that it fell back")
	// 102/502 are deliberately absent: they belong to the s7comm/modbus
	// emulators, and the probe must not fight them for the bind. See
	// ownedPorts.
	want := map[int]bool{2404: true, 20000: true, 44818: true, 4840: true}
	require.Len(t, ports, len(want), "fallback must be the four remaining documented TCP ICS ports")
	for _, p := range ports {
		require.True(t, want[p], "unexpected fallback port %d", p)
	}

	// A usable list must NOT trigger the fallback.
	// 102 is filtered out as an owned port, leaving a still-valid list.
	ports, fellBack = portsForStart("2404,102")
	require.False(t, fellBack, "a valid list must not fall back")
	require.Equal(t, []int{2404}, ports, "102 must be dropped: the s7comm honeypot owns it")

	// Partly-valid keeps the good entries rather than falling back wholesale.
	ports, fellBack = portsForStart("2404, oops, 44818")
	require.False(t, fellBack, "a partly-valid list must not fall back")
	require.Equal(t, []int{2404, 44818}, ports)
}

func TestParsePortsKeepsValidEntriesAndDropsTypos(t *testing.T) {
	// 102 is dropped as owned, not as a typo -- both are silently skipped.
	got := parsePorts("2404, oops, 102, 70000, , 44818")
	want := []int{2404, 44818}
	if len(got) != len(want) {
		t.Fatalf("parsePorts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsePorts = %v, want %v", got, want)
		}
	}
}

// --- Start(), the production entry point ---------------------------------------

// Start() was the one path with no coverage at all: it reads the env, parses the
// port list, builds the semaphore and binds every listener. Everything else was
// tested by calling serve() with a listener the test made itself, which skips
// all of that. This drives the real entry point end to end over a port the test
// picks, so a regression in env handling or listener setup fails here rather
// than silently producing a node that binds nothing.
func TestStartBindsConfiguredPortsAndCaptures(t *testing.T) {
	restoreDeadline := shrinkReadDeadline(t, 300*time.Millisecond)
	defer restoreDeadline()

	// Discover a free high port by binding :0, then release it for Start().
	// A racing bind is possible in principle; if it happens, Start logs and
	// skips that listener and the capture below fails loudly rather than hanging.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := probe.Addr().(*net.TCPAddr).Port
	require.NoError(t, probe.Close())

	t.Setenv("ICS_PROBE_PORTS", strconv.Itoa(port))
	captured := installFakeSave(t)

	h := New().(*honeypot)
	go h.Start()

	// Give Start a moment to bind before dialling.
	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NoError(t, err, "Start() should have bound port %d from ICS_PROBE_PORTS", port)
	defer conn.Close()

	_, err = conn.Write([]byte{0x03, 0x00, 0x00, 0x16})
	require.NoError(t, err)

	req := waitForCapture(t, captured)
	require.Equal(t, uint32(port), req.Port, "captured port must be the one Start() bound")
	require.Equal(t, []byte{0x03, 0x00, 0x00, 0x16}, req.FirstBytes)
	require.NotNil(t, serverParse(req.RemoteAddr), "remote_addr must survive the server's parse logic")
}
