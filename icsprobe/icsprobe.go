// Package icsprobe is a passive measurement instrument, not a honeypot: it
// binds otherwise-unused industrial-protocol ports, accepts a TCP connection,
// records the first bytes the client sends plus timing, and closes. It
// answers nothing and emulates no protocol. The point is to find out whether
// industrial scanning actually reaches our address space before investing in
// a real S7comm/Modbus/etc. emulator.
package icsprobe

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	// defaultPortsCSV is the four remaining TCP industrial-protocol ports
	// probed when ICS_PROBE_PORTS is unset: IEC 60870-5-104, DNP3,
	// EtherNet/IP, OPC UA. It originally covered six (also S7comm and
	// Modbus), but both have since graduated to real emulators -- see below.
	//
	// BACnet (47808) is UDP, not TCP, and is deliberately out of scope for
	// v1 -- this package only implements TCP listeners.
	//
	// 102 (S7comm) is DELIBERATELY ABSENT: it now belongs to the s7comm
	// honeypot, which emulates a real S7-300 on that port.
	// 502 (Modbus) is DELIBERATELY ABSENT for the same reason: it now
	// belongs to the modbus honeypot, which emulates a real Modicon M221 on
	// that port (threat_gg-4zzd.11). Both graduated ports lived in
	// ProfileICS alongside this probe, so leaving them here made them
	// collide -- and because the probe registers first it would win the
	// bind, silently preventing the emulator from ever starting while the
	// node still looked healthy and the port still looked "listening".
	// That exact bug shipped once already, for s7comm/102.
	//
	// This is the lifecycle every one of these ports is expected to follow:
	// the instrument measures demand, and once that demand justifies building
	// a real emulator, the port GRADUATES from the probe to the honeypot.
	// TestProbePortsDoNotCollideWithRealHoneypots enforces it.
	defaultPortsCSV = "2404,20000,44818,4840"

	// maxReadBytes caps how much of the client's opening data we capture.
	// This is a telemetry instrument, not a protocol parser, so we only need
	// enough of the initial burst to fingerprint the scanner.
	maxReadBytes = 256

	// maxConcurrentConnections bounds how many connections are being actively
	// handled (i.e. blocked in the read-with-deadline below) at once, across
	// all configured ports combined. Each handled connection is short-lived
	// (at most readDeadline), so a modest shared cap absorbs a scan burst
	// without letting a flood spawn unbounded goroutines: once the cap is
	// hit, Start's accept loops block acquiring a slot, which backpressures
	// into the kernel's listen backlog instead of the process.
	maxConcurrentConnections = 500
)

// readDeadline bounds how long we wait for the client's opening bytes. We
// want a scanner's initial burst, not to run a tarpit. A package var (like
// persistence.saveTimeout) so tests can shrink it instead of eating a real
// multi-second sleep per case.
var readDeadline = 5 * time.Second

// saveIcsProbe is a package var so tests can inject a fake without a gRPC
// client, following the saveSession/getCommandResponse pattern in adb.
var saveIcsProbe = persistence.SaveIcsProbe

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
	sem    chan struct{}
}

// New builds the honeypot. It is side-effect free: no sockets are opened
// until Start is called.
func New() honeypots.Honeypot {
	return &honeypot{
		logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "icsprobe").Logger(),
	}
}

func (h *honeypot) Name() string {
	return "icsprobe"
}

func (h *honeypot) Start() {
	raw := os.Getenv("ICS_PROBE_PORTS")
	ports, fellBack := portsForStart(raw)
	if fellBack {
		// Fall back to the defaults rather than starting nothing.
		//
		// This is a measurement instrument, and its whole purpose is to answer
		// "does industrial scanning reach our address space?". A node that
		// starts no listeners produces zero rows -- and zero rows is
		// indistinguishable from a confident "no ICS scanning reaches us",
		// which is the answer that would kill the entire ICS investment. A
		// misconfigured env var must not be able to manufacture that
		// conclusion silently.
		//
		// So we fail toward collecting data and make the misconfiguration loud.
		// Note a partly-valid list is NOT affected: parsePorts already keeps
		// the good entries and drops the typos, so this only fires when nothing
		// at all could be parsed and the operator's intent is unknowable.
		h.logger.Error().Str("ICS_PROBE_PORTS", raw).Str("using", defaultPortsCSV).
			Msg("icsprobe: no valid ports parsed from ICS_PROBE_PORTS, falling back to defaults")
	}

	if h.sem == nil {
		h.sem = make(chan struct{}, maxConcurrentConnections)
	}

	for _, port := range ports {
		addr := fmt.Sprintf(":%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			// A single port failing to bind (e.g. 102 is privileged, and the
			// agent may run unprivileged outside of production) must not
			// take down the other listeners or the process.
			h.logger.Error().Err(err).Str("addr", addr).Msg("icsprobe: failed to bind listener")
			continue
		}
		h.logger.Info().Str("addr", addr).Msg("starting icsprobe listener")
		go h.serve(listener)
	}
}

// serve runs the accept loop for one listener until Accept fails, at which
// point the listener is assumed unusable (e.g. closed) and this goroutine
// exits; other ports' listeners are unaffected.
func (h *honeypot) serve(listener net.Listener) {
	addr := listener.Addr().String()
	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Debug().Err(err).Str("addr", addr).Msg("icsprobe: listener stopped accepting")
			return
		}

		h.sem <- struct{}{} // blocks if at capacity; see maxConcurrentConnections
		go func() {
			defer func() { <-h.sem }()
			h.handleConnection(conn)
		}()
	}
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	connectedAt := time.Now()
	remoteAddr := conn.RemoteAddr().String()
	port := localPort(conn)
	guid := uuid.NewV4().String()

	if err := conn.SetReadDeadline(connectedAt.Add(readDeadline)); err != nil {
		h.logger.Debug().Err(err).Str("guid", guid).Int("port", port).Msg("icsprobe: set read deadline failed")
	}

	buf := make([]byte, maxReadBytes)
	// A single read: we want the client's opening burst, not a protocol
	// exchange. Any error here (timeout, EOF, reset) just means "no more
	// bytes right now" -- for a bare scanner connect that IS the signal, so
	// it is not treated as a failure.
	n, _ := conn.Read(buf)

	var ttfbMs uint32
	if n > 0 {
		ttfbMs = uint32(time.Since(connectedAt).Milliseconds())
	}
	durationMs := uint32(time.Since(connectedAt).Milliseconds())

	req := &proto.IcsProbeRequest{
		RemoteAddr: remoteAddr,
		Guid:       guid,
		Port:       uint32(port),
		FirstBytes: append([]byte(nil), buf[:n]...),
		ByteCount:  uint32(n),
		TtfbMs:     ttfbMs,
		DurationMs: durationMs,
	}

	if err := saveIcsProbe(req); err != nil {
		h.logger.Error().Err(err).Str("guid", guid).Int("port", port).Msg("icsprobe: failed to persist probe")
	}
}

// localPort reports the TCP port a connection was accepted on. Deriving it
// from the connection itself (rather than threading a port value through
// from Start) keeps handleConnection correct for both fixed production ports
// and the ephemeral ":0" ports tests bind to.
func localPort(conn net.Conn) int {
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		return tcpAddr.Port
	}
	return 0
}

// parsePorts parses a comma-separated port list, defaulting to
// defaultPortsCSV when raw is blank. Malformed entries (non-numeric, out of
// the 1-65535 range) are skipped rather than causing a panic or aborting the
// whole list -- a typo in one entry of ICS_PROBE_PORTS shouldn't take out the
// rest.
func parsePorts(raw string) []int {
	if strings.TrimSpace(raw) == "" {
		raw = defaultPortsCSV
	}

	var ports []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			continue
		}
		// Never bind a port a real emulator owns, even if explicitly configured.
		// The probe registers before the emulators, so it would win the bind and
		// silently prevent the emulator from starting -- on a node that still
		// looks entirely healthy.
		if _, owned := ownedPorts[p]; owned {
			continue
		}
		ports = append(ports, p)
	}
	return ports
}

// portsForStart resolves the port list Start will bind, reporting whether it had
// to fall back to the defaults.
//
// Split out of Start so the fallback decision is directly testable: exercising
// it through Start would mean binding the real default ports, one of which (102)
// is privileged and all of which would collide with a running agent.
func portsForStart(raw string) (ports []int, fellBack bool) {
	ports = parsePorts(raw)
	if len(ports) > 0 {
		return ports, false
	}
	return parsePorts(""), true
}

// ownedPorts are industrial ports served by a REAL ICS emulator in ProfileICS,
// which the passive probe must never bind.
//
// Kept as a plain list rather than importing the honeypot packages: icsprobe is
// the lowest-level ICS component and must not depend on the emulators above it.
// The cross-check that this list stays in step with what is actually registered
// lives in the main package's TestProbePortsDoNotCollideWithRealHoneypots.
var ownedPorts = map[int]string{
	102: "s7comm",
	502: "modbus",
}

// DefaultPorts is the probe's built-in port list, for tests and diagnostics.
func DefaultPorts() []int { return parsePorts("") }

// PortsFromEnv resolves the ports the probe would actually bind right now,
// including the ICS_PROBE_PORTS override and the owned-port filter.
func PortsFromEnv() []int {
	ports, _ := portsForStart(os.Getenv("ICS_PROBE_PORTS"))
	return ports
}
