// Package modbus emulates a Schneider Electric Modicon M221 logic
// controller (a TM221CE40T) speaking Modbus/TCP on port 502.
//
// It is a honeypot: nothing it reports is real, and nothing an attacker
// asks it to do is ever executed -- no command runs, no state outside this
// package's own per-attacker-IP maps changes. See persona.go for the
// device identity values (and their provenance), and icscore for the
// shared per-attacker-IP scoping (icscore.Store) and session/capture
// scaffolding (icscore.Session) this package is built on -- the same
// foundation s7comm's Siemens S7-300 emulator uses, extracted there once
// this second protocol needed the identical machinery.
package modbus

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/icscore"
	"github.com/rs/zerolog"
)

const (
	defaultPort = "502"

	// idleTimeout/totalTimeout bound one connection's lifetime -- mirroring
	// s7comm.go's precedent. A real engineering/HMI session is a handful of
	// request/response pairs, not an open-ended pipe.
	// maxConcurrentSessions is how many simultaneous Modbus/TCP connections
	// this device will serve before answering SERVER_DEVICE_BUSY.
	//
	// INVENTED, per 4zzd.3, but sized against real traffic rather than taste:
	// observed peak concurrency in production is 2 sessions (average 1.06)
	// across the whole fleet, so 16 sits about eight times above anything we
	// have ever seen while still being a plausible small-PLC figure. The
	// margin is the point -- the cap exists to remove the "accepts hundreds"
	// tell, NOT to shed load, and it must never be the reason a capture is
	// missed.
	maxConcurrentSessions = 16

	idleTimeout  = 30 * time.Second
	totalTimeout = 300 * time.Second

	// maxPDUsPerConnection caps how many Modbus requests one connection may
	// exchange, so a scripted flood can't hold a goroutine open forever --
	// the same bound s7comm places on S7 PDUs per connection.
	maxPDUsPerConnection = 500
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
	// pacer models CPU response latency across this device's concurrent
	// sessions -- see icscore.Pacer (threat_gg-4zzd.9).
	pacer icscore.Pacer
}

// New builds the honeypot. It is side-effect free: no socket is opened
// until Start is called.
func New() honeypots.Honeypot {
	return &honeypot{
		logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "modbus").Logger(),
	}
}

func (h *honeypot) Name() string { return "modbus" }

func (h *honeypot) Start() {
	port := os.Getenv("MODBUS_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Error().Err(err).Str("port", port).Msg("failed to start modbus listener")
		return
	}
	h.logger.Info().Str("port", port).Msg("starting modbus honeypot")
	h.serve(ln)
}

// serve runs the accept loop until the listener stops accepting. Split from
// Start so tests can drive an ephemeral (":0") listener directly.
func (h *honeypot) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			h.logger.Debug().Err(err).Msg("modbus listener stopped accepting")
			return
		}
		go h.handleConnection(conn)
	}
}

// handleConnection drives one TCP connection: a bounded sequence of
// MBAP-framed Modbus PDUs. host (the connection's remote address, run
// through icscore.RemoteHost) is what scopes all coil/holding-register
// write state -- see state.go.
func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Register this session with the pacer so every concurrent session
	// slows the others, the way communication jobs compete for a real
	// CPU's scan cycle (threat_gg-4zzd.9).
	defer h.pacer.Enter()()

	host := icscore.RemoteHost(conn.RemoteAddr())

	// Backstop: a slice-bounds bug anywhere in this package's parsing must
	// never take the whole agent process down. mbap.go/pdu.go both validate
	// lengths before indexing, so this should be unreachable in practice --
	// but a honeypot parsing hostile input is exactly the wrong place to
	// rely on "should be".
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error().Interface("panic", r).Str("remote", host).Msg("recovered panic in modbus handler")
		}
	}()

	sess := newSession()
	defer persistSession(h.logger, host, sess)

	h.logger.Info().Str("remote", host).Msg("new modbus connection")
	conn.SetDeadline(time.Now().Add(totalTimeout))
	reader := bufio.NewReader(conn)

	// Every early `return` below deliberately ends the connection outright
	// (via the deferred conn.Close()) rather than trying to recover and
	// keep serving -- this package's answer to "malformed/truncated/
	// oversized input must not panic": for MBAP-layer failures, closing the
	// connection is the chosen "protocol error" response, mirroring
	// s7comm's handleConnection.
	for i := 0; i < maxPDUsPerConnection; i++ {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		hdr, pdu, err := readMBAP(reader)
		if err != nil {
			return
		}
		if len(pdu) == 0 {
			// readMBAP's minLength check already guarantees this in
			// practice (length>=2 means unit id + at least 1 PDU byte) --
			// this is a defensive backstop, not a reachable path.
			return
		}

		// Reaching here means a syntactically valid MBAP+PDU frame arrived,
		// regardless of what function code it names -- that is itself
		// signal (a genuine protocol engagement, not scan noise), so it
		// advances the session even before dispatch decides whether the
		// function is one this honeypot implements.
		sess.advance(stageEngaged)
		// The MBAP header is otherwise consumed purely to build the response
		// echo, but its unit id and transaction id are the only session-level
		// client fingerprint Modbus/TCP offers -- record them before dispatch,
		// so a request we decline still contributes what it reveals.
		sess.recordFrame(hdr)

		// Over the cap the device is "busy" -- but the connection is still
		// accepted, read and recorded. Refusing at the TCP layer would cost us
		// the capture, which is the one thing this honeypot must not trade away
		// for fidelity.
		var resp []byte
		if h.pacer.AtCapacity(maxConcurrentSessions) {
			sess.record(operation{
				Kind:    "refused_server_busy",
				Detail:  fmt.Sprintf("function 0x%02X refused: %d concurrent sessions is at this device's limit", pdu[0], h.pacer.Active()),
				Raw:     pdu,
				Handled: false,
			})
			resp = buildException(pdu[0], excServerDeviceBusy)
		} else {
			resp = handlePDU(pdu, host, sess)
		}
		if resp == nil {
			continue // parsed fine, nothing plausible to answer with -- keep the session open
		}
		// Pace immediately before the write: the delay is only a fingerprint
		// fix if it sits between the request and the reply.
		h.pacer.Pace()
		if err := writeMBAP(conn, hdr, resp); err != nil {
			return
		}
	}

	h.logger.Debug().Str("remote", host).Msg("modbus connection ended (PDU limit reached)")
}
