// Package s7comm emulates a Siemens S7-300 class PLC speaking classic
// S7comm over TCP/102 (TPKT + ISO-COTP + S7 PDUs).
//
// It is a honeypot: nothing it reports is real, and nothing an attacker asks
// it to do is ever executed -- no command runs, no state outside this
// package's own per-attacker-IP maps changes. See persona.go for the device
// identity values (and their provenance), and icscore for the shared
// per-attacker-IP scoping (icscore.Store) and session/capture scaffolding
// (icscore.Session) this package is built on: a write or a CPU STOP from one
// attacker must never become visible to another, which is the exact bug
// this project has already shipped once in a different honeypot's
// globally-mutable emulated state.
package s7comm

import (
	"bufio"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/icscore"
	"github.com/rs/zerolog"
)

const (
	defaultPort = "102"

	// idleTimeout/totalTimeout bound one connection's lifetime -- mirroring
	// mongo.go's precedent. A real engineering session is a handful of
	// request/response pairs, not an open-ended pipe.
	idleTimeout  = 30 * time.Second
	totalTimeout = 300 * time.Second

	// maxPDUsPerConnection caps how many S7 PDUs one connection may
	// exchange, so a scripted flood can't hold a goroutine open forever.
	maxPDUsPerConnection = 500
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

// New builds the honeypot. It is side-effect free: no socket is opened until
// Start is called.
func New() honeypots.Honeypot {
	return &honeypot{
		logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "s7comm").Logger(),
	}
}

func (h *honeypot) Name() string { return "s7comm" }

func (h *honeypot) Start() {
	port := os.Getenv("S7COMM_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Error().Err(err).Str("port", port).Msg("failed to start s7comm listener")
		return
	}
	h.logger.Info().Str("port", port).Msg("starting s7comm honeypot")
	h.serve(ln)
}

// serve runs the accept loop until the listener stops accepting. Split from
// Start so tests can drive an ephemeral (":0") listener directly.
func (h *honeypot) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			h.logger.Debug().Err(err).Msg("s7comm listener stopped accepting")
			return
		}
		go h.handleConnection(conn)
	}
}

// handleConnection drives one TCP connection: a single COTP Connect
// Request/Confirm handshake, followed by a bounded number of COTP Data
// TPDUs each carrying one S7 PDU. ip (the connection's remote address) is
// what scopes all read/write/CPU-mode state -- see state.go.
func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	host := icscore.RemoteHost(conn.RemoteAddr())

	// Backstop: a slice-bounds bug anywhere in this package's parsing must
	// never take the whole agent process down. tpkt.go/cotp.go/pdu.go all
	// validate lengths before indexing, so this should be unreachable in
	// practice -- but a honeypot parsing hostile input is exactly the wrong
	// place to rely on "should be".
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error().Interface("panic", r).Str("remote", host).Msg("recovered panic in s7comm handler")
		}
	}()

	sess := newSession()
	defer persistSession(h.logger, host, sess)

	h.logger.Info().Str("remote", host).Msg("new s7comm connection")
	conn.SetDeadline(time.Now().Add(totalTimeout))
	reader := bufio.NewReader(conn)

	// Every early `return` below deliberately ends the connection outright
	// (via the deferred conn.Close()) rather than trying to recover and keep
	// serving -- this is the honeypot's answer to "malformed/truncated input
	// must not panic": for TPKT, COTP, and S7-header-layer failures alike,
	// closing the connection is the chosen "protocol error" response, so
	// every failure path here is a plain `return`, never a `break` that
	// could be mistaken for "skip this PDU and keep the connection open".
	connected := false
	for i := 0; i < maxPDUsPerConnection; i++ {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		payload, err := readTPKT(reader)
		if err != nil {
			return
		}
		if len(payload) < 2 {
			return
		}

		switch payload[1] { // COTP TPDU type byte
		case cotpCR:
			if connected {
				return // a second CR on an already-connected session isn't valid COTP
			}
			cr, err := parseCR(payload)
			if err != nil {
				return
			}
			if err := writeTPKT(conn, buildCC(cr, nextCOTPRef())); err != nil {
				return
			}
			connected = true
			sess.advance(stageCOTP)
			sess.setTSAPs(cr.srcTSAP, cr.dstTSAP)

		case cotpDT:
			if !connected {
				return // data before a connection was ever confirmed
			}
			s7payload, err := parseDT(payload)
			if err != nil {
				return
			}
			resp, ok := handlePDU(s7payload, host, sess)
			if !ok {
				return
			}
			if resp == nil {
				continue // parsed fine, nothing plausible to answer with -- keep the session open
			}
			if err := writeTPKT(conn, buildDT(resp)); err != nil {
				return
			}

		default:
			// Any other COTP TPDU type (DR, ER, ...): nothing plausible to
			// answer with, so end the session rather than guess.
			return
		}
	}

	h.logger.Debug().Str("remote", host).Msg("s7comm connection ended (PDU limit reached)")
}

// cotpRefCounter feeds nextCOTPRef. Seeded from the current time (rather
// than always starting at 0/1) purely so restarts don't hand out identical
// reference sequences; the exact value has no protocol meaning as long as it
// doesn't collide within one connection, which a monotonically increasing
// counter guarantees.
var cotpRefCounter uint32 = uint32(time.Now().UnixNano())

func nextCOTPRef() uint16 {
	return uint16(atomic.AddUint32(&cotpRefCounter, 1))
}
