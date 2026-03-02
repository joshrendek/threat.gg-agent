package rdp

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort  = "3389"
	totalTimeout = 60 * time.Second
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	port    string
	tlsCert tls.Certificate
	logger  zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{
		logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "rdp").Logger(),
	}
}

func (h *honeypot) Name() string {
	return "rdp"
}

func (h *honeypot) Start() {
	port := os.Getenv("RDP_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	h.port = port

	cert, err := generateSelfSignedCert()
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to generate self-signed cert")
	}
	h.tlsCert = cert

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start rdp listener")
	}
	h.logger.Info().Str("addr", addr).Msg("starting rdp honeypot")

	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("accept error")
			continue
		}
		go h.handleConnection(conn)
	}
}

type session struct {
	guid               string
	remoteIP           string
	cookieUsername     string
	requestedProtocols uint32
	ntlmUsername       string
	ntlmDomain         string
	ntlmWorkstation    string
	ntlmHash           string
	tlsCert            tls.Certificate
	logger             zerolog.Logger
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if remoteAddr == "" {
		remoteAddr = conn.RemoteAddr().String()
	}

	sess := &session{
		guid:     uuid.NewV4().String(),
		remoteIP: remoteAddr,
		tlsCert:  h.tlsCert,
		logger:   h.logger,
	}

	h.logger.Info().Str("session", sess.guid).Str("remote", remoteAddr).Msg("new connection")

	conn.SetDeadline(time.Now().Add(totalTimeout))

	// Step 1: Read TPKT + X.224 Connection Request
	payload, err := readTPKT(conn)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read TPKT")
		return
	}

	x224Req, err := parseX224Request(payload)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to parse X.224 request")
		return
	}

	sess.cookieUsername = x224Req.cookie
	sess.requestedProtocols = x224Req.requestedProtocols

	h.logger.Debug().
		Str("session", sess.guid).
		Str("cookie", x224Req.cookie).
		Uint32("protocols", x224Req.requestedProtocols).
		Bool("has_neg", x224Req.hasNegReq).
		Msg("X.224 connection request")

	// Step 2: Respond based on client capabilities
	if x224Req.requestedProtocols&protocolHybrid != 0 {
		// Client supports NLA (CredSSP/NTLM) -- capture credentials
		if err := writeX224Confirm(conn, protocolHybrid); err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to send X.224 confirm")
			return
		}

		handleNTLM(conn, sess)
	} else {
		// Client does not support NLA, just confirm with standard RDP
		if err := writeX224Confirm(conn, protocolRDP); err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to send X.224 confirm")
			return
		}
	}

	h.logger.Info().
		Str("session", sess.guid).
		Str("cookie", sess.cookieUsername).
		Str("ntlm_user", sess.ntlmUsername).
		Str("ntlm_domain", sess.ntlmDomain).
		Msg("session ended")

	persistSession(sess)
}

func persistSession(sess *session) {
	if sess.cookieUsername == "" && sess.ntlmUsername == "" {
		return
	}

	req := &proto.RdpRequest{
		RemoteAddr:         sess.remoteIP,
		Guid:               sess.guid,
		RequestedProtocols: sess.requestedProtocols,
		CookieUsername:     sess.cookieUsername,
		NtlmUsername:       sess.ntlmUsername,
		NtlmDomain:         sess.ntlmDomain,
		NtlmWorkstation:    sess.ntlmWorkstation,
		NtlmHash:           sess.ntlmHash,
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "panic saving rdp session: %v\n", r)
			}
		}()
		if err := persistence.SaveRdpConnect(req); err != nil {
			sess.logger.Error().Err(err).Msg("error saving rdp session")
		}
	}()
}
