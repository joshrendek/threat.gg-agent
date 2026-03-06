package vnc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	defaultPort       = "5900"
	connectionTimeout = 30 * time.Second
	serverName        = "threat.gg VNC"
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

type session struct {
	guid          string
	remoteIP      string
	clientVersion string
	securityType  byte
	challenge     []byte
	response      []byte
	sharedFlag    bool
	pixelFormat   string
	encodings     []int32
}

func New() honeypots.Honeypot {
	return &honeypot{
		logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "vnc").Logger(),
	}
}

func (h *honeypot) Name() string {
	return "vnc"
}

func (h *honeypot) Start() {
	port := os.Getenv("VNC_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start vnc listener")
	}
	h.logger.Info().Str("addr", addr).Msg("starting vnc honeypot")

	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("accept error")
			continue
		}
		go h.handleConnection(conn)
	}
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
	}

	h.logger.Info().Str("session", sess.guid).Str("remote", remoteAddr).Msg("new connection")

	_ = conn.SetDeadline(time.Now().Add(connectionTimeout))

	if err := writeProtocolVersion(conn); err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("write protocol version failed")
		return
	}

	clientVersion, err := readProtocolVersion(conn)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("read protocol version failed")
		return
	}
	sess.clientVersion = clientVersion

	if err := writeSecurityTypes(conn); err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("write security types failed")
		return
	}

	securityType, err := readSecuritySelection(conn)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("read security selection failed")
		return
	}
	sess.securityType = securityType

	if securityType == securityTypeVNCAuth {
		sess.challenge = make([]byte, challengeLength)
		if _, err := rand.Read(sess.challenge); err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("generate challenge failed")
			return
		}
		if err := writeChallenge(conn, sess.challenge); err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("write challenge failed")
			return
		}
		response, err := readChallengeResponse(conn)
		if err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("read challenge response failed")
			return
		}
		sess.response = response
	}

	// Return "OK" regardless of credentials to keep clients engaged.
	if err := writeSecurityResult(conn, 0); err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("write security result failed")
		return
	}

	sharedFlag, err := readSharedFlag(conn)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("read shared flag failed")
		return
	}
	sess.sharedFlag = sharedFlag

	if err := writeServerInit(conn, serverName); err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("write server init failed")
		return
	}

	pixelFormat, encodings, err := readClientPreferences(conn)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("read client preferences failed")
	}
	sess.pixelFormat = pixelFormat
	sess.encodings = encodings

	persistSession(sess, h.logger)
}

func persistSession(sess *session, logger zerolog.Logger) {
	data := map[string]any{
		"security_type": sess.securityType,
		"shared_flag":   sess.sharedFlag,
	}
	if sess.pixelFormat != "" {
		data["pixel_format"] = sess.pixelFormat
	}
	if len(sess.encodings) > 0 {
		data["encodings"] = sess.encodings
	}

	serialized, err := json.Marshal(data)
	if err != nil {
		logger.Error().Err(err).Msg("marshal vnc data failed")
		return
	}

	req := &proto.VncRequest{
		RemoteAddr:    sess.remoteIP,
		Guid:          sess.guid,
		ClientVersion: sess.clientVersion,
		ChallengeHex:  hex.EncodeToString(sess.challenge),
		ResponseHex:   hex.EncodeToString(sess.response),
		Data:          string(serialized),
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "panic saving vnc session: %v\n", r)
			}
		}()
		if err := persistence.SaveVncConnect(req); err != nil {
			logger.Error().Err(err).Msg("save vnc connect failed")
		}
	}()
}
