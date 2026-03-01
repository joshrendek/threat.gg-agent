package mysql

import (
	"bufio"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	maxCommands  = 500
	totalTimeout = 300 * time.Second
	idleTimeout  = 30 * time.Second
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "mysql").Logger()}
}

func (h *honeypot) Name() string {
	return "mysql"
}

func (h *honeypot) Start() {
	port := os.Getenv("MYSQL_HONEYPOT_PORT")
	if port == "" {
		port = "3306"
	}

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start mysql listener")
	}
	h.logger.Info().Str("addr", addr).Msg("starting mysql honeypot")

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
	guid     string
	username string
	database string
	remoteIP string
	queries  []string
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

	conn.SetDeadline(time.Now().Add(totalTimeout))

	connID := rand.Uint32()

	// Send server greeting
	if err := sendHandshake(conn, connID); err != nil {
		h.logger.Debug().Err(err).Msg("failed to send handshake")
		return
	}

	// Read client auth response
	reader := bufio.NewReader(conn)
	payload, _, err := readPacket(reader)
	if err != nil {
		h.logger.Debug().Err(err).Msg("failed to read auth response")
		return
	}

	creds := parseHandshakeResponse(payload)
	sess.username = creds.username
	sess.database = creds.database

	h.logger.Info().
		Str("session", sess.guid).
		Str("username", creds.username).
		Str("database", creds.database).
		Msg("auth received")

	// Send OK (auth success)
	if err := writeOKPacket(conn, 2, 0, 0); err != nil {
		return
	}

	// Command phase
	for i := 0; i < maxCommands; i++ {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		payload, seqID, err := readPacket(reader)
		if err != nil {
			break
		}

		if len(payload) == 0 {
			continue
		}

		cmdByte := payload[0]
		cmdData := ""
		if len(payload) > 1 {
			cmdData = string(payload[1:])
		}

		var cmdErr error
		switch cmdByte {
		case comQuery:
			sess.queries = append(sess.queries, cmdData)
			h.logger.Debug().
				Str("session", sess.guid).
				Str("query", truncate(cmdData, 200)).
				Msg("query received")
			_, cmdErr = handleComQuery(conn, seqID+1, cmdData)

		case comPing:
			cmdErr = handleComPing(conn, seqID+1)

		case comInitDB:
			sess.database = cmdData
			sess.queries = append(sess.queries, "USE "+cmdData)
			cmdErr = handleComInitDB(conn, seqID+1)

		case comStatistics:
			cmdErr = handleComStatistics(conn, seqID+1)

		case comQuit:
			return

		default:
			// Unknown command: return OK
			cmdErr = writeOKPacket(conn, seqID+1, 0, 0)
		}

		if cmdErr != nil {
			break
		}
	}

	h.logger.Info().
		Str("session", sess.guid).
		Int("queries", len(sess.queries)).
		Msg("session ended")

	go h.persistSession(sess)
}

func (h *honeypot) persistSession(sess *session) {
	if len(sess.queries) == 0 && sess.username == "" {
		return
	}

	req := &proto.MysqlRequest{
		RemoteAddr: sess.remoteIP,
		Guid:       sess.guid,
		Username:   sess.username,
		Password:   "",
	}
	if err := persistence.SaveMysqlLogin(req); err != nil {
		h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist mysql login")
		return
	}

	for _, q := range sess.queries {
		qReq := &proto.QueryRequest{
			Guid:  sess.guid,
			Query: q,
		}
		if err := persistence.SaveQuery(qReq); err != nil {
			h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist query")
		}
	}
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
