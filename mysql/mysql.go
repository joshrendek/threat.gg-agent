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
	// maxCommands bounds how many commands one session may issue before the honeypot stops
	// reading, so a single connection cannot buffer captured queries without limit.
	maxCommands = 500
	// maxConsecutivePersistFailures bounds how long a session's persistence goroutine will
	// keep trying against an unresponsive backend. See the loop in persistSession.
	maxConsecutivePersistFailures = 3
	// totalTimeout caps a whole session; idleTimeout caps the wait for each next command.
	totalTimeout = 300 * time.Second
	idleTimeout  = 30 * time.Second
)

var _ honeypots.Honeypot = &honeypot{}

// Indirected for tests, matching the mssql package.
var (
	saveMysqlLogin = persistence.SaveMysqlLogin
	saveQuery      = persistence.SaveQuery
)

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
	// scramble and authData are the two halves of the mysql_native_password exchange.
	// Both are needed to produce a crackable artifact; see nativePasswordArtifact.
	scramble []byte
	authData []byte
	// authPlugin is the plugin the client named, and it decides whether the pair above may
	// be labelled a native-password digest at all. See nativePasswordArtifact.
	authPlugin string
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
	scramble, err := sendHandshake(conn, connID)
	if err != nil {
		h.logger.Debug().Err(err).Msg("failed to send handshake")
		return
	}
	sess.scramble = scramble

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
	sess.authData = creds.authData
	sess.authPlugin = creds.authPlugin

	h.logger.Info().
		Str("session", sess.guid).
		Str("username", creds.username).
		Str("database", creds.database).
		Msg("auth received")

	// From here on the credential is captured, so every exit must run persistSession.
	// A bare return would lose it exactly where it is most valuable: a credential-spraying
	// scanner sends its auth response and closes without waiting for the reply, which is
	// precisely when writing the OK packet fails. Same family as the COM_QUIT case below.
	defer func() { go h.persistSession(sess) }()

	// Send OK (auth success)
	if err := writeOKPacket(conn, 2, 0, 0); err != nil {
		return
	}

	// Command phase
commandLoop:
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
			_, cmdErr = handleComQueryForSession(conn, seqID+1, cmdData, sess.guid)

		case comPing:
			cmdErr = handleComPing(conn, seqID+1)

		case comInitDB:
			sess.database = cmdData
			sess.queries = append(sess.queries, "USE "+cmdData)
			cmdErr = handleComInitDB(conn, seqID+1)

		case comStatistics:
			cmdErr = handleComStatistics(conn, seqID+1)

		case comQuit:
			// Break the loop rather than return: returning skipped persistSession below,
			// so a client that disconnected politely -- which every real MySQL driver
			// does -- had its entire session discarded, credentials and queries alike.
			// The best-behaved sessions were the ones we dropped.
			break commandLoop

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
	// persistSession runs from the deferred call above, which covers this exit too.
}

// persistSession records the login and then every query the session issued. It skips only
// sessions that produced nothing at all -- no username, no credential, no query -- so an
// ordinary port scan that opens a connection and leaves does not manufacture an attacker
// row. Any one of the three is enough to record: an unauthenticated query, a credential
// with no follow-up, and an anonymous login are all worth keeping.
//
// Order matters and is not incidental: the server materializes the attacker row from the
// login, and SaveQuery only writes an attacker_commands row keyed by the same guid. Saving
// queries first (or after a failed login) would leave commands pointing at a guid that
// never appears in attackers, so they would be invisible in the dashboard rather than
// merely late. That is why a login error returns instead of pressing on.
func (h *honeypot) persistSession(sess *session) {
	// authData is part of the test because MySQL allows anonymous accounts: a client can
	// authenticate with an empty username and still send a real native-password response.
	// Checking only the username and queries discarded exactly that -- a captured
	// credential, thrown away for want of a name to file it under.
	if len(sess.queries) == 0 && sess.username == "" && len(sess.authData) == 0 {
		return
	}

	req := &proto.MysqlRequest{
		RemoteAddr: sess.remoteIP,
		Guid:       sess.guid,
		Username:   sess.username,
		Password:   nativePasswordArtifact(sess.scramble, sess.authData, sess.authPlugin),
	}
	if err := saveMysqlLogin(req); err != nil {
		h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist mysql login")
		return
	}

	// Queries are saved here rather than inline in the command loop so they cannot outrun
	// the login above. Capture is deliberately independent of the cmdresp override lookup:
	// that path skips credential-bearing statements to avoid forwarding secrets to the
	// response server -- isSensitiveMySQLLookup drops anything containing "identified by",
	// "set password" or "password(" -- which used to mean the statements most worth having
	// were the ones guaranteed to be recorded nowhere.
	// A single failure is transient and must not cost the rest of the session -- the
	// statement worth having is as likely to be last as first. A run of them means the
	// backend is down, and grinding through the remaining queries would hold this
	// goroutine, and the session's captured payloads, for maxCommands * saveTimeout
	// (~42 minutes at 500 x 5s) while succeeding at nothing. Give up after a few.
	consecutiveFailures := 0
	for i, query := range sess.queries {
		if err := saveQuery(&proto.QueryRequest{
			Guid:        sess.guid,
			Query:       query,
			CommandType: "mysql",
		}); err != nil {
			h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist mysql query")
			consecutiveFailures++
			if consecutiveFailures >= maxConsecutivePersistFailures {
				h.logger.Error().
					Str("session", sess.guid).
					Int("abandoned", len(sess.queries)-i-1).
					Msg("abandoning mysql query persistence; backend appears unavailable")
				return
			}
			continue
		}
		consecutiveFailures = 0
	}
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
