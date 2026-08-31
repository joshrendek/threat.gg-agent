package mssql

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	maxQueries            = 64
	idleTimeout           = 30 * time.Second
	sessionLimit          = 5 * time.Minute
	persistSlotsN         = 32
	maxConnections        = 128
	overrideCacheEntries  = 64
	overrideLookupTimeout = 500 * time.Millisecond
)

var (
	saveMssqlLogin = persistence.SaveMssqlLogin
	saveQuery      = persistence.SaveQuery
	lookupResponse = func(commandType, command string) (string, bool) {
		return cmdresp.LookupWithin(commandType, command, overrideLookupTimeout)
	}
	persistSlots           = make(chan struct{}, persistSlotsN)
	defaultConnectionSlots = make(chan struct{}, maxConnections)
)

var _ honeypots.Honeypot = (*honeypot)(nil)

type honeypot struct {
	logger          zerolog.Logger
	idleTimeout     time.Duration
	sessionLimit    time.Duration
	queryLimit      int
	connectionSlots chan struct{}
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "mssql").Logger()}
}

func (h *honeypot) Name() string { return "mssql" }

func (h *honeypot) Start() {
	port := os.Getenv("MSSQL_HONEYPOT_PORT")
	if port == "" {
		port = "1433"
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start mssql listener")
	}
	h.logger.Info().Str("addr", listener.Addr().String()).Msg("starting mssql honeypot")
	h.serve(listener)
}

func (h *honeypot) serve(listener net.Listener) {
	slots := h.effectiveConnectionSlots()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			h.logger.Error().Err(err).Msg("accept error")
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				h.handleConnection(conn)
			}()
		default:
			h.logger.Warn().Msg("rejecting mssql connection: session limit reached")
			_ = conn.Close()
		}
	}
}

func (h *honeypot) effectiveConnectionSlots() chan struct{} {
	if h.connectionSlots != nil {
		return h.connectionSlots
	}
	return defaultConnectionSlots
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()
	started := time.Now()
	sessionEnd := started.Add(h.effectiveSessionLimit())
	h.setDeadline(conn, sessionEnd)
	guid := uuid.NewV4().String()
	remoteIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}

	typeID, _, err := readMessage(conn)
	if err != nil || typeID != packetPrelogin {
		return
	}
	if err := writeMessage(conn, packetReply, preloginResponse()); err != nil {
		return
	}
	h.setDeadline(conn, sessionEnd)
	typeID, payload, err := readMessage(conn)
	if err != nil || typeID != packetLogin7 {
		return
	}
	login, err := parseLogin7(payload)
	if err != nil {
		_ = writeMessage(conn, packetReply, errorResponse(18456, "Login failed for user."))
		return
	}
	// Capture the package var BEFORE spawning (kubelet/kubelet.go:138 does the
	// same). Reading saveMssqlLogin from inside the persist goroutine is a data
	// race (threat_gg-x59t): tests swap these vars in setup and restore them in
	// t.Cleanup, so a goroutine still in flight from an earlier test reads the var
	// while the next test writes it. Capturing binds the goroutine to the function
	// that was installed when the work was queued.
	saveLogin := saveMssqlLogin
	h.persist(func() error {
		return saveLogin(&proto.MssqlRequest{
			Guid: guid, RemoteAddr: remoteIP, Username: login.username, Password: login.password,
			Hostname: login.hostname, AppName: login.appName, ServerName: login.serverName,
			Library: login.library, Database: login.database, TdsVersion: login.tdsVersion,
		})
	})
	h.setDeadline(conn, sessionEnd)
	if err := writeMessage(conn, packetReply, postLoginResponse(login.database)); err != nil {
		return
	}

	overrides := make(map[string]overrideResult)
	for queryCount := 0; queryCount < h.effectiveQueryLimit() && time.Now().Before(sessionEnd); queryCount++ {
		h.setDeadline(conn, sessionEnd)
		typeID, payload, err = readMessage(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				h.logger.Debug().Err(err).Str("session", guid).Msg("mssql session ended")
			}
			return
		}
		if typeID != packetSQLBatch {
			_ = writeMessage(conn, packetReply, errorResponse(40515, "The request type is not supported."))
			continue
		}
		query := parseSQLBatch(payload)
		if query == "" {
			_ = writeMessage(conn, packetReply, appendDone(nil, 0, 0))
			continue
		}
		// Captured before spawning, for the same reason as the login path above.
		saveQ := saveQuery
		h.persist(func() error {
			return saveQ(&proto.QueryRequest{Guid: guid, Query: query, CommandType: "mssql"})
		})
		normalized := normalizeQuery(query)
		authored, ok := "", false
		if cached, exists := overrides[normalized]; exists {
			authored, ok = cached.response, cached.matched
		} else {
			authored, ok = lookupResponse("mssql", normalized)
			if len(overrides) < overrideCacheEntries {
				overrides[normalized] = overrideResult{response: authored, matched: ok}
			}
		}
		h.setDeadline(conn, sessionEnd)
		if ok {
			err = writeMessage(conn, packetReply, resultResponse("result", []string{authored}))
		} else {
			err = writeMessage(conn, packetReply, responseForQuery(query))
		}
		if err != nil {
			return
		}
	}
}

type overrideResult struct {
	response string
	matched  bool
}

func (h *honeypot) effectiveIdleTimeout() time.Duration {
	if h.idleTimeout > 0 {
		return h.idleTimeout
	}
	return idleTimeout
}

func (h *honeypot) effectiveSessionLimit() time.Duration {
	if h.sessionLimit > 0 {
		return h.sessionLimit
	}
	return sessionLimit
}

func (h *honeypot) effectiveQueryLimit() int {
	if h.queryLimit > 0 {
		return h.queryLimit
	}
	return maxQueries
}

func (h *honeypot) setDeadline(conn net.Conn, sessionEnd time.Time) {
	deadline := time.Now().Add(h.effectiveIdleTimeout())
	if sessionEnd.Before(deadline) {
		deadline = sessionEnd
	}
	_ = conn.SetDeadline(deadline)
}

func (h *honeypot) persist(save func() error) {
	// Capture the channel before spawning, the way kubelet/kubelet.go:135 does.
	//
	// Reading the persistSlots PACKAGE VAR from inside the goroutine's defer is a
	// data race (threat_gg-x59t): tests swap persistSlots to size the queue, and a
	// goroutine spawned before the swap would then release a slot on the NEW
	// channel while the test writes the var. Capturing binds each goroutine to the
	// channel it actually acquired from, so acquire and release always pair up on
	// the same channel regardless of any later reassignment.
	slots := persistSlots
	select {
	case slots <- struct{}{}:
		go func() {
			defer func() { <-slots }()
			if err := save(); err != nil {
				h.logger.Error().Err(err).Msg("failed to persist mssql telemetry")
			}
		}()
	default:
		h.logger.Warn().Msg("dropping mssql telemetry: persistence queue full")
	}
}

func responseForQuery(query string) []byte {
	normalized := normalizeQuery(query)
	switch {
	case strings.Contains(normalized, "@@version"):
		return resultResponse("", []string{"Microsoft SQL Server 2022 (RTM-CU14) (KB5038325) - 16.0.4135.4 (X64)\n\tEnterprise Edition on Linux"})
	case strings.Contains(normalized, "db_name()"):
		return resultResponse("", []string{"master"})
	case strings.Contains(normalized, "system_user"), strings.Contains(normalized, "suser_sname"):
		return resultResponse("", []string{"CORP\\svc-sql"})
	case strings.Contains(normalized, "sys.databases"), strings.Contains(normalized, "sysdatabases"):
		return resultResponse("name", []string{"master", "tempdb", "model", "msdb", "Finance", "HR"})
	case strings.HasPrefix(normalized, "select"):
		return resultResponse("", []string{"1"})
	case strings.HasPrefix(normalized, "use "), strings.HasPrefix(normalized, "set "),
		strings.HasPrefix(normalized, "exec "), strings.HasPrefix(normalized, "execute "),
		strings.HasPrefix(normalized, "create "), strings.HasPrefix(normalized, "alter "),
		strings.HasPrefix(normalized, "drop "), strings.HasPrefix(normalized, "insert "),
		strings.HasPrefix(normalized, "update "), strings.HasPrefix(normalized, "delete "):
		return appendDone(nil, 0, 0)
	default:
		return errorResponse(102, "Incorrect syntax near the specified token.")
	}
}

func normalizeQuery(query string) string {
	return strings.ToLower(strings.Join(strings.Fields(query), " "))
}
