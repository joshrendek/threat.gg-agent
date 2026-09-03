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

// Package-level DEFAULTS, assigned once here and never reassigned. The hooks
// tests need to replace live on the honeypot struct instead (threat_gg-x59t):
// connection goroutines outlive both serve() and the test that started them,
// so a package var a test swaps in setup and restores in t.Cleanup is read by
// a goroutine from the previous test while the next test writes it. That race
// cannot be closed by capturing the var into a local before spawning -- the
// capture itself is the racing read. It is closed by having nothing to swap.
// connectionSlots already worked this way; the rest now match it.
var (
	defaultSaveLogin = persistence.SaveMssqlLogin
	defaultSaveQuery = persistence.SaveQuery
	defaultLookup    = func(commandType, command string) (string, bool) {
		return cmdresp.LookupWithin(commandType, command, overrideLookupTimeout)
	}
	defaultPersistSlots    = make(chan struct{}, persistSlotsN)
	defaultConnectionSlots = make(chan struct{}, maxConnections)
)

var _ honeypots.Honeypot = (*honeypot)(nil)

type honeypot struct {
	logger       zerolog.Logger
	idleTimeout  time.Duration
	sessionLimit time.Duration
	queryLimit   int

	// Per-instance overrides. nil means "use the package default". Tests set
	// these on the struct they construct; nothing ever mutates package state.
	connectionSlots chan struct{}
	persistSlots    chan struct{}
	saveLogin       func(*proto.MssqlRequest) error
	saveQuery       func(*proto.QueryRequest) error
	lookup          func(commandType, command string) (string, bool)
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

func (h *honeypot) effectivePersistSlots() chan struct{} {
	if h.persistSlots != nil {
		return h.persistSlots
	}
	return defaultPersistSlots
}

func (h *honeypot) effectiveSaveLogin() func(*proto.MssqlRequest) error {
	if h.saveLogin != nil {
		return h.saveLogin
	}
	return defaultSaveLogin
}

func (h *honeypot) effectiveSaveQuery() func(*proto.QueryRequest) error {
	if h.saveQuery != nil {
		return h.saveQuery
	}
	return defaultSaveQuery
}

func (h *honeypot) effectiveLookup() func(commandType, command string) (string, bool) {
	if h.lookup != nil {
		return h.lookup
	}
	return defaultLookup
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
	saveLogin := h.effectiveSaveLogin()
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
		saveQ := h.effectiveSaveQuery()
		h.persist(func() error {
			return saveQ(&proto.QueryRequest{Guid: guid, Query: query, CommandType: "mssql"})
		})
		normalized := normalizeQuery(query)
		authored, ok := "", false
		if cached, exists := overrides[normalized]; exists {
			authored, ok = cached.response, cached.matched
		} else {
			authored, ok = h.effectiveLookup()("mssql", normalized)
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
	// Bind acquire and release to the same channel: the deferred release must
	// hand the slot back to the channel it came from.
	slots := h.effectivePersistSlots()
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
