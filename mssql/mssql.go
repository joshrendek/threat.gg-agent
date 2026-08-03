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
	maxQueries    = 64
	idleTimeout   = 30 * time.Second
	sessionLimit  = 5 * time.Minute
	persistSlotsN = 32
)

var (
	saveMssqlLogin = persistence.SaveMssqlLogin
	saveQuery      = persistence.SaveQuery
	lookupResponse = cmdresp.Lookup
	persistSlots   = make(chan struct{}, persistSlotsN)
)

var _ honeypots.Honeypot = (*honeypot)(nil)

type honeypot struct{ logger zerolog.Logger }

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
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			h.logger.Error().Err(err).Msg("accept error")
			continue
		}
		go h.handleConnection(conn)
	}
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()
	started := time.Now()
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
	_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
	typeID, payload, err := readMessage(conn)
	if err != nil || typeID != packetLogin7 {
		return
	}
	login, err := parseLogin7(payload)
	if err != nil {
		_ = writeMessage(conn, packetReply, errorResponse(18456, "Login failed for user."))
		return
	}
	h.persist(func() error {
		return saveMssqlLogin(&proto.MssqlRequest{
			Guid: guid, RemoteAddr: remoteIP, Username: login.username, Password: login.password,
			Hostname: login.hostname, AppName: login.appName, ServerName: login.serverName,
			Library: login.library, Database: login.database, TdsVersion: login.tdsVersion,
		})
	})
	if err := writeMessage(conn, packetReply, loginResponse(login.database)); err != nil {
		return
	}

	for queryCount := 0; queryCount < maxQueries && time.Since(started) < sessionLimit; queryCount++ {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
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
		h.persist(func() error {
			return saveQuery(&proto.QueryRequest{Guid: guid, Query: query, CommandType: "mssql"})
		})
		if authored, ok := lookupResponse("mssql", query); ok {
			err = writeMessage(conn, packetReply, resultResponse("result", []string{authored}))
		} else {
			err = writeMessage(conn, packetReply, responseForQuery(query))
		}
		if err != nil {
			return
		}
	}
}

func (h *honeypot) persist(save func() error) {
	select {
	case persistSlots <- struct{}{}:
		go func() {
			defer func() { <-persistSlots }()
			if err := save(); err != nil {
				h.logger.Error().Err(err).Msg("failed to persist mssql telemetry")
			}
		}()
	default:
		h.logger.Warn().Msg("dropping mssql telemetry: persistence queue full")
	}
}

func responseForQuery(query string) []byte {
	normalized := strings.ToLower(strings.Join(strings.Fields(query), " "))
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
