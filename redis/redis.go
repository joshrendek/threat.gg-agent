package redis

import (
	"bufio"
	"io"
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

	// maxServerLookupLen bounds the attacker-controlled command we forward to the server's
	// response lookup; anything longer skips the lookup and falls back to local handlers.
	maxServerLookupLen = 4096
)

// getCommandResponse is an injectable seam over the gRPC call so the server-matched and
// miss/error paths are unit-testable without a live server.
var getCommandResponse = persistence.GetCommandResponse

// serverResponse writes an admin-authored redis response VERBATIM to w when the server has
// a Matched row for (command_type="redis", payload=fullCmd). RESP is line-oriented text, so
// the stored response is exact RESP frames authored by the admin (e.g. "+PONG\r\n",
// "$4\r\nPONG\r\n"). Returns handled=true when it served the command (caller skips the
// hardcoded switch); on miss, error, or oversized input it returns handled=false and the
// caller falls back to the local handlers, so behavior never regresses if the server is
// unreachable or has no row. Matched (not an empty Response) distinguishes an intentionally
// silent authored row from a miss.
func serverResponse(fullCmd string, w io.Writer) (handled bool, err error) {
	if len(fullCmd) > maxServerLookupLen {
		return false, nil
	}
	resp, lookupErr := getCommandResponse(&proto.CommandRequest{Command: fullCmd, CommandType: "redis"})
	if lookupErr != nil || resp == nil || !resp.Matched {
		return false, nil
	}
	_, werr := io.WriteString(w, resp.Response)
	return true, werr
}

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "redis").Logger()}
}

func (h *honeypot) Name() string {
	return "redis"
}

func (h *honeypot) Start() {
	port := os.Getenv("REDIS_HONEYPOT_PORT")
	if port == "" {
		port = "6379"
	}

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start redis listener")
	}
	h.logger.Info().Str("addr", addr).Msg("starting redis honeypot")

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
	password string
	remoteIP string
	commands []string
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

	reader := bufio.NewReader(conn)

	for i := 0; i < maxCommands; i++ {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		args, err := parseCommand(reader)
		if err != nil {
			break
		}

		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		fullCmd := strings.Join(args, " ")
		sess.commands = append(sess.commands, fullCmd)

		h.logger.Debug().
			Str("session", sess.guid).
			Str("command", cmd).
			Msg("command received")

		// Server-authored response override (admin-editable command_responses, scoped to
		// command_type="redis"). On a Matched row we write it verbatim and skip the
		// hardcoded switch; on miss/error we fall through so behavior never regresses if
		// the server is unreachable.
		if handled, respErr := serverResponse(fullCmd, conn); handled {
			if respErr != nil {
				break
			}
			continue
		}

		var cmdErr error
		switch cmd {
		case "PING":
			cmdErr = handlePing(args, conn)
		case "AUTH":
			cmdErr = handleAuth(args, conn, sess)
		case "INFO":
			cmdErr = handleInfo(args, conn)
		case "CONFIG":
			if len(args) > 1 {
				sub := strings.ToUpper(args[1])
				switch sub {
				case "GET":
					cmdErr = handleConfigGet(args, conn)
				case "SET":
					cmdErr = handleConfigSet(args, conn)
				default:
					cmdErr = handleUnknown(fullCmd, conn)
				}
			} else {
				cmdErr = handleError(conn, "wrong number of arguments for 'config' command")
			}
		case "SET":
			cmdErr = handleSet(args, conn)
		case "GET":
			cmdErr = handleGet(args, conn)
		case "DEL":
			cmdErr = handleDel(args, conn)
		case "KEYS":
			cmdErr = handleKeys(args, conn)
		case "DBSIZE":
			cmdErr = handleDbsize(conn)
		case "SELECT":
			cmdErr = handleSelect(conn)
		case "COMMAND":
			cmdErr = handleCommand(args, conn)
		case "CLIENT":
			cmdErr = handleClient(args, conn)
		case "SLAVEOF", "REPLICAOF":
			cmdErr = handleSlaveof(conn)
		case "MODULE":
			cmdErr = handleModuleLoad(conn)
		case "EVAL", "EVALSHA":
			cmdErr = handleEval(conn)
		case "QUIT":
			handleQuit(conn)
			return
		default:
			cmdErr = handleUnknown(cmd, conn)
		}

		if cmdErr != nil {
			break
		}
	}

	h.logger.Info().
		Str("session", sess.guid).
		Int("commands", len(sess.commands)).
		Msg("session ended")

	go h.persistSession(sess)
}

func handleError(conn net.Conn, msg string) error {
	return writeError(conn, msg)
}

func (h *honeypot) persistSession(sess *session) {
	if len(sess.commands) == 0 {
		return
	}

	req := &proto.RedisConnectRequest{
		RemoteAddr: sess.remoteIP,
		Guid:       sess.guid,
		Username:   sess.username,
		Password:   sess.password,
	}
	if err := persistence.SaveRedisConnect(req); err != nil {
		h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist redis connect")
		return
	}

	for _, cmd := range sess.commands {
		cmdReq := &proto.RedisCommandRequest{
			Guid:    sess.guid,
			Command: cmd,
		}
		if err := persistence.SaveRedisCommand(cmdReq); err != nil {
			h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist redis command")
		}
	}
}
