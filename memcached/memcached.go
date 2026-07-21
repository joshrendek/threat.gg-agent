package memcached

import (
	"bufio"
	"io"
	"net"
	"os"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort  = "11211"
	idleTimeout  = 30 * time.Second
	totalTimeout = 300 * time.Second
	maxCommands  = 500

	// maxLineLen caps a single command line so an unbounded write can't exhaust memory.
	maxLineLen = 8 * 1024
	// maxDataBlock caps the payload we drain after a storage command (real memcached
	// default item size is 1MB); anything larger is refused with SERVER_ERROR.
	maxDataBlock = 1 << 20
)

// Persistence seams — overridable in tests so the listener needs no live gRPC server.
var (
	saveMemcachedConnect = persistence.SaveMemcachedConnect
	saveMemcachedCommand = persistence.SaveMemcachedCommand
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "memcached").Logger()}
}

func (h *honeypot) Name() string {
	return "memcached"
}

func (h *honeypot) Start() {
	port := os.Getenv("MEMCACHED_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start memcached listener")
	}
	h.logger.Info().Str("port", port).Msg("starting memcached honeypot")
	h.serve(ln)
}

// serve runs the accept loop. Split from Start so tests can drive an ephemeral listener.
func (h *honeypot) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("accept error")
			return
		}
		go h.handleConnection(conn)
	}
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if host == "" {
		host = conn.RemoteAddr().String()
	}

	guid := uuid.NewV4().String()
	h.logger.Info().Str("session", guid).Str("remote", host).Msg("new connection")

	// A bare TCP connection to :11211 is itself a signal (memcached amplification
	// scanning), so record the connect up front. Protocol is the text/ascii protocol.
	go h.persistConnect(host, guid)

	conn.SetDeadline(time.Now().Add(totalTimeout))
	reader := bufio.NewReaderSize(conn, maxLineLen)

	for i := 0; i < maxCommands; i++ {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		line, err := readLine(reader)
		if err != nil {
			break
		}

		cmd := parseCommand(line)

		// A storage command is followed by a data block of the declared length; drain it
		// so the payload is never parsed as the next command line.
		if n, ok := cmd.storageDataBytes(); ok {
			if n > maxDataBlock {
				if _, werr := io.WriteString(conn, "SERVER_ERROR object too large for cache\r\n"); werr != nil {
					break
				}
				// Best effort: skip the oversized payload without buffering it in memory.
				if _, derr := io.CopyN(io.Discard, reader, int64(n)+2); derr != nil {
					break
				}
				h.recordCommand(guid, cmd.raw)
				continue
			}
			if err := drainDataBlock(reader, n); err != nil {
				break
			}
		}

		h.recordCommand(guid, cmd.raw)

		h.logger.Debug().Str("session", guid).Str("command", cmd.name).Msg("command received")

		// Server-authored response override (admin-editable command_responses, scoped to
		// command_type="memcached"), keyed by the raw command line. On a Matched row we
		// write it verbatim; on a miss/error we fall through to the hardcoded defaults so
		// behavior never regresses when the server is unreachable.
		if resp, ok := cmdresp.LookupAndRecord("memcached", cmd.raw, guid); ok {
			if _, werr := io.WriteString(conn, resp); werr != nil {
				break
			}
			continue
		}

		resp, closeConn := defaultResponse(cmd)
		if resp != "" {
			if _, werr := io.WriteString(conn, resp); werr != nil {
				break
			}
		}
		if closeConn {
			break
		}
	}

	h.logger.Info().Str("session", guid).Msg("session ended")
}

// readLine reads one CRLF/LF-terminated command line, rejecting an overlong line.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLineLen {
		return "", io.ErrShortBuffer
	}
	return line, nil
}

// drainDataBlock consumes the n-byte payload plus its trailing CRLF that follows a
// storage command, so it is not mistaken for the next command line.
func drainDataBlock(reader *bufio.Reader, n int) error {
	_, err := io.CopyN(io.Discard, reader, int64(n)+2)
	return err
}

func (h *honeypot) recordCommand(guid, raw string) {
	if raw == "" {
		return
	}
	go func() {
		if err := saveMemcachedCommand(&proto.MemcachedCommandRequest{Guid: guid, Command: raw}); err != nil {
			h.logger.Error().Err(err).Str("session", guid).Msg("failed to persist memcached command")
		}
	}()
}

func (h *honeypot) persistConnect(host, guid string) {
	req := &proto.MemcachedConnectRequest{
		RemoteAddr: host,
		Guid:       guid,
		Protocol:   "ascii",
	}
	if err := saveMemcachedConnect(req); err != nil {
		h.logger.Error().Err(err).Str("session", guid).Msg("failed to persist memcached connect")
	}
}
