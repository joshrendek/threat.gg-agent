package telnet

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/rs/zerolog/log"

	"github.com/joshrendek/threat.gg-agent/persistence"
	pb "github.com/joshrendek/threat.gg-agent/proto"
)

const (
	defaultPort      = "23"
	maxCommands      = 500
	maxLoginAttempts = 3
	connTimeout      = 300 * time.Second
	idleTimeout      = 30 * time.Second
	maxLineLength    = 4096
	banner           = "\r\nBusyBox v1.30.1 () built-in shell (ash)\r\n\r\n"
	hostname         = "device"
)

type honeypot struct {
	port string
}

func New() *honeypot {
	port := os.Getenv("TELNET_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	return &honeypot{port: port}
}

func (h *honeypot) Name() string {
	return "telnet"
}

func (h *honeypot) Start() {
	ln, err := net.Listen("tcp", ":"+h.port)
	if err != nil {
		log.Error().Err(err).Msg("telnet honeypot listen error")
		return
	}
	log.Info().Str("port", h.port).Msg("starting Telnet honeypot")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error().Err(err).Msg("telnet accept error")
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(connTimeout))

	remoteAddr := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remoteAddr)
	if host == "" {
		host = remoteAddr
	}

	guid := uuid.NewV4().String()

	// Send IAC negotiations
	if err := negotiateOptions(conn); err != nil {
		return
	}

	// Small delay to let IAC responses arrive
	time.Sleep(100 * time.Millisecond)

	reader := bufio.NewReaderSize(conn, maxLineLength)

	// Drain any IAC responses from client
	drainIAC(conn, reader)

	// Login loop
	var username, password string
	authenticated := false

	for attempt := 0; attempt < maxLoginAttempts; attempt++ {
		// Send login prompt
		fmt.Fprintf(conn, "%s login: ", hostname)
		conn.SetDeadline(time.Now().Add(idleTimeout))

		userLine, err := readLine(reader)
		if err != nil {
			return
		}
		username = strings.TrimSpace(string(stripIAC([]byte(userLine))))

		// Disable echo for password
		disableEcho(conn)
		fmt.Fprint(conn, "Password: ")
		conn.SetDeadline(time.Now().Add(idleTimeout))

		passLine, err := readLine(reader)
		if err != nil {
			return
		}
		password = strings.TrimSpace(string(stripIAC([]byte(passLine))))

		// Re-enable echo
		enableEcho(conn)
		fmt.Fprint(conn, "\r\n")

		// Accept any non-empty credentials
		if username != "" {
			authenticated = true

			// Persist login
			go persistence.SaveTelnetLogin(&pb.TelnetLoginRequest{
				RemoteAddr: host,
				Guid:       guid,
				Username:   username,
				Password:   password,
			})

			break
		}

		fmt.Fprint(conn, "\r\nLogin incorrect\r\n\r\n")
	}

	if !authenticated {
		return
	}

	// Send banner and prompt
	fmt.Fprint(conn, banner)
	fmt.Fprint(conn, "~ # ")

	// Command loop
	cmdCount := 0
	for cmdCount < maxCommands {
		conn.SetDeadline(time.Now().Add(idleTimeout))

		line, err := readLine(reader)
		if err != nil {
			break
		}

		cleanLine := strings.TrimSpace(string(stripIAC([]byte(line))))
		if cleanLine == "" {
			fmt.Fprint(conn, "~ # ")
			continue
		}

		cmdCount++

		// Persist command
		go persistence.SaveTelnetCommand(&pb.TelnetCommandRequest{
			Guid:    guid,
			Command: cleanLine,
		})

		response, shouldExit := executeCommand(cleanLine)
		if shouldExit {
			return
		}

		if response != "" {
			fmt.Fprint(conn, response)
		}
		fmt.Fprint(conn, "~ # ")
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	var line []byte
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return string(line), err
		}

		// Handle IAC inline
		if b == IAC {
			// Read command byte
			cmd, err := reader.ReadByte()
			if err != nil {
				return string(line), err
			}
			switch cmd {
			case WILL, WONT, DO, DONT:
				reader.ReadByte() // skip option
			case SB:
				// Read until IAC SE
				for {
					sb, err := reader.ReadByte()
					if err != nil {
						return string(line), err
					}
					if sb == IAC {
						se, _ := reader.ReadByte()
						if se == SE {
							break
						}
					}
				}
			}
			continue
		}

		if b == '\n' || b == '\r' {
			// Consume trailing \n after \r if present
			if b == '\r' {
				next, err := reader.Peek(1)
				if err == nil && len(next) > 0 && next[0] == '\n' {
					reader.ReadByte()
				}
			}
			return string(line), nil
		}

		if len(line) < maxLineLength {
			line = append(line, b)
		}
	}
}

// drainIAC reads any pending IAC negotiation responses from the client
func drainIAC(conn net.Conn, reader *bufio.Reader) {
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		if b == IAC {
			cmd, err := reader.ReadByte()
			if err != nil {
				break
			}
			switch cmd {
			case WILL, WONT, DO, DONT:
				reader.ReadByte()
			case SB:
				for {
					sb, err := reader.ReadByte()
					if err != nil {
						return
					}
					if sb == IAC {
						se, _ := reader.ReadByte()
						if se == SE {
							break
						}
					}
				}
			}
		} else {
			reader.UnreadByte()
			break
		}
	}
}
