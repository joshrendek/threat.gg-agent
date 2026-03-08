package smtp

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
	defaultPort           = "25"
	defaultSubmissionPort = "587"
	connTimeout           = 300 * time.Second
	idleTimeout           = 30 * time.Second
	maxRecipients         = 50
	maxBodySize           = 10 * 1024 * 1024 // 10MB
	maxCommands           = 100
	smtpHostname          = "mail.corp.com"
	banner                = "220 mail.corp.com ESMTP Postfix (Ubuntu)"
)

type smtpState int

const (
	stateInit smtpState = iota
	stateGreeted
	stateAuthUser
	stateAuthPass
	stateMailFrom
	stateRcptTo
	stateData
)

type emailCapture struct {
	mailFrom string
	rcptTo   []string
	body     string
	subject  string
}

type session struct {
	guid       string
	remoteIP   string
	state      smtpState
	ehloDomain string
	username   string
	password   string
	authMethod string
	mailFrom   string
	rcptTo     []string
	emails     []emailCapture
	cmdCount   int
}

type honeypot struct {
	ports []string
}

func New() *honeypot {
	var ports []string
	port := os.Getenv("SMTP_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	if port != "" {
		ports = append(ports, port)
	}

	subPort := os.Getenv("SMTP_HONEYPOT_SUBMISSION_PORT")
	if subPort == "" {
		subPort = defaultSubmissionPort
	}
	if subPort != "" {
		ports = append(ports, subPort)
	}

	return &honeypot{ports: ports}
}

func (h *honeypot) Name() string {
	return "smtp"
}

func (h *honeypot) Start() {
	for _, port := range h.ports {
		go h.listenOnPort(port)
	}
	select {}
}

func (h *honeypot) listenOnPort(port string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Error().Err(err).Str("port", port).Msg("smtp honeypot listen error")
		return
	}
	log.Info().Str("port", port).Msg("starting SMTP honeypot")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Error().Err(err).Msg("smtp accept error")
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

	sess := &session{
		guid:     uuid.NewV4().String(),
		remoteIP: host,
		state:    stateInit,
	}

	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	writeLine(writer, banner)

	for sess.cmdCount < maxCommands {
		conn.SetDeadline(time.Now().Add(idleTimeout))

		if sess.state == stateData {
			body := readBody(reader)
			if len(body) > maxBodySize {
				body = body[:maxBodySize]
			}

			subject := extractSubject(body)
			sess.emails = append(sess.emails, emailCapture{
				mailFrom: sess.mailFrom,
				rcptTo:   append([]string{}, sess.rcptTo...),
				body:     body,
				subject:  subject,
			})

			writeLine(writer, "250 OK")
			sess.state = stateGreeted
			sess.mailFrom = ""
			sess.rcptTo = nil
			continue
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		sess.cmdCount++

		cmd, args := parseCommand(line)

		switch cmd {
		case "EHLO":
			sess.ehloDomain = args
			sess.state = stateGreeted
			writeLine(writer, buildEhloResponse(smtpHostname))

		case "HELO":
			sess.ehloDomain = args
			sess.state = stateGreeted
			writeLine(writer, "250 OK")

		case "AUTH":
			parts := strings.SplitN(args, " ", 2)
			method := strings.ToUpper(parts[0])
			switch method {
			case "LOGIN":
				sess.authMethod = "LOGIN"
				writeLine(writer, "334 VXNlcm5hbWU6") // base64 "Username:"
				sess.state = stateAuthUser
			case "PLAIN":
				sess.authMethod = "PLAIN"
				if len(parts) > 1 {
					user, pass := decodeAuthPlain(parts[1])
					sess.username = user
					sess.password = pass
					writeLine(writer, "235 Authentication successful")
					sess.state = stateGreeted
				} else {
					writeLine(writer, "334")
					sess.state = stateAuthUser
				}
			default:
				writeLine(writer, "504 Unrecognized authentication type")
			}

		case "MAIL":
			sess.mailFrom = parseAddress(args)
			sess.rcptTo = nil
			sess.state = stateMailFrom
			writeLine(writer, "250 OK")

		case "RCPT":
			if len(sess.rcptTo) >= maxRecipients {
				writeLine(writer, "452 Too many recipients")
			} else {
				sess.rcptTo = append(sess.rcptTo, parseAddress(args))
				sess.state = stateRcptTo
				writeLine(writer, "250 OK")
			}

		case "DATA":
			writeLine(writer, "354 Start mail input; end with <CRLF>.<CRLF>")
			sess.state = stateData

		case "VRFY":
			writeLine(writer, "252 Cannot VRFY user")

		case "EXPN":
			writeLine(writer, "252 Cannot EXPN")

		case "STARTTLS":
			writeLine(writer, "220 Ready to start TLS")
			return // close connection — no real TLS

		case "RSET":
			sess.mailFrom = ""
			sess.rcptTo = nil
			if sess.state > stateGreeted {
				sess.state = stateGreeted
			}
			writeLine(writer, "250 OK")

		case "NOOP":
			writeLine(writer, "250 OK")

		case "QUIT":
			writeLine(writer, "221 Bye")
			persistSession(sess)
			return

		default:
			if sess.state == stateAuthUser {
				sess.username = decodeAuthLogin(strings.TrimSpace(line))
				writeLine(writer, "334 UGFzc3dvcmQ6") // base64 "Password:"
				sess.state = stateAuthPass
			} else if sess.state == stateAuthPass {
				sess.password = decodeAuthLogin(strings.TrimSpace(line))
				writeLine(writer, "235 Authentication successful")
				sess.state = stateGreeted
			} else {
				writeLine(writer, "502 Command not implemented")
			}
		}
	}

	persistSession(sess)
}

func readBody(reader *bufio.Reader) string {
	var body strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			break
		}
		// Dot-stuffing: line starting with ".." should be de-stuffed to "."
		if strings.HasPrefix(trimmed, "..") {
			line = line[1:]
		}
		if body.Len()+len(line) > maxBodySize {
			body.WriteString(line[:maxBodySize-body.Len()])
			break
		}
		body.WriteString(line)
	}
	return body.String()
}

func writeLine(writer *bufio.Writer, line string) {
	fmt.Fprintf(writer, "%s\r\n", line)
	writer.Flush()
}

func persistSession(sess *session) {
	go persistence.SaveSmtpLogin(&pb.SmtpLoginRequest{
		RemoteAddr: sess.remoteIP,
		Guid:       sess.guid,
		EhloDomain: sess.ehloDomain,
		Username:   sess.username,
		Password:   sess.password,
		AuthMethod: sess.authMethod,
	})

	for _, email := range sess.emails {
		go persistence.SaveSmtpEmail(&pb.SmtpEmailRequest{
			Guid:     sess.guid,
			MailFrom: email.mailFrom,
			RcptTo:   email.rcptTo,
			Body:     truncateString(email.body, 10*1024),
			Subject:  email.subject,
		})
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
