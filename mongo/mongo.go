package mongo

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort  = "27017"
	idleTimeout  = 30 * time.Second
	totalTimeout = 300 * time.Second
	maxMessages  = 200
)

// Persistence seams — overridable in tests so the listener needs no live gRPC server.
var (
	saveMongoConnect = persistence.SaveMongoConnect
	saveMongoCommand = persistence.SaveMongoCommand
)

// requestCounter feeds the responseTo-independent requestID we stamp on replies.
var requestCounter int32

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "mongodb").Logger()}
}

func (h *honeypot) Name() string {
	return "mongodb"
}

func (h *honeypot) Start() {
	port := os.Getenv("MONGO_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start mongodb listener")
	}
	h.logger.Info().Str("port", port).Msg("starting mongodb honeypot")
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

// session accumulates what we learned across one connection. Credentials and the driver
// version trickle in across separate commands (hello, then saslStart), so we persist the
// connect once at the end with the best values seen.
type session struct {
	guid          string
	remoteIP      string
	username      string
	password      string
	clientVersion string
	commands      []string
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()

	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if host == "" {
		host = conn.RemoteAddr().String()
	}

	sess := &session{guid: uuid.NewV4().String(), remoteIP: host}
	defer h.persistSession(sess)

	h.logger.Info().Str("session", sess.guid).Str("remote", host).Msg("new connection")

	conn.SetDeadline(time.Now().Add(totalTimeout))
	reader := bufio.NewReader(conn)

	for i := 0; i < maxMessages; i++ {
		conn.SetReadDeadline(time.Now().Add(idleTimeout))

		header, payload, err := readMessage(reader)
		if err != nil {
			break
		}

		reply, err := h.dispatch(header, payload, sess)
		if err != nil {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("dispatch error")
			break
		}
		if reply == nil {
			continue
		}
		if _, err := conn.Write(reply); err != nil {
			break
		}
	}

	h.logger.Info().Str("session", sess.guid).Int("commands", len(sess.commands)).Msg("session ended")
}

// dispatch parses one wire message, updates the session, and returns the bytes to write
// back (nil to write nothing). Unknown opcodes end the session.
func (h *honeypot) dispatch(header msgHeader, payload []byte, sess *session) ([]byte, error) {
	replyID := atomic.AddInt32(&requestCounter, 1)

	switch header.opCode {
	case opQuery:
		collection, query, err := parseOpQuery(payload)
		if err != nil {
			return nil, err
		}
		doc, err := decodeDocument(query)
		if err != nil {
			return nil, err
		}
		cmdName := doc.firstKey()
		h.observe(sess, cmdName, collection, doc)
		return buildOpReply(replyID, header.requestID, commandResponse(cmdName, doc)), nil

	case opMsg:
		body, err := parseOpMsg(payload)
		if err != nil {
			return nil, err
		}
		doc, err := decodeDocument(body)
		if err != nil {
			return nil, err
		}
		cmdName := doc.firstKey()
		ns := ""
		if db, ok := doc.lookup("$db"); ok {
			ns = db.str
		}
		h.observe(sess, cmdName, ns, doc)
		return buildOpMsgReply(replyID, header.requestID, commandResponse(cmdName, doc)), nil

	default:
		return nil, errWire
	}
}

// observe records the command and harvests credentials / driver metadata into the session.
func (h *honeypot) observe(sess *session, cmdName, namespace string, doc bsonDocument) {
	label := cmdName
	if namespace != "" {
		label = cmdName + " " + namespace
	}
	sess.commands = append(sess.commands, label)

	if cv := extractClientVersion(doc); cv != "" {
		sess.clientVersion = cv
	}

	switch cmdName {
	case "saslStart", "saslContinue", "authenticate":
		user, pass, _ := extractCredentials(cmdName, doc)
		if user != "" {
			sess.username = user
		}
		if pass != "" {
			sess.password = pass
		}
	}
}

// readMessage reads one complete wire message, validating the declared length so a hostile
// length prefix cannot drive an unbounded allocation.
func readMessage(r *bufio.Reader) (msgHeader, []byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return msgHeader{}, nil, err
	}
	total := int(binary.LittleEndian.Uint32(lenBuf[:]))
	if total < headerLen || total > maxMessageLen {
		return msgHeader{}, nil, errWire
	}
	buf := make([]byte, total)
	copy(buf, lenBuf[:])
	if _, err := io.ReadFull(r, buf[4:]); err != nil {
		return msgHeader{}, nil, err
	}
	header, err := parseHeader(buf[:headerLen])
	if err != nil {
		return msgHeader{}, nil, err
	}
	return header, buf[headerLen:], nil
}

func (h *honeypot) persistSession(sess *session) {
	// A connection to :27017 is itself a scan signal, so record the connect even without
	// captured credentials.
	connectReq := &proto.MongoConnectRequest{
		RemoteAddr:    sess.remoteIP,
		Guid:          sess.guid,
		Username:      sess.username,
		Password:      sess.password,
		ClientVersion: sess.clientVersion,
	}
	if err := saveMongoConnect(connectReq); err != nil {
		h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist mongo connect")
		return
	}

	for _, cmd := range sess.commands {
		if err := saveMongoCommand(&proto.MongoCommandRequest{Guid: sess.guid, Command: cmd}); err != nil {
			h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist mongo command")
		}
	}
}
