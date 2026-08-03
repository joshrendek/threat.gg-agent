// Package amqp emulates a bounded RabbitMQ-compatible AMQP 0-9-1 server.
package amqp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort       = "5672"
	frameEnd          = 0xce
	maxFrameBytes     = 128 << 10
	maxOperations     = 128
	maxBodyCapture    = 32 << 10
	maxConnections    = 128
	idleTimeout       = 45 * time.Second
	connectionTimeout = 5 * time.Minute
)

var saveSession = persistence.SaveAmqpSession
var connectionSlots = make(chan struct{}, maxConnections)
var persistenceSlots = make(chan struct{}, 32)

type honeypot struct{ logger zerolog.Logger }

// New constructs the AMQP honeypot.
func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "amqp").Logger()}
}
func (h *honeypot) Name() string { return "amqp" }
func (h *honeypot) Start() {
	port := os.Getenv("AMQP_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start AMQP listener")
	}
	h.logger.Info().Str("port", port).Msg("starting AMQP honeypot")
	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("AMQP accept failed")
			continue
		}
		select {
		case connectionSlots <- struct{}{}:
			go func() { defer func() { <-connectionSlots }(); h.handleConnection(conn) }()
		default:
			_ = conn.Close()
		}
	}
}

type session struct {
	guid, remote, protocol, username, password, vhost string
	properties                                        map[string]string
	operations                                        []string
	publishes                                         map[uint16]*publish
	confirms                                          map[uint16]bool
	deliveryTag                                       uint64
}
type publish struct {
	exchange, routingKey string
	size                 uint64
	body                 []byte
	received             uint64
}
type frame struct {
	typeID  byte
	channel uint16
	payload []byte
}

func (h *honeypot) handleConnection(conn net.Conn) {
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	s := &session{guid: uuid.NewV4().String(), remote: host, properties: make(map[string]string), publishes: make(map[uint16]*publish), confirms: make(map[uint16]bool)}
	defer persist(s)
	_ = conn.SetDeadline(time.Now().Add(connectionTimeout))
	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	switch string(header) {
	case "AMQP\x00\x00\x09\x01":
		s.protocol = "AMQP 0-9-1"
	case "AMQP\x00\x01\x00\x00":
		s.protocol = "AMQP 1.0"
		s.addOperation("PROTOCOL AMQP_1_0_UNSUPPORTED")
		_, _ = conn.Write([]byte("AMQP\x00\x00\x09\x01"))
		return
	default:
		return
	}
	if err := writeMethod(conn, 0, 10, 10, connectionStart()); err != nil {
		return
	}
	for i := 0; i < 512; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		f, err := readFrame(conn)
		if err != nil {
			return
		}
		if f.typeID == 8 {
			_ = writeFrame(conn, frame{typeID: 8})
			continue
		}
		if f.typeID == 2 {
			if s.handleContentHeader(f) && s.confirms[f.channel] {
				s.deliveryTag++
				_ = writeMethod(conn, f.channel, 60, 80, append(appendUint64(nil, s.deliveryTag), 0))
			}
			continue
		}
		if f.typeID == 3 {
			if complete := s.handleContentBody(f); complete && s.confirms[f.channel] {
				s.deliveryTag++
				_ = writeMethod(conn, f.channel, 60, 80, append(appendUint64(nil, s.deliveryTag), 0))
			}
			continue
		}
		if f.typeID != 1 || len(f.payload) < 4 {
			return
		}
		classID, methodID := binary.BigEndian.Uint16(f.payload[:2]), binary.BigEndian.Uint16(f.payload[2:4])
		args := f.payload[4:]
		if !s.handleMethod(conn, f.channel, classID, methodID, args) {
			return
		}
	}
}

func (s *session) handleMethod(conn net.Conn, channel, classID, methodID uint16, args []byte) bool {
	switch {
	case classID == 10 && methodID == 11: // Connection.StartOk
		props, mechanism, response, err := parseStartOK(args)
		if err != nil {
			return false
		}
		s.properties = props
		s.username, s.password = parseSASL(mechanism, response)
		s.addOperation("CONNECTION_START_OK mechanism=" + bounded(mechanism, 32))
		return writeMethod(conn, 0, 10, 30, connectionTune()) == nil
	case classID == 10 && methodID == 31: // Connection.TuneOk
		return true
	case classID == 10 && methodID == 40: // Connection.Open
		vhost, _, err := readShortString(args)
		if err != nil {
			return false
		}
		s.vhost = bounded(vhost, 1024)
		s.addOperation("CONNECTION_OPEN vhost=" + quote(s.vhost))
		return writeMethod(conn, 0, 10, 41, []byte{0}) == nil
	case classID == 10 && methodID == 50: // Connection.Close
		_ = writeMethod(conn, 0, 10, 51, nil)
		return false
	case classID == 20 && methodID == 10: // Channel.Open
		s.addOperation(fmt.Sprintf("CHANNEL_OPEN channel=%d", channel))
		return writeMethod(conn, channel, 20, 11, []byte{0, 0, 0, 0}) == nil
	case classID == 20 && methodID == 40: // Channel.Close
		return writeMethod(conn, channel, 20, 41, nil) == nil
	case classID == 40 && methodID == 10: // Exchange.Declare
		exchange, kind, err := parseExchangeDeclare(args)
		if err != nil {
			return false
		}
		s.addOperation("EXCHANGE_DECLARE exchange=" + quote(exchange) + " type=" + quote(kind))
		return writeMethod(conn, channel, 40, 11, nil) == nil
	case classID == 50 && methodID == 10: // Queue.Declare
		queue, err := parseQueueDeclare(args)
		if err != nil {
			return false
		}
		if queue == "" {
			queue = "amq.gen-" + s.guid[:12]
		}
		s.addOperation("QUEUE_DECLARE queue=" + quote(queue))
		var out []byte
		out = appendShortString(out, queue)
		out = append(out, make([]byte, 8)...)
		return writeMethod(conn, channel, 50, 11, out) == nil
	case classID == 50 && methodID == 20: // Queue.Bind
		queue, exchange, routing, err := parseQueueBind(args)
		if err != nil {
			return false
		}
		s.addOperation("QUEUE_BIND queue=" + quote(queue) + " exchange=" + quote(exchange) + " routing_key=" + quote(routing))
		return writeMethod(conn, channel, 50, 21, nil) == nil
	case classID == 60 && methodID == 10: // Basic.Qos
		return writeMethod(conn, channel, 60, 11, nil) == nil
	case classID == 60 && methodID == 20: // Basic.Consume
		queue, tag, err := parseBasicConsume(args)
		if err != nil {
			return false
		}
		if tag == "" {
			tag = "amq.ctag-" + s.guid[:12]
		}
		s.addOperation("BASIC_CONSUME queue=" + quote(queue) + " consumer_tag=" + quote(tag))
		return writeMethod(conn, channel, 60, 21, appendShortString(nil, tag)) == nil
	case classID == 60 && methodID == 40: // Basic.Publish
		exchange, routing, err := parseBasicPublish(args)
		if err != nil {
			return false
		}
		s.publishes[channel] = &publish{exchange: exchange, routingKey: routing}
		return true
	case classID == 85 && methodID == 10: // Confirm.Select
		s.addOperation(fmt.Sprintf("CONFIRM_SELECT channel=%d", channel))
		s.confirms[channel] = true
		return writeMethod(conn, channel, 85, 11, nil) == nil
	default:
		s.addOperation(fmt.Sprintf("METHOD class=%d method=%d channel=%d", classID, methodID, channel))
		return true
	}
}

func (s *session) handleContentHeader(f frame) bool {
	p := s.publishes[f.channel]
	if p == nil || len(f.payload) < 12 || binary.BigEndian.Uint16(f.payload[:2]) != 60 {
		return false
	}
	p.size = binary.BigEndian.Uint64(f.payload[4:12])
	if p.size == 0 {
		s.finishPublish(f.channel)
		return true
	}
	return false
}
func (s *session) handleContentBody(f frame) bool {
	p := s.publishes[f.channel]
	if p == nil {
		return false
	}
	remaining := maxBodyCapture - len(p.body)
	if remaining > 0 {
		if remaining > len(f.payload) {
			remaining = len(f.payload)
		}
		p.body = append(p.body, f.payload[:remaining]...)
	}
	p.received += uint64(len(f.payload))
	if p.received >= p.size {
		s.finishPublish(f.channel)
		return true
	}
	return false
}
func (s *session) finishPublish(channel uint16) {
	p := s.publishes[channel]
	if p == nil {
		return
	}
	s.addOperation("BASIC_PUBLISH exchange=" + quote(p.exchange) + " routing_key=" + quote(p.routingKey) +
		" body_base64=" + base64.StdEncoding.EncodeToString(p.body))
	delete(s.publishes, channel)
}
func (s *session) addOperation(value string) {
	if len(s.operations) < maxOperations {
		s.operations = append(s.operations, bounded(value, 8192))
	}
}

func persist(s *session) {
	if s.protocol == "" {
		return
	}
	in := &pb.AmqpSessionRequest{RemoteAddr: bounded(s.remote, 128), Guid: s.guid, Username: bounded(s.username, 1024),
		Password: bounded(s.password, 4096), Vhost: bounded(s.vhost, 1024), Protocol: s.protocol,
		ClientProperties: boundedProperties(s.properties), Operations: append([]string(nil), s.operations...)}
	slots := persistenceSlots
	select {
	case slots <- struct{}{}:
		save := saveSession
		go func() { defer func() { <-slots }(); _ = save(in) }()
	default:
	}
}

func boundedProperties(in map[string]string) map[string]string {
	out := make(map[string]string)
	for _, key := range []string{"product", "version", "platform", "information", "connection_name"} {
		if value := in[key]; value != "" && len(out) < 32 {
			out[key] = bounded(value, 1024)
		}
	}
	return out
}

func readFrame(r io.Reader) (frame, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return frame{}, err
	}
	size := binary.BigEndian.Uint32(header[3:])
	if size > maxFrameBytes {
		return frame{}, errors.New("AMQP frame is too large")
	}
	payload := make([]byte, int(size)+1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return frame{}, err
	}
	if payload[len(payload)-1] != frameEnd {
		return frame{}, errors.New("invalid AMQP frame terminator")
	}
	return frame{typeID: header[0], channel: binary.BigEndian.Uint16(header[1:3]), payload: payload[:len(payload)-1]}, nil
}
func writeFrame(w io.Writer, f frame) error {
	if len(f.payload) > maxFrameBytes {
		return errors.New("AMQP frame is too large")
	}
	header := make([]byte, 7)
	header[0] = f.typeID
	binary.BigEndian.PutUint16(header[1:3], f.channel)
	binary.BigEndian.PutUint32(header[3:], uint32(len(f.payload)))
	_, err := w.Write(append(append(header, f.payload...), frameEnd))
	return err
}
func writeMethod(w io.Writer, channel, classID, methodID uint16, args []byte) error {
	payload := make([]byte, 4, 4+len(args))
	binary.BigEndian.PutUint16(payload[:2], classID)
	binary.BigEndian.PutUint16(payload[2:4], methodID)
	payload = append(payload, args...)
	return writeFrame(w, frame{typeID: 1, channel: channel, payload: payload})
}
func connectionStart() []byte {
	out := []byte{0, 9, 0, 0, 0, 0}
	out = appendLongString(out, "PLAIN AMQPLAIN")
	out = appendLongString(out, "en_US")
	return out
}
func connectionTune() []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint16(out[:2], 2047)
	binary.BigEndian.PutUint32(out[2:6], maxFrameBytes)
	binary.BigEndian.PutUint16(out[6:], 30)
	return out
}

func parseStartOK(data []byte) (map[string]string, string, []byte, error) {
	props, rest, err := parseTable(data)
	if err != nil {
		return nil, "", nil, err
	}
	mechanism, rest, err := readShortString(rest)
	if err != nil {
		return nil, "", nil, err
	}
	response, rest, err := readLongBytes(rest)
	if err != nil {
		return nil, "", nil, err
	}
	_, _, err = readShortString(rest)
	return props, mechanism, response, err
}
func parseSASL(mechanism string, response []byte) (string, string) {
	if mechanism == "PLAIN" {
		parts := bytes.Split(response, []byte{0})
		if len(parts) >= 3 {
			return bounded(string(parts[len(parts)-2]), 1024), bounded(string(parts[len(parts)-1]), 4096)
		}
	}
	if mechanism == "AMQPLAIN" {
		values, _, err := parseTable(response)
		if err == nil {
			return bounded(values["LOGIN"], 1024), bounded(values["PASSWORD"], 4096)
		}
	}
	return "", ""
}

func parseExchangeDeclare(data []byte) (string, string, error) {
	if len(data) < 2 {
		return "", "", io.ErrUnexpectedEOF
	}
	exchange, rest, err := readShortString(data[2:])
	if err != nil {
		return "", "", err
	}
	kind, _, err := readShortString(rest)
	return bounded(exchange, 255), bounded(kind, 255), err
}
func parseQueueDeclare(data []byte) (string, error) {
	if len(data) < 2 {
		return "", io.ErrUnexpectedEOF
	}
	queue, _, err := readShortString(data[2:])
	return bounded(queue, 255), err
}
func parseQueueBind(data []byte) (string, string, string, error) {
	if len(data) < 2 {
		return "", "", "", io.ErrUnexpectedEOF
	}
	queue, rest, err := readShortString(data[2:])
	if err != nil {
		return "", "", "", err
	}
	exchange, rest, err := readShortString(rest)
	if err != nil {
		return "", "", "", err
	}
	routing, _, err := readShortString(rest)
	return bounded(queue, 255), bounded(exchange, 255), bounded(routing, 255), err
}
func parseBasicConsume(data []byte) (string, string, error) {
	if len(data) < 2 {
		return "", "", io.ErrUnexpectedEOF
	}
	queue, rest, err := readShortString(data[2:])
	if err != nil {
		return "", "", err
	}
	tag, _, err := readShortString(rest)
	return bounded(queue, 255), bounded(tag, 255), err
}
func parseBasicPublish(data []byte) (string, string, error) {
	if len(data) < 2 {
		return "", "", io.ErrUnexpectedEOF
	}
	exchange, rest, err := readShortString(data[2:])
	if err != nil {
		return "", "", err
	}
	routing, _, err := readShortString(rest)
	return bounded(exchange, 255), bounded(routing, 255), err
}

func parseTable(data []byte) (map[string]string, []byte, error) {
	if len(data) < 4 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	if n > len(data)-4 || n > 64<<10 {
		return nil, nil, errors.New("invalid AMQP field table")
	}
	fieldData, rest := data[4:4+n], data[4+n:]
	out := make(map[string]string)
	for len(fieldData) > 0 {
		key, tail, err := readShortString(fieldData)
		if err != nil || len(tail) < 1 {
			return nil, nil, errors.New("invalid AMQP table field")
		}
		typeID := tail[0]
		tail = tail[1:]
		var value string
		switch typeID {
		case 'S':
			b, next, err := readLongBytes(tail)
			if err != nil {
				return nil, nil, err
			}
			value, tail = string(b), next
		case 't':
			if len(tail) < 1 {
				return nil, nil, io.ErrUnexpectedEOF
			}
			value = strconv.FormatBool(tail[0] != 0)
			tail = tail[1:]
		case 'I':
			if len(tail) < 4 {
				return nil, nil, io.ErrUnexpectedEOF
			}
			value = strconv.FormatInt(int64(int32(binary.BigEndian.Uint32(tail))), 10)
			tail = tail[4:]
		case 'F':
			nested, next, err := parseTable(tail)
			if err != nil {
				return nil, nil, err
			}
			value = fmt.Sprint(nested)
			tail = next
		default:
			return nil, nil, fmt.Errorf("unsupported AMQP table type %q", typeID)
		}
		if len(out) < 32 {
			out[bounded(key, 128)] = bounded(value, 1024)
		}
		fieldData = tail
	}
	return out, rest, nil
}
func readShortString(data []byte) (string, []byte, error) {
	if len(data) < 1 {
		return "", nil, io.ErrUnexpectedEOF
	}
	n := int(data[0])
	if n > len(data)-1 {
		return "", nil, io.ErrUnexpectedEOF
	}
	return string(data[1 : 1+n]), data[1+n:], nil
}
func readLongBytes(data []byte) ([]byte, []byte, error) {
	if len(data) < 4 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	if n > len(data)-4 || n > maxFrameBytes {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return data[4 : 4+n], data[4+n:], nil
}
func appendShortString(out []byte, value string) []byte {
	value = bounded(value, 255)
	return append(append(out, byte(len(value))), value...)
}
func appendLongString(out []byte, value string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(value)))
	return append(append(out, n[:]...), value...)
}
func appendUint64(out []byte, value uint64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], value)
	return append(out, n[:]...)
}
func bounded(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
func quote(value string) string {
	return strconv.Quote(bounded(strings.ToValidUTF8(value, "�"), 1024))
}
