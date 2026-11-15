// Package freeswitch serves a bounded SIP persona for observing FreeSWITCH
// MESSAGE exploitation without originating calls, relaying messages, or
// executing any submitted body.
package freeswitch

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog/log"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort    = "5060"
	maxHeaderBytes = 16 << 10
	maxBodyBytes   = 64 << 10
	maxRequests    = 64
	idleTimeout    = 20 * time.Second
)

var saveEvent = persistence.SavePersonaEvent
var saveSem = make(chan struct{}, 64)

type honeypot struct{ port string }

func New() honeypots.Honeypot {
	port := os.Getenv("FREESWITCH_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	return &honeypot{port: port}
}

func (h *honeypot) Name() string { return "freeswitch" }

func (h *honeypot) Start() {
	go h.listenUDP()
	h.listenTCP()
}

func (h *honeypot) listenTCP() {
	listener, err := net.Listen("tcp", ":"+h.port)
	if err != nil {
		log.Error().Err(err).Str("port", h.port).Msg("FreeSWITCH SIP TCP listen error")
		return
	}
	log.Info().Str("port", h.port).Msg("starting FreeSWITCH SIP TCP honeypot")
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Error().Err(err).Msg("FreeSWITCH SIP TCP accept error")
			continue
		}
		go handleTCP(connection)
	}
}

func (h *honeypot) listenUDP() {
	packetConnection, err := net.ListenPacket("udp", ":"+h.port)
	if err != nil {
		log.Error().Err(err).Str("port", h.port).Msg("FreeSWITCH SIP UDP listen error")
		return
	}
	log.Info().Str("port", h.port).Msg("starting FreeSWITCH SIP UDP honeypot")
	buffer := make([]byte, maxHeaderBytes+maxBodyBytes+1)
	for {
		count, address, err := packetConnection.ReadFrom(buffer)
		if err != nil {
			continue
		}
		packet := append([]byte(nil), buffer[:count]...)
		event, response, parseErr := classify(packet, address.String(), 1)
		if parseErr != nil {
			continue
		}
		_, _ = packetConnection.WriteTo([]byte(response), address)
		persist(event)
	}
}

func handleTCP(connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReaderSize(connection, maxHeaderBytes)
	for sequence := 1; sequence <= maxRequests; sequence++ {
		_ = connection.SetDeadline(time.Now().Add(idleTimeout))
		packet, err := readMessage(reader)
		if err != nil {
			return
		}
		event, response, err := classify(packet, connection.RemoteAddr().String(), sequence)
		if err != nil {
			return
		}
		_, _ = io.WriteString(connection, response)
		persist(event)
	}
}

func persist(event *proto.PersonaEventRequest) {
	if event == nil || saveEvent == nil {
		return
	}
	select {
	case saveSem <- struct{}{}:
		go func() {
			defer func() { <-saveSem }()
			if err := saveEvent(event); err != nil {
				log.Error().Err(err).Msg("failed to save FreeSWITCH SIP event")
			}
		}()
	default:
		// Keep the unauthenticated protocol surface responsive if telemetry is
		// unavailable; never create an unbounded persistence queue.
	}
}

func readMessage(reader *bufio.Reader) ([]byte, error) {
	var header bytes.Buffer
	for header.Len() <= maxHeaderBytes {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) || header.Len()+len(line) > maxHeaderBytes {
			return nil, errors.New("SIP headers exceed limit")
		}
		header.Write(line)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}
	_, headers, err := parseHeader(header.Bytes())
	if err != nil {
		return nil, err
	}
	length := 0
	if value := firstHeader(headers, "content-length", "l"); value != "" {
		length, err = strconv.Atoi(strings.TrimSpace(value))
		if err != nil || length < 0 || length > maxBodyBytes {
			return nil, errors.New("invalid SIP content length")
		}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return append(header.Bytes(), body...), nil
}

func classify(packet []byte, remote string, sequence int) (*proto.PersonaEventRequest, string, error) {
	if len(packet) > maxHeaderBytes+maxBodyBytes {
		return nil, "", errors.New("SIP packet exceeds limit")
	}
	start, headers, err := parseHeader(packet)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Fields(start)
	if len(parts) < 3 {
		return nil, "", errors.New("invalid SIP request line")
	}
	method := strings.ToUpper(parts[0])
	if method != "OPTIONS" && method != "REGISTER" && method != "MESSAGE" {
		method = "UNKNOWN"
	}
	body := messageBody(packet)
	if len(body) > maxBodyBytes {
		return nil, "", errors.New("SIP body exceeds limit")
	}
	selector := toSelector(firstHeader(headers, "to", "t"))
	callID := firstHeader(headers, "call-id", "i")
	cseqNumber, cseqMethod := parseCSeq(firstHeader(headers, "cseq"))
	headerNames := make([]string, 0, len(headers))
	for name := range headers {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	bodyHash := sha256.Sum256(body)
	callHash := sha256.Sum256([]byte(callID))
	sessionHash := sha256.Sum256([]byte(remoteHost(remote) + "\x00" + callID))
	action, cve, status := "sip_"+strings.ToLower(method), "", 200
	if method == "REGISTER" {
		status = 401
	}
	if method == "MESSAGE" {
		status = 202
		if selector == "api_plus" {
			action, cve, status = "sip_message_api_selector", "CVE-2026-116779", 403
		}
	}
	metadata := map[string]string{
		"transport_sequence":  strconv.Itoa(sequence),
		"to_selector":         selector,
		"auth_header_present": strconv.FormatBool(firstHeader(headers, "authorization", "proxy-authorization") != ""),
		"header_names":        bounded(strings.Join(headerNames, ","), 1024),
		"header_count":        strconv.Itoa(len(headerNames)),
		"body_size":           strconv.Itoa(len(body)),
		"body_sha256":         hex.EncodeToString(bodyHash[:]),
		"call_id_sha256":      hex.EncodeToString(callHash[:]),
		"cseq_number":         bounded(cseqNumber, 20),
		"cseq_method":         bounded(cseqMethod, 16),
		"content_type":        bounded(strings.ToLower(firstHeader(headers, "content-type", "c")), 96),
	}
	event := &proto.PersonaEventRequest{
		RemoteAddr: remoteHost(remote), Guid: uuid.NewV4().String(), SessionId: hex.EncodeToString(sessionHash[:12]),
		Persona: "freeswitch", Family: "freeswitch-sip", Version: "FreeSWITCH 1.10.12", Action: action,
		Method: method, Path: "sip:" + selector, AuthBypass: cve != "", Cve: cve,
		Evidence: bounded(structuralEvidence(metadata), 1024), StatusCode: int32(status), Metadata: metadata,
	}
	return event, response(status, headers), nil
}

func parseHeader(packet []byte) (string, map[string][]string, error) {
	headerEnd := bytes.Index(packet, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(packet, []byte("\n\n"))
	}
	if headerEnd < 0 || headerEnd > maxHeaderBytes {
		return "", nil, errors.New("unterminated SIP headers")
	}
	lines := strings.Split(strings.ReplaceAll(string(packet[:headerEnd]), "\r\n", "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", nil, errors.New("missing SIP request line")
	}
	headers := map[string][]string{}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || len(name) > 64 || len(value) > 4096 {
			continue
		}
		headers[name] = append(headers[name], strings.TrimSpace(value))
	}
	return lines[0], headers, nil
}

func messageBody(packet []byte) []byte {
	if index := bytes.Index(packet, []byte("\r\n\r\n")); index >= 0 {
		return packet[index+4:]
	}
	if index := bytes.Index(packet, []byte("\n\n")); index >= 0 {
		return packet[index+2:]
	}
	return nil
}

func firstHeader(headers map[string][]string, names ...string) string {
	for _, name := range names {
		if values := headers[name]; len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func toSelector(value string) string {
	lower := strings.ToLower(value)
	if index := strings.Index(lower, "sip:"); index >= 0 {
		user := lower[index+4:]
		if end := strings.IndexAny(user, "@;> "); end >= 0 {
			user = user[:end]
		}
		if user == "api" {
			return "api"
		}
		if strings.HasPrefix(user, "api+") {
			return "api_plus"
		}
		if user != "" {
			return "ordinary_user"
		}
	}
	return "unknown"
}

func parseCSeq(value string) (string, string) {
	parts := strings.Fields(value)
	if len(parts) > 1 {
		for _, char := range parts[0] {
			if char < '0' || char > '9' {
				return "", ""
			}
		}
		method := strings.ToUpper(parts[1])
		if method != "OPTIONS" && method != "REGISTER" && method != "MESSAGE" {
			method = "UNKNOWN"
		}
		return parts[0], method
	}
	return "", ""
}

func response(status int, headers map[string][]string) string {
	reason := map[int]string{200: "OK", 202: "Accepted", 401: "Unauthorized", 403: "Forbidden"}[status]
	var builder strings.Builder
	fmt.Fprintf(&builder, "SIP/2.0 %d %s\r\n", status, reason)
	for _, name := range []string{"via", "from", "to", "call-id", "cseq"} {
		if value := firstHeader(headers, name); value != "" {
			fmt.Fprintf(&builder, "%s: %s\r\n", canonicalHeader(name), boundedHeader(value))
		}
	}
	if status == 401 {
		builder.WriteString("WWW-Authenticate: Digest realm=\"freeswitch\", nonce=\"synthetic\"\r\n")
	}
	builder.WriteString("Server: FreeSWITCH-mod_sofia/1.10.12\r\nContent-Length: 0\r\n\r\n")
	return builder.String()
}

func canonicalHeader(name string) string {
	if name == "call-id" {
		return "Call-ID"
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

func boundedHeader(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, value)
	return bounded(value, 1024)
}

func remoteHost(address string) string {
	if host, _, err := net.SplitHostPort(address); err == nil {
		return bounded(host, 128)
	}
	return bounded(address, 128)
}

func structuralEvidence(metadata map[string]string) string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+metadata[key])
	}
	return strings.Join(parts, " ")
}

func bounded(value string, limit int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
