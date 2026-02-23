package kafka

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "kafka").Logger()}
}

func (h *honeypot) Name() string {
	return "kafka"
}

func (h *honeypot) Start() {
	port := os.Getenv("KAFKA_PORT")
	if port == "" {
		port = "9092"
	}

	addr := ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start kafka listener")
	}
	h.logger.Info().Str("addr", addr).Msg("starting kafka honeypot")

	for {
		conn, err := listener.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("accept error")
			continue
		}
		go h.handleConnection(conn)
	}
}

// session tracks state for a single attacker connection.
type session struct {
	guid     string
	clientID string
	username string
	password string
	remoteIP string
	requests []apiRequestLog
}

// apiRequestLog captures one Kafka API request for persistence.
type apiRequestLog struct {
	ApiKeyName string `json:"api_key"`
	ApiKey     int16  `json:"api_key_num"`
	ApiVersion int16  `json:"api_version"`
	Details    any    `json:"details,omitempty"`
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

	conn.SetDeadline(time.Now().Add(60 * time.Second))

	for i := 0; i < 100; i++ { // max 100 requests per connection
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		hdr, body, err := readRequest(conn)
		if err != nil {
			break
		}

		if sess.clientID == "" && hdr.ClientID != "" {
			sess.clientID = hdr.ClientID
		}

		h.logger.Debug().
			Str("session", sess.guid).
			Str("api_key", apiKeyName(hdr.ApiKey)).
			Int16("version", hdr.ApiVersion).
			Str("client_id", hdr.ClientID).
			Msg("request")

		var respPayload []byte
		var reqLog apiRequestLog

		switch hdr.ApiKey {
		case apiApiVersions:
			// ApiVersions v3+ uses flexible encoding in the body (compact arrays + tagged fields)
			// but ALWAYS uses response header v0 (no tagged fields in header) for backward compat.
			if hdr.ApiVersion >= 3 {
				respPayload = buildApiVersionsV3Response()
			} else {
				respPayload = buildApiVersionsResponse()
			}
			reqLog = apiRequestLog{ApiKeyName: "ApiVersions", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion}

		case apiMetadata:
			respPayload = buildMetadataResponse()
			topics := parseMetadataTopics(body)
			reqLog = apiRequestLog{ApiKeyName: "Metadata", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion,
				Details: map[string]any{"requested_topics": topics}}

		case apiProduce:
			respPayload = buildProduceResponse(body)
			topic, msgCount, msgSize := parseProduceInfo(body)
			reqLog = apiRequestLog{ApiKeyName: "Produce", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion,
				Details: map[string]any{"topic": topic, "message_count": msgCount, "message_size": msgSize}}

		case apiFetch:
			respPayload = buildFetchResponse()
			topic, partition := parseFetchInfo(body)
			reqLog = apiRequestLog{ApiKeyName: "Fetch", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion,
				Details: map[string]any{"topic": topic, "partition": partition}}

		case apiListOffsets:
			respPayload = buildListOffsetsResponse()
			reqLog = apiRequestLog{ApiKeyName: "ListOffsets", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion}

		case apiFindCoordinator:
			respPayload = buildFindCoordinatorResponse()
			reqLog = apiRequestLog{ApiKeyName: "FindCoordinator", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion}

		case apiSaslHandshake:
			respPayload = buildSaslHandshakeResponse()
			reqLog = apiRequestLog{ApiKeyName: "SaslHandshake", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion}

		case apiSaslAuthenticate:
			user, pass := parseSaslPlain(body)
			sess.username = user
			sess.password = pass
			respPayload = buildSaslAuthenticateResponse()
			reqLog = apiRequestLog{ApiKeyName: "SaslAuthenticate", ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion,
				Details: map[string]any{"username": user}}
			h.logger.Info().
				Str("session", sess.guid).
				Str("username", user).
				Msg("SASL auth attempt")

		default:
			// Unknown API key — return an error response (UNSUPPORTED_VERSION)
			respPayload = []byte{0, 35} // error_code 35 = UNSUPPORTED_VERSION
			reqLog = apiRequestLog{ApiKeyName: fmt.Sprintf("Unknown(%d)", hdr.ApiKey), ApiKey: hdr.ApiKey, ApiVersion: hdr.ApiVersion}
		}

		sess.requests = append(sess.requests, reqLog)

		if err := writeResponse(conn, hdr.CorrelationID, respPayload); err != nil {
			break
		}
	}

	h.logger.Info().
		Str("session", sess.guid).
		Int("requests", len(sess.requests)).
		Msg("session ended")

	// Persist asynchronously
	go h.persistSession(sess)
}

func (h *honeypot) persistSession(sess *session) {
	if len(sess.requests) == 0 {
		return
	}

	// Create attacker record
	req := &proto.KafkaRequest{
		RemoteAddr: sess.remoteIP,
		Guid:       sess.guid,
		Username:   sess.username,
		Password:   sess.password,
		ClientId:   sess.clientID,
	}
	if err := persistence.SaveKafkaConnect(req); err != nil {
		h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist kafka connect")
		return
	}

	// Create attacker_command records for each API request
	for _, r := range sess.requests {
		data, _ := json.Marshal(r)
		apiReq := &proto.KafkaApiRequest{
			Guid:       sess.guid,
			ApiKeyName: r.ApiKeyName,
			Data:       string(data),
		}
		if err := persistence.SaveKafkaApiRequest(apiReq); err != nil {
			h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist kafka api request")
		}
	}
}

// parseMetadataTopics extracts topic names from a Metadata request body.
func parseMetadataTopics(body []byte) []string {
	if len(body) < 4 {
		return []string{"(all topics)"}
	}
	count := int32(binary.BigEndian.Uint32(body[0:4]))
	if count <= 0 {
		return []string{"(all topics)"}
	}
	offset := 4
	var topics []string
	for i := int32(0); i < count && offset+2 <= len(body); i++ {
		tLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if tLen > 0 && offset+tLen <= len(body) {
			topics = append(topics, string(body[offset:offset+tLen]))
			offset += tLen
		}
	}
	if len(topics) == 0 {
		return []string{"(all topics)"}
	}
	return topics
}

// parseProduceInfo extracts basic info from a Produce request body.
func parseProduceInfo(body []byte) (topic string, msgCount, msgSize int) {
	// v0-v2: acks(2) + timeout(4) + topics_count(4) + topic_string + ...
	if len(body) < 10 {
		return "unknown", 0, 0
	}
	offset := 6 // skip acks + timeout
	if offset+4 > len(body) {
		return "unknown", 0, 0
	}
	offset += 4 // skip array count
	if offset+2 > len(body) {
		return "unknown", 0, 0
	}
	tLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if tLen > 0 && offset+tLen <= len(body) {
		topic = string(body[offset : offset+tLen])
	} else {
		topic = "unknown"
	}
	// Approximate: remaining bytes are the message payload
	msgSize = len(body)
	msgCount = 1
	return topic, msgCount, msgSize
}

// parseFetchInfo extracts topic and partition from a Fetch request.
func parseFetchInfo(body []byte) (topic string, partition int32) {
	// v0: replica_id(4) + max_wait(4) + min_bytes(4) + topics_count(4) + topic_string + partitions...
	if len(body) < 16 {
		return "unknown", -1
	}
	offset := 12 // skip replica_id + max_wait + min_bytes
	if offset+4 > len(body) {
		return "unknown", -1
	}
	offset += 4 // skip array count
	if offset+2 > len(body) {
		return "unknown", -1
	}
	tLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if tLen > 0 && offset+tLen <= len(body) {
		topic = string(body[offset : offset+tLen])
		offset += tLen
	} else {
		return "unknown", -1
	}
	// partitions: count(4) + partition_id(4)...
	if offset+8 <= len(body) {
		offset += 4 // skip partition count
		partition = int32(binary.BigEndian.Uint32(body[offset : offset+4]))
	}
	return topic, partition
}
