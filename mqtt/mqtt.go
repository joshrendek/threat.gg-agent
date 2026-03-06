package mqtt

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort  = "1883"
	idleTimeout  = 30 * time.Second
	sessionLimit = 500
)

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

type session struct {
	guid string
	ip   string
	conn *connectData
	cmds []string
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "mqtt").Logger()}
}

func (h *honeypot) Name() string {
	return "mqtt"
}

func (h *honeypot) Start() {
	port := os.Getenv("MQTT_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start mqtt listener")
	}
	h.logger.Info().Str("port", port).Msg("starting mqtt honeypot")

	for {
		conn, err := ln.Accept()
		if err != nil {
			h.logger.Error().Err(err).Msg("accept error")
			continue
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

	sess := &session{guid: uuid.NewV4().String(), ip: host}
	defer h.persistSession(sess)

	if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
		return
	}
	fixed, payload, err := readPacket(conn)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			h.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read connect packet")
		}
		return
	}

	if fixed>>4 != packetTypeConnect {
		h.logger.Debug().Int("packet_type", int(fixed>>4)).Str("session", sess.guid).Msg("first packet was not CONNECT")
		return
	}

	cd, err := parseConnectPacket(payload)
	if err != nil {
		h.logger.Debug().Err(err).Str("session", sess.guid).Msg("invalid connect packet")
		return
	}
	sess.conn = cd

	if _, err := conn.Write(buildConnAck(cd.protocolLevel)); err != nil {
		return
	}

	for i := 0; i < sessionLimit; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		fixed, payload, err = readPacket(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				h.logger.Debug().Err(err).Str("session", sess.guid).Msg("packet read ended")
			}
			return
		}

		typeNibble := fixed >> 4
		flags := fixed & 0x0F

		switch typeNibble {
		case packetTypePublish:
			cmd, err := parsePublishCommand(payload, flags)
			if err == nil {
				sess.cmds = append(sess.cmds, cmd)
			}
		case packetTypeSubscribe:
			cmd, err := parseSubscribeCommand(payload)
			if err == nil {
				sess.cmds = append(sess.cmds, cmd)
				topic := firstTopicFromSubscribe(cmd)
				_, _ = conn.Write(buildPublishPacket(topic, `{"temp":22.3,"status":"ok"}`))
			}
		case packetTypePingReq:
			_, _ = conn.Write([]byte{0xD0, 0x00})
		case packetTypeDisconnect:
			return
		default:
			sess.cmds = append(sess.cmds, fmt.Sprintf("PACKET type=%d len=%d", typeNibble, len(payload)))
		}
	}
}

func firstTopicFromSubscribe(cmd string) string {
	parts := strings.SplitN(strings.TrimPrefix(cmd, "SUBSCRIBE "), ",", 2)
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return "sensors/temperature"
	}
	topic := strings.TrimSpace(parts[0])
	topic = strings.ReplaceAll(topic, "#", "status")
	topic = strings.ReplaceAll(topic, "+", "device")
	if topic == "" {
		return "sensors/temperature"
	}
	return topic
}

func (h *honeypot) persistSession(sess *session) {
	if sess.conn == nil {
		return
	}

	connectReq := &pb.MqttConnectRequest{
		RemoteAddr:    sess.ip,
		Guid:          sess.guid,
		ClientId:      sess.conn.clientID,
		Username:      sess.conn.username,
		Password:      sess.conn.password,
		ProtocolName:  sess.conn.protocolName,
		ProtocolLevel: int32(sess.conn.protocolLevel),
		CleanSession:  sess.conn.cleanSession,
		KeepaliveSecs: int32(sess.conn.keepAliveSecs),
	}
	if err := persistence.SaveMqttConnect(connectReq); err != nil {
		h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist mqtt connect")
		return
	}

	for _, cmd := range sess.cmds {
		if err := persistence.SaveMqttCommand(&pb.MqttCommandRequest{Guid: sess.guid, Command: cmd}); err != nil {
			h.logger.Error().Err(err).Str("session", sess.guid).Msg("failed to persist mqtt command")
		}
	}
}
