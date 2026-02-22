package openclaw

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
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
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "openclaw").Logger()}
}

func (h *honeypot) Name() string {
	return "openclaw"
}

func (h *honeypot) Start() {
	port := os.Getenv("OPENCLAW_PORT")
	if port == "" {
		port = "18789"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.wsHandler)

	addr := ":" + port
	h.logger.Info().Str("addr", addr).Msg("starting openclaw honeypot")
	if err := http.ListenAndServe(addr, mux); err != nil {
		h.logger.Fatal().Err(err).Msg("failed to start openclaw")
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// connectMsg represents the client's connect message after receiving the challenge.
type connectMsg struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Payload struct {
		Type           string   `json:"type"`
		AuthToken      string   `json:"auth_token"`
		ClientID       string   `json:"client_id"`
		ClientVersion  string   `json:"client_version"`
		ClientPlatform string   `json:"client_platform"`
		ClientMode     string   `json:"client_mode"`
		Role           string   `json:"role"`
		Scopes         []string `json:"scopes"`
		DeviceID       string   `json:"device_id"`
		DevicePublicKey string  `json:"device_public_key"`
		MinProtocol    int32    `json:"min_protocol"`
		MaxProtocol    int32    `json:"max_protocol"`
	} `json:"payload"`
}

func (h *honeypot) wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error().Err(err).Msg("websocket upgrade failed")
		return
	}
	defer conn.Close()

	sessionID := uuid.NewV4().String()
	remoteAddr, _, _ := net.SplitHostPort(r.RemoteAddr)
	if remoteAddr == "" {
		remoteAddr = r.RemoteAddr
	}

	h.logger.Info().Str("session", sessionID).Str("remote", remoteAddr).Msg("new connection")

	// Send challenge
	nonce := randomHex(16)
	challenge := map[string]interface{}{
		"type":  "event",
		"event": "connect.challenge",
		"payload": map[string]interface{}{
			"nonce": nonce,
			"ts":    time.Now().Unix(),
		},
	}
	if err := conn.WriteJSON(challenge); err != nil {
		h.logger.Error().Err(err).Msg("failed to send challenge")
		return
	}

	// Read connect message
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	conn.SetReadLimit(64 * 1024)

	var cm connectMsg
	if err := conn.ReadJSON(&cm); err != nil {
		h.logger.Warn().Err(err).Str("session", sessionID).Msg("no connect message")
		return
	}

	h.logger.Info().
		Str("session", sessionID).
		Str("auth_token", truncate(cm.Payload.AuthToken, 16)).
		Str("client_version", cm.Payload.ClientVersion).
		Str("role", cm.Payload.Role).
		Msg("connect received")

	// Send hello-ok
	helloOk := map[string]interface{}{
		"type": "res",
		"id":   cm.ID,
		"ok":   true,
		"payload": map[string]interface{}{
			"type":     "hello-ok",
			"protocol": 3,
			"policy": map[string]interface{}{
				"tickIntervalMs": 15000,
			},
		},
	}
	if err := conn.WriteJSON(helloOk); err != nil {
		h.logger.Error().Err(err).Msg("failed to send hello-ok")
		return
	}

	// Read loop: capture subsequent messages
	var messages []string
	for i := 0; i < 100; i++ {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		messages = append(messages, string(raw))

		// Ack any request-type messages
		var msg map[string]interface{}
		if json.Unmarshal(raw, &msg) == nil {
			if msgType, _ := msg["type"].(string); msgType == "req" {
				ack := map[string]interface{}{
					"type":    "res",
					"id":      msg["id"],
					"ok":      true,
					"payload": map[string]interface{}{},
				}
				conn.WriteJSON(ack)
			}
		}
	}

	h.logger.Info().
		Str("session", sessionID).
		Int("messages", len(messages)).
		Msg("session ended")

	// Persist asynchronously
	go func() {
		req := &proto.OpenclawRequest{
			RemoteAddr:      remoteAddr,
			Guid:            sessionID,
			AuthToken:       cm.Payload.AuthToken,
			ClientId:        cm.Payload.ClientID,
			ClientVersion:   cm.Payload.ClientVersion,
			ClientPlatform:  cm.Payload.ClientPlatform,
			ClientMode:      cm.Payload.ClientMode,
			Role:            cm.Payload.Role,
			Scopes:          cm.Payload.Scopes,
			DeviceId:        cm.Payload.DeviceID,
			DevicePublicKey: cm.Payload.DevicePublicKey,
			MinProtocol:     cm.Payload.MinProtocol,
			MaxProtocol:     cm.Payload.MaxProtocol,
			Messages:        messages,
		}
		if err := persistence.SaveOpenclawConnect(req); err != nil {
			h.logger.Error().Err(err).Str("session", sessionID).Msg("failed to persist")
		}
	}()
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return fmt.Sprintf("%s...", s[:maxLen])
}
