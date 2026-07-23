// Package llmcore holds the shared HTTP machinery for the LLM-serving honeypots
// (vLLM, Ollama, Ray, LocalAI, llama.cpp, ComfyUI): request capture with a body cap,
// JSON/error helpers, and the dynamic completion generators. Each product package is a
// thin wrapper that configures identity + routes and reuses this core.
package llmcore

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

// MaxBodySize caps how much of a request body is captured (defense in depth,
// independent of any global middleware).
const MaxBodySize = 1 << 20 // 1MB

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "llmcore").Logger()

// ParseModel returns the JSON "model" field from body, or "" if absent/unparseable.
func ParseModel(body []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	return m.Model
}

// Capture returns middleware that records each request (method/path/headers/body +
// parsed model + user-agent) into a proto.LlmRequest, saves it via save in a
// recover-guarded goroutine, then calls next. The body is read with a 1MB LimitReader
// and restored so downstream handlers can read it again. Mirrors etcd.captureRequests.
func Capture(save func(*proto.LlmRequest) error) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captureAndSave(r, save)
			next.ServeHTTP(w, r)
		})
	}
}

func captureAndSave(r *http.Request, save func(*proto.LlmRequest) error) {
	guid := uuid.NewV4()

	var body string
	if r.Body != nil {
		data, _ := io.ReadAll(io.LimitReader(r.Body, MaxBodySize+1))
		_ = r.Body.Close()
		captured := data
		if len(captured) > MaxBodySize {
			captured = captured[:MaxBodySize]
		}
		body = string(captured)
		// Restore the body (even after a partial/errored read) so downstream can re-read it.
		r.Body = io.NopCloser(bytes.NewReader(data))
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	in := &proto.LlmRequest{
		RemoteAddr: ip,
		Guid:       guid.String(),
		Headers:    persistence.HttpToMap(map[string][]string(r.Header)),
		Path:       r.URL.Path,
		Method:     r.Method,
		Body:       body,
		Model:      ParseModel([]byte(body)),
		UserAgent:  r.UserAgent(),
	}
	logger.Info().Str("method", in.Method).Str("path", in.Path).Str("remote_addr", in.RemoteAddr).Msg("llm request")

	go func(req *proto.LlmRequest) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error().Interface("panic", rec).Msg("panic saving llm request")
			}
		}()
		if err := save(req); err != nil {
			logger.Error().Err(err).Msg("error saving llm request")
		}
	}(in)
}

// WriteJSON marshals v and writes it with the given status and application/json.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes an OpenAI-style error envelope: {"error":{"message","type","code"}}.
func WriteError(w http.ResponseWriter, status int, message, errType, code string) {
	WriteJSON(w, status, map[string]any{
		"error": map[string]any{"message": message, "type": errType, "code": code},
	})
}
