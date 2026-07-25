package llamacpp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/llmcore"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort  = "8082"
	defaultModel = "llama-2-7b-chat.Q4_K_M.gguf"
)

var _ honeypots.Honeypot = &honeypot{}
var saveLlamacppRequest = persistence.SaveLlamacppRequest

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "llamacpp").Logger()}
}

func (h *honeypot) Name() string { return "llamacpp" }

func (h *honeypot) Start() {
	port := os.Getenv("LLAMACPP_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	h.logger.Info().Str("port", port).Msg("starting llamacpp honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), buildHandler())).Msg("failed to start")
}

// buildHandler composes the full middleware chain (capture + cmdresp override + routing), split
// out from Start so tests can exercise it directly — matches the ollama/vllm packages' pattern.
func buildHandler() http.Handler {
	return llmcore.Capture(saveLlamacppRequest)(cmdresp.MuxMiddleware("llamacpp")(newRouter()))
}

// profile: llama.cpp's server is cpp-httplib, which appends "; charset=utf-8" to JSON on its
// entire surface — unlike Ollama, where only the native /api/* routes get the charset and the
// separate OpenAI-compat /v1/* layer does not. llama.cpp has no such split (one process, one
// framework), so OpenAICompatContentType carries the same charset into /v1/chat/completions and
// its error paths too. See llmcore/profile.go's CT* doc comment (threat_gg-5g1).
var profile = llmcore.Profile{
	DefaultModel:            defaultModel,
	ContentType:             llmcore.CTJSONCharset,
	OpenAICompatContentType: llmcore.CTJSONCharset,
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/props", handleProps).Methods("GET")
	r.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, map[string]any{"status": "ok"})
	}).Methods("GET")
	r.HandleFunc("/v1/models", handleModels).Methods("GET")
	r.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.ChatCompletion(w, req, profile)
	}).Methods("POST")
	r.HandleFunc("/completion", handleCompletion).Methods("POST")
	// threat_gg-5g1: /tokenize, /detokenize and /slots are standard llama-server endpoints,
	// verified 404 on the live fleet. Shapes confirmed against the current server source
	// (github.com/ggml-org/llama.cpp tools/server/server-context.cpp, post_tokenize/
	// post_detokenize/get_slots handlers) — see endpoints.go.
	r.HandleFunc("/tokenize", handleTokenize).Methods("POST")
	r.HandleFunc("/detokenize", handleDetokenize).Methods("POST")
	r.HandleFunc("/slots", handleSlots).Methods("GET")
	r.PathPrefix("/").HandlerFunc(handleNotFound)
	return r
}

// handleNotFound reproduces cpp-httplib's error_handler for unrouted paths: real llama.cpp
// registers `srv->set_error_handler(...)` (server-http.cpp) which, for a 404, always writes this
// exact envelope regardless of the route's own error shape — verified against
// github.com/ggml-org/llama.cpp tools/server/server-http.cpp.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusNotFound, llmcore.CTJSONCharset, notFoundBody{
		Error: notFoundError{Message: "File Not Found", Type: "not_found_error", Code: http.StatusNotFound},
	})
}

type notFoundError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    int    `json:"code"`
}

type notFoundBody struct {
	Error notFoundError `json:"error"`
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, map[string]any{
		"object": "list",
		"data":   []map[string]any{{"id": defaultModel, "object": "model", "created": time.Now().Unix(), "owned_by": "llamacpp"}},
	})
}

// handleCompletion is llama.cpp's native (non-OpenAI) /completion endpoint.
func handleCompletion(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, map[string]any{
		"content":             " Hello! How can I help you today?",
		"id_slot":             0,
		"stop":                true,
		"model":               defaultModel,
		"tokens_predicted":    9,
		"tokens_evaluated":    6,
		"generation_settings": map[string]any{"model": defaultModel, "n_ctx": 4096},
		"prompt":              "",
		"stopped_eos":         true,
		"stopped_word":        false,
		"stopped_limit":       false,
		"id":                  uuid.NewV4().String(),
	})
}

// readJSONBody parses a JSON object body into v, ignoring parse errors (an empty/absent v is
// the harmless failure mode for these endpoints, matching how the rest of the package treats
// malformed management-endpoint bodies).
func readJSONBody(r *http.Request, v any) {
	b, _ := io.ReadAll(io.LimitReader(r.Body, llmcore.MaxBodySize))
	_ = json.Unmarshal(b, v)
}
