package llamacpp

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/llmcore"
	"github.com/joshrendek/threat.gg-agent/persistence"
	uuid "github.com/satori/go.uuid"
	"github.com/rs/zerolog"
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
	handler := llmcore.Capture(saveLlamacppRequest)(cmdresp.MuxMiddleware("llamacpp")(newRouter()))
	h.logger.Info().Str("port", port).Msg("starting llamacpp honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), handler)).Msg("failed to start")
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/props", handleProps).Methods("GET")
	r.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		llmcore.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}).Methods("GET")
	r.HandleFunc("/v1/models", handleModels).Methods("GET")
	r.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.ChatCompletion(w, req, defaultModel)
	}).Methods("POST")
	r.HandleFunc("/completion", handleCompletion).Methods("POST")
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		llmcore.WriteError(w, http.StatusNotFound, "Not Found", "invalid_request_error", "")
	})
	return r
}

func handleProps(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"system_prompt":               "",
		"default_generation_settings": map[string]any{"model": defaultModel, "n_ctx": 4096, "temperature": 0.8},
		"total_slots":                 1,
		"chat_template":               "{{ .System }}\n{{ .Prompt }}",
	})
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   []map[string]any{{"id": defaultModel, "object": "model", "created": time.Now().Unix(), "owned_by": "llamacpp"}},
	})
}

// handleCompletion is llama.cpp's native (non-OpenAI) /completion endpoint.
func handleCompletion(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"content":            " Hello! How can I help you today?",
		"id_slot":            0,
		"stop":               true,
		"model":              defaultModel,
		"tokens_predicted":   9,
		"tokens_evaluated":   6,
		"generation_settings": map[string]any{"model": defaultModel, "n_ctx": 4096},
		"prompt":             "",
		"stopped_eos":        true,
		"stopped_word":       false,
		"stopped_limit":      false,
		"id":                 uuid.NewV4().String(),
	})
}
