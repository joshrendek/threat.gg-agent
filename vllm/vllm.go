package vllm

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
	"github.com/rs/zerolog"
)

const (
	defaultPort  = "8000"
	defaultModel = "meta-llama/Meta-Llama-3-8B-Instruct"
	serverHeader = "uvicorn"
)

var _ honeypots.Honeypot = &honeypot{}
var saveVllmRequest = persistence.SaveVllmRequest

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "vllm").Logger()}
}

func (h *honeypot) Name() string { return "vllm" }

func (h *honeypot) Start() {
	port := os.Getenv("VLLM_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	handler := llmcore.Capture(saveVllmRequest)(cmdresp.MuxMiddleware("vllm")(newRouter()))
	h.logger.Info().Str("port", port).Msg("starting vllm honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), handler)).Msg("failed to start")
}

// identityHeaders stamps the vLLM server identity on every response.
func identityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", serverHeader)
		next.ServeHTTP(w, r)
	})
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/models", handleModels).Methods("GET")
	r.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.ChatCompletion(w, req, defaultModel)
	}).Methods("POST")
	r.HandleFunc("/v1/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.Completion(w, req, defaultModel)
	}).Methods("POST")
	r.HandleFunc("/health", handleHealth).Methods("GET")
	r.HandleFunc("/version", handleVersion).Methods("GET")
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
	return identityHeaders(r)
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	created := time.Now().Unix()
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data": []map[string]any{{
			"id": defaultModel, "object": "model", "created": created, "owned_by": "vllm",
			"root": defaultModel, "parent": nil,
			"permission": []map[string]any{{"id": "modelperm-vllm", "object": "model_permission"}},
		}},
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{"version": "0.5.4"})
}

func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteError(w, http.StatusNotFound, "Not Found", "invalid_request_error", "")
}
