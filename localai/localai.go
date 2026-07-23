package localai

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
	defaultPort  = "8081"
	defaultModel = "gpt-4"
)

var _ honeypots.Honeypot = &honeypot{}
var saveLocalaiRequest = persistence.SaveLocalaiRequest

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "localai").Logger()}
}

func (h *honeypot) Name() string { return "localai" }

func (h *honeypot) Start() {
	port := os.Getenv("LOCALAI_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	handler := llmcore.Capture(saveLocalaiRequest)(cmdresp.MuxMiddleware("localai")(newRouter()))
	h.logger.Info().Str("port", port).Msg("starting localai honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), handler)).Msg("failed to start")
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/models", handleModels).Methods("GET")
	r.HandleFunc("/models", handleModels).Methods("GET")
	r.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.ChatCompletion(w, req, defaultModel)
	}).Methods("POST")
	r.HandleFunc("/v1/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.Completion(w, req, defaultModel)
	}).Methods("POST")
	r.HandleFunc("/readyz", func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) }).Methods("GET")
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		llmcore.WriteError(w, http.StatusNotFound, "Not Found", "invalid_request_error", "")
	})
	return r
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data": []map[string]any{
			{"id": "gpt-4", "object": "model", "created": time.Now().Unix(), "owned_by": "localai"},
			{"id": "gpt-3.5-turbo", "object": "model", "created": time.Now().Unix(), "owned_by": "localai"},
		},
	})
}
