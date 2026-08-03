// Package lmstudio emulates LM Studio 0.4.x on its signature port. It exposes
// the native v1 REST API alongside OpenAI- and Anthropic-compatible inference
// endpoints while keeping all catalog mutations scoped to the caller IP.
package lmstudio

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
	defaultPort    = "1234"
	defaultModel   = "openai/gpt-oss-20b"
	embeddingModel = "text-embedding-nomic-embed-text-v1.5"
)

var _ honeypots.Honeypot = &honeypot{}
var saveLmstudioRequest = persistence.SaveLmstudioRequest

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "lmstudio").Logger()}
}

func (h *honeypot) Name() string { return "lmstudio" }

func (h *honeypot) Start() {
	port := os.Getenv("LMSTUDIO_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           buildHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	h.logger.Info().Str("port", port).Msg("starting LM Studio honeypot")
	h.logger.Fatal().Err(server.ListenAndServe()).Msg("failed to start LM Studio honeypot")
}

var profile = llmcore.Profile{
	DefaultModel:            defaultModel,
	ContentType:             llmcore.CTJSONCharset,
	OpenAICompatContentType: llmcore.CTJSONCharset,
	KnownModel:              func(r *http.Request, key string) bool { return models.has(r, key) },
}

func buildHandler() http.Handler {
	return llmcore.Capture(saveLmstudioRequest)(
		identityHeaders(cmdresp.LLMMuxMiddleware("lmstudio")(newRouter())),
	)
}

func identityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		next.ServeHTTP(w, r)
	})
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	get := []string{http.MethodGet, http.MethodHead}

	// LM Studio native v1 REST API (0.4.0+).
	r.HandleFunc("/api/v1/models", handleNativeModels).Methods(get...)
	r.HandleFunc("/api/v1/models/load", handleLoad).Methods(http.MethodPost)
	r.HandleFunc("/api/v1/models/unload", handleUnload).Methods(http.MethodPost)
	r.HandleFunc("/api/v1/models/download", handleDownload).Methods(http.MethodPost)
	r.HandleFunc("/api/v1/models/download/status/{job}", handleDownloadStatus).Methods(http.MethodGet)
	r.HandleFunc("/api/v1/chat", handleNativeChat).Methods(http.MethodPost)

	// OpenAI-compatible endpoints.
	r.HandleFunc("/v1/models", handleOpenAIModels).Methods(get...)
	r.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.ChatCompletion(w, req, profile)
	}).Methods(http.MethodPost)
	r.HandleFunc("/v1/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.Completion(w, req, profile)
	}).Methods(http.MethodPost)
	r.HandleFunc("/v1/responses", handleResponses).Methods(http.MethodPost)
	r.HandleFunc("/v1/embeddings", handleEmbeddings).Methods(http.MethodPost)

	// Anthropic-compatible endpoint introduced in LM Studio 0.4.1.
	r.HandleFunc("/v1/messages", handleMessages).Methods(http.MethodPost)

	// Express falls through to a 200 JSON error for unknown endpoint/method
	// combinations. This unusual behavior is a useful LM Studio fingerprint.
	r.NotFoundHandler = http.HandlerFunc(handleUnexpected)
	r.MethodNotAllowedHandler = http.HandlerFunc(handleUnexpected)
	return r
}

func handleUnexpected(w http.ResponseWriter, r *http.Request) {
	writeCompactJSON(w, http.StatusOK, map[string]string{
		"error": fmt.Sprintf("Unexpected endpoint or method. (%s %s)", r.Method, r.URL.Path),
	})
}
