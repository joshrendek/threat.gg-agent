// Package ollama emulates an exposed, unauthenticated Ollama server (default port 11434) —
// the port internet scanners hunt for reachable LLM inference, and by volume the busiest of
// the LLM-infra honeypots.
//
// Behaviour is matched against a real Ollama 0.30.11: Ollama is built on Gin, so it emits no
// Server header, answers unrouted paths with Gin's plain-text "404 page not found", and appends
// "; charset=utf-8" to its /api/* JSON content type while its OpenAI-compat /v1/* layer does
// not. Divergences from the real server are deliberate and commented.
package ollama

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/llmcore"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/rs/zerolog"
)

const (
	defaultPort  = "11434"
	defaultModel = "llama3.2:latest"
	// version is advertised by /api/version. It has to stay consistent with the feature surface
	// below: /v1/responses, capabilities[] and details.context_length only exist on modern
	// Ollama, so claiming an old 0.3.x here would be an impossible combination.
	version  = "0.30.11"
	rootBody = "Ollama is running"
)

var _ honeypots.Honeypot = &honeypot{}
var saveOllamaRequest = persistence.SaveOllamaRequest

// profile describes Ollama's OpenAI-compat surface: short completion ids, an "fp_ollama"
// system fingerprint, and a catalog that makes unknown models 404 the way a real box does.
var profile = llmcore.Profile{
	DefaultModel:      defaultModel,
	ContentType:       llmcore.CTJSONCharset,
	SystemFingerprint: "fp_ollama",
	ShortIDs:          true,
	KnownModel:        func(r *http.Request, m string) bool { return models.has(r, m) },
}

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "ollama").Logger()}
}

func (h *honeypot) Name() string { return "ollama" }

func (h *honeypot) Start() {
	port := os.Getenv("OLLAMA_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	h.logger.Info().Str("port", port).Msg("starting ollama honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), buildHandler())).Msg("failed to start")
}

// buildHandler composes the full chain. corsHeaders wraps cmdresp so CORS is applied even when
// an admin-authored override short-circuits the router (the jenkins ordering pattern). Note
// there is deliberately no Server header: real Ollama sends none, so stamping one would be a
// positive honeypot signature rather than a missing detail.
func buildHandler() http.Handler {
	return llmcore.Capture(saveOllamaRequest)(corsHeaders(cmdresp.MuxMiddleware("ollama")(newRouter())))
}

// corsAllowHeaders is the exact allow-list a modern Ollama echoes on a preflight, including the
// OpenAI SDK's X-Stainless-* telemetry headers. The list is distinctive enough to fingerprint
// on, so it is reproduced verbatim rather than approximated.
const corsAllowHeaders = "Authorization,Content-Type,User-Agent,Accept,X-Requested-With," +
	"Openai-Beta,X-Stainless-Arch,X-Stainless-Async,X-Stainless-Custom-Poll-Interval," +
	"X-Stainless-Helper-Method,X-Stainless-Lang,X-Stainless-Os,X-Stainless-Package-Version," +
	"X-Stainless-Poll-Helper,X-Stainless-Retry-Count,X-Stainless-Runtime," +
	"X-Stainless-Runtime-Version,X-Stainless-Timeout"

// corsHeaders emulates a box started with OLLAMA_ORIGINS=*. That is both what a machine
// deliberately exposed to the internet typically runs (it is usually exposed so some web UI can
// reach it) and the more inviting configuration: the default origin policy 403s any
// browser-originated probe before it ever reaches a handler.
func corsHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "43200")
			if allowed := allowedMethods(r.URL.Path); allowed != "" {
				w.Header().Set("Allow", allowed)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// routeMethods records which methods each route accepts, so 405s can carry the Allow header Gin
// sets and preflights can answer accurately.
var routeMethods = map[string]string{
	"/":                    "HEAD, GET",
	"/api/tags":            "HEAD, GET",
	"/api/version":         "HEAD, GET",
	"/api/ps":              "HEAD, GET",
	"/api/generate":        "POST",
	"/api/chat":            "POST",
	"/api/show":            "POST",
	"/api/pull":            "POST",
	"/api/push":            "POST",
	"/api/create":          "POST",
	"/api/copy":            "POST",
	"/api/delete":          "DELETE",
	"/api/embed":           "POST",
	"/api/embeddings":      "POST",
	"/v1/models":           "HEAD, GET",
	"/v1/chat/completions": "POST",
	"/v1/completions":      "POST",
	"/v1/responses":        "POST",
	"/v1/embeddings":       "POST",
}

func allowedMethods(path string) string {
	p := path
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	if m, ok := routeMethods[p]; ok {
		return m
	}
	if strings.HasPrefix(p, "/api/blobs/") {
		return "HEAD, POST"
	}
	return ""
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	// Gin matches HEAD on routes registered for GET; gorilla/mux does not, so HEAD is listed
	// explicitly. Without it, HEAD / fell through to the 404 handler while a real Ollama
	// answers 200 — a one-request tell.
	get := []string{http.MethodGet, http.MethodHead}

	r.HandleFunc("/", handleRoot).Methods(get...)
	r.HandleFunc("/api/tags", handleTags).Methods(get...)
	r.HandleFunc("/api/version", handleVersion).Methods(get...)
	r.HandleFunc("/api/ps", handlePs).Methods(get...)
	r.HandleFunc("/api/generate", func(w http.ResponseWriter, req *http.Request) {
		llmcore.OllamaGenerate(w, req, profile)
	}).Methods(http.MethodPost)
	r.HandleFunc("/api/chat", func(w http.ResponseWriter, req *http.Request) {
		llmcore.OllamaChat(w, req, profile)
	}).Methods(http.MethodPost)
	r.HandleFunc("/api/show", handleShow).Methods(http.MethodPost)
	r.HandleFunc("/api/pull", handlePull).Methods(http.MethodPost)
	r.HandleFunc("/api/push", handlePush).Methods(http.MethodPost)
	r.HandleFunc("/api/create", handleCreate).Methods(http.MethodPost)
	r.HandleFunc("/api/copy", handleCopy).Methods(http.MethodPost)
	r.HandleFunc("/api/delete", handleDelete).Methods(http.MethodDelete)
	r.HandleFunc("/api/embed", handleEmbedAPI).Methods(http.MethodPost)
	// Legacy route: 500, not 501, for the identical refusal (see handleEmbedLegacyAPI).
	r.HandleFunc("/api/embeddings", handleEmbedLegacyAPI).Methods(http.MethodPost)
	r.HandleFunc("/api/blobs/{digest}", handleBlob).Methods(http.MethodHead, http.MethodPost)

	// OpenAI-compatible layer. These answer with bare application/json (no charset) because
	// inside Ollama they are served by a different handler chain than the /api/* routes.
	r.HandleFunc("/v1/models", handleV1Models).Methods(get...)
	r.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.ChatCompletion(w, req, profile)
	}).Methods(http.MethodPost)
	r.HandleFunc("/v1/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.Completion(w, req, profile)
	}).Methods(http.MethodPost)
	r.HandleFunc("/v1/responses", handleResponses).Methods(http.MethodPost)
	r.HandleFunc("/v1/embeddings", handleEmbedV1).Methods(http.MethodPost)

	r.NotFoundHandler = http.HandlerFunc(handleNotFound)
	r.MethodNotAllowedHandler = http.HandlerFunc(handleMethodNotAllowed)
	return r
}

// handleNotFound reproduces Gin's default 404: plain text, no charset parameter, no JSON body.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", llmcore.CTText)
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404 page not found")
}

// handleMethodNotAllowed reproduces Gin's 405, including the Allow header listing the methods
// the route does accept.
func handleMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if allowed := allowedMethods(r.URL.Path); allowed != "" {
		w.Header().Set("Allow", allowed)
	}
	w.Header().Set("Content-Type", llmcore.CTText)
	w.WriteHeader(http.StatusMethodNotAllowed)
	fmt.Fprint(w, "405 method not allowed")
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", llmcore.CTTextCharset)
	w.Header().Set("Content-Length", fmt.Sprint(len(rootBody)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	fmt.Fprint(w, rootBody)
}

type tagsResponse struct {
	Models []CatalogModel `json:"models"`
}

func handleTags(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, tagsResponse{Models: models.list(r)})
}

type versionResponse struct {
	Version string `json:"version"`
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, versionResponse{Version: version})
}

type psModel struct {
	Name      string  `json:"name"`
	Model     string  `json:"model"`
	Size      int64   `json:"size"`
	Digest    string  `json:"digest"`
	Details   Details `json:"details"`
	ExpiresAt string  `json:"expires_at"`
	SizeVRAM  int64   `json:"size_vram"`
}

type psResponse struct {
	Models []psModel `json:"models"`
}

// handlePs lists the models currently resident. Because llmcore already tracks residency for its
// timing model, an attacker who runs a completion and then checks /api/ps sees the model they
// just used listed as loaded — and sees it fall off once keep_alive expires, like a real server.
func handlePs(w http.ResponseWriter, r *http.Request) {
	out := []psModel{}
	for name, expires := range llmcore.ResidentModels() {
		m, ok := models.get(r, name)
		if !ok {
			continue
		}
		out = append(out, psModel{
			Name: m.Name, Model: m.Model, Size: m.Size, Digest: m.Digest,
			Details:   m.Details,
			ExpiresAt: expires.UTC().Format(time.RFC3339Nano),
			SizeVRAM:  m.Size,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, psResponse{Models: out})
}

type v1ModelsResponse struct {
	Object string          `json:"object"`
	Data   []llmcore.Model `json:"data"`
}

func handleV1Models(w http.ResponseWriter, r *http.Request) {
	list := models.list(r)
	data := make([]llmcore.Model, 0, len(list))
	for _, m := range list {
		created, err := time.Parse(time.RFC3339Nano, m.ModifiedAt)
		if err != nil {
			created = time.Now()
		}
		data = append(data, llmcore.Model{
			ID: m.Name, Object: "model", Created: created.Unix(), OwnedBy: "library",
		})
	}
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSON, v1ModelsResponse{Object: "list", Data: data})
}
