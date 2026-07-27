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
	// vllmVersion is reported by /version and stamped into the OpenAPI schema. Unlike Ollama,
	// uvicorn genuinely does send a Server header, so serverHeader above stays.
	vllmVersion = "0.6.3"
)

var modelsCreated = time.Now().Unix()

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
	h.logger.Info().Str("port", port).Msg("starting vllm honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), buildHandler())).Msg("failed to start")
}

// buildHandler composes the full middleware chain. identityHeaders wraps the cmdresp
// override so the Server header is stamped even when an admin-authored response
// short-circuits the router (matches the jenkins honeypot's override-safe ordering).
func buildHandler() http.Handler {
	return llmcore.Capture(saveVllmRequest)(identityHeaders(cmdresp.LLMMuxMiddleware("vllm")(newRouter())))
}

// identityHeaders stamps the vLLM server identity on every response.
func identityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", serverHeader)
		next.ServeHTTP(w, r)
	})
}

// profile is vLLM's OpenAI surface: bare application/json (FastAPI adds no charset), no
// system_fingerprint (vLLM omits the field entirely, unlike Ollama), long opaque completion ids,
// and no model catalog — vLLM serves whatever single model it was launched with, so it does not
// have Ollama's notion of a model that could be absent.
var profile = llmcore.Profile{
	DefaultModel: defaultModel,
	ContentType:  llmcore.CTJSON,
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	get := []string{http.MethodGet, http.MethodHead}

	r.HandleFunc("/v1/models", handleModels).Methods(get...)
	r.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.ChatCompletion(w, req, profile)
	}).Methods("POST")
	r.HandleFunc("/v1/completions", func(w http.ResponseWriter, req *http.Request) {
		llmcore.Completion(w, req, profile)
	}).Methods("POST")
	r.HandleFunc("/v1/embeddings", handleEmbeddings).Methods("POST")
	r.HandleFunc("/health", handleHealth).Methods(get...)
	r.HandleFunc("/ping", handleHealth).Methods(get...)
	r.HandleFunc("/version", handleVersion).Methods(get...)
	// The endpoint Xpanse and friends actually scrape.
	r.HandleFunc("/metrics", handleMetrics).Methods(get...)
	r.HandleFunc("/tokenize", handleTokenize).Methods("POST")
	r.HandleFunc("/detokenize", handleDetokenize).Methods("POST")
	// FastAPI mounts interactive docs by default; their absence on a box that is otherwise
	// obviously FastAPI is itself a discrepancy.
	r.HandleFunc("/openapi.json", handleOpenAPI).Methods(get...)
	r.HandleFunc("/docs", handleDocs).Methods(get...)
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
	return r
}

// Response payloads are structs rather than maps so the JSON key order matches the real
// server's; encoding/json sorts map keys alphabetically, which no real implementation does.

type modelPermission struct {
	ID     string `json:"id"`
	Object string `json:"object"`
}

type modelEntry struct {
	ID          string            `json:"id"`
	Object      string            `json:"object"`
	Created     int64             `json:"created"`
	OwnedBy     string            `json:"owned_by"`
	Root        string            `json:"root"`
	Parent      *string           `json:"parent"`
	MaxModelLen int               `json:"max_model_len"`
	Permission  []modelPermission `json:"permission"`
}

type modelsResponse struct {
	Object string       `json:"object"`
	Data   []modelEntry `json:"data"`
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSON, modelsResponse{
		Object: "list",
		Data: []modelEntry{{
			ID: defaultModel, Object: "model", Created: modelsCreated, OwnedBy: "vllm",
			Root: defaultModel, MaxModelLen: 8192,
			Permission: []modelPermission{{ID: "modelperm-vllm", Object: "model_permission"}},
		}},
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type versionResponse struct {
	Version string `json:"version"`
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSON, versionResponse{Version: vllmVersion})
}

func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	// A generative model served by vLLM has no embedding task, and this is the error it gives.
	llmcore.WriteOpenAIError(w, profile, http.StatusBadRequest,
		"The model does not support Embeddings API", "BadRequestError")
}

type tokenizeResponse struct {
	Count       int    `json:"count"`
	MaxModelLen int    `json:"max_model_len"`
	Tokens      []int  `json:"tokens"`
	TokenStrs   *[]int `json:"token_strs"`
}

func handleTokenize(w http.ResponseWriter, r *http.Request) {
	text := llmcore.PromptOf(r)
	tokens := llmcore.PseudoTokens(text)
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSON, tokenizeResponse{
		Count: len(tokens), MaxModelLen: 8192, Tokens: tokens,
	})
}

type detokenizeResponse struct {
	Prompt string `json:"prompt"`
}

func handleDetokenize(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSON, detokenizeResponse{Prompt: ""})
}

func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSON, openAPISchema())
}

func handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, swaggerHTML)
}

// handleCatchAll reproduces FastAPI's default 404 body. The previous OpenAI-style error envelope
// was wrong for every unrouted path: FastAPI answers {"detail":"Not Found"}, and vLLM does not
// customise it.
func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusNotFound, llmcore.CTJSON, detailResponse{Detail: "Not Found"})
}

type detailResponse struct {
	Detail string `json:"detail"`
}
