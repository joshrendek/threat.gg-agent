package vllm

import (
	"fmt"
	"net/http"
	"os"
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
	defaultPort  = "8000"
	defaultModel = "meta-llama/Meta-Llama-3-8B-Instruct"
	serverHeader = "uvicorn"
	// vllmVersion is reported by /version and stamped into the OpenAPI schema. Unlike Ollama,
	// uvicorn genuinely does send a Server header, so serverHeader above stays.
	//
	// It is not a free-floating string: the route table and embeddingsDisabledMessage below are
	// both version-specific, and a scanner can cross-check either against /version. Changing it
	// means re-reading the matching vllm/entrypoints/openai/ sources at the new tag.
	vllmVersion = "0.6.3"
	// embeddingsDisabledMessage is what a generation-only server says when asked for embeddings,
	// and the wording changed with the code path. 0.6.x builds OpenAIServingEmbedding
	// unconditionally and short-circuits inside it:
	//
	//	if not self._enabled:
	//	    return self.create_error_response("Embedding API disabled")
	//
	// (vllm/entrypoints/openai/serving_embedding.py at v0.6.3). 0.7.0 moved the check up into
	// api_server.py — `handler = embedding(raw_request); if handler is None: … message="The model
	// does not support Embeddings API"` — which is where the string this honeypot used to emit
	// comes from. Emitting the 0.7 wording while /version claimed 0.6.3 was a free version
	// cross-check for anyone who had read either source (threat_gg-6jp).
	embeddingsDisabledMessage = "Embedding API disabled"
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

// buildHandler composes the full middleware chain, in the order the real stack nests. uvicorn is
// outermost and stamps Server on everything — including the preflight reply CORSMiddleware
// generates without entering the app — so identityHeaders wraps corsHeaders. CORSMiddleware in
// turn sits above the FastAPI app, so both wrap the cmdresp override, and an admin-authored
// response that short-circuits the router still carries the right identity and CORS headers
// (the jenkins honeypot's override-safe ordering).
func buildHandler() http.Handler {
	return llmcore.Capture(saveVllmRequest)(
		identityHeaders(corsHeaders(cmdresp.LLMMuxMiddleware("vllm")(newRouter()))))
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
// and a single-model catalog. vLLM serves exactly the one model it was launched with and
// _check_model 404s every other name, so KnownModel is the backstop that stops the shared
// generators completing for a model this box does not have. The wire-level rejection is owned by
// requireKnownModel, which writes vLLM's flat error envelope; llmcore's WriteModelNotFoundV1
// would write OpenAI's nested one.
var profile = llmcore.Profile{
	DefaultModel: defaultModel,
	ContentType:  llmcore.CTJSON,
	KnownModel:   func(_ *http.Request, m string) bool { return m == defaultModel },
}

// route is one FastAPI path operation. methods nil means "any method", which is how a mounted
// ASGI sub-app behaves; otherwise the list doubles as the Allow header for a 405.
type route struct {
	path    string
	methods []string
	handler http.HandlerFunc
}

// getMethods is what Starlette records for an @router.get route: it adds HEAD implicitly
// whenever GET is present.
var getMethods = []string{http.MethodGet, http.MethodHead}

var postMethods = []string{http.MethodPost}

func routes() []route {
	return []route{
		{"/v1/models", getMethods, handleModels},
		{"/v1/chat/completions", postMethods, requireKnownModel(func(w http.ResponseWriter, req *http.Request) {
			llmcore.ChatCompletion(w, req, profile)
		})},
		{"/v1/completions", postMethods, requireKnownModel(func(w http.ResponseWriter, req *http.Request) {
			llmcore.Completion(w, req, profile)
		})},
		// Deliberately not gated on the model: on a generation-only server vLLM answers
		// /v1/embeddings before it ever validates the model — the "no embeddings" branch sits
		// above _check_model in both the 0.6.x serving_embedding path and the later
		// api_server handler-is-None path — so an unknown model here still gets the 400.
		{"/v1/embeddings", postMethods, handleEmbeddings},
		{"/health", getMethods, handleHealth},
		// Deliberately no /ping. The SageMaker-oriented
		// `@router.api_route("/ping", methods=["GET", "POST"])` first appears in v0.7.0; v0.6.2,
		// 0.6.3, 0.6.4 and 0.6.6 have no /ping at all, only /health. Serving it on a box whose
		// /version says 0.6.3 contradicted the version claim, and registering it GET/HEAD
		// contradicted upstream twice over, so the unrouted 404 is the faithful answer. If vllmVersion
		// is ever bumped past 0.7.0, add it back as {GET, POST, HEAD} — Starlette's Route adds
		// HEAD implicitly to any route that lists GET, api_route included.
		{"/version", getMethods, handleVersion},
		// The endpoint Xpanse and friends actually scrape. vLLM appends it as a Mount of
		// prometheus_client's ASGI app rather than a path operation, and that app ignores the
		// request method, so this route accepts any verb instead of 405ing non-GET.
		{"/metrics", nil, handleMetrics},
		{"/tokenize", postMethods, requireKnownModel(handleTokenize)},
		{"/detokenize", postMethods, requireKnownModel(handleDetokenize)},
		// FastAPI mounts interactive docs by default; their absence on a box that is otherwise
		// obviously FastAPI is itself a discrepancy.
		{"/openapi.json", getMethods, handleOpenAPI},
		{"/docs", getMethods, handleDocs},
	}
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	allow := map[string]string{}
	for _, rt := range routes() {
		registered := r.HandleFunc(rt.path, rt.handler)
		if rt.methods != nil {
			registered.Methods(rt.methods...)
			allow[rt.path] = strings.Join(rt.methods, ", ")
		}
	}
	// A registered path reached with the wrong verb is a 405, not a 404. Both handlers have to
	// be hung off the router rather than expressed as a PathPrefix("/") catch-all route: a
	// catch-all matches the method-mismatch case too, which is exactly how GET
	// /v1/chat/completions used to come back as FastAPI's 404.
	r.MethodNotAllowedHandler = methodNotAllowedHandler(allow)
	r.NotFoundHandler = http.HandlerFunc(handleNotFound)
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

// handleEmbeddings refuses the way a generation-only server does. create_error_response defaults
// to err_type "BadRequestError" and HTTPStatus.BAD_REQUEST, and vLLM echoes that status into the
// body's `code`, so writeError's status argument carries both. The message itself is
// version-specific — see embeddingsDisabledMessage.
func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusBadRequest, embeddingsDisabledMessage, "BadRequestError")
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

// handleNotFound reproduces FastAPI's default 404 body for a path that is not routed at all.
// The previous OpenAI-style error envelope was wrong for every unrouted path: FastAPI answers
// {"detail":"Not Found"}, and vLLM does not customise it.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusNotFound, llmcore.CTJSON, detailResponse{Detail: "Not Found"})
}

// methodNotAllowedHandler reproduces what Starlette does for a routed path reached with an
// unregistered verb: Route.handle raises HTTPException(405, headers={"Allow": …}), which
// FastAPI's default handler renders as {"detail":"Method Not Allowed"}. Both the status and the
// Allow header distinguish this from the unrouted 404 above, and a scanner that probes GET on a
// POST-only endpoint reads a 404 there as "this path does not exist".
func methodNotAllowedHandler(allow map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods, ok := allow[r.URL.Path]
		if !ok {
			// mux only routes here after a path matched a method-restricted route, so this is
			// unreachable; answer as unrouted rather than invent an Allow header.
			handleNotFound(w, r)
			return
		}
		w.Header().Set("Allow", methods)
		llmcore.WriteJSONCT(w, http.StatusMethodNotAllowed, llmcore.CTJSON,
			detailResponse{Detail: "Method Not Allowed"})
	})
}

type detailResponse struct {
	Detail string `json:"detail"`
}
