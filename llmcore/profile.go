package llmcore

import "net/http"

// JSON content types. Products differ in whether their web framework appends a charset, and
// scanners can tell them apart on that alone: Gin (Ollama's /api/*) and cpp-httplib
// (llama.cpp) append "; charset=utf-8"; FastAPI (vLLM), Fiber (LocalAI) and Ollama's own
// OpenAI-compat layer (/v1/*) do not.
const (
	CTJSON        = "application/json"
	CTJSONCharset = "application/json; charset=utf-8"
	CTNDJSON      = "application/x-ndjson"
	CTText        = "text/plain"
	CTTextCharset = "text/plain; charset=utf-8"
	CTEventStream = "text/event-stream"
)

// Profile describes how one product's HTTP surface behaves on the wire. The generators are
// shared across all six LLM honeypots; the per-product differences that a fingerprinting
// scanner can observe live here rather than being hardcoded into each generator.
type Profile struct {
	// DefaultModel is used when the request body names no model.
	DefaultModel string
	// ContentType is the JSON content type for this surface. Defaults to CTJSON.
	ContentType string
	// SystemFingerprint is echoed in OpenAI-shaped responses ("fp_ollama" for Ollama).
	// Empty omits the field entirely, which is what vLLM does.
	SystemFingerprint string
	// ShortIDs makes completion ids look like Ollama's ("chatcmpl-964") rather than the
	// long opaque ids OpenAI and vLLM emit.
	ShortIDs bool
	// KnownModel reports whether a model exists in the catalog *as this requester sees it*. nil
	// accepts any model; a non-nil predicate makes the surface return a faithful
	// model-not-found error, which is what a real server does for a name it has not pulled.
	//
	// It takes the request because catalog mutations (/api/pull, /api/delete, /api/copy) are
	// scoped per source IP. A global catalog would let one anonymous caller delete the
	// advertised models and disarm the honeypot for everyone.
	KnownModel func(r *http.Request, model string) bool
}

func (p Profile) ct() string {
	if p.ContentType == "" {
		return CTJSON
	}
	return p.ContentType
}

// known reports whether model is servable for this requester.
func (p Profile) known(r *http.Request, model string) bool {
	return p.KnownModel == nil || p.KnownModel(r, model)
}

// resolveModel returns the requested model (or the profile default) plus whether the surface
// should serve it for this requester. Callers write the product-appropriate not-found error
// when ok is false.
func (p Profile) resolveModel(r *http.Request, body []byte) (model string, ok bool) {
	model = modelOr(body, p.DefaultModel)
	return model, p.known(r, model)
}

// Error envelopes are structs, not maps: encoding/json sorts map keys alphabetically, which
// would emit {"code":…,"message":…,"param":…,"type":…} where every real server emits
// {"message":…,"type":…,"param":…,"code":…}.

type openAIErrorBody struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    *string `json:"code"`
}

type openAIErrorEnvelope struct {
	Error openAIErrorBody `json:"error"`
}

type ollamaErrorEnvelope struct {
	Error string `json:"error"`
}

// WriteOpenAIError writes the OpenAI error envelope used by /v1/* surfaces:
// {"error":{"message":…,"type":…,"param":null,"code":null}}. Matches Ollama's OpenAI-compat
// layer byte-for-byte, including the explicit nulls and their position.
func WriteOpenAIError(w http.ResponseWriter, p Profile, status int, message, errType string) {
	w.Header().Set("Content-Type", CTJSON)
	w.WriteHeader(status)
	writeCompactJSON(w, openAIErrorEnvelope{Error: openAIErrorBody{Message: message, Type: errType}})
}

// WriteOllamaError writes the flat {"error":"…"} envelope Ollama's native /api/* routes use.
func WriteOllamaError(w http.ResponseWriter, p Profile, status int, message string) {
	w.Header().Set("Content-Type", p.ct())
	w.WriteHeader(status)
	writeCompactJSON(w, ollamaErrorEnvelope{Error: message})
}

// WriteModelNotFoundV1 is the /v1/* model-not-found response.
func WriteModelNotFoundV1(w http.ResponseWriter, p Profile, model string) {
	WriteOpenAIError(w, p, http.StatusNotFound, "model '"+model+"' not found", "not_found_error")
}

// WriteModelNotFoundAPI is the /api/* model-not-found response.
func WriteModelNotFoundAPI(w http.ResponseWriter, p Profile, model string) {
	WriteOllamaError(w, p, http.StatusNotFound, "model '"+model+"' not found")
}
