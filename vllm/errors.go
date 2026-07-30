package vllm

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/joshrendek/threat.gg-agent/llmcore"
)

// vLLM does not use OpenAI's nested {"error":{…}} envelope. Its ErrorResponse
// (vllm/entrypoints/openai/protocol.py, unchanged from 0.4 through 0.10.1) is a flat pydantic
// model serialised in declaration order, and `code` is the integer HTTP status rather than
// OpenAI's nullable string:
//
//	class ErrorResponse(OpenAIBaseModel):
//	    object: str = "error"
//	    message: str
//	    type: str
//	    param: Optional[str] = None
//	    code: int
//
// so the wire body is
// {"object":"error","message":"…","type":"NotFoundError","param":null,"code":404}.
// llmcore.WriteOpenAIError emits OpenAI's/Ollama's nested shape with a null code, which is
// correct for the surfaces that share it and wrong here — hence this package-local writer
// rather than a change to the helper five other honeypots depend on.
type errorResponse struct {
	Object  string  `json:"object"`
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    int     `json:"code"`
}

// writeError mirrors OpenAIServing.create_error_response: the HTTP status is echoed into the
// body's `code`, so the two can never disagree.
func writeError(w http.ResponseWriter, status int, message, errType string) {
	llmcore.WriteJSONCT(w, status, llmcore.CTJSON, errorResponse{
		Object: "error", Message: message, Type: errType, Code: status,
	})
}

// writeModelNotFound reproduces OpenAIServing._check_model's response verbatim, backticks and
// trailing period included.
func writeModelNotFound(w http.ResponseWriter, model string) {
	writeError(w, http.StatusNotFound, "The model `"+model+"` does not exist.", "NotFoundError")
}

// requireKnownModel rejects any model this server was not launched with, which is what a real
// vLLM does on every route that resolves a model: _check_model is the first statement of
// create_chat_completion, create_completion, create_tokenize and create_detokenize.
//
// Serving exactly one model is the reason the check exists, not a reason to skip it — vLLM has
// no catalog precisely because everything other than the single launched model is absent. A box
// that advertises one model on /v1/models and then completes "totally-fake-model-xyz" is
// self-evidently not vLLM.
//
// The gate lives here rather than relying solely on Profile.KnownModel because llmcore reports
// a missing model through WriteModelNotFoundV1, whose envelope is OpenAI's, not vLLM's.
func requireKnownModel(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if model, ok := requestedModel(r); !ok {
			writeModelNotFound(w, model)
			return
		}
		next(w, r)
	}
}

// requestedModel returns the model named by the request body and whether this server serves it.
// A body that names no model falls back to the served model, matching the shared generators'
// DefaultModel behaviour (real vLLM would 422 on the missing required field instead; that
// divergence is llmcore-wide and predates this gate). An explicitly empty name is a name this
// server does not have, so it is rejected like any other — hence the pointer parse rather than
// llmcore.ParseModel, which cannot tell absent from "".
func requestedModel(r *http.Request) (string, bool) {
	var parsed struct {
		Model *string `json:"model"`
	}
	if err := json.Unmarshal(peekBody(r), &parsed); err != nil || parsed.Model == nil {
		return defaultModel, true
	}
	return *parsed.Model, *parsed.Model == defaultModel
}

// peekBody reads the body and puts it back so the handler behind the gate — and llmcore's
// generators behind that — can still read it.
func peekBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, llmcore.MaxBodySize))
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body
}
