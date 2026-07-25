package llmcore

import (
	"net/http/httptest"
	"testing"
)

// Regression coverage for the PR #33 review: the charset fix (Profile.OpenAICompatContentType)
// only had success-path coverage. WriteOpenAIError is the shared error writer for every
// OpenAI-compat surface (malformed JSON, unknown model, embeddings refusals, …), so its content
// type must track the same per-profile rule as the success path.

// A profile that sets OpenAICompatContentType (llama.cpp's shape) must carry that charset on its
// error path too, not just on a successful completion.
func TestWriteOpenAIErrorHonoursOpenAICompatContentType(t *testing.T) {
	p := Profile{OpenAICompatContentType: CTJSONCharset}
	rec := httptest.NewRecorder()
	WriteOpenAIError(rec, p, 400, "bad request", "invalid_request_error")
	if got := rec.Header().Get("Content-Type"); got != CTJSONCharset {
		t.Errorf("content-type = %q, want %q", got, CTJSONCharset)
	}
}

// A profile that leaves OpenAICompatContentType unset (Ollama and vLLM) must keep the bare,
// no-charset content type on its error path — this is the pre-existing, already-verified
// behaviour, and the new field must not regress it.
func TestWriteOpenAIErrorDefaultsToBareJSON(t *testing.T) {
	p := Profile{}
	rec := httptest.NewRecorder()
	WriteOpenAIError(rec, p, 404, "model not found", "not_found_error")
	if got := rec.Header().Get("Content-Type"); got != CTJSON {
		t.Errorf("content-type = %q, want bare %q", got, CTJSON)
	}
}
