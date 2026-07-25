package localai

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression tests for threat_gg-3kd.

func do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, r)
	return rec
}

// Real LocalAI exposes /healthz and /readyz side by side (core/http/routes/health.go), both a
// bare 200 with no body.
func TestHealthzMatchesReadyz(t *testing.T) {
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := do(t, "GET", path, "")
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("%s: body %q, want empty", path, rec.Body.String())
		}
	}
}

// POST /v1/embeddings must return the OpenAI embeddings shape, not a 404 — embeddings are a
// headline LocalAI feature. Shape verified against core/http/endpoints/openai/embeddings.go +
// core/schema/openai.go (see embeddings.go's source comment).
func TestEmbeddingsReturnsOpenAIShape(t *testing.T) {
	rec := do(t, "POST", "/v1/embeddings", `{"model":"text-embedding-ada-002","input":"hello world"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type %q, want bare application/json", got)
	}
	var resp struct {
		Object string `json:"object"`
		Model  string `json:"model"`
		Data   []struct {
			Embedding []float32 `json:"embedding"`
			Index     int       `json:"index"`
			Object    string    `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if resp.Object != "list" {
		t.Errorf("object = %q, want list", resp.Object)
	}
	// LocalAI echoes the caller's own model string verbatim, not a normalised/default one.
	if resp.Model != "text-embedding-ada-002" {
		t.Errorf("model = %q, want echoed back verbatim", resp.Model)
	}
	if len(resp.Data) != 1 || resp.Data[0].Object != "embedding" || len(resp.Data[0].Embedding) != embeddingDims {
		t.Errorf("data shape wrong: %+v", resp.Data)
	}
	if strings.Contains(rec.Body.String(), `"usage"`) || strings.Contains(rec.Body.String(), `"choices"`) {
		t.Errorf("embeddings response must omit usage/choices: %s", rec.Body.String())
	}
}

// Multiple strings in "input" produce one embedding item per string, index in order.
func TestEmbeddingsMultipleInputs(t *testing.T) {
	rec := do(t, "POST", "/v1/embeddings", `{"model":"m","input":["a","b","c"]}`)
	var resp struct {
		Data []struct {
			Index int `json:"index"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Data) != 3 {
		t.Fatalf("got %d items, want 3", len(resp.Data))
	}
	for i, item := range resp.Data {
		if item.Index != i {
			t.Errorf("item %d has index %d", i, item.Index)
		}
	}
}

// encoding_format:"base64" packs the vector as a base64 string instead of a float array — the
// Node.js OpenAI SDK (v4+) sends this by default.
func TestEmbeddingsBase64Format(t *testing.T) {
	rec := do(t, "POST", "/v1/embeddings", `{"model":"m","input":"hi","encoding_format":"base64"}`)
	var resp struct {
		Data []struct {
			Embedding string `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Data) != 1 {
		t.Fatalf("got %d items, want 1", len(resp.Data))
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Data[0].Embedding)
	if err != nil {
		t.Fatalf("embedding is not valid base64: %v", err)
	}
	if len(raw) != embeddingDims*4 {
		t.Errorf("decoded %d bytes, want %d (dims * 4 bytes/float32)", len(raw), embeddingDims*4)
	}
}

// Real LocalAI (EmbeddingsEndpoint) rejects a request with no model via echo.ErrBadRequest,
// which Echo's DefaultHTTPErrorHandler renders as {"message":"Bad Request"} — not the OpenAI
// error envelope this package's chat/completions error path uses.
func TestEmbeddingsMissingModelIsBadRequest(t *testing.T) {
	rec := do(t, "POST", "/v1/embeddings", `{"input":"hi"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"message":"Bad Request"}` {
		t.Errorf("body %q, want %q", got, `{"message":"Bad Request"}`)
	}
	// Echo's JSON content type is bare, even though LocalAI has migrated off Fiber onto Echo —
	// see embeddings.go's source comment.
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type %q, want bare application/json", got)
	}
}

// PR #33 review (ERROR 1): a batch bigger than maxEmbeddingItems must be rejected before any
// vector is allocated for it, not silently truncated to the cap.
func TestEmbeddingsOversizedBatchIsRejected(t *testing.T) {
	inputs := make([]string, maxEmbeddingItems+1)
	for i := range inputs {
		inputs[i] = "x"
	}
	body, err := json.Marshal(map[string]any{"model": "m", "input": inputs})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	rec := do(t, "POST", "/v1/embeddings", string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	var resp struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if resp.Message == "" {
		t.Error("oversized-batch response has no message")
	}
}

// A batch at exactly the cap must still succeed — the limit rejects what is over budget, not
// what is at it.
func TestEmbeddingsBatchAtCapSucceeds(t *testing.T) {
	inputs := make([]string, maxEmbeddingItems)
	for i := range inputs {
		inputs[i] = "x"
	}
	body, err := json.Marshal(map[string]any{"model": "m", "input": inputs})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	rec := do(t, "POST", "/v1/embeddings", string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct{} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Data) != maxEmbeddingItems {
		t.Errorf("got %d items, want %d", len(resp.Data), maxEmbeddingItems)
	}
}
