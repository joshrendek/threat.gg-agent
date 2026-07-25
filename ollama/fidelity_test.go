package ollama

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Regression tests for PRD 033. Every expectation here was captured from a real Ollama 0.30.11,
// not from documentation — the reference transcript is quoted inline per assertion. A scanner
// that has touched a genuine Ollama can distinguish it from ours on any of these, so each one
// that regresses is a fingerprint the honeypot leaks.

func do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, r)
	return rec
}

// Real: no Server header on any response. Ollama is Gin; Gin never sets one.
func TestNoServerHeaderAnywhere(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/", ""},
		{"GET", "/api/tags", ""},
		{"GET", "/api/version", ""},
		{"GET", "/v1/models", ""},
		{"GET", "/definitely-not-a-route", ""},
		{"POST", "/api/chat", `{"model":"llama3.2:latest","messages":[{"role":"user","content":"hi"}],"stream":false}`},
	} {
		if got := do(t, tc.method, tc.path, tc.body).Header().Get("Server"); got != "" {
			t.Errorf("%s %s: Server header set to %q; real Ollama sends none", tc.method, tc.path, got)
		}
	}
}

// Real: /api/* is "application/json; charset=utf-8" (Gin), /v1/* is bare "application/json"
// (the OpenAI-compat layer). Serving one charset convention everywhere is a tell.
func TestContentTypeCharsetSplit(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/api/tags", "application/json; charset=utf-8"},
		{"/api/version", "application/json; charset=utf-8"},
		{"/api/ps", "application/json; charset=utf-8"},
		{"/v1/models", "application/json"},
	} {
		if got := do(t, "GET", tc.path, "").Header().Get("Content-Type"); got != tc.want {
			t.Errorf("%s: content-type %q, want %q", tc.path, got, tc.want)
		}
	}
}

// Real: `404 page not found`, Content-Type text/plain (no charset), Content-Length 18.
func TestNotFoundIsGinPlainText(t *testing.T) {
	// /props and /metrics are both observed in prod against the ollama port.
	for _, path := range []string{"/props", "/metrics", "/nonexistent-xyz"} {
		rec := do(t, "GET", path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/plain" {
			t.Errorf("%s: content-type %q, want text/plain", path, got)
		}
		if got := rec.Body.String(); got != "404 page not found" {
			t.Errorf("%s: body %q, want %q", path, got, "404 page not found")
		}
	}
}

// Real: GET /api/generate -> 405, Allow: POST, body "405 method not allowed".
func TestMethodNotAllowedCarriesAllow(t *testing.T) {
	rec := do(t, "GET", "/api/generate", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "POST" {
		t.Errorf("Allow %q, want POST", got)
	}
	if got := rec.Body.String(); got != "405 method not allowed" {
		t.Errorf("body %q", got)
	}
}

// Real: HEAD / -> 200 with Content-Length 17. gorilla/mux does not imply HEAD from GET, so this
// used to fall through to the 404 handler.
func TestHeadRootAnswers200(t *testing.T) {
	rec := do(t, "HEAD", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Length"); got != "17" {
		t.Errorf("Content-Length %q, want 17", got)
	}
}

// Real (OLLAMA_ORIGINS=*): preflight -> 204 with the X-Stainless-* allow-header list.
func TestCORSPreflight(t *testing.T) {
	rec := do(t, "OPTIONS", "/api/chat", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rec.Code)
	}
	h := rec.Header()
	if h.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("allow-origin %q", h.Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(h.Get("Access-Control-Allow-Headers"), "X-Stainless-Retry-Count") {
		t.Errorf("allow-headers missing the OpenAI SDK telemetry headers: %q", h.Get("Access-Control-Allow-Headers"))
	}
	if h.Get("Access-Control-Max-Age") != "43200" {
		t.Errorf("max-age %q, want 43200", h.Get("Access-Control-Max-Age"))
	}
}

// Real: a model the box has not pulled 404s. /api/* uses {"error":"model 'x' not found"};
// /v1/* uses the OpenAI envelope with explicit nulls.
func TestUnknownModelIsRejected(t *testing.T) {
	rec := do(t, "POST", "/api/chat", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":false}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/api/chat unknown model: status %d, want 404", rec.Code)
	}
	if got := rec.Body.String(); got != `{"error":"model 'gpt-4o' not found"}` {
		t.Errorf("/api/chat body %q", got)
	}

	rec = do(t, "POST", "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/v1 unknown model: status %d, want 404", rec.Code)
	}
	want := `{"error":{"message":"model 'gpt-4o' not found","type":"not_found_error","param":null,"code":null}}`
	if got := rec.Body.String(); got != want {
		t.Errorf("/v1 body:\n got %s\nwant %s", got, want)
	}
}

// The two names captured traffic actually probes must keep working.
func TestAdvertisedModelsStillServe(t *testing.T) {
	for _, m := range []string{"llama3.2:latest", "mistral:latest"} {
		rec := do(t, "POST", "/api/chat",
			`{"model":"`+m+`","messages":[{"role":"user","content":"Hello"}],"stream":false}`)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", m, rec.Code)
		}
	}
	// And every advertised model must be servable, or the catalog is lying.
	for _, m := range models.list(httptest.NewRequest("GET", "/", nil)) {
		rec := do(t, "POST", "/api/generate", `{"model":"`+m.Name+`","prompt":"hi","stream":false}`)
		if rec.Code != http.StatusOK {
			t.Errorf("advertised model %s not servable: status %d", m.Name, rec.Code)
		}
	}
}

// Real: malformed JSON -> 400 with the parse error echoed.
func TestMalformedJSONIsRejected(t *testing.T) {
	rec := do(t, "POST", "/api/generate", `not-json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("body %q", rec.Body.String())
	}
}

// Real: POST /api/show {} -> 400 {"error":"model is required"}.
func TestShowRequiresModel(t *testing.T) {
	rec := do(t, "POST", "/api/show", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if got := rec.Body.String(); got != `{"error":"model is required"}` {
		t.Errorf("body %q", got)
	}
}

// Real /api/show carries model_info (~36 keys), a tensor inventory and capabilities. The old
// five-key stub was recognisable at a glance.
func TestShowIsDetailed(t *testing.T) {
	rec := do(t, "POST", "/api/show", `{"model":"llama3.2:latest"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp showResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.ModelInfo) < 15 {
		t.Errorf("model_info has %d keys, real responses carry ~36", len(resp.ModelInfo))
	}
	if len(resp.Tensors) < 50 {
		t.Errorf("tensors has %d entries, real responses list one per layer", len(resp.Tensors))
	}
	if len(resp.Capabilities) == 0 {
		t.Error("capabilities missing")
	}
}

// /api/pull is observed in prod from three distinct IPs pulling llama3.2:1b. It must stream
// progress and leave the model listed, so the attacker goes on to use it.
func TestPullStreamsAndRegistersModel(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const name = "llama3.2:1b"
	t.Cleanup(func() { models.remove(httptest.NewRequest("GET", "/", nil), name) })

	rec := do(t, "POST", "/api/pull", `{"name":"`+name+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Errorf("content-type %q, want application/x-ndjson", got)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected a progress stream, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "pulling manifest") {
		t.Errorf("first line %q, want pulling manifest", lines[0])
	}
	if !strings.Contains(lines[len(lines)-1], `"success"`) {
		t.Errorf("last line %q, want success", lines[len(lines)-1])
	}
	// Every line must be valid JSON: a client streaming NDJSON will choke otherwise.
	for i, ln := range lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(ln), &v); err != nil {
			t.Fatalf("line %d is not JSON: %q", i, ln)
		}
	}
	if !models.has(httptest.NewRequest("GET", "/", nil), name) {
		t.Fatal("pulled model did not appear in the catalog")
	}
	// ...and is now servable and listed, which is the point of the divergence.
	if rec := do(t, "POST", "/api/generate", `{"model":"`+name+`","prompt":"hi","stream":false}`); rec.Code != http.StatusOK {
		t.Errorf("pulled model not servable: status %d", rec.Code)
	}
	if !strings.Contains(do(t, "GET", "/api/tags", "").Body.String(), name) {
		t.Error("pulled model missing from /api/tags")
	}
}

// /v1/responses is probed in prod by open-router-cli using models we advertise. Real modern
// Ollama implements it, so a 404 fails a validator the honeypot should pass.
func TestResponsesAPI(t *testing.T) {
	rec := do(t, "POST", "/v1/responses",
		`{"model":"mistral:latest","input":"Reply with OK.","temperature":0,"max_output_tokens":1,"stream":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var resp struct {
		Object string `json:"object"`
		Status string `json:"status"`
		Output []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v — %s", err, rec.Body.String())
	}
	if resp.Object != "response" || resp.Status != "completed" {
		t.Errorf("object=%q status=%q", resp.Object, resp.Status)
	}
	if len(resp.Output) == 0 || len(resp.Output[0].Content) == 0 || resp.Output[0].Content[0].Text != "OK" {
		t.Errorf("echo probe not answered: %s", rec.Body.String())
	}
}

// Real: 501, because no model in the catalog has embedding support.
func TestEmbeddingsReturn501(t *testing.T) {
	for _, path := range []string{"/api/embed", "/api/embeddings", "/v1/embeddings"} {
		rec := do(t, "POST", path, `{"model":"mistral:latest","input":"hi"}`)
		if rec.Code != http.StatusNotImplemented {
			t.Errorf("%s: status %d, want 501", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "does not support embeddings") {
			t.Errorf("%s: body %q", path, rec.Body.String())
		}
	}
}

// Real bodies are marshalled directly, with no trailing newline; json.Encoder.Encode adds one
// and inflates Content-Length by a byte against every real server.
func TestNoTrailingNewlineInJSONBodies(t *testing.T) {
	for _, path := range []string{"/api/tags", "/api/version", "/api/ps", "/v1/models"} {
		if body := do(t, "GET", path, "").Body.String(); strings.HasSuffix(body, "\n") {
			t.Errorf("%s: body has a trailing newline", path)
		}
	}
}

// encoding/json sorts map keys alphabetically; real servers marshal structs, so the key order is
// declaration order. Building payloads from maps produced an ordering no Ollama emits.
func TestTagsKeyOrderMatchesReal(t *testing.T) {
	body := do(t, "GET", "/api/tags", "").Body.String()
	want := []string{`"name"`, `"model"`, `"modified_at"`, `"size"`, `"digest"`, `"details"`, `"capabilities"`}
	idx := 0
	for _, key := range want {
		i := strings.Index(body[idx:], key)
		if i < 0 {
			t.Fatalf("key %s missing or out of order in /api/tags; real order is %v", key, want)
		}
		idx += i
	}
	// details itself is ordered too.
	di := strings.Index(body, `"details"`)
	sub := body[di:]
	for _, key := range []string{`"parent_model"`, `"format"`, `"family"`, `"families"`, `"parameter_size"`, `"quantization_level"`} {
		i := strings.Index(sub, key)
		if i < 0 {
			t.Fatalf("details key %s missing or out of order", key)
		}
		sub = sub[i:]
	}
}

// Real: system_fingerprint "fp_ollama" on every /v1 response and every SSE chunk.
func TestSystemFingerprintPresent(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"hi"}]}`)
	if !strings.Contains(rec.Body.String(), `"system_fingerprint":"fp_ollama"`) {
		t.Errorf("missing system_fingerprint: %s", rec.Body.String())
	}
}

// Real: max_tokens=1 truncates and reports finish_reason "length", not "stop".
func TestMaxTokensProducesLengthFinish(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"Reply with OK."}],"max_tokens":1,"stream":false}`)
	if !strings.Contains(rec.Body.String(), `"finish_reason":"length"`) {
		t.Errorf("want finish_reason length: %s", rec.Body.String())
	}
	// Ollama's native knob is options.num_predict.
	rec = do(t, "POST", "/api/chat",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"Hello"}],"stream":false,"options":{"num_predict":2}}`)
	if !strings.Contains(rec.Body.String(), `"done_reason":"length"`) {
		t.Errorf("want done_reason length: %s", rec.Body.String())
	}
}

// The old implementation returned these five constants on every request, so two requests from
// one scanner produced byte-identical duration fields.
func TestDurationsAreNotConstant(t *testing.T) {
	const banned = `"total_duration":1234567890`
	body1 := do(t, "POST", "/api/generate", `{"model":"mistral:latest","prompt":"hi","stream":false}`).Body.String()
	body2 := do(t, "POST", "/api/generate", `{"model":"mistral:latest","prompt":"hi there friend","stream":false}`).Body.String()
	for _, b := range []string{body1, body2} {
		if strings.Contains(b, banned) {
			t.Fatalf("placeholder duration still present: %s", b)
		}
	}
	re := regexp.MustCompile(`"total_duration":(\d+)`)
	m1, m2 := re.FindStringSubmatch(body1), re.FindStringSubmatch(body2)
	if m1 == nil || m2 == nil {
		t.Fatalf("no total_duration in responses")
	}
	if m1[1] == m2[1] {
		t.Errorf("total_duration identical across two different requests: %s", m1[1])
	}
	if !strings.Contains(body1, `"prompt_eval_duration"`) || !strings.Contains(body1, `"context"`) {
		t.Errorf("/api/generate missing prompt_eval_duration or context: %s", body1)
	}
}

// Real streams advance created_at per chunk; ours reused one timestamp for the whole stream.
func TestStreamTimestampsAdvance(t *testing.T) {
	rec := do(t, "POST", "/api/generate",
		`{"model":"mistral:latest","prompt":"tell me about databases","stream":true}`)
	var stamps []string
	for _, ln := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
		var v struct {
			CreatedAt string `json:"created_at"`
		}
		if json.Unmarshal([]byte(ln), &v) == nil && v.CreatedAt != "" {
			stamps = append(stamps, v.CreatedAt)
		}
	}
	if len(stamps) < 3 {
		t.Fatalf("expected a multi-chunk stream, got %d chunks", len(stamps))
	}
	if stamps[0] == stamps[len(stamps)-1] {
		t.Errorf("created_at identical across the whole stream (%s)", stamps[0])
	}
}

// Real SSE terminates with a literal "data: [DONE]".
func TestSSETerminator(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"say pong"}],"max_tokens":20,"stream":true}`)
	body := rec.Body.String()
	if !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Errorf("stream does not end with [DONE]: %q", body[max(0, len(body)-80):])
	}
	if !strings.Contains(body, `"system_fingerprint":"fp_ollama"`) {
		t.Errorf("SSE chunks missing system_fingerprint")
	}
}

// /api/ps should reflect a model that was just used, and fall off when keep_alive is 0.
func TestPsReflectsResidency(t *testing.T) {
	do(t, "POST", "/api/chat",
		`{"model":"gemma3:12b","messages":[{"role":"user","content":"hi"}],"stream":false}`)
	if !strings.Contains(do(t, "GET", "/api/ps", "").Body.String(), "gemma3:12b") {
		t.Error("/api/ps does not list a model that was just used")
	}
	do(t, "POST", "/api/chat",
		`{"model":"gemma3:12b","messages":[{"role":"user","content":"hi"}],"stream":false,"keep_alive":0}`)
	if strings.Contains(do(t, "GET", "/api/ps", "").Body.String(), "gemma3:12b") {
		t.Error("/api/ps still lists a model unloaded with keep_alive:0")
	}
}
