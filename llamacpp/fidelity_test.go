package llamacpp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// Regression tests for threat_gg-5g1. llama.cpp's server is cpp-httplib end to end (native and
// OpenAI-compat routes alike), so every JSON response — including /v1/chat/completions — carries
// "; charset=utf-8", unlike Ollama and vLLM where only part of the surface does.

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

// Every JSON-emitting route on this honeypot must carry the charset — verified against
// tools/server/server-http.cpp (error handler) and the wire behaviour cpp-httplib exhibits
// end-to-end, including its OpenAI-compat layer (unlike Ollama's, which does not).
func TestContentTypeCharsetEverywhere(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/props", ""},
		{"GET", "/health", ""},
		{"GET", "/v1/models", ""},
		{"GET", "/slots", ""},
		{"POST", "/completion", `{"prompt":"hello"}`},
		{"POST", "/tokenize", `{"content":"hello"}`},
		{"POST", "/detokenize", `{"tokens":[1,2,3]}`},
		{"POST", "/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`},
		{"GET", "/definitely-not-a-route", ""},
	} {
		rec := do(t, tc.method, tc.path, tc.body)
		if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("%s %s: content-type %q, want application/json; charset=utf-8", tc.method, tc.path, got)
		}
	}
}

// Real cpp-httplib's error_handler always answers a 404 with this exact envelope, regardless of
// which route's error path would otherwise fire — verified against
// tools/server/server-http.cpp's srv->set_error_handler.
func TestNotFoundIsCppHttplibShape(t *testing.T) {
	rec := do(t, "GET", "/definitely-not-a-route", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	want := `{"error":{"message":"File Not Found","type":"not_found_error","code":404}}`
	if got := rec.Body.String(); got != want {
		t.Errorf("body %q, want %q", got, want)
	}
}

// /props' chat_template must be Jinja2 (the model's real template), not the Go text/template
// syntax ("{{ .System }}") an Ollama Modelfile would use on a llama.cpp endpoint.
func TestPropsChatTemplateIsJinja2(t *testing.T) {
	rec := do(t, "GET", "/props", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		ChatTemplate string `json:"chat_template"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if strings.Contains(resp.ChatTemplate, "{{ .System }}") || strings.Contains(resp.ChatTemplate, "{{ .Prompt }}") {
		t.Errorf("chat_template still looks like a Go text/template: %q", resp.ChatTemplate)
	}
	if !strings.Contains(resp.ChatTemplate, "{%") || !strings.Contains(resp.ChatTemplate, "{{") {
		t.Errorf("chat_template does not look like Jinja2: %q", resp.ChatTemplate)
	}
	if !strings.Contains(resp.ChatTemplate, "[INST]") {
		t.Errorf("chat_template does not match the advertised Llama-2-chat model: %q", resp.ChatTemplate)
	}
}

// /props' key set is verified against the README's documented shape (see props.go's source
// comment): default_generation_settings, total_slots, model_path, chat_template,
// chat_template_caps, modalities, media_marker, build_info, is_sleeping — not the old five-key
// stub (which also carried a stray "system_prompt" key the real endpoint does not have).
func TestPropsKeySetMatchesDocumentedShape(t *testing.T) {
	body := do(t, "GET", "/props", "").Body.String()
	for _, key := range []string{
		`"default_generation_settings"`, `"total_slots"`, `"model_path"`, `"chat_template"`,
		`"chat_template_caps"`, `"modalities"`, `"media_marker"`, `"build_info"`, `"is_sleeping"`,
	} {
		if !strings.Contains(body, key) {
			t.Errorf("/props missing documented key %s: %s", key, body)
		}
	}
	if strings.Contains(body, `"system_prompt"`) {
		t.Error(`/props still carries "system_prompt", which is not part of the real response`)
	}
	var resp struct {
		DefaultGenerationSettings struct {
			ID           int  `json:"id"`
			IDTask       int  `json:"id_task"`
			NCtx         int  `json:"n_ctx"`
			IsProcessing bool `json:"is_processing"`
			NextToken    struct {
				HasNextToken bool `json:"has_next_token"`
			} `json:"next_token"`
		} `json:"default_generation_settings"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.DefaultGenerationSettings.NCtx != slotNCtx {
		t.Errorf("default_generation_settings.n_ctx = %d, want %d", resp.DefaultGenerationSettings.NCtx, slotNCtx)
	}
}

// POST /tokenize: {"tokens":[...]} by default, or [{"id","piece"}, ...] with with_pieces:true —
// verified against tools/server/server-context.cpp's post_tokenize handler.
func TestTokenize(t *testing.T) {
	rec := do(t, "POST", "/tokenize", `{"content":"hello world"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Tokens []int `json:"tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal plain tokens: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Tokens) == 0 {
		t.Fatal("no tokens returned")
	}

	rec = do(t, "POST", "/tokenize", `{"content":"hello world","with_pieces":true}`)
	var piecesResp struct {
		Tokens []struct {
			ID    int    `json:"id"`
			Piece string `json:"piece"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &piecesResp); err != nil {
		t.Fatalf("unmarshal with_pieces tokens: %v; body=%s", err, rec.Body.String())
	}
	if len(piecesResp.Tokens) == 0 {
		t.Fatal("no tokens returned for with_pieces:true")
	}
	var rebuilt strings.Builder
	for _, tok := range piecesResp.Tokens {
		rebuilt.WriteString(tok.Piece)
	}
	if rebuilt.String() != "hello world" {
		t.Errorf("pieces do not reconstruct the input: got %q, want %q", rebuilt.String(), "hello world")
	}
}

// POST /detokenize: {"content": "..."} — verified against post_detokenize. We hold no real
// vocabulary to reverse fabricated /tokenize ids through, so the honest answer is empty.
func TestDetokenize(t *testing.T) {
	rec := do(t, "POST", "/detokenize", `{"tokens":[1000,2000,3000]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Content *string `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if resp.Content == nil {
		t.Fatal(`"content" key missing from /detokenize response`)
	}
}

// GET /slots: an array of slot objects, matching total_slots:1 from /props — verified against
// get_slots / server_slot::to_json in server-context.cpp.
func TestSlots(t *testing.T) {
	rec := do(t, "GET", "/slots", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var slots []struct {
		ID           int  `json:"id"`
		NCtx         int  `json:"n_ctx"`
		Speculative  bool `json:"speculative"`
		IsProcessing bool `json:"is_processing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &slots); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if len(slots) != 1 {
		t.Fatalf("got %d slots, want 1 (matches /props total_slots)", len(slots))
	}
	if slots[0].NCtx != slotNCtx {
		t.Errorf("slot n_ctx = %d, want %d", slots[0].NCtx, slotNCtx)
	}
	if slots[0].IsProcessing {
		t.Error("a fresh slot must not be reported as processing")
	}
}

// The capture middleware must see these new routes too, so attacker requests to them are
// recorded rather than silently answered and dropped. isSignalPath already allowlists /slots,
// /tokenize, /detokenize (llmcore/filter.go's exactSignalPaths) — this exercises the full
// buildHandler() chain, not just the router, to confirm capture actually fires for them.
func TestNewEndpointsAreCaptured(t *testing.T) {
	orig := saveLlamacppRequest
	t.Cleanup(func() { saveLlamacppRequest = orig })

	var mu sync.Mutex
	captured := map[string]bool{}
	saveLlamacppRequest = func(req *proto.LlmRequest) error {
		mu.Lock()
		captured[req.Path] = true
		mu.Unlock()
		return nil
	}

	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/tokenize", `{"content":"hi"}`},
		{"POST", "/detokenize", `{"tokens":[1]}`},
		{"GET", "/slots", ""},
	} {
		var r *http.Request
		if tc.body != "" {
			r = httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		} else {
			r = httptest.NewRequest(tc.method, tc.path, nil)
		}
		rec := httptest.NewRecorder()
		buildHandler().ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Errorf("%s %s: status %d", tc.method, tc.path, rec.Code)
		}
	}

	// Capture is async (fire-and-forget goroutine); give it a moment to land.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(captured)
		mu.Unlock()
		if n == 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/tokenize", "/detokenize", "/slots"} {
		if !captured[path] {
			t.Errorf("%s was not captured", path)
		}
	}
}
