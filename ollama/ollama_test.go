package ollama

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveOllamaRequest = func(*proto.LlmRequest) error { return nil }
	os.Exit(m.Run())
}

func TestRootBanner(t *testing.T) {
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Ollama is running") {
		t.Fatalf("root banner: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTagsList(t *testing.T) {
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/tags", nil))
	var resp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Models) == 0 {
		t.Fatalf("tags: %v %s", err, rec.Body.String())
	}
}

func TestGenerateNonStreamAndOpenAIAlias(t *testing.T) {
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/generate",
		strings.NewReader(`{"model":"llama3.2","prompt":"hi","stream":false}`)))
	if !strings.Contains(rec.Body.String(), `"done":true`) {
		t.Fatalf("generate: %s", rec.Body.String())
	}
	// OpenAI-compat alias
	rec2 := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`)))
	if !strings.Contains(rec2.Body.String(), `"chat.completion"`) {
		t.Fatalf("v1 alias: %s", rec2.Body.String())
	}
}

// TestCORSSurvivesCmdrespOverride pins the middleware ordering: an admin-authored cmdresp
// override short-circuits the router, and the identity middleware must still have run.
//
// This test previously asserted the opposite of what it does now — it required a
// "Server: Ollama" header. That header was the single worst fingerprint on the honeypot: real
// Ollama is built on Gin and sends no Server header at all, so emitting one was a positive
// honeypot signature rather than a missing detail. The ordering guarantee is still worth
// pinning, so the assertion now rides on the CORS header, which real Ollama does send.
func TestCORSSurvivesCmdrespOverride(t *testing.T) {
	orig := cmdresp.GetCommandResponseWithin
	cmdresp.GetCommandResponseWithin = func(*proto.CommandRequest, time.Duration) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: `{"overridden":true}`, Matched: true}, nil
	}
	t.Cleanup(func() { cmdresp.GetCommandResponseWithin = orig })
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	// Cross-origin, because CORS headers are only emitted for a real CORS request.
	req.Header.Set("Origin", "http://evil.test")
	buildHandler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "overridden") {
		t.Fatalf("expected override body, got %s", rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("CORS header lost on cmdresp override: %q", got)
	}
	if got := rec.Header().Get("Server"); got != "" {
		t.Fatalf("Server header must never be set (real Ollama sends none), got %q", got)
	}
}
