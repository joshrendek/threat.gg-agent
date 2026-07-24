package llmcore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestIsSignalPath(t *testing.T) {
	signal := []string{
		"/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/embeddings",
		"/v1/responses", // new OpenAI Responses API — caught by the /v1/ rule
		"/api/tags", "/api/generate", "/api/chat", "/api/version", "/api/ps",
		"/api/show", "/api/pull", "/api/embeddings", "/api/jobs/", "/api/jobs/raysubmit_x",
		"/api/cluster_status", "/models", "/props", "/health", "/readyz", "/metrics",
		"/completion", "/tokenize", "/system_stats", "/object_info", "/queue", "/prompt",
		"/nodes", "/v1/models/", // trailing slash tolerated
	}
	for _, p := range signal {
		if !isSignalPath(p) {
			t.Errorf("isSignalPath(%q) = false, want true (signal)", p)
		}
	}
	noise := []string{
		"", "/", "/favicon.ico", "/SDK/webLanguage", "/login", "/robots.txt", "/sitemap.xml",
		"/nice ports,/Trinity.txt.bak", "*", "/mcp", "/sse", "/api", "/app", "/_next",
		"/_next/server", "/api/route", "/../../../../etc/passwd", "/HNAP1", "/webui",
		"/.well-known/security.txt", "/evox/about", "/sdk",
	}
	for _, p := range noise {
		if isSignalPath(p) {
			t.Errorf("isSignalPath(%q) = true, want false (noise)", p)
		}
	}
}

func TestCaptureDropsNoiseSavesSignal(t *testing.T) {
	call := func(method, path, body string) (saved bool, servedNext bool) {
		got := make(chan *proto.LlmRequest, 1)
		save := func(in *proto.LlmRequest) error { got <- in; return nil }
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true; w.WriteHeader(200) })
		var rdr *strings.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		var req *http.Request
		if rdr != nil {
			req = httptest.NewRequest(method, path, rdr)
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		Capture(save)(next).ServeHTTP(httptest.NewRecorder(), req)
		select {
		case <-got:
			return true, nextCalled
		case <-time.After(150 * time.Millisecond):
			return false, nextCalled
		}
	}

	// Noise: NOT persisted, but the honeypot still responds (next called).
	for _, tc := range []struct{ m, p string }{
		{"GET", "/"}, {"GET", "/favicon.ico"}, {"POST", "/api/route"}, {"GET", "/HNAP1"},
	} {
		saved, served := call(tc.m, tc.p, "")
		if saved {
			t.Errorf("%s %s: was persisted, want dropped as noise", tc.m, tc.p)
		}
		if !served {
			t.Errorf("%s %s: downstream handler not called (honeypot must still respond)", tc.m, tc.p)
		}
	}

	// Signal: persisted.
	saved, served := call("POST", "/v1/chat/completions", `{"model":"x","messages":[]}`)
	if !saved {
		t.Error("POST /v1/chat/completions: not persisted, want captured (signal)")
	}
	if !served {
		t.Error("signal request: downstream not called")
	}
	if saved, _ := call("GET", "/api/tags", ""); !saved {
		t.Error("GET /api/tags: not persisted, want captured (signal)")
	}
}
