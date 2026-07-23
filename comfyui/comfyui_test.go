package comfyui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveComfyuiRequest = func(*proto.LlmRequest) error { return nil }
	os.Exit(m.Run())
}

func TestSystemStatsAndPrompt(t *testing.T) {
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/system_stats", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "system") {
		t.Fatalf("system_stats: %d %s", rec.Code, rec.Body.String())
	}
	// Workflow submission (custom-node RCE surface) — returns a prompt_id.
	rec2 := httptest.NewRecorder()
	newRouter().ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/prompt",
		strings.NewReader(`{"prompt":{"1":{"class_type":"Evil"}}}`)))
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), "prompt_id") {
		t.Fatalf("prompt: %d %s", rec2.Code, rec2.Body.String())
	}
}
