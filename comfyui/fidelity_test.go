package comfyui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression tests for threat_gg-3kd. Real ComfyUI's PromptQueue.get_history (execution.py)
// returns {} both when nothing has ever completed and when a specific prompt_id is unknown —
// this honeypot never actually executes a submitted /prompt workflow, so both cases are always
// true here.

func do(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHistoryIsEmptyObject(t *testing.T) {
	rec := do(t, "GET", "/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "{}" {
		t.Errorf("body %q, want %q", got, "{}")
	}
}

func TestHistoryByPromptIDIsEmptyObject(t *testing.T) {
	rec := do(t, "GET", "/history/00000000-0000-4000-8000-000000000000")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "{}" {
		t.Errorf("body %q, want %q", got, "{}")
	}
}
