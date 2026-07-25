package comfyui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression tests for threat_gg-3kd. Real ComfyUI's PromptQueue.get_history (execution.py)
// returns {} both when nothing has ever completed and when a specific prompt_id is unknown —
// this honeypot never actually executes a submitted /prompt workflow, so both cases are always
// true here.

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

func TestHistoryIsEmptyObject(t *testing.T) {
	rec := do(t, "GET", "/history", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "{}" {
		t.Errorf("body %q, want %q", got, "{}")
	}
}

func TestHistoryByPromptIDIsEmptyObject(t *testing.T) {
	rec := do(t, "GET", "/history/00000000-0000-4000-8000-000000000000", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "{}" {
		t.Errorf("body %q, want %q", got, "{}")
	}
}

// PR #33 review: the two tests above only prove /history is {} on a fresh router — they would
// still pass even if a regression started recording submitted prompts into some in-memory
// history. The actual contract is that /history stays {} *after* a workflow has been submitted
// via /prompt too, since this honeypot never executes what it accepts.
func TestHistoryStaysEmptyAfterPromptSubmission(t *testing.T) {
	promptRec := do(t, "POST", "/prompt", `{"prompt":{"1":{"class_type":"KSampler"}}}`)
	if promptRec.Code != http.StatusOK {
		t.Fatalf("/prompt: status %d", promptRec.Code)
	}
	var promptResp struct {
		PromptID string `json:"prompt_id"`
	}
	if err := json.Unmarshal(promptRec.Body.Bytes(), &promptResp); err != nil {
		t.Fatalf("unmarshal /prompt response: %v; body=%s", err, promptRec.Body.String())
	}
	if promptResp.PromptID == "" {
		t.Fatal("/prompt did not return a prompt_id")
	}

	if got := strings.TrimSpace(do(t, "GET", "/history", "").Body.String()); got != "{}" {
		t.Errorf("/history after submission: body %q, want %q", got, "{}")
	}
	if got := strings.TrimSpace(do(t, "GET", "/history/"+promptResp.PromptID, "").Body.String()); got != "{}" {
		t.Errorf("/history/%s after submission: body %q, want %q", promptResp.PromptID, got, "{}")
	}
}
