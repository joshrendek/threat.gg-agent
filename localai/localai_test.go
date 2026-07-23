package localai

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveLocalaiRequest = func(*proto.LlmRequest) error { return nil }
	os.Exit(m.Run())
}

func TestLocalaiModelsAndChat(t *testing.T) {
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"list"`) {
		t.Fatalf("models: %d %s", rec.Code, rec.Body.String())
	}
	// LocalAI also serves a bare /models alias.
	rec2 := httptest.NewRecorder()
	newRouter().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/models", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("/models alias status = %d", rec2.Code)
	}
	rec3 := httptest.NewRecorder()
	newRouter().ServeHTTP(rec3, httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`)))
	if !strings.Contains(rec3.Body.String(), `"chat.completion"`) {
		t.Fatalf("chat not dynamic: %s", rec3.Body.String())
	}
}
