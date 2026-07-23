package llamacpp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveLlamacppRequest = func(*proto.LlmRequest) error { return nil }
	os.Exit(m.Run())
}

func TestLlamacppPropsAndCompletion(t *testing.T) {
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/props", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "default_generation_settings") {
		t.Fatalf("props: %d %s", rec.Code, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	newRouter().ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/completion",
		strings.NewReader(`{"prompt":"hello"}`)))
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), `"content"`) {
		t.Fatalf("completion: %d %s", rec2.Code, rec2.Body.String())
	}
}
