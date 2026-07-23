package ray

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveRayRequest = func(*proto.LlmRequest) error { return nil }
	os.Exit(m.Run())
}

func TestVersionAndJobSubmit(t *testing.T) {
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version"`) {
		t.Fatalf("version: %d %s", rec.Code, rec.Body.String())
	}
	// ShadowRay job submission — the highest-signal endpoint. Returns a submission id.
	rec2 := httptest.NewRecorder()
	newRouter().ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/api/jobs/",
		strings.NewReader(`{"entrypoint":"python -c 'import os; os.system(\"id\")'"}`)))
	if rec2.Code != http.StatusOK || !strings.Contains(rec2.Body.String(), "submission_id") {
		t.Fatalf("job submit: %d %s", rec2.Code, rec2.Body.String())
	}
}
