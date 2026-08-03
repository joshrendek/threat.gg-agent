package kubernetes

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

func TestResolvePortDefault(t *testing.T) {
	if port := resolvePort(); port != defaultPort {
		t.Fatalf("expected default port %q, got %q", defaultPort, port)
	}
}

func TestResolvePortOverride(t *testing.T) {
	t.Setenv("KUBERNETES_HONEYPOT_PORT", "16443")

	if port := resolvePort(); port != "16443" {
		t.Fatalf("expected overridden port %q, got %q", "16443", port)
	}
}

func TestCatchAllHandlerBoundsChunkedBodies(t *testing.T) {
	h := &honeypot{logger: zerolog.Nop()}
	req := httptest.NewRequest(http.MethodPost, "/unknown", strings.NewReader("small body"))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.catchAllHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected chunked request to succeed, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/unknown", strings.NewReader(strings.Repeat("x", maxKubernetesBodyBytes+1)))
	rec = httptest.NewRecorder()
	h.catchAllHandler(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized request to return 413, got %d", rec.Code)
	}
}

func TestLoggingMiddlewareCapturesStatusWithoutLoggingQuerySecrets(t *testing.T) {
	var output bytes.Buffer
	h := &honeypot{logger: zerolog.New(&output)}
	handler := h.LoggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing?access_token=super-secret", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(output.String(), `"status":404`) {
		t.Fatalf("expected logged 404 status, response=%d log=%s", rec.Code, output.String())
	}
	if strings.Contains(output.String(), "super-secret") {
		t.Fatalf("query secret leaked into log: %s", output.String())
	}
}

func TestRolesHandlerConcurrentReadsAndWrites(t *testing.T) {
	roleStoreMu.Lock()
	roleStore = make(map[string][]Role)
	roleStoreMu.Unlock()
	h := &honeypot{logger: zerolog.Nop()}
	const writers = 16
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles", strings.NewReader(`{"kind":"Role"}`))
			req = mux.SetURLVars(req, map[string]string{"namespace": "default"})
			h.rolesHandler(httptest.NewRecorder(), req)
		}()
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles", nil)
			req = mux.SetURLVars(req, map[string]string{"namespace": "default"})
			h.rolesHandler(httptest.NewRecorder(), req)
		}()
	}
	wg.Wait()
	roleStoreMu.RLock()
	got := len(roleStore["default"])
	roleStoreMu.RUnlock()
	if got != writers {
		t.Fatalf("expected %d stored roles, got %d", writers, got)
	}
}
