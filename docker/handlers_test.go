package docker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func newTestRouter() *mux.Router {
	r := mux.NewRouter()
	registerRoutes(r)
	return r
}

func TestPing(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/_ping", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); body != "OK" {
		t.Errorf("expected 'OK', got %q", body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", ct)
	}
}

func TestVersion(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/version", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if v, ok := result["Version"].(string); !ok || v != serverVersion {
		t.Errorf("expected version %s, got %v", serverVersion, result["Version"])
	}
	if v, ok := result["ApiVersion"].(string); !ok || v != apiVersion {
		t.Errorf("expected api version %s, got %v", apiVersion, result["ApiVersion"])
	}
}

func TestInfo(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/info", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if v, ok := result["ServerVersion"].(string); !ok || v != serverVersion {
		t.Errorf("expected server version %s, got %v", serverVersion, result["ServerVersion"])
	}
	if v, ok := result["Containers"].(float64); !ok || v != 3 {
		t.Errorf("expected 3 containers, got %v", result["Containers"])
	}
}

func TestContainerList(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/containers/json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON array: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 containers, got %d", len(result))
	}
}

func TestContainerCreate(t *testing.T) {
	r := newTestRouter()
	body := `{"Image":"xmrig/xmrig:latest","Cmd":["xmrig","--url=pool.mining.com"],"HostConfig":{"Binds":["/:/host"]}}`
	req := httptest.NewRequest("POST", "/containers/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := result["Id"]; !ok {
		t.Error("response missing 'Id' field")
	}
	if _, ok := result["Warnings"]; !ok {
		t.Error("response missing 'Warnings' field")
	}
}

func TestContainerStart(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("POST", "/containers/abc123/start", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestExecCreate(t *testing.T) {
	r := newTestRouter()
	body := `{"Cmd":["sh","-c","cat /etc/shadow"],"AttachStdout":true,"AttachStderr":true}`
	req := httptest.NewRequest("POST", "/containers/abc123/exec", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := result["Id"]; !ok {
		t.Error("response missing 'Id' field")
	}
}

func TestExecStart(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("POST", "/exec/abc123/start", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestImageList(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/images/json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON array: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 images, got %d", len(result))
	}
}

func TestImageCreate(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("POST", "/images/create?fromImage=alpine&tag=latest", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Pulling") {
		t.Error("expected pull progress in response")
	}
}

func TestCatchAll(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/v1.43/some/unknown/path", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestContainerInspect(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/containers/abc123/json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := result["Id"]; !ok {
		t.Error("response missing 'Id' field")
	}
	if _, ok := result["State"]; !ok {
		t.Error("response missing 'State' field")
	}
}

func TestBasicAuthExtraction(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/_ping", nil)
	req.SetBasicAuth("admin", "secret123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServerHeaders(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest("GET", "/version", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	server := w.Header().Get("Server")
	if !strings.Contains(server, "Docker") {
		t.Errorf("expected Docker in Server header, got %q", server)
	}
	apiVer := w.Header().Get("Api-Version")
	if apiVer != apiVersion {
		t.Errorf("expected Api-Version %s, got %q", apiVersion, apiVer)
	}
}
