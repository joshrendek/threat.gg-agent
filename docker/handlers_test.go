package docker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func newTestRouter() http.Handler {
	r := mux.NewRouter()
	registerRoutes(r)
	return normalizeAPIVersion(r)
}

func TestVersionedRoutesUseCanonicalHandlers(t *testing.T) {
	tests := []struct {
		method string
		path   string
		body   string
		status int
		want   string
	}{
		{"GET", "/v1.43/_ping", "", http.StatusOK, "OK"},
		{"GET", "/v1.43/version", "", http.StatusOK, `"ApiVersion": "1.43"`},
		{"GET", "/v1.43/info", "", http.StatusOK, `"ServerVersion": "24.0.7"`},
		{"GET", "/v1.43/containers/json", "", http.StatusOK, `"Names"`},
		{"POST", "/v1.43/containers/create", `{"Image":"alpine"}`, http.StatusCreated, fakeContainerID},
		{"POST", "/v1.43/containers/" + fakeContainerID + "/start", "", http.StatusNoContent, ""},
		{"GET", "/v1.43/containers/" + fakeContainerID + "/json", "", http.StatusOK, fakeContainerID},
		{"POST", "/v1.43/containers/" + fakeContainerID + "/exec", `{}`, http.StatusCreated, fakeExecID},
		{"POST", "/v1.43/exec/" + fakeExecID + "/start", `{}`, http.StatusOK, ""},
		{"GET", "/v1.43/images/json", "", http.StatusOK, `"RepoTags"`},
		{"POST", "/v1.43/images/create", "", http.StatusOK, "Pulling"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			r := newTestRouter()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tt.status, w.Body.String())
			}
			if tt.want != "" && !strings.Contains(w.Body.String(), tt.want) {
				t.Fatalf("body %q does not contain %q", w.Body.String(), tt.want)
			}
		})
	}
}

func TestNormalizeAPIVersionPreservesOriginalPathForCapture(t *testing.T) {
	var normalizedPath, capturedPath string
	handler := normalizeAPIVersion(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		normalizedPath = r.URL.Path
		capturedPath = capturedRequestPath(r)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1.43/containers/create", nil))
	if normalizedPath != "/containers/create" {
		t.Fatalf("normalized path = %q", normalizedPath)
	}
	if capturedPath != "/v1.43/containers/create" {
		t.Fatalf("captured path = %q", capturedPath)
	}
}

func TestNormalizeAPIVersionLeavesNonVersionPrefixAlone(t *testing.T) {
	var got string
	normalizeAPIVersion(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/version", nil))
	if got != "/version" {
		t.Fatalf("path = %q", got)
	}
}

func TestCaptureWrapsMatchedAndUnmatchedOverridesExactlyOnce(t *testing.T) {
	for _, matched := range []bool{true, false} {
		t.Run(map[bool]string{true: "matched", false: "unmatched"}[matched], func(t *testing.T) {
			saved := make(chan *proto.DockerRequest, 2)
			originalSave := saveDockerRequest
			originalLookup := cmdresp.GetCommandResponse
			saveDockerRequest = func(request *proto.DockerRequest) error {
				saved <- request
				return nil
			}
			cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
				return &proto.CommandResponse{Response: "OVERRIDE", Matched: matched}, nil
			}
			t.Cleanup(func() {
				saveDockerRequest = originalSave
				cmdresp.GetCommandResponse = originalLookup
			})

			nextCalls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalls++
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"Image":"alpine"}` {
					t.Errorf("downstream body = %q", body)
				}
				w.WriteHeader(http.StatusAccepted)
			})
			handler := normalizeAPIVersion(captureRequests(cmdresp.MuxMiddleware("docker")(next)))
			request := httptest.NewRequest(http.MethodPost, "/v1.43/containers/create", strings.NewReader(`{"Image":"alpine"}`))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			select {
			case captured := <-saved:
				if captured.Path != "/v1.43/containers/create" || captured.Body != `{"Image":"alpine"}` {
					t.Fatalf("captured request = %+v", captured)
				}
			case <-time.After(time.Second):
				t.Fatal("request was not captured")
			}
			select {
			case duplicate := <-saved:
				t.Fatalf("request captured twice: %+v", duplicate)
			case <-time.After(25 * time.Millisecond):
			}
			if matched && nextCalls != 0 {
				t.Fatalf("matched override called downstream %d times", nextCalls)
			}
			if !matched && nextCalls != 1 {
				t.Fatalf("unmatched override called downstream %d times", nextCalls)
			}
		})
	}
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
