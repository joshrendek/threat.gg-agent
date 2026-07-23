package vllm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveVllmRequest = func(*proto.LlmRequest) error { return nil }
	os.Exit(m.Run())
}

func TestModelsListShape(t *testing.T) {
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Object string `json:"object"`
		Data   []struct {
			ID     string `json:"id"`
			Object string `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Object != "list" || len(resp.Data) == 0 || resp.Data[0].Object != "model" {
		t.Fatalf("bad models list: %s", rec.Body.String())
	}
}

func TestChatCompletionRouteIsDynamic(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`))
	buildHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"chat.completion"`) {
		t.Fatalf("chat route not dynamic: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Model != "x" {
		t.Fatalf("model not echoed: got %q, want %q (body: %s)", resp.Model, "x", rec.Body.String())
	}
}

func TestHealthOK(t *testing.T) {
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("health status = %d", rec.Code)
	}
}

func TestServerHeaderIdentity(t *testing.T) {
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if got := rec.Header().Get("Server"); !strings.Contains(got, "uvicorn") {
		t.Fatalf("Server header = %q, want uvicorn", got)
	}
}

func TestServerHeaderSurvivesCmdrespOverride(t *testing.T) {
	orig := cmdresp.GetCommandResponse
	cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: `{"overridden":true}`, Matched: true}, nil
	}
	t.Cleanup(func() { cmdresp.GetCommandResponse = orig })

	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if !strings.Contains(rec.Body.String(), "overridden") {
		t.Fatalf("expected cmdresp override body, got %s", rec.Body.String())
	}
	if got := rec.Header().Get("Server"); !strings.Contains(got, "uvicorn") {
		t.Fatalf("Server header lost on cmdresp override: %q", got)
	}
}

func TestCatchAll404(t *testing.T) {
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nonexistent", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("catch-all status = %d, want 404", rec.Code)
	}
}
