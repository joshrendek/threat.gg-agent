package vllm

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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

func TestObservedSeedValidators(t *testing.T) {
	tests := []struct {
		name   string
		model  string
		prompt string
		want   string
	}{
		{
			name:   "exact hello-world echo",
			model:  "qwen3.6:27b",
			prompt: "Reply with exactly: hello world",
			want:   "hello world",
		},
		{
			name:   "natural-language multiplication",
			model:  defaultModel,
			prompt: "Calculate 17 multiplied by 23. Return only the number.",
			want:   "391",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"model":      test.model,
				"messages":   []map[string]string{{"role": "user", "content": test.prompt}},
				"max_tokens": 50,
			})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			buildHandler().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
			}
			var response struct {
				Model   string `json:"model"`
				Choices []struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				} `json:"choices"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if response.Model != test.model {
				t.Errorf("model = %q, want %q", response.Model, test.model)
			}
			if len(response.Choices) != 1 || response.Choices[0].Message.Content != test.want {
				t.Fatalf("response = %s, want content %q", rec.Body.String(), test.want)
			}
		})
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
	orig := cmdresp.GetCommandResponseWithin
	cmdresp.GetCommandResponseWithin = func(*proto.CommandRequest, time.Duration) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: `{"overridden":true}`, Matched: true}, nil
	}
	t.Cleanup(func() { cmdresp.GetCommandResponseWithin = orig })

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
