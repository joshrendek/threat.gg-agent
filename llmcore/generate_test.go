package llmcore

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestChatCompletionNonStreamEchoesModelAndShape(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"mixtral","messages":[{"role":"user","content":"hi there"}]}`))
	rec := httptest.NewRecorder()
	ChatCompletion(rec, req, Profile{DefaultModel: "gpt-3.5-turbo"})

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q", ct)
	}
	var resp struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v; body=%s", err, rec.Body.String())
	}
	if !strings.HasPrefix(resp.ID, "chatcmpl-") {
		t.Fatalf("id = %q, want chatcmpl- prefix", resp.ID)
	}
	if resp.Object != "chat.completion" {
		t.Fatalf("object = %q", resp.Object)
	}
	if resp.Model != "mixtral" {
		t.Fatalf("model = %q, want echoed mixtral", resp.Model)
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Role != "assistant" ||
		resp.Choices[0].Message.Content == "" || resp.Choices[0].FinishReason != "stop" {
		t.Fatalf("bad choices: %+v", resp.Choices)
	}
	if resp.Usage.PromptTokens <= 0 || resp.Usage.CompletionTokens <= 0 ||
		resp.Usage.TotalTokens != resp.Usage.PromptTokens+resp.Usage.CompletionTokens {
		t.Fatalf("bad usage: %+v", resp.Usage)
	}
}

func TestChatCompletionStreamEmitsSSEChunksAndDone(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"llama3","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	rec := httptest.NewRecorder()
	ChatCompletion(rec, req, Profile{DefaultModel: "gpt-3.5-turbo"})

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"object":"chat.completion.chunk"`) {
		t.Fatalf("missing chunk object; body=%s", body)
	}
	if !strings.Contains(body, `"finish_reason":"stop"`) {
		t.Fatalf("missing terminal finish_reason; body=%s", body)
	}
	if !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Fatalf("stream must end with data: [DONE]; body=%s", body)
	}
}

func TestOllamaGenerateNonStream(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/generate",
		strings.NewReader(`{"model":"llama3.2","prompt":"why is the sky blue","stream":false}`))
	rec := httptest.NewRecorder()
	OllamaGenerate(rec, req, Profile{DefaultModel: "llama3.2"})
	var resp struct {
		Model    string `json:"model"`
		Response string `json:"response"`
		Done     bool   `json:"done"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v; body=%s", err, rec.Body.String())
	}
	if resp.Model != "llama3.2" || resp.Response == "" || !resp.Done {
		t.Fatalf("bad ollama generate resp: %+v", resp)
	}
}

func TestOllamaGenerateStreamNDJSONEndsDone(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/generate",
		strings.NewReader(`{"model":"llama3.2","prompt":"hi"}`)) // stream defaults true
	rec := httptest.NewRecorder()
	OllamaGenerate(rec, req, Profile{DefaultModel: "llama3.2"})
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("want multiple NDJSON lines, got %d", len(lines))
	}
	var last struct {
		Done bool `json:"done"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil || !last.Done {
		t.Fatalf("last NDJSON line must have done:true; got %q", lines[len(lines)-1])
	}
}

func TestOllamaGenerateEmptyPromptUsesLoadAndUnloadLifecycle(t *testing.T) {
	const model = "qwen2.5-coder:7b"
	models.mu.Lock()
	original := models.residing
	models.residing = map[string]time.Time{}
	models.mu.Unlock()
	t.Cleanup(func() {
		models.mu.Lock()
		models.residing = original
		models.mu.Unlock()
	})

	tests := []struct {
		name       string
		body       string
		reason     string
		wantLoaded bool
	}{
		{
			name:       "null prompt loads despite stream true",
			body:       `{"model":"qwen2.5-coder:7b","prompt":null,"stream":true}`,
			reason:     "load",
			wantLoaded: true,
		},
		{
			name:       "explicit empty prompt loads",
			body:       `{"model":"qwen2.5-coder:7b","prompt":"","stream":false}`,
			reason:     "load",
			wantLoaded: true,
		},
		{
			name:       "zero keep alive unloads",
			body:       `{"model":"qwen2.5-coder:7b","prompt":null,"keep_alive":0}`,
			reason:     "unload",
			wantLoaded: false,
		},
		{
			name:       "negative keep alive retains indefinitely",
			body:       `{"model":"qwen2.5-coder:7b","prompt":null,"keep_alive":-1}`,
			reason:     "load",
			wantLoaded: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/generate", strings.NewReader(test.body))
			rec := httptest.NewRecorder()
			OllamaGenerate(rec, req, Profile{DefaultModel: model})
			if got := rec.Header().Get("Content-Type"); got != CTJSON {
				t.Fatalf("content type = %q, want %q", got, CTJSON)
			}
			var response map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("invalid JSON: %v; body=%s", err, rec.Body.String())
			}
			if response["model"] != model || response["response"] != "" ||
				response["done"] != true || response["done_reason"] != test.reason {
				t.Fatalf("lifecycle response = %#v", response)
			}
			if len(response) != 5 {
				t.Fatalf("lifecycle response keys = %#v, want only real Ollama's five keys", response)
			}
			_, loaded := ResidentModels()[model]
			if loaded != test.wantLoaded {
				t.Fatalf("loaded = %v, want %v", loaded, test.wantLoaded)
			}
			if strings.Contains(test.body, `"keep_alive":-1`) {
				if deadline := ResidentModels()[model]; deadline.Year() != 9999 {
					t.Fatalf("indefinite residency deadline = %v, want year 9999 sentinel", deadline)
				}
			}
		})
	}
}

func TestOllamaGenerateMissingBodyIsNotLifecycleRequest(t *testing.T) {
	for _, test := range []struct {
		name string
		body func() io.Reader
	}{
		{name: "nil body"},
		{name: "empty reader", body: func() io.Reader { return strings.NewReader("") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var body io.Reader
			if test.body != nil {
				body = test.body()
			}
			req := httptest.NewRequest(http.MethodPost, "/api/generate", body)
			rec := httptest.NewRecorder()
			OllamaGenerate(rec, req, Profile{DefaultModel: "llama3.2:latest"})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Body.String(); got != `{"error":"missing request body"}` {
				t.Fatalf("body = %q", got)
			}
		})
	}
}

func TestOllamaGenerateLifecycleRequiresModel(t *testing.T) {
	for _, body := range []string{`{}`, `{"prompt":null}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/generate", strings.NewReader(body))
		rec := httptest.NewRecorder()
		OllamaGenerate(rec, req, Profile{DefaultModel: "llama3.2:latest"})
		if rec.Code != http.StatusNotFound {
			t.Fatalf("body %s: status = %d, want 404; response=%s", body, rec.Code, rec.Body.String())
		}
		if got := rec.Body.String(); got != `{"error":"model '' not found"}` {
			t.Fatalf("body %s: response = %q", body, got)
		}
	}
}
