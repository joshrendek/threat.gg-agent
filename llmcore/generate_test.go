package llmcore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChatCompletionNonStreamEchoesModelAndShape(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"mixtral","messages":[{"role":"user","content":"hi there"}]}`))
	rec := httptest.NewRecorder()
	ChatCompletion(rec, req, "gpt-3.5-turbo")

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
	ChatCompletion(rec, req, "gpt-3.5-turbo")

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
	OllamaGenerate(rec, req, "llama3.2")
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
	OllamaGenerate(rec, req, "llama3.2")
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
