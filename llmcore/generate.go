package llmcore

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
)

// Model is one entry in an OpenAI /v1/models or Ollama catalog listing.
type Model struct {
	ID      string
	Created int64
	OwnedBy string
}

// replyPool holds benign, plausible assistant completions. They look like a real model
// reply but never actually help the attacker; the value is capturing the request, not
// producing useful output.
var replyPool = []string{
	"Hello! I'm here to help. Could you tell me a bit more about what you're trying to do?",
	"Sure — I can help with that. Let me know the specifics and I'll walk you through it.",
	"That's an interesting question. Here's a high-level overview to get you started.",
	"I understand what you're asking. Let me break this down step by step.",
	"Happy to help! Here are a few things to consider before we begin.",
}

func pickReply() string { return replyPool[rand.Intn(len(replyPool))] }

// estTokens is a cheap, plausible token estimate (~4 chars/token, floor 1).
func estTokens(s string) int {
	n := len(s) / 4
	if n < 1 {
		n = 1
	}
	return n
}

func wantsStream(body []byte, defaultStream bool) bool {
	var m struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.Stream == nil {
		return defaultStream
	}
	return *m.Stream
}

func promptText(body []byte) string {
	var m struct {
		Prompt   string `json:"prompt"`
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &m)
	if m.Prompt != "" {
		return m.Prompt
	}
	if len(m.Messages) > 0 {
		return m.Messages[len(m.Messages)-1].Content
	}
	return ""
}

func readBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
	return b
}

func modelOr(body []byte, def string) string {
	if m := ParseModel(body); m != "" {
		return m
	}
	return def
}

// ChatCompletion writes an OpenAI /v1/chat/completions response, streaming SSE chunks
// when the request asks for "stream":true (default false for chat).
func ChatCompletion(w http.ResponseWriter, r *http.Request, defaultModel string) {
	body := readBody(r)
	model := modelOr(body, defaultModel)
	reply := pickReply()
	id := "chatcmpl-" + uuid.NewV4().String()
	created := time.Now().Unix()

	if wantsStream(body, false) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		writeChunk := func(delta map[string]any, finish any) {
			chunk := map[string]any{
				"id": id, "object": "chat.completion.chunk", "created": created, "model": model,
				"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finish}},
			}
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
		}
		writeChunk(map[string]any{"role": "assistant"}, nil)
		for _, word := range splitWords(reply) {
			writeChunk(map[string]any{"content": word}, nil)
		}
		writeChunk(map[string]any{}, "stop")
		fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	pt := estTokens(promptText(body))
	ct := estTokens(reply)
	WriteJSON(w, http.StatusOK, map[string]any{
		"id": id, "object": "chat.completion", "created": created, "model": model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": reply},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct},
	})
}

// Completion writes an OpenAI /v1/completions (legacy text completion) response.
func Completion(w http.ResponseWriter, r *http.Request, defaultModel string) {
	body := readBody(r)
	model := modelOr(body, defaultModel)
	reply := pickReply()
	pt := estTokens(promptText(body))
	ct := estTokens(reply)
	WriteJSON(w, http.StatusOK, map[string]any{
		"id": "cmpl-" + uuid.NewV4().String(), "object": "text_completion",
		"created": time.Now().Unix(), "model": model,
		"choices": []map[string]any{{
			"text": reply, "index": 0, "logprobs": nil, "finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": pt, "completion_tokens": ct, "total_tokens": pt + ct},
	})
}

// OllamaGenerate writes an Ollama /api/generate response. Ollama streams NDJSON by
// default (one JSON object per line), ending with a done:true summary line; "stream":false
// collapses to a single object.
func OllamaGenerate(w http.ResponseWriter, r *http.Request, defaultModel string) {
	body := readBody(r)
	model := modelOr(body, defaultModel)
	reply := pickReply()
	created := time.Now().UTC().Format(time.RFC3339Nano)

	if !wantsStream(body, true) {
		WriteJSON(w, http.StatusOK, ollamaFinal(model, created, reply))
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	for _, word := range splitWords(reply) {
		_ = enc.Encode(map[string]any{"model": model, "created_at": created, "response": word, "done": false})
		if flusher != nil {
			flusher.Flush()
		}
	}
	_ = enc.Encode(ollamaFinal(model, created, ""))
	if flusher != nil {
		flusher.Flush()
	}
}

// OllamaChat writes an Ollama /api/chat response (message-shaped, single object when
// stream is false; NDJSON otherwise).
func OllamaChat(w http.ResponseWriter, r *http.Request, defaultModel string) {
	body := readBody(r)
	model := modelOr(body, defaultModel)
	reply := pickReply()
	created := time.Now().UTC().Format(time.RFC3339Nano)
	final := func(content string) map[string]any {
		m := map[string]any{
			"model": model, "created_at": created,
			"message":           map[string]any{"role": "assistant", "content": content},
			"done":              true,
			"total_duration":    1234567890,
			"eval_count":        estTokens(reply),
			"prompt_eval_count": estTokens(promptText(body)),
		}
		return m
	}
	if !wantsStream(body, true) {
		WriteJSON(w, http.StatusOK, final(reply))
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	for _, word := range splitWords(reply) {
		_ = enc.Encode(map[string]any{
			"model": model, "created_at": created,
			"message": map[string]any{"role": "assistant", "content": word}, "done": false,
		})
		if flusher != nil {
			flusher.Flush()
		}
	}
	_ = enc.Encode(final(""))
	if flusher != nil {
		flusher.Flush()
	}
}

func ollamaFinal(model, created, response string) map[string]any {
	return map[string]any{
		"model": model, "created_at": created, "response": response, "done": true,
		"done_reason":       "stop",
		"total_duration":    1234567890,
		"load_duration":     123456,
		"prompt_eval_count": 12,
		"eval_count":        24,
		"eval_duration":     987654,
	}
}

// splitWords chunks s into space-preserving tokens for streaming.
func splitWords(s string) []string {
	var out []string
	cur := ""
	for _, ch := range s {
		cur += string(ch)
		if ch == ' ' {
			out = append(out, cur)
			cur = ""
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
