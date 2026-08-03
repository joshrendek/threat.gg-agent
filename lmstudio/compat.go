package lmstudio

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/llmcore"
	uuid "github.com/satori/go.uuid"
)

type responseContent struct {
	Type        string `json:"type"`
	Text        string `json:"text"`
	Annotations []any  `json:"annotations"`
}

type responseOutput struct {
	ID      string            `json:"id"`
	Type    string            `json:"type"`
	Status  string            `json:"status"`
	Role    string            `json:"role"`
	Content []responseContent `json:"content"`
}

type responseUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type responsesResult struct {
	ID        string           `json:"id"`
	Object    string           `json:"object"`
	CreatedAt int64            `json:"created_at"`
	Status    string           `json:"status"`
	Model     string           `json:"model"`
	Output    []responseOutput `json:"output"`
	Usage     responseUsage    `json:"usage"`
}

func handleResponses(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Model  string          `json:"model"`
		Input  json.RawMessage `json:"input"`
		Stream bool            `json:"stream"`
	}
	if !decodeJSON(r, &request) {
		llmcore.WriteOpenAIError(w, profile, http.StatusBadRequest, "Invalid JSON body", "invalid_request_error")
		return
	}
	if request.Model == "" {
		request.Model = defaultModel
	}
	if candidate, ok := models.get(r, request.Model); !ok || candidate.Type != "llm" {
		llmcore.WriteModelNotFoundV1(w, profile, request.Model)
		return
	}
	prompt := promptFromRaw(request.Input)
	reply := llmcore.ClassifiedReply(r, prompt, request.Model).Text
	words := strings.Fields(reply)
	id := "resp_" + strings.ReplaceAll(uuid.NewV4().String(), "-", "")
	messageID := "msg_" + strings.ReplaceAll(uuid.NewV4().String(), "-", "")
	result := responsesResult{
		ID: id, Object: "response", CreatedAt: time.Now().Unix(), Status: "completed", Model: request.Model,
		Output: []responseOutput{{
			ID: messageID, Type: "message", Status: "completed", Role: "assistant",
			Content: []responseContent{{Type: "output_text", Text: reply, Annotations: []any{}}},
		}},
		Usage: responseUsage{InputTokens: 28 + max(1, len(prompt)/4), OutputTokens: max(1, len(words))},
	}
	result.Usage.TotalTokens = result.Usage.InputTokens + result.Usage.OutputTokens
	if request.Stream {
		streamResponses(w, result, messageID, words)
		return
	}
	writeCompactJSON(w, http.StatusOK, result)
}

func streamResponses(w http.ResponseWriter, result responsesResult, messageID string, words []string) {
	w.Header().Set("Content-Type", llmcore.CTEventStream)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	emit := func(event string, value any) {
		body, _ := json.Marshal(value)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body)
		if flusher != nil {
			flusher.Flush()
		}
	}
	emit("response.created", map[string]any{"type": "response.created", "response": result, "sequence_number": 0})
	for i, word := range words {
		if i+1 < len(words) {
			word += " "
		}
		emit("response.output_text.delta", map[string]any{
			"type": "response.output_text.delta", "item_id": messageID,
			"output_index": 0, "content_index": 0, "delta": word, "sequence_number": i + 1,
		})
	}
	emit("response.completed", map[string]any{
		"type": "response.completed", "response": result, "sequence_number": len(words) + 1,
	})
}

type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicResult struct {
	ID           string             `json:"id"`
	Type         string             `json:"type"`
	Role         string             `json:"role"`
	Model        string             `json:"model"`
	Content      []anthropicContent `json:"content"`
	StopReason   string             `json:"stop_reason"`
	StopSequence *string            `json:"stop_sequence"`
	Usage        anthropicUsage     `json:"usage"`
}

func handleMessages(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Model     string `json:"model"`
		MaxTokens int    `json:"max_tokens"`
		Stream    bool   `json:"stream"`
		Messages  []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if !decodeJSON(r, &request) {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON body")
		return
	}
	if request.Model == "" {
		request.Model = defaultModel
	}
	if candidate, ok := models.get(r, request.Model); !ok || candidate.Type != "llm" {
		writeAnthropicError(w, http.StatusNotFound, "not_found_error", "model: "+request.Model)
		return
	}
	prompt := ""
	if len(request.Messages) > 0 {
		prompt = promptFromRaw(request.Messages[len(request.Messages)-1].Content)
	}
	reply := llmcore.ClassifiedReply(r, prompt, request.Model).Text
	words := strings.Fields(reply)
	if request.MaxTokens > 0 && len(words) > request.MaxTokens {
		words = words[:request.MaxTokens]
		reply = strings.Join(words, " ")
	}
	result := anthropicResult{
		ID: "msg_" + strings.ReplaceAll(uuid.NewV4().String(), "-", ""), Type: "message",
		Role: "assistant", Model: request.Model,
		Content: []anthropicContent{{Type: "text", Text: reply}}, StopReason: "end_turn",
		Usage: anthropicUsage{InputTokens: 28 + max(1, len(prompt)/4), OutputTokens: max(1, len(words))},
	}
	if request.Stream {
		streamMessages(w, result, words)
		return
	}
	writeCompactJSON(w, http.StatusOK, result)
}

func writeAnthropicError(w http.ResponseWriter, status int, errType, message string) {
	writeCompactJSON(w, status, map[string]any{
		"type": "error", "error": map[string]string{"type": errType, "message": message},
	})
}

func streamMessages(w http.ResponseWriter, result anthropicResult, words []string) {
	w.Header().Set("Content-Type", llmcore.CTEventStream)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	emit := func(event string, value any) {
		body, _ := json.Marshal(value)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body)
		if flusher != nil {
			flusher.Flush()
		}
	}
	start := result
	start.Content = []anthropicContent{}
	start.StopReason = ""
	emit("message_start", map[string]any{"type": "message_start", "message": start})
	emit("content_block_start", map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]string{"type": "text", "text": ""}})
	for i, word := range words {
		if i+1 < len(words) {
			word += " "
		}
		emit("content_block_delta", map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": word}})
	}
	emit("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	emit("message_delta", map[string]any{"type": "message_delta", "delta": map[string]string{"stop_reason": "end_turn"}, "usage": map[string]int{"output_tokens": result.Usage.OutputTokens}})
	emit("message_stop", map[string]string{"type": "message_stop"})
}

func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Model string          `json:"model"`
		Input json.RawMessage `json:"input"`
	}
	if !decodeJSON(r, &request) {
		llmcore.WriteOpenAIError(w, profile, http.StatusBadRequest, "Invalid JSON body", "invalid_request_error")
		return
	}
	if request.Model == "" {
		request.Model = embeddingModel
	}
	if candidate, ok := models.get(r, request.Model); !ok || candidate.Type != "embedding" {
		llmcore.WriteModelNotFoundV1(w, profile, request.Model)
		return
	}
	input := promptFromRaw(request.Input)
	vector := deterministicEmbedding(input, 768)
	writeCompactJSON(w, http.StatusOK, struct {
		Object string `json:"object"`
		Data   []struct {
			Object    string    `json:"object"`
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}{
		Object: "list",
		Data: []struct {
			Object    string    `json:"object"`
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		}{{Object: "embedding", Embedding: vector, Index: 0}},
		Model: request.Model,
		Usage: struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		}{PromptTokens: max(1, len(input)/4), TotalTokens: max(1, len(input)/4)},
	})
}

func deterministicEmbedding(input string, dimensions int) []float64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(input))
	seed := h.Sum64()
	out := make([]float64, dimensions)
	var norm float64
	for i := range out {
		value := math.Sin(float64(seed%1_000_003)+float64(i)*1.61803398875) * 0.1
		out[i] = value
		norm += value * value
	}
	norm = math.Sqrt(norm)
	for i := range out {
		out[i] = math.Round(out[i]/norm*1e8) / 1e8
	}
	return out
}
