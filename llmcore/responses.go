package llmcore

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// The OpenAI Responses API (/v1/responses). Captured prod traffic shows open-router-cli probing
// this endpoint with models the honeypot advertises, so a 404 here fails a validator that a real
// modern Ollama would have passed. Field order and the explicit nulls mirror a real response.

type responseOutputContent struct {
	Type        string `json:"type"`
	Text        string `json:"text"`
	Annotations []any  `json:"annotations"`
	Logprobs    []any  `json:"logprobs"`
}

type responseOutput struct {
	ID      string                  `json:"id"`
	Type    string                  `json:"type"`
	Status  string                  `json:"status"`
	Role    string                  `json:"role"`
	Content []responseOutputContent `json:"content"`
}

type responseTextFormat struct {
	Type string `json:"type"`
}

type responseText struct {
	Format responseTextFormat `json:"format"`
}

type responseUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type responsesPayload struct {
	ID                 string           `json:"id"`
	Object             string           `json:"object"`
	CreatedAt          int64            `json:"created_at"`
	CompletedAt        int64            `json:"completed_at"`
	Status             string           `json:"status"`
	IncompleteDetails  *string          `json:"incomplete_details"`
	Model              string           `json:"model"`
	PreviousResponseID *string          `json:"previous_response_id"`
	Instructions       *string          `json:"instructions"`
	Output             []responseOutput `json:"output"`
	Error              *string          `json:"error"`
	Tools              []any            `json:"tools"`
	ToolChoice         string           `json:"tool_choice"`
	Truncation         string           `json:"truncation"`
	ParallelToolCalls  bool             `json:"parallel_tool_calls"`
	Text               responseText     `json:"text"`
	TopP               float64          `json:"top_p"`
	PresencePenalty    float64          `json:"presence_penalty"`
	FrequencyPenalty   float64          `json:"frequency_penalty"`
	TopLogprobs        int              `json:"top_logprobs"`
	Temperature        float64          `json:"temperature"`
	Reasoning          *string          `json:"reasoning"`
	Usage              responseUsage    `json:"usage"`
}

// Responses writes an OpenAI Responses API (/v1/responses) reply.
func Responses(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOpenAIError(w, p, http.StatusBadRequest, msg, "invalid_request_error")
		return
	}
	model, known := p.resolveModel(body)
	if !known {
		WriteModelNotFoundV1(w, p, model)
		return
	}
	prompt := promptText(body)
	reply, chunks, _ := capReply(smartReply(prompt), maxTokensOf(body))
	now := time.Now().Unix()
	in := promptTokensFor(prompt)

	WriteJSONCT(w, http.StatusOK, CTJSON, responsesPayload{
		ID:        fmt.Sprintf("resp_%d", rand.Intn(100000)),
		Object:    "response",
		CreatedAt: now, CompletedAt: now,
		Status: "completed",
		Model:  model,
		Output: []responseOutput{{
			ID:     fmt.Sprintf("msg_%d", rand.Intn(1000000)),
			Type:   "message",
			Status: "completed",
			Role:   "assistant",
			Content: []responseOutputContent{{
				Type: "output_text", Text: reply,
				Annotations: []any{}, Logprobs: []any{},
			}},
		}},
		Tools: []any{}, ToolChoice: "auto", Truncation: "disabled",
		ParallelToolCalls: true,
		Text:              responseText{Format: responseTextFormat{Type: "text"}},
		TopP:              1, Temperature: 1,
		Usage: responseUsage{InputTokens: in, OutputTokens: len(chunks), TotalTokens: in + len(chunks)},
	})
}

// PromptOf returns the prompt/input text from a request body, for surfaces that need it outside
// the generators (vLLM's /tokenize, for instance).
func PromptOf(r *http.Request) string { return promptText(readBody(r)) }

// PseudoTokens produces a plausible token-id sequence for text. Used by /tokenize, where the
// count and rough shape are what a caller checks, not the specific vocabulary indices.
func PseudoTokens(text string) []int {
	n := estTokens(text)
	out := make([]int, 0, n+1)
	out = append(out, 128000) // BOS
	for i := 0; i < n; i++ {
		out = append(out, 1000+rand.Intn(126000))
	}
	return out
}

// WriteEmbeddingsUnsupported reproduces the 501 a real Ollama returns when the requested model
// has no embedding support — which is true of every model in the advertised catalog. Fabricating
// a plausible embedding vector would be more work and less accurate than the real refusal.
func WriteEmbeddingsUnsupported(w http.ResponseWriter, p Profile, openAIShape bool) {
	const msg = "This server does not support embeddings. Start it with `--embeddings`"
	if openAIShape {
		WriteOpenAIError(w, p, http.StatusNotImplemented, msg, "api_error")
		return
	}
	WriteOllamaError(w, p, http.StatusNotImplemented, msg)
}
