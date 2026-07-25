package llmcore

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Model is one entry in an OpenAI /v1/models listing.
type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
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

var (
	// echoRe matches the liveness/echo probes scanners use to confirm an endpoint really runs
	// a model before abusing it: "say pong", "reply with OK", "repeat after me: X", etc.
	echoRe = regexp.MustCompile(`(?i)^\s*(?:say|repeat(?:\s+after\s+me)?|reply(?:\s+with)?|respond(?:\s+with)?|output|print|echo)\b[:,\s]+(.+)$`)
	// arithRe matches trivial arithmetic liveness checks: "what is 2+2", "10 * 3".
	arithRe = regexp.MustCompile(`(?i)^\s*(?:what(?:'s| is)\s+)?(\d{1,6})\s*([-+*/xX])\s*(\d{1,6})\s*=?\s*\??\s*$`)
)

// smartReply returns a response tuned to pass the liveness/validation probes that scanners run
// to confirm an exposed LLM endpoint is a real, instruction-following model before they start
// abusing it. Matching those probes (echo, arithmetic, greeting) makes the honeypot look real,
// so the attacker escalates to their actual prompts — which we capture. Anything else falls
// back to the generic pool, which reads as a safety-tuned deflection.
func smartReply(prompt string) string {
	p := strings.TrimSpace(prompt)
	if p == "" {
		return pickReply()
	}
	if m := echoRe.FindStringSubmatch(p); m != nil {
		if s := cleanEcho(m[1]); s != "" {
			return s
		}
	}
	if m := arithRe.FindStringSubmatch(p); m != nil {
		if s, ok := computeArith(m[1], m[2], m[3]); ok {
			return s
		}
	}
	switch strings.ToLower(strings.Trim(p, " .!?")) {
	case "hi", "hello", "hey", "yo", "greetings":
		return "Hello! How can I help you today?"
	}
	return pickReply()
}

// cleanEcho strips wrapping quotes and trailing punctuation from an echo payload and caps its
// length so a huge "say <...>" can't produce an unbounded reply.
func cleanEcho(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'`")
	s = strings.TrimRight(s, " .!?\n\r\t")
	s = strings.Trim(s, "\"'`")
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		s = s[:2000]
	}
	return s
}

// computeArith evaluates a trivial two-operand integer expression, returning ("", false) on
// bad operands or division by zero (so the caller falls back to a generic reply).
func computeArith(a, op, b string) (string, bool) {
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return "", false
	}
	var r int
	switch op {
	case "+":
		r = x + y
	case "-":
		r = x - y
	case "*", "x", "X":
		r = x * y
	case "/":
		if y == 0 {
			return "", false
		}
		r = x / y
	default:
		return "", false
	}
	return strconv.Itoa(r), true
}

// estTokens is a cheap, plausible token estimate (~4 chars/token, floor 1).
func estTokens(s string) int {
	n := len(s) / 4
	if n < 1 {
		n = 1
	}
	return n
}

// chatTemplateTokens approximates the system prompt and chat-template scaffolding a real server
// prepends before the user's text. Real Ollama reports prompt_eval_count ~30 for a one-word
// prompt, so reporting only the user's own token count is conspicuously low.
const chatTemplateTokens = 28

func promptTokensFor(text string) int { return chatTemplateTokens + estTokens(text) }

func wantsStream(body []byte, defaultStream bool) bool {
	var m struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.Stream == nil {
		return defaultStream
	}
	return *m.Stream
}

// maxTokensOf reads the generation cap under any of the names these surfaces accept: OpenAI's
// max_tokens and max_completion_tokens, the Responses API's max_output_tokens, and Ollama's
// options.num_predict. Returns 0 when uncapped.
func maxTokensOf(body []byte) int {
	var m struct {
		MaxTokens           *int `json:"max_tokens"`
		MaxCompletionTokens *int `json:"max_completion_tokens"`
		MaxOutputTokens     *int `json:"max_output_tokens"`
		Options             struct {
			NumPredict *int `json:"num_predict"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return 0
	}
	for _, v := range []*int{m.MaxTokens, m.MaxCompletionTokens, m.MaxOutputTokens, m.Options.NumPredict} {
		if v != nil && *v > 0 {
			return *v
		}
	}
	return 0
}

// capReply truncates reply to at most max generated tokens and reports the finish reason a real
// server would return. Hitting the cap yields "length", not "stop" — scanners routinely send
// max_tokens=1 and read the finish reason back, so always reporting "stop" is a giveaway.
func capReply(reply string, max int) (text string, chunks []string, finish string) {
	chunks = splitWords(reply)
	if max > 0 && len(chunks) >= max {
		chunks = chunks[:max]
		return strings.TrimRight(strings.Join(chunks, ""), " "), chunks, "length"
	}
	return reply, chunks, "stop"
}

func promptText(body []byte) string {
	var m struct {
		Prompt   string `json:"prompt"`
		Input    string `json:"input"`
		Content  string `json:"content"` // llama.cpp's /tokenize and /completion use "content".
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &m)
	if m.Prompt != "" {
		return m.Prompt
	}
	if m.Input != "" {
		return m.Input
	}
	if m.Content != "" {
		return m.Content
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

// ValidJSONBody reports whether body parses as a JSON object, along with the parse error a real
// server would echo when it does not. Real servers 400 on malformed input; happily returning a
// completion for "not-json" is a tell.
func ValidJSONBody(body []byte) (string, bool) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return "", true
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return err.Error(), false
	}
	return "", true
}

func completionID(p Profile, prefix string) string {
	if p.ShortIDs {
		// Ollama's OpenAI layer emits a short numeric suffix, e.g. chatcmpl-964.
		return fmt.Sprintf("%s-%d", prefix, rand.Intn(1000))
	}
	return fmt.Sprintf("%s-%016x%016x", prefix, rand.Uint64(), rand.Uint64())
}

// -- OpenAI-shaped payloads. Field order mirrors the real servers' struct order; building these
// from map[string]any would sort the keys alphabetically, which no real implementation does.

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIChatChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type openAIChatResponse struct {
	ID                string             `json:"id"`
	Object            string             `json:"object"`
	Created           int64              `json:"created"`
	Model             string             `json:"model"`
	SystemFingerprint string             `json:"system_fingerprint,omitempty"`
	Choices           []openAIChatChoice `json:"choices"`
	Usage             openAIUsage        `json:"usage"`
}

type openAIDelta struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChunkChoice struct {
	Index        int         `json:"index"`
	Delta        openAIDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type openAIChatChunk struct {
	ID                string              `json:"id"`
	Object            string              `json:"object"`
	Created           int64               `json:"created"`
	Model             string              `json:"model"`
	SystemFingerprint string              `json:"system_fingerprint,omitempty"`
	Choices           []openAIChunkChoice `json:"choices"`
}

type openAITextChoice struct {
	Text         string `json:"text"`
	Index        int    `json:"index"`
	Logprobs     *int   `json:"logprobs"`
	FinishReason string `json:"finish_reason"`
}

type openAITextResponse struct {
	ID                string             `json:"id"`
	Object            string             `json:"object"`
	Created           int64              `json:"created"`
	Model             string             `json:"model"`
	SystemFingerprint string             `json:"system_fingerprint,omitempty"`
	Choices           []openAITextChoice `json:"choices"`
	Usage             openAIUsage        `json:"usage"`
}

// ChatCompletion writes an OpenAI /v1/chat/completions response, streaming SSE chunks
// when the request asks for "stream":true (default false for chat).
func ChatCompletion(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOpenAIError(w, p, http.StatusBadRequest, msg, "invalid_request_error")
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundV1(w, p, model)
		return
	}
	reply, chunks, finish := capReply(smartReply(promptText(body)), maxTokensOf(body))
	id := completionID(p, "chatcmpl")
	created := time.Now().Unix()

	if wantsStream(body, false) {
		w.Header().Set("Content-Type", CTEventStream)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		emit := func(content string, finish *string) {
			b, _ := json.Marshal(openAIChatChunk{
				ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
				SystemFingerprint: p.SystemFingerprint,
				Choices: []openAIChunkChoice{{
					Index: 0,
					Delta: openAIDelta{Role: "assistant", Content: content},
					// finish_reason is explicitly null until the terminal chunk.
					FinishReason: finish,
				}},
			})
			fmt.Fprintf(w, "data: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
		}
		for _, c := range chunks {
			emit(c, nil)
		}
		emit("", &finish)
		fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	pt := promptTokensFor(promptText(body))
	WriteJSONCT(w, http.StatusOK, p.openAICT(), openAIChatResponse{
		ID: id, Object: "chat.completion", Created: created, Model: model,
		SystemFingerprint: p.SystemFingerprint,
		Choices: []openAIChatChoice{{
			Index:        0,
			Message:      chatMessage{Role: "assistant", Content: reply},
			FinishReason: finish,
		}},
		Usage: openAIUsage{PromptTokens: pt, CompletionTokens: len(chunks), TotalTokens: pt + len(chunks)},
	})
}

// Completion writes an OpenAI /v1/completions (legacy text completion) response.
func Completion(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOpenAIError(w, p, http.StatusBadRequest, msg, "invalid_request_error")
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundV1(w, p, model)
		return
	}
	reply, chunks, finish := capReply(smartReply(promptText(body)), maxTokensOf(body))
	pt := promptTokensFor(promptText(body))
	WriteJSONCT(w, http.StatusOK, p.openAICT(), openAITextResponse{
		ID: completionID(p, "cmpl"), Object: "text_completion",
		Created: time.Now().Unix(), Model: model,
		SystemFingerprint: p.SystemFingerprint,
		Choices: []openAITextChoice{{
			Text: reply, Index: 0, Logprobs: nil, FinishReason: finish,
		}},
		Usage: openAIUsage{PromptTokens: pt, CompletionTokens: len(chunks), TotalTokens: pt + len(chunks)},
	})
}

// -- Ollama-native /api payloads.

type ollamaGenerateChunk struct {
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
}

type ollamaGenerateFinal struct {
	Model              string `json:"model"`
	CreatedAt          string `json:"created_at"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	DoneReason         string `json:"done_reason"`
	Context            []int  `json:"context,omitempty"`
	TotalDuration      int64  `json:"total_duration"`
	LoadDuration       int64  `json:"load_duration"`
	PromptEvalCount    int    `json:"prompt_eval_count"`
	PromptEvalDuration int64  `json:"prompt_eval_duration"`
	EvalCount          int    `json:"eval_count"`
	EvalDuration       int64  `json:"eval_duration"`
}

type ollamaChatChunk struct {
	Model     string      `json:"model"`
	CreatedAt string      `json:"created_at"`
	Message   chatMessage `json:"message"`
	Done      bool        `json:"done"`
}

type ollamaChatFinal struct {
	Model              string      `json:"model"`
	CreatedAt          string      `json:"created_at"`
	Message            chatMessage `json:"message"`
	Done               bool        `json:"done"`
	DoneReason         string      `json:"done_reason"`
	TotalDuration      int64       `json:"total_duration"`
	LoadDuration       int64       `json:"load_duration"`
	PromptEvalCount    int         `json:"prompt_eval_count"`
	PromptEvalDuration int64       `json:"prompt_eval_duration"`
	EvalCount          int         `json:"eval_count"`
	EvalDuration       int64       `json:"eval_duration"`
}

// nowNano formats a timestamp the way Ollama does: RFC3339 with nanosecond precision. Each
// streamed chunk gets a fresh one, so timestamps advance across a stream instead of every
// chunk repeating the value computed when the handler started.
func nowNano() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// fakeContext synthesises the token-id array Ollama returns from /api/generate. Real ids are
// vocabulary indices bracketed by high-numbered special tokens; omitting the field entirely is
// what gives a fake away, not the specific ids.
func fakeContext(n int) []int {
	if n < 1 {
		n = 1
	}
	if n > 512 {
		n = 512
	}
	out := make([]int, 0, n+6)
	out = append(out, 151644, 8948, 198) // <|im_start|> system \n
	for i := 0; i < n; i++ {
		out = append(out, 1000+rand.Intn(126000))
	}
	out = append(out, 151645, 198, 151643) // <|im_end|> \n <|endoftext|>
	return out
}

// ndjsonWriter returns a helper that marshals and flushes one NDJSON line per call.
func ndjsonWriter(w http.ResponseWriter) func(any) {
	flusher, _ := w.(http.Flusher)
	return func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "%s\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// OllamaGenerate writes an Ollama /api/generate response. Ollama streams NDJSON by
// default (one JSON object per line), ending with a done:true summary line; "stream":false
// collapses to a single object.
func OllamaGenerate(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOllamaError(w, p, http.StatusBadRequest, msg)
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundAPI(w, p, model)
		return
	}
	prompt := promptText(body)
	reply, chunks, finish := capReply(smartReply(prompt), maxTokensOf(body))
	pt := promptTokensFor(prompt)
	t := newTimings(model, keepAliveOf(body), pt, len(chunks))

	final := func(response string) ollamaGenerateFinal {
		return ollamaGenerateFinal{
			Model: model, CreatedAt: nowNano(), Response: response, Done: true,
			DoneReason:         finish,
			Context:            fakeContext(pt + len(chunks)),
			TotalDuration:      t.Total.Nanoseconds(),
			LoadDuration:       t.Load.Nanoseconds(),
			PromptEvalCount:    pt,
			PromptEvalDuration: t.PromptEval.Nanoseconds(),
			EvalCount:          len(chunks),
			EvalDuration:       t.Eval.Nanoseconds(),
		}
	}

	if !wantsStream(body, true) {
		WriteJSONCT(w, http.StatusOK, p.ct(), final(reply))
		return
	}
	w.Header().Set("Content-Type", CTNDJSON)
	w.WriteHeader(http.StatusOK)
	writeLine := ndjsonWriter(w)
	for _, c := range chunks {
		writeLine(ollamaGenerateChunk{Model: model, CreatedAt: nowNano(), Response: c, Done: false})
	}
	writeLine(final(""))
}

// OllamaChat writes an Ollama /api/chat response (message-shaped, single object when
// stream is false; NDJSON otherwise).
func OllamaChat(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOllamaError(w, p, http.StatusBadRequest, msg)
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundAPI(w, p, model)
		return
	}
	prompt := promptText(body)
	reply, chunks, finish := capReply(smartReply(prompt), maxTokensOf(body))
	pt := promptTokensFor(prompt)
	t := newTimings(model, keepAliveOf(body), pt, len(chunks))

	final := func(content string) ollamaChatFinal {
		return ollamaChatFinal{
			Model: model, CreatedAt: nowNano(),
			Message: chatMessage{Role: "assistant", Content: content},
			Done:    true, DoneReason: finish,
			TotalDuration:      t.Total.Nanoseconds(),
			LoadDuration:       t.Load.Nanoseconds(),
			PromptEvalCount:    pt,
			PromptEvalDuration: t.PromptEval.Nanoseconds(),
			EvalCount:          len(chunks),
			EvalDuration:       t.Eval.Nanoseconds(),
		}
	}

	if !wantsStream(body, true) {
		WriteJSONCT(w, http.StatusOK, p.ct(), final(reply))
		return
	}
	w.Header().Set("Content-Type", CTNDJSON)
	w.WriteHeader(http.StatusOK)
	writeLine := ndjsonWriter(w)
	for _, c := range chunks {
		writeLine(ollamaChatChunk{
			Model: model, CreatedAt: nowNano(),
			Message: chatMessage{Role: "assistant", Content: c}, Done: false,
		})
	}
	writeLine(final(""))
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
