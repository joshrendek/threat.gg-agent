package llmcore

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func writeOpenAIToolReply(w http.ResponseWriter, body []byte, p Profile, model string, call toolCall) {
	call.ID, call.Type = completionID(Profile{}, "call"), "function"
	call.Function.Arguments = string(mustJSON(call.Function.Arguments))
	id, created := completionID(p, "chatcmpl"), time.Now().Unix()
	pt, ct := promptTokensFor(promptText(body)), estTokens(call.Function.Arguments.(string))
	if !wantsStream(body, false) {
		WriteJSONCT(w, http.StatusOK, p.openAICT(), openAIChatResponse{
			ID: id, Object: "chat.completion", Created: created, Model: model, SystemFingerprint: p.SystemFingerprint,
			Choices: []openAIChatChoice{{Index: 0, Message: chatMessage{Role: "assistant", ToolCalls: []toolCall{call}}, FinishReason: "tool_calls"}},
			Usage:   openAIUsage{PromptTokens: pt, CompletionTokens: ct, TotalTokens: pt + ct},
		})
		return
	}
	w.Header().Set("Content-Type", CTEventStream)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	emit := func(delta openAIDelta, finish *string) {
		b, _ := json.Marshal(openAIChatChunk{
			ID: id, Object: "chat.completion.chunk", Created: created, Model: model, SystemFingerprint: p.SystemFingerprint,
			Choices: []openAIChunkChoice{{Index: 0, Delta: delta, FinishReason: finish}},
		})
		fmt.Fprintf(w, "data: %s\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	index, finish := 0, "tool_calls"
	call.Index = &index
	emit(openAIDelta{Role: "assistant", ToolCalls: []toolCall{call}}, nil)
	emit(openAIDelta{}, &finish)
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func writeOllamaToolReply(w http.ResponseWriter, body []byte, p Profile, model string, call toolCall) {
	pt, ct := promptTokensFor(promptText(body)), estTokens(string(mustJSON(call.Function.Arguments)))
	t := newTimings(model, keepAliveOf(body), pt, ct)
	final := ollamaChatFinal{
		Model: model, CreatedAt: nowNano(), Message: chatMessage{Role: "assistant", ToolCalls: []toolCall{call}},
		Done: true, DoneReason: "stop", TotalDuration: t.Total.Nanoseconds(), LoadDuration: t.Load.Nanoseconds(),
		PromptEvalCount: pt, PromptEvalDuration: t.PromptEval.Nanoseconds(), EvalCount: ct, EvalDuration: t.Eval.Nanoseconds(),
	}
	if !wantsStream(body, true) {
		WriteJSONCT(w, http.StatusOK, p.ct(), final)
		return
	}
	w.Header().Set("Content-Type", CTNDJSON)
	w.WriteHeader(http.StatusOK)
	writeLine := ndjsonWriter(w)
	index := 0
	call.Function.Index = &index
	writeLine(ollamaChatChunk{Model: model, CreatedAt: nowNano(), Message: chatMessage{Role: "assistant", ToolCalls: []toolCall{call}}})
	final.Message.ToolCalls = nil
	final.CreatedAt = nowNano()
	writeLine(final)
}
