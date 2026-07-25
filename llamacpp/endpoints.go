package llamacpp

import (
	"net/http"

	"github.com/joshrendek/threat.gg-agent/llmcore"
)

// threat_gg-5g1: POST /tokenize, POST /detokenize and GET /slots were verified 404 on the live
// fleet. All three are standard llama-server endpoints; shapes below are confirmed against the
// current server source, not just the README, since the README's /detokenize section documents
// only the request fields and omits the response shape entirely:
//
//	github.com/ggml-org/llama.cpp tools/server/server-context.cpp
//	  post_tokenize   (~line 4870): {"tokens": [...]}, or [{"id","piece"}, ...] with with_pieces
//	  post_detokenize (~line 4911): {"content": "..."}
//	  get_slots       (~line 4445): array of server_slot::to_json() (~line 632); an idle slot with
//	                  no completions ever run on it (our case, always) reduces to
//	                  {"id","n_ctx","speculative","is_processing"} with no "params"/"prompt"/
//	                  "next_token" (those only appear once a task has run on the slot).

// -- POST /tokenize

type tokenizeRequest struct {
	Content    string `json:"content"`
	WithPieces bool   `json:"with_pieces"`
}

// tokenPiece is the with_pieces:true shape. Real llama.cpp emits piece as a []byte array instead
// of a string when the token's bytes are not valid UTF-8; ours are always valid UTF-8 substrings
// of the input, so the string form is all this honeypot ever needs.
type tokenPiece struct {
	ID    int    `json:"id"`
	Piece string `json:"piece"`
}

type tokenizeResponse struct {
	// Tokens holds either []int (with_pieces false) or []tokenPiece (with_pieces true) — the
	// two shapes the real endpoint switches between on the same field.
	Tokens any `json:"tokens"`
}

func handleTokenize(w http.ResponseWriter, r *http.Request) {
	var req tokenizeRequest
	readJSONBody(r, &req)

	tokens := llmcore.PseudoTokens(req.Content)
	if !req.WithPieces {
		llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, tokenizeResponse{Tokens: tokens})
		return
	}

	chunks := splitIntoChunks(req.Content, len(tokens))
	pieces := make([]tokenPiece, len(tokens))
	for i, id := range tokens {
		pieces[i] = tokenPiece{ID: id, Piece: chunks[i]}
	}
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, tokenizeResponse{Tokens: pieces})
}

// splitIntoChunks divides content into n contiguous, non-overlapping runs of runes (so a
// with_pieces response at least looks like a segmentation of the real input instead of unrelated
// placeholder text). n is always >= 1 (see llmcore.PseudoTokens); an empty content yields n empty
// strings.
func splitIntoChunks(content string, n int) []string {
	if n < 1 {
		n = 1
	}
	runes := []rune(content)
	out := make([]string, n)
	chunkSize := len(runes) / n
	if chunkSize < 1 {
		chunkSize = 1
	}
	pos := 0
	for i := 0; i < n; i++ {
		if pos >= len(runes) {
			continue
		}
		end := pos + chunkSize
		if i == n-1 || end > len(runes) {
			end = len(runes)
		}
		out[i] = string(runes[pos:end])
		pos = end
	}
	return out
}

// -- POST /detokenize

type detokenizeRequest struct {
	Tokens []int `json:"tokens"`
}

type detokenizeResponse struct {
	Content string `json:"content"`
}

// handleDetokenize always answers with the empty string. Real llama.cpp round-trips the token
// ids through its own vocabulary; the ids our /tokenize hands out are fabricated (see
// llmcore.PseudoTokens) and correspond to no real vocabulary, so there is nothing correct to
// reverse them into. Matches vLLM's handleDetokenize stub for the same reason: an honest "we
// don't know" reads better than a fabricated string that would not survive a careful check.
func handleDetokenize(w http.ResponseWriter, r *http.Request) {
	var req detokenizeRequest
	readJSONBody(r, &req)
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, detokenizeResponse{Content: ""})
}

// -- GET /slots

// slotInfo is server_slot::to_json(only_metrics=true) for a slot that has never run a task: real
// llama.cpp only adds "id_task"/"n_prompt_tokens"/"params"/"next_token"/etc. once ptask (the
// slot's current or most recent task) is non-null. A slot in this honeypot never actually runs a
// completion internally, so it stays in that minimal shape indefinitely — which is also exactly
// the shape a freshly started real server reports before its first request.
type slotInfo struct {
	ID           int  `json:"id"`
	NCtx         int  `json:"n_ctx"`
	Speculative  bool `json:"speculative"`
	IsProcessing bool `json:"is_processing"`
}

// handleSlots reports a single idle slot, matching the total_slots:1 (the default --parallel
// value) already advertised by /props.
func handleSlots(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, []slotInfo{
		{ID: 0, NCtx: slotNCtx, Speculative: false, IsProcessing: false},
	})
}
