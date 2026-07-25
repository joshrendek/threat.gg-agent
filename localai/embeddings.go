package localai

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"time"

	"github.com/joshrendek/threat.gg-agent/llmcore"
	uuid "github.com/satori/go.uuid"
)

// threat_gg-3kd: POST /v1/embeddings verified 404 on the live fleet. Embeddings are a headline
// LocalAI feature (not a refusal, unlike Ollama/vLLM — see llmcore.WriteEmbeddingsUnsupported and
// vllm's handleEmbeddings), so a 404 here is a tell. Response shape verified against the current
// source:
//
//	github.com/mudler/LocalAI core/http/endpoints/openai/embeddings.go (EmbeddingsEndpoint)
//	  + core/schema/openai.go (OpenAIResponse, Item, Item.MarshalJSON)
//
// Confirmed from that source: the response echoes the caller's own "model" string verbatim
// (LocalAI's comment: "we have to return what the user sent here, due to OpenAI spec"), omits
// "usage" and "choices" entirely (both are nil *pointer-or-slice `omitempty` fields on this
// path), and supports encoding_format:"base64" — the Node.js OpenAI SDK (v4+) sends that by
// default. floatsToBase64 below is the same little-endian float32-packing scheme as the real
// server's helper of the same name.
//
// A missing "model" fails the same way real LocalAI does: EmbeddingsEndpoint returns
// echo.ErrBadRequest, and Echo's DefaultHTTPErrorHandler renders that as {"message":"Bad
// Request"} with a bare "application/json" content type (github.com/labstack/echo/v4 echo.go,
// DefaultHTTPErrorHandler + the MIMEApplicationJSON constant, which — confirmed from the same
// source — is unsuffixed even though LocalAI has migrated off Fiber onto Echo; the "no charset"
// assumption this package's profile already encodes still holds).
//
// Not reproduced: the actual embedding values are fabricated (no real model backs this
// honeypot), and only the plain-string/array-of-strings "input" shapes are parsed — the
// less common array-of-token-ids form is not.

// embeddingDims is a plausible embedding width: OpenAI's text-embedding-ada-002, the dimension
// most embedding-consuming client code is written against.
const embeddingDims = 1536

// PR #33 review (two independent reviewers): the request body is capped at 1MB
// (llmcore.MaxBodySize), but nothing capped how many items "input" could contain. Each item's
// output cost (fakeEmbedding's embeddingDims-length vector, then its JSON serialization) is
// fixed regardless of how short that item's own string was, so a 1MB array of one-character
// strings — hundreds of thousands of items — turns into gigabytes of allocation and CPU from a
// single request to a public, unauthenticated honeypot.
//
// maxEmbeddingItems is picked to look like a real batch, not to be the largest tolerable number:
// embedding clients (LangChain, llama-index, the OpenAI SDKs) default to batching in the tens,
// not thousands, so a legitimate caller never notices this cap. maxEmbeddingOutputFloats is the
// same budget re-expressed as total floats and checked independently, before any vector is
// allocated — currently a restatement of maxEmbeddingItems given a fixed embeddingDims, but it
// stays correct on its own if a future change ever makes per-item width vary.
//
// Checked, per the review's request: vLLM's and Ollama's embeddings paths only ever write a
// fixed refusal (llmcore.WriteEmbeddingsUnsupported / vllm's handleEmbeddings) without parsing
// "input" or allocating per item at all, so they cannot amplify this way. llama.cpp implements no
// embeddings endpoint. LocalAI is the only product here that actually fabricates a vector per
// input item.
const (
	maxEmbeddingItems        = 64
	maxEmbeddingOutputFloats = maxEmbeddingItems * embeddingDims
)

type embeddingsRequest struct {
	Model          string          `json:"model"`
	Input          json.RawMessage `json:"input"`
	EncodingFormat string          `json:"encoding_format"`
}

// embeddingInputs accepts either a single string or an array of strings — the two shapes the
// OpenAI embeddings API allows for "input" that a real client actually sends.
func embeddingInputs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		return multi
	}
	return nil
}

// fakeEmbedding fabricates a plausible-looking unit-scale vector. No real model backs this
// honeypot, so the values themselves carry no meaning; only their shape (length, magnitude) is
// checked by any real client.
func fakeEmbedding(dims int) []float32 {
	out := make([]float32, dims)
	for i := range out {
		out[i] = rand.Float32()*2 - 1
	}
	return out
}

// floatsToBase64 packs a float32 slice as little-endian bytes and base64-encodes it — the same
// encoding real LocalAI uses for encoding_format:"base64" (core/http/endpoints/openai/embeddings.go).
func floatsToBase64(floats []float32) string {
	buf := make([]byte, len(floats)*4)
	for i, f := range floats {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

type embeddingItem struct {
	Embedding any    `json:"embedding"`
	Index     int    `json:"index"`
	Object    string `json:"object"`
}

type embeddingsResponse struct {
	Created int64           `json:"created"`
	Object  string          `json:"object"`
	ID      string          `json:"id"`
	Model   string          `json:"model"`
	Data    []embeddingItem `json:"data"`
}

type echoErrorBody struct {
	Message string `json:"message"`
}

func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	var req embeddingsRequest
	b, _ := io.ReadAll(io.LimitReader(r.Body, llmcore.MaxBodySize))
	_ = json.Unmarshal(b, &req)

	if req.Model == "" {
		llmcore.WriteJSONCT(w, http.StatusBadRequest, llmcore.CTJSON, echoErrorBody{Message: "Bad Request"})
		return
	}

	inputs := embeddingInputs(req.Input)
	if len(inputs) == 0 {
		inputs = []string{""}
	}

	// Reject an oversized batch outright rather than silently truncating it — truncating would
	// itself be a tell (the returned item count would not match what the caller sent). Real
	// LocalAI has no known explicit batch-size check of its own (it would just try to process
	// whatever it was given), so this message is invented rather than sourced; it reuses the same
	// Echo-style {"message":...} 400 shape this endpoint already uses for a missing model, since
	// that is this product's one verified error convention rather than a second, inconsistent one.
	if len(inputs) > maxEmbeddingItems || len(inputs)*embeddingDims > maxEmbeddingOutputFloats {
		llmcore.WriteJSONCT(w, http.StatusBadRequest, llmcore.CTJSON, echoErrorBody{
			Message: fmt.Sprintf("batch size %d exceeds the maximum of %d inputs per request", len(inputs), maxEmbeddingItems),
		})
		return
	}

	data := make([]embeddingItem, len(inputs))
	for i := range inputs {
		vec := fakeEmbedding(embeddingDims)
		item := embeddingItem{Index: i, Object: "embedding"}
		if req.EncodingFormat == "base64" {
			item.Embedding = floatsToBase64(vec)
		} else {
			item.Embedding = vec
		}
		data[i] = item
	}

	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSON, embeddingsResponse{
		Created: time.Now().Unix(),
		Object:  "list",
		ID:      uuid.NewV4().String(),
		Model:   req.Model,
		Data:    data,
	})
}
