package ollama

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/llmcore"
)

// maxBody caps how much of a management-endpoint body we parse. Inference bodies are capped
// separately inside llmcore.
const maxBody = 1 << 20

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	return json.Unmarshal(b, v)
}

// modelRequest covers the several field names Ollama's management endpoints accept for "which
// model": /api/show and /api/pull take "model" (with "name" still honoured for compatibility).
type modelRequest struct {
	Model  string `json:"model"`
	Name   string `json:"name"`
	Source string `json:"source"`
	Dest   string `json:"destination"`
}

func (m modelRequest) model() string {
	if m.Model != "" {
		return m.Model
	}
	return m.Name
}

// -- /api/show

type showResponse struct {
	License      string         `json:"license"`
	Modelfile    string         `json:"modelfile"`
	Parameters   string         `json:"parameters"`
	Template     string         `json:"template"`
	Details      Details        `json:"details"`
	ModelInfo    map[string]any `json:"model_info"`
	Tensors      []tensor       `json:"tensors"`
	Capabilities []string       `json:"capabilities"`
	ModifiedAt   string         `json:"modified_at"`
}

type tensor struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Shape []int  `json:"shape"`
}

// modelInfo synthesises the GGUF metadata block /api/show returns. Real responses carry ~36
// architecture-prefixed keys; a five-key stub is the giveaway, not the exact values.
func modelInfo(m CatalogModel) map[string]any {
	a := m.arch
	heads := m.Details.EmbeddingLength / 128
	if heads < 1 {
		heads = 8
	}
	return map[string]any{
		"general.architecture":                  a,
		"general.basename":                      strings.SplitN(m.Name, ":", 2)[0],
		"general.file_type":                     15,
		"general.parameter_count":               m.Size / 2 * 3,
		"general.quantization_version":          2,
		"general.type":                          "model",
		a + ".attention.head_count":             heads,
		a + ".attention.head_count_kv":          8,
		a + ".attention.layer_norm_rms_epsilon": 1e-05,
		a + ".block_count":                      m.blocks,
		a + ".context_length":                   m.Details.ContextLength,
		a + ".embedding_length":                 m.Details.EmbeddingLength,
		a + ".feed_forward_length":              m.Details.EmbeddingLength * 4,
		a + ".rope.dimension_count":             128,
		a + ".rope.freq_base":                   500000,
		a + ".vocab_size":                       128256,
		"tokenizer.ggml.bos_token_id":           128000,
		"tokenizer.ggml.eos_token_id":           128009,
		"tokenizer.ggml.model":                  "gpt2",
		"tokenizer.ggml.pre":                    a,
	}
}

// tensorList synthesises the per-layer tensor inventory /api/show reports, following the GGUF
// naming convention (token_embd, output_norm, blk.N.*).
func tensorList(m CatalogModel) []tensor {
	embd := m.Details.EmbeddingLength
	if embd == 0 {
		embd = 4096
	}
	ffn := embd * 4
	out := []tensor{
		{Name: "output_norm.weight", Type: "F32", Shape: []int{embd}},
		{Name: "token_embd.weight", Type: "Q6_K", Shape: []int{embd, 128256}},
	}
	for i := 0; i < m.blocks; i++ {
		p := fmt.Sprintf("blk.%d.", i)
		out = append(out,
			tensor{Name: p + "attn_norm.weight", Type: "F32", Shape: []int{embd}},
			tensor{Name: p + "attn_q.weight", Type: "Q4_K", Shape: []int{embd, embd}},
			tensor{Name: p + "attn_k.weight", Type: "Q4_K", Shape: []int{embd, embd / 4}},
			tensor{Name: p + "attn_v.weight", Type: "Q6_K", Shape: []int{embd, embd / 4}},
			tensor{Name: p + "attn_output.weight", Type: "Q4_K", Shape: []int{embd, embd}},
			tensor{Name: p + "ffn_norm.weight", Type: "F32", Shape: []int{embd}},
			tensor{Name: p + "ffn_gate.weight", Type: "Q4_K", Shape: []int{embd, ffn}},
			tensor{Name: p + "ffn_up.weight", Type: "Q4_K", Shape: []int{embd, ffn}},
			tensor{Name: p + "ffn_down.weight", Type: "Q6_K", Shape: []int{ffn, embd}},
		)
	}
	return out
}

func handleShow(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	if err := readJSON(r, &req); err != nil {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, err.Error())
		return
	}
	if req.model() == "" {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, "model is required")
		return
	}
	m, ok := models.get(req.model())
	if !ok {
		llmcore.WriteModelNotFoundAPI(w, profile, normalize(req.model()))
		return
	}
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, showResponse{
		License: "MIT License\n\nPermission is hereby granted, free of charge, to any person " +
			"obtaining a copy of this software and associated documentation files.",
		Modelfile: fmt.Sprintf("# Modelfile generated by \"ollama show\"\n"+
			"# To build a new Modelfile based on this, replace FROM with:\n"+
			"# FROM %s\n\nFROM /root/.ollama/models/blobs/sha256-%s\nTEMPLATE \"\"\"{{ .System }}{{ .Prompt }}\"\"\"",
			m.Name, m.Digest),
		Parameters:   "stop                           \"<|start_header_id|>\"\nstop                           \"<|end_header_id|>\"\nstop                           \"<|eot_id|>\"",
		Template:     "{{ if .System }}<|start_header_id|>system<|end_header_id|>\n\n{{ .System }}<|eot_id|>{{ end }}{{ if .Prompt }}<|start_header_id|>user<|end_header_id|>\n\n{{ .Prompt }}<|eot_id|>{{ end }}<|start_header_id|>assistant<|end_header_id|>\n\n",
		Details:      m.Details,
		ModelInfo:    modelInfo(m),
		Tensors:      tensorList(m),
		Capabilities: m.Capabilities,
		ModifiedAt:   m.ModifiedAt,
	})
}

// -- /api/pull

type pullStatus struct {
	Status    string `json:"status"`
	Digest    string `json:"digest,omitempty"`
	Total     int64  `json:"total,omitempty"`
	Completed int64  `json:"completed,omitempty"`
}

// pullLayers is how many blob layers a pull reports before finishing.
const pullLayers = 3

// pullStepDelay paces the fake download. Overridden to zero in tests so the suite does not spend
// seconds waiting on deliberately-slow output.
var pullStepDelay = func() time.Duration {
	return time.Duration(120+rand.Intn(180)) * time.Millisecond
}

// handlePull streams a convincing model download. This is a deliberate divergence from the real
// server, which actually fetches from a registry: we stream plausible progress and then add the
// model to this instance's catalog, so an attacker who pulls a model finds it in /api/tags and
// goes on to use it — and that follow-up traffic is the payload worth capturing.
//
// Progress is paced over a few seconds rather than the minutes a real multi-GB pull takes: long
// enough not to look instantaneous, short enough that concurrent pulls cannot tie the honeypot
// up. The pacing aborts as soon as the client disconnects.
func handlePull(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	if err := readJSON(r, &req); err != nil {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, err.Error())
		return
	}
	name := req.model()
	if name == "" {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, "model is required")
		return
	}

	w.Header().Set("Content-Type", llmcore.CTNDJSON)
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	ctx := r.Context()
	emit := func(v pullStatus) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "%s\n", b); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return ctx.Err() == nil
	}

	if !emit(pullStatus{Status: "pulling manifest"}) {
		return
	}

	target := synthesize(name)
	remaining := target.Size
	for layer := 0; layer < pullLayers && remaining > 0; layer++ {
		digest := pseudoDigest(fmt.Sprintf("%s/layer/%d", normalize(name), layer))
		size := remaining
		if layer < pullLayers-1 {
			size = remaining / 2
		}
		remaining -= size
		short := digest[:12]
		steps := 6 + rand.Intn(5)
		for s := 1; s <= steps; s++ {
			done := size * int64(s) / int64(steps)
			if !emit(pullStatus{
				Status: "pulling " + short, Digest: "sha256:" + digest,
				Total: size, Completed: done,
			}) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(pullStepDelay()):
			}
		}
	}

	for _, s := range []string{"verifying sha256 digest", "writing manifest", "success"} {
		if !emit(pullStatus{Status: s}) {
			return
		}
	}
	models.add(target)
}

// -- /api/push, /api/create

// handlePush mirrors the real failure path: an unauthenticated box has no registry credentials,
// so a push gets as far as the manifest lookup and stops.
func handlePush(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	_ = readJSON(r, &req)
	w.Header().Set("Content-Type", llmcore.CTNDJSON)
	w.WriteHeader(http.StatusOK)
	writeLine(w, map[string]string{"status": "retrieving manifest"})
	writeLine(w, map[string]string{"status": "couldn't retrieve manifest"})
	writeLine(w, map[string]string{
		"error": fmt.Sprintf("open /root/.ollama/models/manifests/registry.ollama.ai/%s: no such file or directory",
			strings.ReplaceAll(normalize(req.model()), ":", "/")),
	})
}

// handleCreate answers the way a real server does when the FROM model is not present locally:
// it starts pulling the base layer and fails on the manifest.
func handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Model string `json:"model"`
		Name  string `json:"name"`
		From  string `json:"from"`
	}
	_ = readJSON(r, &req)
	w.Header().Set("Content-Type", llmcore.CTNDJSON)
	w.WriteHeader(http.StatusOK)
	if req.From != "" && models.has(req.From) {
		for _, s := range []string{"using existing layer", "creating new layer", "writing manifest", "success"} {
			writeLine(w, map[string]string{"status": s})
		}
		return
	}
	writeLine(w, map[string]string{"status": "pulling manifest"})
	writeLine(w, map[string]string{"error": "pull model manifest: file does not exist"})
}

func writeLine(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "%s\n", b)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// -- /api/copy, /api/delete

func handleCopy(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	if err := readJSON(r, &req); err != nil {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, err.Error())
		return
	}
	src, ok := models.get(req.Source)
	if !ok {
		// Note the escaped-quote form here: real Ollama uses %q for copy but '%s' for show.
		llmcore.WriteOllamaError(w, profile, http.StatusNotFound,
			fmt.Sprintf("model %q not found", req.Source))
		return
	}
	if req.Dest != "" {
		copied := src
		copied.Name = normalize(req.Dest)
		copied.Model = copied.Name
		copied.ModifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
		models.add(copied)
	}
	w.WriteHeader(http.StatusOK)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	if err := readJSON(r, &req); err != nil {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, err.Error())
		return
	}
	if !models.remove(req.model()) {
		llmcore.WriteModelNotFoundAPI(w, profile, normalize(req.model()))
		return
	}
	w.WriteHeader(http.StatusOK)
}

// -- /api/blobs

var digestRe = regexp.MustCompile(`^sha256[:-][a-f0-9]{64}$`)

func handleBlob(w http.ResponseWriter, r *http.Request) {
	digest := mux.Vars(r)["digest"]
	if !digestRe.MatchString(digest) {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, "invalid digest format")
		return
	}
	// A blob the server does not hold: real Ollama 404s HEAD and accepts POST uploads.
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// -- embeddings

// handleEmbedAPI and handleEmbedV1 report the 501 a real server returns for a model without
// embedding support, which is true of every model in the advertised catalog. Inventing a
// plausible float vector would be both more work and less accurate than the genuine refusal.
func handleEmbedAPI(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	_ = readJSON(r, &req)
	if req.model() != "" && !models.has(req.model()) {
		llmcore.WriteOllamaError(w, profile, http.StatusNotFound,
			fmt.Sprintf("model %q not found, try pulling it first", req.model()))
		return
	}
	llmcore.WriteEmbeddingsUnsupported(w, profile, false)
}

func handleEmbedV1(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	_ = readJSON(r, &req)
	if req.model() != "" && !models.has(req.model()) {
		llmcore.WriteOpenAIError(w, profile, http.StatusNotFound,
			fmt.Sprintf("model %q not found, try pulling it first", req.model()), "not_found_error")
		return
	}
	llmcore.WriteEmbeddingsUnsupported(w, profile, true)
}

// -- /v1/responses

func handleResponses(w http.ResponseWriter, r *http.Request) {
	llmcore.Responses(w, r, profile)
}
