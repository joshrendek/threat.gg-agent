package ollama

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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

// showResponse is the wire shape returned by Ollama's /api/show endpoint.
//
// modelfile and tensors are omitempty because api.ShowResponse declares them that way and a cloud
// model has neither: its /api/show is proxied from ollama.com, which knows nothing about any
// local blob. Emitting "modelfile":"" and "tensors":null for a cloud model would be a tell.
// model_info deliberately has no omitempty — the real struct omits it too, so it is present even
// when sparse.
type showResponse struct {
	License      string         `json:"license,omitempty"`
	Modelfile    string         `json:"modelfile,omitempty"`
	Parameters   string         `json:"parameters,omitempty"`
	Template     string         `json:"template,omitempty"`
	System       string         `json:"system,omitempty"`
	Details      showDetails    `json:"details"`
	ModelInfo    map[string]any `json:"model_info"`
	Tensors      []tensor       `json:"tensors,omitempty"`
	Capabilities []string       `json:"capabilities"`
	ModifiedAt   string         `json:"modified_at"`
}

// showDetails is intentionally separate from Details. Ollama includes context_length and
// embedding_length in /api/tags, but omits both from /api/show's details object.
type showDetails struct {
	ParentModel       string   `json:"parent_model"`
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
}

// tensor describes one GGUF tensor inventory entry exposed by /api/show.
type tensor struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Shape []int  `json:"shape"`
}

// showFixtureFS embeds captured /api/show responses for hermetic production use.
//
//go:embed testdata/show_qwen2.5-coder_7b_ollama-0.30.11.json
//go:embed testdata/show_gemma3_12b_ollama-0.30.11.json
var showFixtureFS embed.FS

// groundedShowFixtures contains the two models production scanners inspect most heavily, captured
// byte-for-byte from a real Ollama 0.30.11. The captures preserve license, template, GGUF
// metadata, tensor order, quantization types and multimodal inventory rather than guessing.
var groundedShowFixtures = loadGroundedShowFixtures()

func loadGroundedShowFixtures() map[string]showResponse {
	files := map[string]string{
		"qwen2.5-coder:7b": "testdata/show_qwen2.5-coder_7b_ollama-0.30.11.json",
		"gemma3:12b":       "testdata/show_gemma3_12b_ollama-0.30.11.json",
	}
	out := make(map[string]showResponse, len(files))
	for model, path := range files {
		b, err := showFixtureFS.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("read grounded Ollama fixture %s: %v", path, err))
		}
		var resp showResponse
		if err := json.Unmarshal(b, &resp); err != nil {
			panic(fmt.Sprintf("decode grounded Ollama fixture %s: %v", path, err))
		}
		out[model] = resp
	}
	return out
}

// registryDocFS embeds the license, template and parameter layers Ollama's registry ships for the
// advertised models that have no full captured /api/show fixture.
//
//go:embed testdata/registry
var registryDocFS embed.FS

// registryDoc names the layer files backing one model's documentary /api/show fields.
type registryDoc struct{ license, template, params string }

// registryDocSources maps a model to its registry layers (threat_gg-y0i). Before this, the four
// models without a captured fixture returned no license, template or parameters at all, while a
// real `ollama show llama3.2` returns all three — and /api/show is actively probed.
//
// PRD 034 concluded that hand-authored model_info and tensor blobs are *more* fingerprintable
// than a missing field, because they drift into self-contradiction. These three fields are a
// different kind of thing: they are opaque published strings with exactly one correct value, and
// every byte here was pulled from registry.ollama.ai and checksum-verified against the digest in
// the model's own manifest. Nothing is paraphrased, reflowed or reconstructed — including the
// "orginal" typo in Llama 3.2's template and the fullwidth U+FF5C delimiters in DeepSeek's, both
// of which are genuinely in the shipped blobs.
//
// mistral:latest and llava:latest share the license and params files because they genuinely ship
// byte-identical layers (llava:latest is the v1.6-Mistral build, so it inherits Mistral's
// Apache-2.0 and its [INST] stop tokens). testdata/registry/README.md records every digest.
var registryDocSources = map[string]registryDoc{
	"llama3.2:latest": {"llama3.2_latest.license", "llama3.2_latest.template", "llama3.2_latest.params"},
	"mistral:latest":  {"apache-2.0.license", "mistral_latest.template", "inst_stop.params"},
	"deepseek-r1:8b":  {"deepseek-r1_8b.license", "deepseek-r1_8b.template", "deepseek-r1_8b.params"},
	"llava:latest":    {"apache-2.0.license", "llava_latest.template", "inst_stop.params"},
}

// modelDocs holds the rendered documentary fields for one model.
type modelDocs struct{ license, template, parameters string }

var registryDocs = loadRegistryDocs()

func loadRegistryDocs() map[string]modelDocs {
	read := func(name string) []byte {
		b, err := registryDocFS.ReadFile("testdata/registry/" + name)
		if err != nil {
			panic(fmt.Sprintf("read Ollama registry layer %s: %v", name, err))
		}
		return b
	}
	out := make(map[string]modelDocs, len(registryDocSources))
	for model, src := range registryDocSources {
		params, err := renderParameters(read(src.params))
		if err != nil {
			panic(fmt.Sprintf("render Ollama params layer %s: %v", src.params, err))
		}
		out[model] = modelDocs{
			license:    string(read(src.license)),
			template:   string(read(src.template)),
			parameters: params,
		}
	}
	return out
}

// renderParameters reproduces how Ollama turns a model's raw params layer into the flat string
// /api/show reports. The real server formats each value as fmt.Sprintf("%-*s %#v", 30, key, value)
// and joins with newlines, so a key is left-padded to 30 columns, then one space, then the Go
// literal form of the value — which is why strings come back quoted and numbers do not. A list
// value (stop tokens) expands to one line per element, in slice order.
//
// Keys are emitted in sorted order. Ollama itself ranges over a map here, so upstream ordering is
// formally unspecified, but the captured gemma3:12b fixture came back alphabetical and this
// honeypot's response caches depend on a byte-stable body anyway.
func renderParameters(raw []byte) (string, error) {
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	keys := make([]string, 0, len(parsed))
	for k := range parsed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lines []string
	for _, k := range keys {
		values := []any{parsed[k]}
		if list, ok := parsed[k].([]any); ok {
			values = list
		}
		for _, v := range values {
			lines = append(lines, fmt.Sprintf("%-*s %#v", 30, k, v))
		}
	}
	return strings.Join(lines, "\n"), nil
}

type architectureProfile struct {
	architecture      string
	basename          string
	parameterCount    int64
	blockCount        int
	contextLength     int
	embeddingLength   int
	feedForwardLength int
	vocabSize         int
	headCount         int
	headCountKV       int
	ropeDimension     int
	ropeFreqBase      int
	tokenizerModel    string
	tokenizerPre      string
	bosTokenID        int
	eosTokenID        int
	vision            *visionProfile
}

type visionProfile struct {
	blockCount        int
	embeddingLength   int
	feedForwardLength int
	patchSize         int
	imageSize         int
}

// architectureProfiles cover advertised models without captured fixture JSON in testdata.
// Values come from their published model architectures. Every metadata dimension is also used by
// the tensor inventory, so these responses cannot contradict themselves.
var architectureProfiles = map[string]architectureProfile{
	"llama3.2:latest": {
		architecture: "llama", basename: "Llama-3.2-3B-Instruct",
		parameterCount: 3212749888, blockCount: 28, contextLength: 131072,
		embeddingLength: 3072, feedForwardLength: 8192, vocabSize: 128256,
		headCount: 24, headCountKV: 8, ropeDimension: 128, ropeFreqBase: 500000,
		tokenizerModel: "gpt2", tokenizerPre: "llama-bpe", bosTokenID: 128000, eosTokenID: 128009,
	},
	"mistral:latest": {
		architecture: "llama", basename: "Mistral-7B-Instruct-v0.3",
		parameterCount: 7248023552, blockCount: 32, contextLength: 32768,
		embeddingLength: 4096, feedForwardLength: 14336, vocabSize: 32768,
		headCount: 32, headCountKV: 8, ropeDimension: 128, ropeFreqBase: 1000000,
		tokenizerModel: "llama", tokenizerPre: "default", bosTokenID: 1, eosTokenID: 2,
	},
	"deepseek-r1:8b": {
		architecture: "llama", basename: "DeepSeek-R1-Distill-Llama-8B",
		parameterCount: 8030261248, blockCount: 32, contextLength: 131072,
		embeddingLength: 4096, feedForwardLength: 14336, vocabSize: 128256,
		headCount: 32, headCountKV: 8, ropeDimension: 128, ropeFreqBase: 500000,
		tokenizerModel: "gpt2", tokenizerPre: "llama-bpe", bosTokenID: 128000, eosTokenID: 128001,
	},
	"llava:latest": {
		architecture: "llama", basename: "LLaVA-v1.5-7B",
		parameterCount: 7066308608, blockCount: 32, contextLength: 4096,
		embeddingLength: 4096, feedForwardLength: 11008, vocabSize: 32000,
		headCount: 32, headCountKV: 32, ropeDimension: 128, ropeFreqBase: 10000,
		tokenizerModel: "llama", tokenizerPre: "default", bosTokenID: 1, eosTokenID: 2,
		vision: &visionProfile{
			blockCount: 24, embeddingLength: 1024, feedForwardLength: 4096,
			patchSize: 14, imageSize: 336,
		},
	},
}

func profileFor(m CatalogModel) architectureProfile {
	if isSeedModel(m) {
		if p, ok := architectureProfiles[showProfileName(m)]; ok {
			return p
		}
	}
	// Any identity without a complete grounded architecture profile uses a self-consistent,
	// deliberately modest fallback rather than claiming metadata from a named real model.
	heads := m.Details.EmbeddingLength / 128
	if heads < 1 {
		heads = 8
	}
	return architectureProfile{
		architecture: m.arch, basename: strings.SplitN(m.Name, ":", 2)[0],
		parameterCount: m.Size / 2 * 3, blockCount: m.blocks,
		contextLength: m.Details.ContextLength, embeddingLength: m.Details.EmbeddingLength,
		feedForwardLength: m.Details.EmbeddingLength * 4, vocabSize: 32000,
		headCount: heads, headCountKV: max(1, heads/4), ropeDimension: 128,
		ropeFreqBase: 10000, tokenizerModel: "llama", tokenizerPre: "default",
		bosTokenID: 1, eosTokenID: 2,
	}
}

// cloudShowProfile holds what /api/show reports for a cloud model beyond what its /api/tags entry
// already carries. A real server does not read the local stub to answer this — it proxies
// ollama.com — so these are the upstream registry's own values, captured from that endpoint.
type cloudShowProfile struct {
	// architecture is the vendor's architecture slug, which upstream reports as details.family.
	architecture string
	// parameterCount is the exact upstream count. details.parameter_size is its decimal string.
	parameterCount int64
	// modifiedAt is the upstream publication timestamp, deliberately not the local manifest mtime
	// that /api/tags reports for the same model. On a real box those two genuinely disagree.
	modifiedAt string
}

var cloudShowProfiles = map[string]cloudShowProfile{
	"gpt-oss:120b-cloud":    {architecture: "gptoss", parameterCount: 116829156672, modifiedAt: "2025-08-05T00:00:00Z"},
	"deepseek-v4-pro:cloud": {architecture: "deepseek4", parameterCount: 1600000000000, modifiedAt: "2026-04-24T00:00:00Z"},
	"glm-5.2:cloud":         {architecture: "glm5.2", parameterCount: 756162687872, modifiedAt: "2026-06-16T08:00:00-07:00"},
	"kimi-k2.6:cloud":       {architecture: "kimi-k2", parameterCount: 1042000000000, modifiedAt: "2026-03-31T00:00:00Z"},
	"minimax-m2.7:cloud":    {architecture: "minimax-m2", parameterCount: 229000000000, modifiedAt: "2026-03-18T00:00:00Z"},
}

// parseParameterCount converts a vendor parameter label ("117B", "1.6T", "0") into an approximate
// count. Only reached for a cloud stub we do not advertise, where the label is all there is.
func parseParameterCount(label string) int64 {
	if label == "" {
		return 0
	}
	mult := float64(1)
	digits := label
	switch strings.ToUpper(label[len(label)-1:]) {
	case "M":
		mult, digits = 1e6, label[:len(label)-1]
	case "B":
		mult, digits = 1e9, label[:len(label)-1]
	case "T":
		mult, digits = 1e12, label[:len(label)-1]
	}
	n, err := strconv.ParseFloat(digits, 64)
	if err != nil {
		return 0
	}
	return int64(n * mult)
}

// buildCloudShow answers /api/show for a cloud model the way a real server does: by relaying what
// ollama.com says, which is a far thinner document than a local model's. There is no modelfile,
// license, template, parameters or tensor inventory, because the box holds no blob for it — only
// a four-key model_info, the details block and the capability list.
//
// details also disagrees with the same model's /api/tags entry in three ways, and it disagrees on
// a real server too, so reproducing the disagreement matters: parent_model is populated with the
// upstream name, family carries the architecture slug instead of being empty, and parameter_size
// is the raw integer as a string rather than the vendor's rounded label ("116829156672", not
// "117B"). context_length and embedding_length move out of details and into model_info.
func buildCloudShow(m CatalogModel) showResponse {
	p, grounded := cloudShowProfiles[showProfileName(m)]
	if !grounded {
		p = cloudShowProfile{
			architecture:   strings.SplitN(m.RemoteModel, ":", 2)[0],
			parameterCount: parseParameterCount(m.Details.ParameterSize),
			modifiedAt:     m.ModifiedAt,
		}
	}
	arch := p.architecture
	return showResponse{
		Details: showDetails{
			ParentModel:       m.RemoteModel,
			Family:            arch,
			ParameterSize:     strconv.FormatInt(p.parameterCount, 10),
			QuantizationLevel: m.Details.QuantizationLevel,
		},
		ModelInfo: map[string]any{
			"general.architecture":     arch,
			"general.parameter_count":  p.parameterCount,
			arch + ".context_length":   m.Details.ContextLength,
			arch + ".embedding_length": m.Details.EmbeddingLength,
		},
		Capabilities: m.Capabilities,
		ModifiedAt:   p.modifiedAt,
	}
}

func modelInfo(m CatalogModel) map[string]any {
	p := profileFor(m)
	a := p.architecture
	info := map[string]any{
		"general.architecture":                  a,
		"general.basename":                      p.basename,
		"general.file_type":                     15,
		"general.parameter_count":               p.parameterCount,
		"general.quantization_version":          2,
		"general.type":                          "model",
		a + ".attention.head_count":             p.headCount,
		a + ".attention.head_count_kv":          p.headCountKV,
		a + ".attention.layer_norm_rms_epsilon": 1e-05,
		a + ".block_count":                      p.blockCount,
		a + ".context_length":                   p.contextLength,
		a + ".embedding_length":                 p.embeddingLength,
		a + ".feed_forward_length":              p.feedForwardLength,
		a + ".rope.dimension_count":             p.ropeDimension,
		a + ".rope.freq_base":                   p.ropeFreqBase,
		a + ".vocab_size":                       p.vocabSize,
		"tokenizer.ggml.bos_token_id":           p.bosTokenID,
		"tokenizer.ggml.eos_token_id":           p.eosTokenID,
		"tokenizer.ggml.model":                  p.tokenizerModel,
		"tokenizer.ggml.pre":                    p.tokenizerPre,
	}
	if p.vision != nil {
		info["clip.vision.block_count"] = p.vision.blockCount
		info["clip.vision.embedding_length"] = p.vision.embeddingLength
		info["clip.vision.feed_forward_length"] = p.vision.feedForwardLength
		info["clip.vision.image_size"] = p.vision.imageSize
		info["clip.vision.patch_size"] = p.vision.patchSize
	}
	return info
}

func tensorList(m CatalogModel) []tensor {
	p := profileFor(m)
	embd := p.embeddingLength
	if embd == 0 {
		embd = 4096
	}
	ffn := p.feedForwardLength
	headWidth := embd / p.headCount
	kvWidth := headWidth * p.headCountKV
	capacity := 3 + 9*p.blockCount
	if p.vision != nil {
		capacity += 5 + 8*p.vision.blockCount
	}
	out := make([]tensor, 0, capacity)
	out = append(out, tensor{Name: "token_embd.weight", Type: "Q4_K", Shape: []int{embd, p.vocabSize}})
	for i := 0; i < p.blockCount; i++ {
		p := fmt.Sprintf("blk.%d.", i)
		out = append(out,
			tensor{Name: p + "attn_norm.weight", Type: "F32", Shape: []int{embd}},
			tensor{Name: p + "attn_q.weight", Type: "Q4_K", Shape: []int{embd, embd}},
			tensor{Name: p + "attn_k.weight", Type: "Q4_K", Shape: []int{embd, kvWidth}},
			tensor{Name: p + "attn_v.weight", Type: "Q6_K", Shape: []int{embd, kvWidth}},
			tensor{Name: p + "attn_output.weight", Type: "Q4_K", Shape: []int{embd, embd}},
			tensor{Name: p + "ffn_norm.weight", Type: "F32", Shape: []int{embd}},
			tensor{Name: p + "ffn_gate.weight", Type: "Q4_K", Shape: []int{embd, ffn}},
			tensor{Name: p + "ffn_up.weight", Type: "Q4_K", Shape: []int{embd, ffn}},
			tensor{Name: p + "ffn_down.weight", Type: "Q6_K", Shape: []int{ffn, embd}},
		)
	}
	out = append(out,
		tensor{Name: "output_norm.weight", Type: "F32", Shape: []int{embd}},
		tensor{Name: "output.weight", Type: "Q6_K", Shape: []int{embd, p.vocabSize}},
	)
	if p.vision != nil {
		v := p.vision
		out = append(out,
			tensor{Name: "mm.0.weight", Type: "F16", Shape: []int{v.embeddingLength, embd}},
			tensor{Name: "mm.2.weight", Type: "F16", Shape: []int{embd, embd}},
			tensor{Name: "v.class_embd", Type: "F32", Shape: []int{v.embeddingLength}},
			tensor{Name: "v.patch_embd.weight", Type: "F16", Shape: []int{v.patchSize, v.patchSize, 3, v.embeddingLength}},
			tensor{Name: "v.position_embd.weight", Type: "F16", Shape: []int{v.embeddingLength, 1 + (v.imageSize/v.patchSize)*(v.imageSize/v.patchSize)}},
		)
		for i := 0; i < v.blockCount; i++ {
			prefix := fmt.Sprintf("v.blk.%d.", i)
			out = append(out,
				tensor{Name: prefix + "attn_norm.weight", Type: "F32", Shape: []int{v.embeddingLength}},
				tensor{Name: prefix + "attn_q.weight", Type: "F16", Shape: []int{v.embeddingLength, v.embeddingLength}},
				tensor{Name: prefix + "attn_k.weight", Type: "F16", Shape: []int{v.embeddingLength, v.embeddingLength}},
				tensor{Name: prefix + "attn_v.weight", Type: "F16", Shape: []int{v.embeddingLength, v.embeddingLength}},
				tensor{Name: prefix + "attn_output.weight", Type: "F16", Shape: []int{v.embeddingLength, v.embeddingLength}},
				tensor{Name: prefix + "ffn_norm.weight", Type: "F32", Shape: []int{v.embeddingLength}},
				tensor{Name: prefix + "ffn_up.weight", Type: "F16", Shape: []int{v.embeddingLength, v.feedForwardLength}},
				tensor{Name: prefix + "ffn_down.weight", Type: "F16", Shape: []int{v.feedForwardLength, v.embeddingLength}},
			)
		}
	}
	return out
}

func showDetailsFor(m CatalogModel) showDetails {
	return showDetails{
		ParentModel: m.Details.ParentModel, Format: m.Details.Format,
		Family: m.Details.Family, Families: m.Details.Families,
		ParameterSize: m.Details.ParameterSize, QuantizationLevel: m.Details.QuantizationLevel,
	}
}

func safeModelfileName(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, name)
}

// buildShow selects a captured response by source identity or builds a consistent fallback.
func buildShow(m CatalogModel) showResponse {
	if m.isCloud() {
		return buildCloudShow(m)
	}
	profileName := showProfileName(m)
	if grounded, ok := groundedShowFixtures[profileName]; ok && isSeedModel(m) {
		if m.Name != profileName {
			grounded.Modelfile = strings.Replace(grounded.Modelfile,
				"# FROM "+profileName, "# FROM "+safeModelfileName(m.Name), 1)
		}
		return grounded
	}
	safeName := safeModelfileName(m.Name)
	resp := showResponse{
		Modelfile: fmt.Sprintf("# Modelfile generated by \"ollama show\"\n"+
			"# To build a new Modelfile based on this, replace FROM with:\n"+
			"# FROM %s\n\nFROM /root/.ollama/models/blobs/sha256-%s",
			safeName, m.Digest),
		Details:      showDetailsFor(m),
		ModelInfo:    modelInfo(m),
		Tensors:      tensorList(m),
		Capabilities: m.Capabilities,
		ModifiedAt:   m.ModifiedAt,
	}
	// Attach the registry's own license, template and parameter layers for advertised models
	// (threat_gg-y0i). Gated on isSeedModel for the same reason the grounded fixtures are: these
	// documents belong to a specific registry model, so they may only be served for an entry that
	// still carries that model's digest. A copy inherits them, which is correct — a copied model
	// really does keep the source's template and license.
	if docs, ok := registryDocs[showProfileName(m)]; ok && isSeedModel(m) {
		resp.License = docs.license
		resp.Template = docs.template
		resp.Parameters = docs.parameters
	}
	return resp
}

var seedModelDigests = func() map[string]string {
	out := make(map[string]string, len(seedModels))
	for _, m := range seedModels {
		out[m.Name] = m.Digest
	}
	return out
}()

func showProfileName(m CatalogModel) string {
	if m.showProfile != "" {
		return m.showProfile
	}
	return m.Name
}

// isSeedModel recognizes a grounded seed digest through its preserved source show profile.
func isSeedModel(m CatalogModel) bool {
	digest, ok := seedModelDigests[showProfileName(m)]
	return ok && digest == m.Digest
}

// isImmutableSeedModel reports whether m is a grounded immutable catalog.base seed entry.
func isImmutableSeedModel(m CatalogModel) bool {
	return m.immutableBase && isSeedModel(m)
}

// showCacheKey is the identity triple shared by immutable and per-view response caches.
type showCacheKey struct {
	name, digest, modifiedAt string
}

// showPayload couples a decoded show response with its final serialized representation.
type showPayload struct {
	key      showCacheKey
	response showResponse
	body     []byte
}

// cachedShowPayload is the compact per-view cache representation. Mutable entries only need the
// serialized response at request time, so retaining a second decoded tensor inventory would
// roughly double the bounded cache's memory.
type cachedShowPayload struct {
	key  showCacheKey
	body []byte
}

// advertisedShowPayloads caches final JSON only for immutable base-catalog entries.
// The full model identity is part of the key so a same-name per-IP overlay cannot receive stale
// base metadata. Pulled overlays, including re-pulled seeds with a fresh ModifiedAt, are not cached;
// otherwise attacker-controlled identities could create an unbounded process-lifetime cache.
var advertisedShowPayloads sync.Map

func buildShowPayload(m CatalogModel) showPayload {
	key := showCacheKey{name: m.Name, digest: m.Digest, modifiedAt: m.ModifiedAt}
	response := buildShow(m)
	// Grounded fixtures retain their captured content, but use the stable timestamp belonging to
	// the catalog entry currently being served. Cloud models are the exception: their /api/show
	// timestamp comes from ollama.com and is genuinely different from the local manifest mtime
	// that /api/tags reports, so overwriting it here would erase a real divergence.
	if !m.isCloud() {
		response.ModifiedAt = m.ModifiedAt
	}
	body, err := json.Marshal(response)
	if err != nil {
		// showResponse contains only JSON-native fixture/profile values. A marshal failure is a
		// programmer/configuration error and should fail loudly rather than emit a partial body.
		panic(fmt.Sprintf("marshal Ollama /api/show response for %s: %v", m.Name, err))
	}
	return showPayload{key: key, response: response, body: body}
}

func showPayloadFor(m CatalogModel) showPayload {
	if !isImmutableSeedModel(m) {
		return buildShowPayload(m)
	}
	key := showCacheKey{name: m.Name, digest: m.Digest, modifiedAt: m.ModifiedAt}
	if cached, ok := advertisedShowPayloads.Load(key); ok {
		return cached.(showPayload)
	}
	built := buildShowPayload(m)
	cached, _ := advertisedShowPayloads.LoadOrStore(key, built)
	return cached.(showPayload)
}

// showBodyForRequest adds a bounded cache for mutable overlays. Its entries live inside the
// caller's capped, TTL-evicted catalog view and are replaced by name, so fresh re-pulls cannot
// create a process-lifetime cache entry for every ModifiedAt value.
func showBodyForRequest(r *http.Request, m CatalogModel) []byte {
	if isImmutableSeedModel(m) {
		return showPayloadFor(m).body
	}
	key := showCacheKey{name: m.Name, digest: m.Digest, modifiedAt: m.ModifiedAt}
	v := models.viewForCachedShow(clientIP(r))
	if v == nil {
		return buildShowPayload(m).body
	}

	buildLock := v.showLockFor(m.Name)
	buildLock.Lock()
	defer buildLock.Unlock()

	v.showMu.Lock()
	if cached, ok := v.showPayloads[m.Name]; ok && cached.key == key {
		body := cached.body
		v.showMu.Unlock()
		return body
	}
	v.showMu.Unlock()

	built := buildShowPayload(m)
	return models.cacheShowPayloadIfCurrent(clientIP(r), v, m, buildLock, built)
}

func showFor(m CatalogModel) showResponse {
	return showPayloadFor(m).response
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
	m, ok := models.get(r, req.model())
	if !ok {
		llmcore.WriteModelNotFoundAPI(w, profile, normalize(req.model()))
		return
	}
	body := showBodyForRequest(r, m)
	w.Header().Set("Content-Type", llmcore.CTJSONCharset)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// -- /api/pull

type pullStatus struct {
	Status    string `json:"status"`
	Digest    string `json:"digest,omitempty"`
	Total     int64  `json:"total,omitempty"`
	Completed int64  `json:"completed,omitempty"`
	Error     string `json:"error,omitempty"`
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
	target := buildModelForName(name)
	if target.Name == "" || len(target.Name) > maxModelNameBytes {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, "invalid model name")
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

	for _, s := range []string{"verifying sha256 digest", "writing manifest"} {
		if !emit(pullStatus{Status: s}) {
			return
		}
	}
	if !models.add(r, target) {
		emit(pullStatus{Error: "model storage limit reached"})
		return
	}
	emit(pullStatus{Status: "success"})
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
	if req.From != "" && models.has(r, req.From) {
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
	src, ok := models.get(r, req.Source)
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
		if copied.Name == "" || len(copied.Name) > maxModelNameBytes {
			llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, "invalid model name")
			return
		}
		if !models.replace(r, copied) {
			llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, "model storage limit reached")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	if err := readJSON(r, &req); err != nil {
		llmcore.WriteOllamaError(w, profile, http.StatusBadRequest, err.Error())
		return
	}
	if !models.remove(r, req.model()) {
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

// handleEmbedAPI, handleEmbedLegacyAPI and handleEmbedV1 report the refusal a real server
// returns for a model without embedding support, which is true of every model in the advertised
// catalog. Inventing a plausible float vector would be both more work and less accurate than the
// genuine refusal. The status code is route-specific, not a single constant: measured against a
// real Ollama 0.30.11 (threat_gg-5fb), /api/embed and /v1/embeddings answer 501 but the legacy
// /api/embeddings answers 500 for the identical refusal body — Ollama embeds llama.cpp, and only
// the legacy route's error path surfaces it as an unhandled 500 rather than a deliberate 501.
func handleEmbedAPI(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	_ = readJSON(r, &req)
	if req.model() != "" && !models.has(r, req.model()) {
		llmcore.WriteOllamaError(w, profile, http.StatusNotFound,
			fmt.Sprintf("model %q not found, try pulling it first", req.model()))
		return
	}
	llmcore.WriteEmbeddingsUnsupported(w, profile, http.StatusNotImplemented, false)
}

// handleEmbedLegacyAPI serves the deprecated /api/embeddings route, which returns 500 rather
// than 501 for the same refusal (see handleEmbedAPI's comment).
func handleEmbedLegacyAPI(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	_ = readJSON(r, &req)
	if req.model() != "" && !models.has(r, req.model()) {
		llmcore.WriteOllamaError(w, profile, http.StatusNotFound,
			fmt.Sprintf("model %q not found, try pulling it first", req.model()))
		return
	}
	llmcore.WriteEmbeddingsUnsupported(w, profile, http.StatusInternalServerError, false)
}

func handleEmbedV1(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	_ = readJSON(r, &req)
	if req.model() != "" && !models.has(r, req.model()) {
		llmcore.WriteOpenAIError(w, profile, http.StatusNotFound,
			fmt.Sprintf("model %q not found, try pulling it first", req.model()), "not_found_error")
		return
	}
	llmcore.WriteEmbeddingsUnsupported(w, profile, http.StatusNotImplemented, true)
}

// -- /v1/responses

func handleResponses(w http.ResponseWriter, r *http.Request) {
	llmcore.Responses(w, r, profile)
}
