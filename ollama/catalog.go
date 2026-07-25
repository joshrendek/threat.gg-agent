package ollama

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// Details mirrors the "details" object in Ollama's /api/tags and /api/show payloads. Field
// order matches the real server's struct order — encoding/json sorts map keys alphabetically,
// so building these from maps produces an ordering no real Ollama emits.
type Details struct {
	ParentModel       string   `json:"parent_model"`
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
	ContextLength     int      `json:"context_length,omitempty"`
	EmbeddingLength   int      `json:"embedding_length,omitempty"`
}

// CatalogModel is one locally-present model.
type CatalogModel struct {
	Name         string   `json:"name"`
	Model        string   `json:"model"`
	ModifiedAt   string   `json:"modified_at"`
	Size         int64    `json:"size"`
	Digest       string   `json:"digest"`
	Details      Details  `json:"details"`
	Capabilities []string `json:"capabilities"`

	// arch is the GGUF architecture prefix used to synthesise /api/show model_info keys.
	arch string `json:"-"`
	// blocks is the transformer layer count, used for the /api/show tensor listing.
	blocks int `json:"-"`
}

// seedModels is the advertised catalog. llama3.2:latest and mistral:latest are kept byte-identical
// to what the honeypot has been serving since July — captured traffic shows scanners read
// /api/tags and then probe exactly the names they find there, so renaming them would break the
// validation loop that is already working. The other four widen the surface: since off-catalog
// models now get a faithful 404 (a real box only serves what its owner pulled), the way to keep
// probes landing is to stock a bigger shelf, not to answer for models we do not list.
var seedModels = []CatalogModel{
	{
		Name: "llama3.2:latest", Model: "llama3.2:latest",
		Size:   2019393189,
		Digest: "a80c4f17acd55265feb1f6c8f10a0b2b6b6c7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
		Details: Details{
			Format: "gguf", Family: "llama", Families: []string{"llama"},
			ParameterSize: "3.2B", QuantizationLevel: "Q4_K_M",
			ContextLength: 131072, EmbeddingLength: 3072,
		},
		Capabilities: []string{"completion", "tools"},
		arch:         "llama", blocks: 28,
	},
	{
		Name: "mistral:latest", Model: "mistral:latest",
		Size:   4113301824,
		Digest: "61e88e884507ba5e06c49b40e6226884b2a16e872382c2b44a42f2d119d804a5",
		Details: Details{
			Format: "gguf", Family: "llama", Families: []string{"llama"},
			ParameterSize: "7.2B", QuantizationLevel: "Q4_0",
			ContextLength: 32768, EmbeddingLength: 4096,
		},
		Capabilities: []string{"completion", "tools"},
		arch:         "llama", blocks: 32,
	},
	{
		Name: "qwen2.5-coder:7b", Model: "qwen2.5-coder:7b",
		Size:   4683087561,
		Digest: "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364",
		Details: Details{
			Format: "gguf", Family: "qwen2", Families: []string{"qwen2"},
			ParameterSize: "7.6B", QuantizationLevel: "Q4_K_M",
			ContextLength: 32768, EmbeddingLength: 3584,
		},
		Capabilities: []string{"completion", "tools", "insert"},
		arch:         "qwen2", blocks: 28,
	},
	{
		Name: "gemma3:12b", Model: "gemma3:12b",
		Size:   8149190253,
		Digest: "f4031aab637d1ffa37b42570452ae0e4fad0314754d17ded67322e4b95836f8a",
		Details: Details{
			Format: "gguf", Family: "gemma3", Families: []string{"gemma3"},
			ParameterSize: "12.2B", QuantizationLevel: "Q4_K_M",
			ContextLength: 131072, EmbeddingLength: 3840,
		},
		Capabilities: []string{"completion", "vision"},
		arch:         "gemma3", blocks: 48,
	},
	{
		Name: "deepseek-r1:8b", Model: "deepseek-r1:8b",
		Size:   4920738147,
		Digest: "6995872bfe4c5b2b0e3b1a9c48ec1e2ba1b7f6b4ba9d40e1e4c0e6a0b5f2c3d7",
		Details: Details{
			Format: "gguf", Family: "qwen3", Families: []string{"qwen3"},
			ParameterSize: "8.2B", QuantizationLevel: "Q4_K_M",
			ContextLength: 131072, EmbeddingLength: 4096,
		},
		Capabilities: []string{"completion", "thinking"},
		arch:         "qwen3", blocks: 36,
	},
	{
		Name: "llava:latest", Model: "llava:latest",
		Size:   4733363377,
		Digest: "8dd30f6b0cb19f555f2c7a7ebda861449ea2cc76bf1f44e262931f45fc81d081",
		Details: Details{
			Format: "gguf", Family: "llama", Families: []string{"llama", "clip"},
			ParameterSize: "7B", QuantizationLevel: "Q4_0",
			ContextLength: 32768, EmbeddingLength: 4096,
		},
		Capabilities: []string{"completion", "vision"},
		arch:         "llama", blocks: 32,
	},
}

// catalog is the instance's model list. It is mutable because /api/pull adds to it: an attacker
// who pulls a model and then finds it in /api/tags will go on to use it, which is exactly the
// traffic worth capturing.
type catalog struct {
	mu     sync.RWMutex
	models []CatalogModel
}

var models = newCatalog()

func newCatalog() *catalog {
	c := &catalog{models: make([]CatalogModel, len(seedModels))}
	copy(c.models, seedModels)
	// Stagger the timestamps so the catalog looks accumulated over time rather than seeded at
	// once. Computed at startup and stable thereafter: a scanner polling twice must see the
	// same values.
	base := time.Now().UTC().Add(-27 * 24 * time.Hour)
	for i := range c.models {
		c.models[i].ModifiedAt = base.
			Add(time.Duration(i) * 53 * time.Hour).
			Add(time.Duration(i*7919) * time.Millisecond).
			Format(time.RFC3339Nano)
	}
	return c
}

// normalize applies Ollama's implicit ":latest" tag so "llama3.2" and "llama3.2:latest" resolve
// to the same entry, as they do on a real server.
func normalize(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	if !strings.Contains(n, ":") {
		return n + ":latest"
	}
	return n
}

func (c *catalog) list() []CatalogModel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]CatalogModel, len(c.models))
	copy(out, c.models)
	return out
}

func (c *catalog) get(name string) (CatalogModel, bool) {
	n := normalize(name)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, m := range c.models {
		if m.Name == n {
			return m, true
		}
	}
	return CatalogModel{}, false
}

func (c *catalog) has(name string) bool {
	_, ok := c.get(name)
	return ok
}

// add records a model as locally present. Called by /api/pull once the fake download
// "completes"; a no-op if the model is already listed.
func (c *catalog) add(m CatalogModel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.models {
		if existing.Name == m.Name {
			return
		}
	}
	c.models = append(c.models, m)
}

// remove drops a model, backing /api/delete.
func (c *catalog) remove(name string) bool {
	n := normalize(name)
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, m := range c.models {
		if m.Name == n {
			c.models = append(c.models[:i], c.models[i+1:]...)
			return true
		}
	}
	return false
}

// synthesize builds a plausible catalog entry for a model an attacker pulled. Parameter size and
// footprint are inferred from the tag (":1b", ":70b", …) so a pulled llama3.2:1b does not claim
// to be the same size as a 70B.
func synthesize(name string) CatalogModel {
	n := normalize(name)
	tag := ""
	if i := strings.LastIndex(n, ":"); i >= 0 {
		tag = strings.ToLower(n[i+1:])
	}
	params, size := "7B", int64(4113301824)
	ctx, embd, blocks := 32768, 4096, 32
	switch {
	case strings.HasPrefix(tag, "0.5b"), strings.HasPrefix(tag, "1b"):
		params, size, embd, blocks = "1.2B", 1321098329, 2048, 16
	case strings.HasPrefix(tag, "1.5b"), strings.HasPrefix(tag, "2b"):
		params, size, embd, blocks = "1.8B", 1629518745, 2048, 24
	case strings.HasPrefix(tag, "3b"):
		params, size, embd, blocks = "3.2B", 2019393189, 3072, 28
	case strings.HasPrefix(tag, "13b"), strings.HasPrefix(tag, "14b"):
		params, size, embd, blocks = "13.0B", 7365960935, 5120, 40
	case strings.HasPrefix(tag, "32b"), strings.HasPrefix(tag, "34b"):
		params, size, embd, blocks = "32.8B", 19851349898, 5120, 64
	case strings.HasPrefix(tag, "70b"):
		params, size, embd, blocks = "70.6B", 39969734263, 8192, 80
	}
	return CatalogModel{
		Name: n, Model: n,
		ModifiedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Size:       size,
		Digest:     pseudoDigest(n),
		Details: Details{
			Format: "gguf", Family: "llama", Families: []string{"llama"},
			ParameterSize: params, QuantizationLevel: "Q4_K_M",
			ContextLength: ctx, EmbeddingLength: embd,
		},
		Capabilities: []string{"completion", "tools"},
		arch:         "llama", blocks: blocks,
	}
}

// pseudoDigest derives a stable 64-hex-character digest from a model name, so the same pulled
// model always reports the same digest across /api/tags, /api/show and the pull progress stream.
//
// This must be a real hash. An earlier version concatenated four FNV-1a hashes of the same name
// with a trailing counter, which produced visibly correlated 8-byte blocks —
// 9b7b80336b17…9b7b81336b17…9b7b82336b17 — where a genuine sha256 is uniformly random. That
// pattern was legible in the /api/pull stream and was a fingerprint in its own right.
func pseudoDigest(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}
