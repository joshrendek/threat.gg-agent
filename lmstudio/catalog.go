package lmstudio

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type quantization struct {
	Name          string `json:"name"`
	BitsPerWeight int    `json:"bits_per_weight"`
}

type capabilities struct {
	Vision            bool `json:"vision"`
	TrainedForToolUse bool `json:"trained_for_tool_use"`
}

type loadConfig struct {
	ContextLength       int  `json:"context_length"`
	EvalBatchSize       int  `json:"eval_batch_size,omitempty"`
	Parallel            int  `json:"parallel,omitempty"`
	FlashAttention      bool `json:"flash_attention,omitempty"`
	OffloadKVCacheToGPU bool `json:"offload_kv_cache_to_gpu,omitempty"`
}

type loadedInstance struct {
	ID     string     `json:"id"`
	Config loadConfig `json:"config"`
}

type model struct {
	Type             string           `json:"type"`
	Publisher        string           `json:"publisher"`
	Key              string           `json:"key"`
	DisplayName      string           `json:"display_name"`
	Architecture     string           `json:"architecture,omitempty"`
	Quantization     quantization     `json:"quantization"`
	SizeBytes        int64            `json:"size_bytes"`
	ParamsString     *string          `json:"params_string"`
	LoadedInstances  []loadedInstance `json:"loaded_instances"`
	MaxContextLength int              `json:"max_context_length"`
	Format           string           `json:"format"`
	Capabilities     *capabilities    `json:"capabilities,omitempty"`
	Description      json.RawMessage  `json:"description,omitempty"`
	Variants         []string         `json:"variants,omitempty"`
	SelectedVariant  string           `json:"selected_variant,omitempty"`
}

func text(value string) *string { return &value }

var baseModels = []model{
	{
		Type: "llm", Publisher: "openai", Key: defaultModel, DisplayName: "GPT OSS 20B",
		Architecture: "gpt_oss", Quantization: quantization{Name: "MXFP4", BitsPerWeight: 4},
		SizeBytes: 12_318_445_568, ParamsString: text("20B"), LoadedInstances: []loadedInstance{},
		MaxContextLength: 131072, Format: "gguf",
		Capabilities: &capabilities{Vision: false, TrainedForToolUse: true}, Description: json.RawMessage("null"),
	},
	{
		Type: "llm", Publisher: "ibm", Key: "ibm/granite-4-micro", DisplayName: "Granite 4 Micro",
		Architecture: "granite", Quantization: quantization{Name: "Q4_K_M", BitsPerWeight: 4},
		SizeBytes: 2_146_893_824, ParamsString: text("3B"), LoadedInstances: []loadedInstance{},
		MaxContextLength: 131072, Format: "gguf",
		Capabilities: &capabilities{Vision: false, TrainedForToolUse: true}, Description: json.RawMessage("null"),
	},
	{
		Type: "embedding", Publisher: "nomic-ai", Key: embeddingModel, DisplayName: "Nomic Embed Text v1.5",
		Quantization: quantization{Name: "Q4_K_M", BitsPerWeight: 4}, SizeBytes: 84_106_624,
		ParamsString: nil, LoadedInstances: []loadedInstance{}, MaxContextLength: 2048, Format: "gguf",
	},
}

const (
	maxCatalogViews     = 256
	maxDownloadsPerView = 8
	maxJobsPerView      = 16
	maxModelKeyBytes    = 255
	catalogViewTTL      = time.Hour
)

type downloadJob struct {
	JobID           string `json:"job_id,omitempty"`
	Status          string `json:"status"`
	TotalSizeBytes  int64  `json:"total_size_bytes,omitempty"`
	DownloadedBytes int64  `json:"downloaded_bytes,omitempty"`
	StartedAt       string `json:"started_at,omitempty"`
	CompletedAt     string `json:"completed_at,omitempty"`
}

type catalogView struct {
	loaded     map[string]loadConfig
	downloaded map[string]model
	jobs       map[string]downloadJob
	seen       time.Time
}

type catalog struct {
	mu        sync.Mutex
	views     map[string]*catalogView
	lastSweep time.Time
}

func newCatalog() *catalog { return &catalog{views: map[string]*catalogView{}} }

var models = newCatalog()

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (c *catalog) view(r *http.Request) *catalogView {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.viewLocked(r)
}

func baseModel(key string) (model, bool) {
	for _, candidate := range baseModels {
		if candidate.Key == key || candidate.SelectedVariant == key {
			return candidate, true
		}
	}
	return model{}, false
}

func (c *catalog) get(r *http.Request, key string) (model, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.viewLocked(r)
	if candidate, ok := v.downloaded[key]; ok {
		return candidate, true
	}
	return baseModel(key)
}

func (c *catalog) has(r *http.Request, key string) bool {
	_, ok := c.get(r, key)
	return ok
}

func (c *catalog) viewLocked(r *http.Request) *catalogView {
	// view is normally called without the catalog lock. Helpers already holding
	// it use this smaller form to avoid recursive locking.
	now := time.Now()
	ip := clientIP(r)
	if v := c.views[ip]; v != nil {
		if now.Sub(v.seen) <= catalogViewTTL {
			v.seen = now
			return v
		}
		delete(c.views, ip)
	}
	// Expiry maintenance is paid only when creating a view, never on the
	// inference hot path for an existing client.
	if c.lastSweep.IsZero() || now.Sub(c.lastSweep) >= time.Minute {
		for candidateIP, candidate := range c.views {
			if now.Sub(candidate.seen) > catalogViewTTL {
				delete(c.views, candidateIP)
			}
		}
		c.lastSweep = now
	}
	if len(c.views) >= maxCatalogViews {
		var oldestIP string
		var oldest time.Time
		for candidateIP, candidate := range c.views {
			if oldestIP == "" || candidate.seen.Before(oldest) {
				oldestIP, oldest = candidateIP, candidate.seen
			}
		}
		delete(c.views, oldestIP)
	}
	v := &catalogView{
		loaded: map[string]loadConfig{
			defaultModel: {ContextLength: 32768, EvalBatchSize: 512, Parallel: 4, FlashAttention: true, OffloadKVCacheToGPU: true},
		},
		downloaded: map[string]model{}, jobs: map[string]downloadJob{}, seen: now,
	}
	c.views[ip] = v
	return v
}

func (c *catalog) list(r *http.Request) []model {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.viewLocked(r)
	out := make([]model, 0, len(baseModels)+len(v.downloaded))
	appendModel := func(candidate model) {
		candidate.LoadedInstances = []loadedInstance{}
		if cfg, ok := v.loaded[candidate.Key]; ok {
			candidate.LoadedInstances = append(candidate.LoadedInstances, loadedInstance{ID: candidate.Key, Config: cfg})
		}
		out = append(out, candidate)
	}
	for _, candidate := range baseModels {
		appendModel(candidate)
	}
	keys := make([]string, 0, len(v.downloaded))
	for key := range v.downloaded {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		appendModel(v.downloaded[key])
	}
	return out
}

func (c *catalog) load(r *http.Request, key string, cfg loadConfig) (model, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.viewLocked(r)
	candidate, ok := v.downloaded[key]
	if !ok {
		candidate, ok = baseModel(key)
	}
	if !ok {
		return model{}, false
	}
	if cfg.ContextLength <= 0 || cfg.ContextLength > candidate.MaxContextLength {
		cfg.ContextLength = min(32768, candidate.MaxContextLength)
	}
	if candidate.Type == "llm" {
		if cfg.EvalBatchSize <= 0 || cfg.EvalBatchSize > 4096 {
			cfg.EvalBatchSize = 512
		}
		if cfg.Parallel <= 0 || cfg.Parallel > 16 {
			cfg.Parallel = 4
		}
	}
	v.loaded[candidate.Key] = cfg
	return candidate, true
}

func (c *catalog) unload(r *http.Request, instanceID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.viewLocked(r)
	if _, ok := v.loaded[instanceID]; !ok {
		return false
	}
	delete(v.loaded, instanceID)
	return true
}

func downloadedModel(key string) model {
	clean := strings.TrimSpace(key)
	name := clean
	if i := strings.LastIndex(clean, "/"); i >= 0 && i+1 < len(clean) {
		name = clean[i+1:]
	}
	return model{
		Type: "llm", Publisher: "lmstudio-community", Key: clean, DisplayName: name,
		Architecture: "llama", Quantization: quantization{Name: "Q4_K_M", BitsPerWeight: 4},
		SizeBytes: 4_681_238_528, ParamsString: text("7B"), LoadedInstances: []loadedInstance{},
		MaxContextLength: 32768, Format: "gguf",
		Capabilities: &capabilities{Vision: false, TrainedForToolUse: true}, Description: json.RawMessage("null"),
	}
}

func (c *catalog) download(r *http.Request, key string) (downloadJob, bool) {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > maxModelKeyBytes || strings.ContainsAny(key, "\x00\r\n") {
		return downloadJob{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.viewLocked(r)
	if _, ok := baseModel(key); ok {
		return downloadJob{Status: "already_downloaded"}, true
	}
	if _, exists := v.downloaded[key]; exists {
		return downloadJob{Status: "already_downloaded"}, true
	} else {
		if len(v.downloaded) >= maxDownloadsPerView {
			return downloadJob{}, false
		}
		v.downloaded[key] = downloadedModel(key)
	}
	now := time.Now().UTC()
	h := fnv.New64a()
	_, _ = h.Write([]byte(clientIP(r) + "\x00" + key + "\x00" + now.Format(time.RFC3339Nano)))
	job := downloadJob{
		JobID: fmt.Sprintf("job_%010x", h.Sum64()), Status: "completed",
		TotalSizeBytes: 4_681_238_528, DownloadedBytes: 4_681_238_528,
		StartedAt: now.Add(-9 * time.Minute).Format(time.RFC3339Nano), CompletedAt: now.Format(time.RFC3339Nano),
	}
	if len(v.jobs) >= maxJobsPerView {
		for oldest := range v.jobs {
			delete(v.jobs, oldest)
			break
		}
	}
	v.jobs[job.JobID] = job
	return job, true
}

func (c *catalog) job(r *http.Request, id string) (downloadJob, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.viewLocked(r)
	job, ok := v.jobs[id]
	return job, ok
}
