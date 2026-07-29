package ollama

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Regression tests for threat_gg-1to: Ollama cloud models.
//
// A cloud model is a thin local stub that turns the box into an authenticated proxy to Ollama's
// hosted inference, so an exposed one is effectively free frontier-model access. A scanner
// campaign is enumerating them — ~60 probes across 20+ names on 2026-07-29, every one of which
// this honeypot used to 404, so the operators left immediately.
//
// The expectations below are not derived from documentation. Each was captured from a real Ollama
// 0.30.11 that had actually pulled the model, cross-checked against the raw registry manifest at
// registry.ollama.ai, and (for /api/show) against what ollama.com itself returns.

// The /api/tags entry a real Ollama 0.30.11 emitted for gpt-oss:120b-cloud immediately after
// pulling it. modified_at is the local manifest mtime and is the only field that legitimately
// varies per box, so it is substituted in.
const wantCloudTagsEntry = `{"name":"gpt-oss:120b-cloud","model":"gpt-oss:120b-cloud",` +
	`"remote_model":"gpt-oss:120b","remote_host":"https://ollama.com","modified_at":%q,` +
	`"size":307,"digest":"ac7f7a1e778577c4418f6a25e46e0b45dced6746c75422d4b343aa1495a022ed",` +
	`"details":{"parent_model":"","format":"","family":"","families":null,` +
	`"parameter_size":"117B","quantization_level":"MXFP4","context_length":131072,` +
	`"embedding_length":2880},"capabilities":["completion","tools","thinking"]}`

// What a real server returns from /api/show for the same model. It is far thinner than a local
// model's: the box holds no blob, so there is no modelfile, license, template, parameters or
// tensor inventory — only four model_info keys, details and capabilities.
const wantCloudShow = `{"details":{"parent_model":"gpt-oss:120b","format":"","family":"gptoss",` +
	`"families":null,"parameter_size":"116829156672","quantization_level":"MXFP4"},` +
	`"model_info":{"general.architecture":"gptoss","general.parameter_count":116829156672,` +
	`"gptoss.context_length":131072,"gptoss.embedding_length":2880},` +
	`"capabilities":["completion","tools","thinking"],"modified_at":"2025-08-05T00:00:00Z"}`

func tagsEntry(t *testing.T, model string) json.RawMessage {
	t.Helper()
	var resp struct {
		Models []json.RawMessage `json:"models"`
	}
	body := do(t, "GET", "/api/tags", "").Body.Bytes()
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode /api/tags: %v", err)
	}
	for _, raw := range resp.Models {
		var probe struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("decode /api/tags entry: %v", err)
		}
		if probe.Name == model {
			return raw
		}
	}
	t.Fatalf("%s missing from /api/tags", model)
	return nil
}

// The campaign only escalates against models it can see, so the stubs have to be listed — and
// listed in the exact shape a real pull produces, byte for byte.
func TestCloudModelTagsEntryMatchesRealOllama(t *testing.T) {
	entry := tagsEntry(t, "gpt-oss:120b-cloud")
	var probe struct {
		ModifiedAt string `json:"modified_at"`
	}
	if err := json.Unmarshal(entry, &probe); err != nil {
		t.Fatalf("decode entry: %v", err)
	}
	if want := fmt.Sprintf(wantCloudTagsEntry, probe.ModifiedAt); string(entry) != want {
		t.Errorf("/api/tags cloud entry diverged from captured Ollama 0.30.11:\n got %s\nwant %s",
			entry, want)
	}
}

func TestCloudModelShowMatchesRealOllama(t *testing.T) {
	rec := do(t, "POST", "/api/show", `{"model":"gpt-oss:120b-cloud"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != wantCloudShow {
		t.Errorf("/api/show cloud response diverged from captured Ollama 0.30.11:\n got %s\nwant %s",
			got, wantCloudShow)
	}
}

// A cloud model has no local weights, so anything that describes a local GGUF must be absent.
// Advertising a multi-GB size or a "gguf" format for a model whose blob the box does not hold is
// the single strongest signal that a catalog entry was fabricated.
func TestCloudModelsCarryNoLocalArtifacts(t *testing.T) {
	for _, m := range models.list(httptest.NewRequest("GET", "/", nil)) {
		if !m.isCloud() {
			continue
		}
		t.Run(m.Name, func(t *testing.T) {
			if m.Details.Format != "" {
				t.Errorf("details.format = %q, want empty: there is no local GGUF", m.Details.Format)
			}
			if m.Details.Families != nil {
				t.Errorf("details.families = %v, want null", m.Details.Families)
			}
			if m.Details.ParentModel != "" {
				t.Errorf("tags details.parent_model = %q, want empty", m.Details.ParentModel)
			}
			if m.Size < cloudStubMinSize || m.Size > cloudStubMinSize+cloudStubSizeSpread {
				t.Errorf("size = %d, want a manifest-sized stub in [%d,%d]",
					m.Size, cloudStubMinSize, cloudStubMinSize+cloudStubSizeSpread)
			}
			if m.RemoteModel == "" || m.RemoteHost != cloudHost {
				t.Errorf("remote_model=%q remote_host=%q, want the upstream name and %q",
					m.RemoteModel, m.RemoteHost, cloudHost)
			}
			if strings.HasSuffix(m.RemoteModel, cloudTagSuffix) ||
				strings.HasSuffix(m.RemoteModel, ":"+cloudTag) {
				t.Errorf("remote_model = %q still carries the cloud marker", m.RemoteModel)
			}

			var resp showResponse
			rec := do(t, "POST", "/api/show", `{"model":"`+m.Name+`"}`)
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode /api/show: %v", err)
			}
			if resp.Modelfile != "" {
				t.Error("cloud /api/show must not carry a modelfile")
			}
			if len(resp.Tensors) != 0 {
				t.Errorf("cloud /api/show carried %d tensors, want none", len(resp.Tensors))
			}
			if resp.License != "" || resp.Template != "" || resp.Parameters != "" || resp.System != "" {
				t.Error("cloud /api/show must not carry local documentary layers")
			}
			if len(resp.ModelInfo) != 4 {
				t.Errorf("cloud model_info has %d keys, real proxied responses carry exactly 4",
					len(resp.ModelInfo))
			}
			// The wire body must not contain the keys at all, not merely empty values.
			for _, absent := range []string{`"modelfile"`, `"tensors"`, `"license"`, `"template"`} {
				if strings.Contains(rec.Body.String(), absent) {
					t.Errorf("cloud /api/show body contains %s; real responses omit the key", absent)
				}
			}
		})
	}
}

// /api/show and /api/tags genuinely disagree for a cloud model, because show is proxied from
// ollama.com while tags reads the local stub. A scanner that compares the two endpoints sees the
// disagreement on a real box, so collapsing them would itself be the tell.
func TestCloudShowDivergesFromTagsLikeRealOllama(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	for _, name := range []string{"gpt-oss:120b-cloud", "glm-5.2:cloud", "kimi-k2.6:cloud"} {
		t.Run(name, func(t *testing.T) {
			tagged, ok := models.get(req, name)
			if !ok {
				t.Fatalf("%s not advertised", name)
			}
			var resp showResponse
			rec := do(t, "POST", "/api/show", `{"model":"`+name+`"}`)
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode /api/show: %v", err)
			}
			if resp.Details.ParentModel != tagged.RemoteModel {
				t.Errorf("show parent_model = %q, want the upstream name %q",
					resp.Details.ParentModel, tagged.RemoteModel)
			}
			if resp.Details.Family == "" || resp.Details.Family == tagged.Details.Family {
				t.Errorf("show family = %q, want the architecture slug (tags carries %q)",
					resp.Details.Family, tagged.Details.Family)
			}
			if resp.Details.ParameterSize == tagged.Details.ParameterSize {
				t.Errorf("show parameter_size = %q, want the raw integer rather than the "+
					"vendor label tags reports", resp.Details.ParameterSize)
			}
			if strings.ContainsAny(resp.Details.ParameterSize, "BTM.") {
				t.Errorf("show parameter_size = %q, want a bare decimal integer",
					resp.Details.ParameterSize)
			}
			if resp.ModifiedAt == tagged.ModifiedAt {
				t.Error("show modified_at must be the upstream publication time, not the local mtime")
			}
			// The upstream timestamp is fixed; the local one moves with the pull.
			if want := cloudShowProfiles[name].modifiedAt; resp.ModifiedAt != want {
				t.Errorf("show modified_at = %q, want upstream %q", resp.ModifiedAt, want)
			}
		})
	}
}

// The point of the whole change: an inference probe naming a cloud model must reach the generator
// instead of 404ing. This is the campaign's actual canary prompt.
func TestCloudModelsAcceptTheCampaignCanaryPrompt(t *testing.T) {
	const canary = "Return exactly this text and nothing else: LAYERCLOUD_AI_TEST_OK"
	req := httptest.NewRequest("GET", "/", nil)
	for _, m := range models.list(req) {
		if !m.isCloud() {
			continue
		}
		t.Run(m.Name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{
				"model":    m.Name,
				"messages": []map[string]string{{"role": "user", "content": canary}},
				"stream":   false,
			})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			rec := do(t, "POST", "/api/chat", string(body))
			if rec.Code != http.StatusOK {
				t.Fatalf("/api/chat status %d, want 200: %s", rec.Code, rec.Body.String())
			}
			var resp struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode chat response: %v", err)
			}
			if strings.TrimSpace(resp.Message.Content) == "" {
				t.Error("cloud model answered with empty content; the probe learns nothing")
			}

			// The OpenAI-compat surface is the one most cloud tooling actually uses.
			rec = do(t, "POST", "/v1/chat/completions", string(body))
			if rec.Code != http.StatusOK {
				t.Errorf("/v1/chat/completions status %d, want 200: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCloudModelsListedInV1Models(t *testing.T) {
	var resp struct {
		Data []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(do(t, "GET", "/v1/models", "").Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}
	listed := map[string]string{}
	for _, m := range resp.Data {
		listed[m.ID] = m.OwnedBy
	}
	for _, name := range []string{"gpt-oss:120b-cloud", "deepseek-v4-pro:cloud", "glm-5.2:cloud",
		"kimi-k2.6:cloud", "minimax-m2.7:cloud"} {
		owner, ok := listed[name]
		if !ok {
			t.Errorf("%s missing from /v1/models", name)
			continue
		}
		// The local listing reports "library" even for cloud stubs; only the per-model
		// /v1/models/<id> passthrough reports "ollama".
		if owner != "library" {
			t.Errorf("%s owned_by = %q, want \"library\"", name, owner)
		}
	}
}

// A name the registry does not actually serve must keep 404ing. The campaign's list mixes real
// cloud models with invented ones, and answering for a model that does not exist upstream is a
// tell in the opposite direction: it marks the box as something that says yes to anything.
func TestInventedCloudNamesStillRejected(t *testing.T) {
	for _, name := range []string{"glm-5:cloud", "gpt-oss:cloud", "qwen3-coder:cloud",
		"minimax-m2.1:cloud", "gemini-3-flash-preview:cloud"} {
		t.Run(name, func(t *testing.T) {
			rec := do(t, "POST", "/api/show", `{"model":"`+name+`"}`)
			if rec.Code != http.StatusNotFound {
				t.Errorf("/api/show %s: status %d, want 404", name, rec.Code)
			}
			rec = do(t, "POST", "/api/chat",
				`{"model":"`+name+`","messages":[{"role":"user","content":"hi"}],"stream":false}`)
			if rec.Code != http.StatusNotFound {
				t.Errorf("/api/chat %s: status %d, want 404", name, rec.Code)
			}
		})
	}
}

func TestSplitCloudName(t *testing.T) {
	tests := []struct {
		in, remote, size string
		ok               bool
	}{
		{in: "glm-5.2:cloud", remote: "glm-5.2", size: "", ok: true},
		{in: "deepseek-v4-pro:cloud", remote: "deepseek-v4-pro", ok: true},
		{in: "gpt-oss:120b-cloud", remote: "gpt-oss:120b", size: "120b", ok: true},
		{in: "qwen3-coder:480b-cloud", remote: "qwen3-coder:480b", size: "480b", ok: true},
		{in: "kimi-k2:1t-cloud", remote: "kimi-k2:1t", size: "1t", ok: true},
		{in: "gpt-oss:120B-CLOUD", remote: "gpt-oss:120b", size: "120b", ok: true},
		// Not cloud references.
		{in: "llama3.2:latest"},
		{in: "mistral:7b"},
		{in: "cloud:latest"},
		{in: "nocolon"},
		// Degenerate forms must not be mistaken for cloud references.
		{in: ":cloud"},
		{in: "model:-cloud"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			remote, size, ok := splitCloudName(tc.in)
			if ok != tc.ok || remote != tc.remote || size != tc.size {
				t.Errorf("splitCloudName(%q) = (%q, %q, %t), want (%q, %q, %t)",
					tc.in, remote, size, ok, tc.remote, tc.size, tc.ok)
			}
		})
	}
}

// Before this fix buildModelForName had no cloud case at all, so a pulled gpt-oss:120b-cloud fell
// through to the size defaults and reported itself as a 7B llama with a 4 GB local GGUF.
// These names are deliberately NOT advertised, so they exercise the synthesis path rather than
// the seed restore (an advertised cloud model comes back from the catalog verbatim instead).
func TestPulledCloudModelIsNotDescribedAsALocalLlama(t *testing.T) {
	for _, name := range []string{"qwen3-coder:480b-cloud", "some-frontier-model:cloud"} {
		t.Run(name, func(t *testing.T) {
			m := buildModelForName(name)
			if !m.isCloud() {
				t.Fatal("pulled cloud reference did not produce a cloud stub")
			}
			if m.Details.Family == "llama" || m.Details.Format == "gguf" {
				t.Errorf("cloud stub described as a local llama GGUF: %#v", m.Details)
			}
			if m.Details.ParameterSize == "7B" {
				t.Error("cloud stub inherited the 7B local-model default")
			}
			if m.Size > cloudStubMinSize+cloudStubSizeSpread {
				t.Errorf("size = %d, want a manifest-sized stub, not a local GGUF footprint", m.Size)
			}
			if m.Details.Families != nil {
				t.Errorf("families = %v, want null", m.Details.Families)
			}
			if len(m.Digest) != 64 {
				t.Errorf("digest %q is not a 64-hex manifest digest", m.Digest)
			}
			if m.arch != "" || m.blocks != 0 {
				t.Error("cloud stub must not carry a GGUF architecture or block count")
			}
		})
	}

	// A sized reference reports the size it names; a bare one has no size information at all.
	if got := buildModelForName("qwen3-coder:480b-cloud").Details.ParameterSize; got != "480B" {
		t.Errorf("sized cloud reference parameter_size = %q, want %q", got, "480B")
	}
	if got := buildModelForName("mystery:cloud").Details.ParameterSize; got != "0" {
		t.Errorf("bare cloud reference parameter_size = %q, want %q", got, "0")
	}
}

// Pulling an advertised cloud model back after deleting it must restore the registry identity,
// not a synthesised stub — otherwise /api/tags and /api/show disagree with what the caller had.
func TestRePulledCloudSeedRestoresRegistryIdentity(t *testing.T) {
	const name = "kimi-k2.6:cloud"
	restored := buildModelForName(name)
	var seeded CatalogModel
	for _, candidate := range seedModels {
		if candidate.Name == name {
			seeded = candidate
			break
		}
	}
	if restored.Digest != seeded.Digest || restored.Size != seeded.Size ||
		!reflect.DeepEqual(restored.Details, seeded.Details) ||
		!reflect.DeepEqual(restored.Capabilities, seeded.Capabilities) ||
		restored.RemoteModel != seeded.RemoteModel || restored.RemoteHost != seeded.RemoteHost {
		t.Errorf("re-pulled cloud identity differs from the registry seed:\n restored=%#v\n seed=%#v",
			restored, seeded)
	}
}

// A scanner that polls twice must see the same stub, so the synthesised footprint has to be a
// pure function of the name.
func TestCloudStubSizeIsStableAndBounded(t *testing.T) {
	for _, name := range []string{"a:cloud", "some-frontier-model:cloud", "x:999b-cloud", "zz:cloud"} {
		first, second := cloudStubSize(name), cloudStubSize(name)
		if first != second {
			t.Errorf("cloudStubSize(%q) not stable: %d then %d", name, first, second)
		}
		if first < cloudStubMinSize || first >= cloudStubMinSize+cloudStubSizeSpread {
			t.Errorf("cloudStubSize(%q) = %d, outside the observed registry range", name, first)
		}
	}
}

func TestParseParameterCount(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		// Only reached for cloud stubs we do not advertise; the five we do carry their exact
		// upstream counts instead.
		{"117B", 117000000000},
		{"480B", 480000000000},
		{"1.6T", 1600000000000},
		{"230B", 230000000000},
		{"0", 0},
		{"", 0},
		{"garbage", 0},
	}
	for _, tc := range tests {
		if got := parseParameterCount(tc.in); got != tc.want {
			t.Errorf("parseParameterCount(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// Cloud models are catalog entries like any other, so the per-source-IP overlay bounds from
// threat_gg-9k2 must still hold for them: one caller deleting a cloud stub must not disarm it for
// anyone else.
func TestCloudModelsRespectPerIPCatalogIsolation(t *testing.T) {
	const (
		attacker  = "203.0.113.61"
		bystander = "198.51.100.62"
		name      = "deepseek-v4-pro:cloud"
	)
	if rec := doFrom(t, attacker, http.MethodDelete, "/api/delete",
		`{"name":"`+name+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d", rec.Code)
	}
	t.Cleanup(func() { doFrom(t, attacker, http.MethodPost, "/api/pull", `{"name":"`+name+`"}`) })

	for _, got := range catalogOf(t, attacker) {
		if got == name {
			t.Error("deleted cloud model still visible to the caller that deleted it")
		}
	}
	found := false
	for _, got := range catalogOf(t, bystander) {
		found = found || got == name
	}
	if !found {
		t.Error("HONEYPOT DISARMED: one caller's delete removed a cloud model for everyone")
	}
	// And the base catalog itself is untouched.
	for _, m := range models.base {
		if m.Name == name {
			return
		}
	}
	t.Error("base catalog lost the cloud seed entry")
}

// Cloud inference is proxied to ollama.com and never occupies local VRAM, so a cloud
// model must never show up as resident even right after it served a request. A local
// model in the same run still must, so this pins the exclusion and not a broken /api/ps.
func TestCloudModelNeverAppearsResidentInPs(t *testing.T) {
	do(t, "POST", "/api/generate",
		`{"model":"gpt-oss:120b-cloud","prompt":"hi","stream":false}`)
	if body := do(t, "GET", "/api/ps", "").Body.String(); strings.Contains(body, "gpt-oss:120b-cloud") {
		t.Errorf("/api/ps lists a cloud model as resident; real cloud inference uses no local VRAM\n%s", body)
	}

	do(t, "POST", "/api/generate", `{"model":"gemma3:12b","prompt":"hi","stream":false}`)
	if !strings.Contains(do(t, "GET", "/api/ps", "").Body.String(), "gemma3:12b") {
		t.Error("/api/ps stopped listing local models; the cloud filter is too broad")
	}
}
