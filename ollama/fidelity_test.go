package ollama

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Regression tests for PRD 033. Every expectation here was captured from a real Ollama 0.30.11,
// not from documentation — the reference transcript is quoted inline per assertion. A scanner
// that has touched a genuine Ollama can distinguish it from ours on any of these, so each one
// that regresses is a fingerprint the honeypot leaks.

func do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, r)
	return rec
}

// Real: no Server header on any response. Ollama is Gin; Gin never sets one.
func TestNoServerHeaderAnywhere(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/", ""},
		{"GET", "/api/tags", ""},
		{"GET", "/api/version", ""},
		{"GET", "/v1/models", ""},
		{"GET", "/definitely-not-a-route", ""},
		{"POST", "/api/chat", `{"model":"llama3.2:latest","messages":[{"role":"user","content":"hi"}],"stream":false}`},
	} {
		if got := do(t, tc.method, tc.path, tc.body).Header().Get("Server"); got != "" {
			t.Errorf("%s %s: Server header set to %q; real Ollama sends none", tc.method, tc.path, got)
		}
	}
}

// Real: /api/* is "application/json; charset=utf-8" (Gin), /v1/* is bare "application/json"
// (the OpenAI-compat layer). Serving one charset convention everywhere is a tell.
func TestContentTypeCharsetSplit(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/api/tags", "application/json; charset=utf-8"},
		{"/api/version", "application/json; charset=utf-8"},
		{"/api/ps", "application/json; charset=utf-8"},
		{"/v1/models", "application/json"},
	} {
		if got := do(t, "GET", tc.path, "").Header().Get("Content-Type"); got != tc.want {
			t.Errorf("%s: content-type %q, want %q", tc.path, got, tc.want)
		}
	}
}

// Real: `404 page not found`, Content-Type text/plain (no charset), Content-Length 18.
func TestNotFoundIsGinPlainText(t *testing.T) {
	// /props and /metrics are both observed in prod against the ollama port.
	for _, path := range []string{"/props", "/metrics", "/nonexistent-xyz"} {
		rec := do(t, "GET", path, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/plain" {
			t.Errorf("%s: content-type %q, want text/plain", path, got)
		}
		if got := rec.Body.String(); got != "404 page not found" {
			t.Errorf("%s: body %q, want %q", path, got, "404 page not found")
		}
	}
}

// Real: GET /api/generate -> 405, Allow: POST, body "405 method not allowed".
func TestMethodNotAllowedCarriesAllow(t *testing.T) {
	rec := do(t, "GET", "/api/generate", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "POST" {
		t.Errorf("Allow %q, want POST", got)
	}
	if got := rec.Body.String(); got != "405 method not allowed" {
		t.Errorf("body %q", got)
	}
}

// Real: HEAD / -> 200 with Content-Length 17. gorilla/mux does not imply HEAD from GET, so this
// used to fall through to the 404 handler.
func TestHeadRootAnswers200(t *testing.T) {
	rec := do(t, "HEAD", "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Length"); got != "17" {
		t.Errorf("Content-Length %q, want 17", got)
	}
}

// Real (OLLAMA_ORIGINS=*): preflight -> 204 with the X-Stainless-* allow-header list.
func TestCORSPreflight(t *testing.T) {
	rec := do(t, "OPTIONS", "/api/chat", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rec.Code)
	}
	h := rec.Header()
	if h.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("allow-origin %q", h.Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(h.Get("Access-Control-Allow-Headers"), "X-Stainless-Retry-Count") {
		t.Errorf("allow-headers missing the OpenAI SDK telemetry headers: %q", h.Get("Access-Control-Allow-Headers"))
	}
	if h.Get("Access-Control-Max-Age") != "43200" {
		t.Errorf("max-age %q, want 43200", h.Get("Access-Control-Max-Age"))
	}
}

// Real: a model the box has not pulled 404s. /api/* uses {"error":"model 'x' not found"};
// /v1/* uses the OpenAI envelope with explicit nulls.
func TestUnknownModelIsRejected(t *testing.T) {
	rec := do(t, "POST", "/api/chat", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":false}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/api/chat unknown model: status %d, want 404", rec.Code)
	}
	if got := rec.Body.String(); got != `{"error":"model 'gpt-4o' not found"}` {
		t.Errorf("/api/chat body %q", got)
	}

	rec = do(t, "POST", "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/v1 unknown model: status %d, want 404", rec.Code)
	}
	want := `{"error":{"message":"model 'gpt-4o' not found","type":"not_found_error","param":null,"code":null}}`
	if got := rec.Body.String(); got != want {
		t.Errorf("/v1 body:\n got %s\nwant %s", got, want)
	}
}

// The two names captured traffic actually probes must keep working.
func TestAdvertisedModelsStillServe(t *testing.T) {
	for _, m := range []string{"llama3.2:latest", "mistral:latest"} {
		rec := do(t, "POST", "/api/chat",
			`{"model":"`+m+`","messages":[{"role":"user","content":"Hello"}],"stream":false}`)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", m, rec.Code)
		}
	}
	// And every advertised model must be servable, or the catalog is lying.
	for _, m := range models.list(httptest.NewRequest("GET", "/", nil)) {
		rec := do(t, "POST", "/api/generate", `{"model":"`+m.Name+`","prompt":"hi","stream":false}`)
		if rec.Code != http.StatusOK {
			t.Errorf("advertised model %s not servable: status %d", m.Name, rec.Code)
		}
	}
}

// Real: malformed JSON -> 400 with the parse error echoed.
func TestMalformedJSONIsRejected(t *testing.T) {
	rec := do(t, "POST", "/api/generate", `not-json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("body %q", rec.Body.String())
	}
}

// Real: POST /api/show {} -> 400 {"error":"model is required"}.
func TestShowRequiresModel(t *testing.T) {
	rec := do(t, "POST", "/api/show", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if got := rec.Body.String(); got != `{"error":"model is required"}` {
		t.Errorf("body %q", got)
	}
}

// Real /api/show carries model_info (~36 keys), a tensor inventory and capabilities. The old
// five-key stub was recognisable at a glance.
func TestShowIsDetailed(t *testing.T) {
	rec := do(t, "POST", "/api/show", `{"model":"llama3.2:latest"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp showResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.ModelInfo) < 15 {
		t.Errorf("model_info has %d keys, real responses carry ~36", len(resp.ModelInfo))
	}
	if len(resp.Tensors) < 50 {
		t.Errorf("tensors has %d entries, real responses list one per layer", len(resp.Tensors))
	}
	if len(resp.Capabilities) == 0 {
		t.Error("capabilities missing")
	}
}

func TestGroundedShowProfilesMatchCapturedOllama(t *testing.T) {
	tests := []struct {
		model          string
		modelInfoCount int
		tensorCount    int
		licenseMarker  string
		templateMarker string
		system         string
		fixturePath    string
		fixtureSHA256  string
		requiredTensor tensor
	}{
		{
			model: "qwen2.5-coder:7b", modelInfoCount: 33, tensorCount: 339,
			licenseMarker: "Apache License", templateMarker: "<|fim_prefix|>",
			system:         "You are Qwen, created by Alibaba Cloud. You are a helpful assistant.",
			fixturePath:    "testdata/show_qwen2.5-coder_7b_ollama-0.30.11.json",
			fixtureSHA256:  "c7fd56f0cc81c546c3c69aa80972133037b25d96e98fe52005539f803d242795",
			requiredTensor: tensor{Name: "blk.0.attn_k.bias", Type: "F32", Shape: []int{512}},
		},
		{
			model: "gemma3:12b", modelInfoCount: 36, tensorCount: 1065,
			licenseMarker: "Gemma Terms of Use", templateMarker: "<start_of_turn>",
			fixturePath:    "testdata/show_gemma3_12b_ollama-0.30.11.json",
			fixtureSHA256:  "34da6ab09d374135565e99c7a7fa556353edb5c85aa2864a04c2736579e14943",
			requiredTensor: tensor{Name: "mm.mm_input_projection.weight", Type: "F16", Shape: []int{3840, 1152}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			fixture, err := showFixtureFS.ReadFile(tc.fixturePath)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(fixture)); got != tc.fixtureSHA256 {
				t.Fatalf("fixture checksum = %s, want captured Ollama checksum %s", got, tc.fixtureSHA256)
			}

			rec := do(t, "POST", "/api/show", `{"model":"`+tc.model+`"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			var got showResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			want := groundedShowFixtures[tc.model]
			m, ok := models.get(httptest.NewRequest("GET", "/", nil), tc.model)
			if !ok {
				t.Fatalf("grounded model %q is not advertised", tc.model)
			}
			want.ModifiedAt = m.ModifiedAt
			if !reflect.DeepEqual(got, want) {
				t.Fatal("/api/show response diverged from its grounded Ollama 0.30.11 fixture")
			}
			var fixtureRaw, responseRaw map[string]json.RawMessage
			if err := json.Unmarshal(fixture, &fixtureRaw); err != nil {
				t.Fatalf("decode raw fixture: %v", err)
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &responseRaw); err != nil {
				t.Fatalf("decode raw response keys: %v", err)
			}
			fixtureKeys := make(map[string]bool, len(fixtureRaw))
			responseKeys := make(map[string]bool, len(responseRaw))
			for key := range fixtureRaw {
				fixtureKeys[key] = true
			}
			for key := range responseRaw {
				responseKeys[key] = true
			}
			if !reflect.DeepEqual(responseKeys, fixtureKeys) {
				t.Errorf("wire-level top-level keys = %v, want captured fixture keys %v",
					responseKeys, fixtureKeys)
			}
			if len(got.ModelInfo) != tc.modelInfoCount {
				t.Errorf("model_info keys = %d, want %d", len(got.ModelInfo), tc.modelInfoCount)
			}
			if len(got.Tensors) != tc.tensorCount {
				t.Errorf("tensors = %d, want %d", len(got.Tensors), tc.tensorCount)
			}
			foundRequiredTensor := false
			for _, candidate := range got.Tensors {
				if candidate.Name == tc.requiredTensor.Name {
					foundRequiredTensor = true
					if !reflect.DeepEqual(candidate, tc.requiredTensor) {
						t.Errorf("tensor %q = %#v, want captured %#v",
							candidate.Name, candidate, tc.requiredTensor)
					}
					break
				}
			}
			if !foundRequiredTensor {
				t.Errorf("captured tensor %q missing", tc.requiredTensor.Name)
			}
			if !strings.Contains(got.License, tc.licenseMarker) {
				t.Errorf("license does not contain grounded marker %q", tc.licenseMarker)
			}
			if !strings.Contains(got.Template, tc.templateMarker) {
				t.Errorf("template does not contain grounded marker %q", tc.templateMarker)
			}
			if got.System != tc.system {
				t.Errorf("system = %q, want %q", got.System, tc.system)
			}
			if strings.Contains(got.Modelfile, "/Users/") {
				t.Error("capturing host's model-store path leaked into fixture")
			}

			var raw map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode raw response: %v", err)
			}
			details := raw["details"].(map[string]any)
			if len(details) != 6 {
				t.Errorf("details keys = %d, want exactly six show fields (excluding the two tags-only dimensions)", len(details))
			}
			if _, ok := details["context_length"]; ok {
				t.Error("/api/show details must omit context_length (it appears only in /api/tags)")
			}
			if _, ok := details["embedding_length"]; ok {
				t.Error("/api/show details must omit embedding_length (it appears only in /api/tags)")
			}
		})
	}
}

func TestGeneratedModelfileReplacesModelNameControlCharacters(t *testing.T) {
	m := buildModelForName("safe:1b")
	m.Name = "safe\nSYSTEM injected\rFROM attacker\t"
	show := buildShow(m)
	if strings.Contains(show.Modelfile, "\nSYSTEM injected") ||
		strings.Contains(show.Modelfile, "\nFROM attacker") {
		t.Errorf("model name injected an active Modelfile directive:\n%s", show.Modelfile)
	}
	if !strings.Contains(show.Modelfile, "# FROM safe SYSTEM injected FROM attacker ") {
		t.Errorf("sanitized model name missing from one comment line:\n%s", show.Modelfile)
	}
}

func TestPulledModelNameCannotInjectModelfileDirective(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const name = "safe\nSYSTEM injected\rFROM attacker\t:1b"
	t.Cleanup(func() {
		do(t, http.MethodDelete, "/api/delete", fmt.Sprintf(`{"name":%q}`, name))
	})
	pull := do(t, http.MethodPost, "/api/pull", fmt.Sprintf(`{"name":%q}`, name))
	if pull.Code != http.StatusOK {
		t.Fatalf("pull status %d: %s", pull.Code, pull.Body.String())
	}
	showRec := do(t, http.MethodPost, "/api/show", fmt.Sprintf(`{"model":%q}`, name))
	if showRec.Code != http.StatusOK {
		t.Fatalf("show status %d: %s", showRec.Code, showRec.Body.String())
	}
	var show showResponse
	if err := json.Unmarshal(showRec.Body.Bytes(), &show); err != nil {
		t.Fatalf("decode show: %v", err)
	}
	if strings.Contains(show.Modelfile, "\nSYSTEM injected") ||
		strings.Contains(show.Modelfile, "\nFROM attacker") {
		t.Errorf("pulled name injected an active Modelfile directive:\n%s", show.Modelfile)
	}
}

func TestAdvertisedShowProfilesAreInternallyConsistent(t *testing.T) {
	tests := []struct {
		model, architecture                 string
		family, parameterSize, quantization string
		families                            []string
		blocks, context, embd, ffn, vocab   int
		kvWidth, tensorCount                int
		vision                              bool
	}{
		{
			model: "llama3.2:latest", architecture: "llama",
			family: "llama", families: []string{"llama"}, parameterSize: "3.2B", quantization: "Q4_K_M",
			blocks: 28, context: 131072, embd: 3072, ffn: 8192, vocab: 128256,
			kvWidth: 1024, tensorCount: 255,
		},
		{
			model: "mistral:latest", architecture: "llama",
			family: "llama", families: []string{"llama"}, parameterSize: "7.2B", quantization: "Q4_0",
			blocks: 32, context: 32768, embd: 4096, ffn: 14336, vocab: 32768,
			kvWidth: 1024, tensorCount: 291,
		},
		{
			model: "deepseek-r1:8b", architecture: "llama",
			family: "llama", families: []string{"llama"}, parameterSize: "8.0B", quantization: "Q4_K_M",
			blocks: 32, context: 131072, embd: 4096, ffn: 14336, vocab: 128256,
			kvWidth: 1024, tensorCount: 291,
		},
		{
			model: "llava:latest", architecture: "llama",
			family: "llama", families: []string{"llama", "clip"}, parameterSize: "7B", quantization: "Q4_0",
			blocks: 32, context: 4096, embd: 4096, ffn: 11008, vocab: 32000,
			kvWidth: 4096, tensorCount: 488, vision: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.model, func(t *testing.T) {
			rec := do(t, "POST", "/api/show", `{"model":"`+tc.model+`"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			var resp showResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode generated /api/show response: %v", err)
			}
			wantShowDetails := showDetails{
				Format: "gguf", Family: tc.family, Families: tc.families,
				ParameterSize: tc.parameterSize, QuantizationLevel: tc.quantization,
			}
			if !reflect.DeepEqual(resp.Details, wantShowDetails) {
				t.Errorf("/api/show details = %#v, want %#v", resp.Details, wantShowDetails)
			}

			tagsRec := do(t, "GET", "/api/tags", "")
			var tags struct {
				Models []CatalogModel `json:"models"`
			}
			if err := json.Unmarshal(tagsRec.Body.Bytes(), &tags); err != nil {
				t.Fatalf("decode /api/tags: %v", err)
			}
			var tagged *CatalogModel
			for i := range tags.Models {
				if tags.Models[i].Name == tc.model {
					tagged = &tags.Models[i]
					break
				}
			}
			if tagged == nil {
				t.Fatalf("%s missing from /api/tags", tc.model)
			}
			wantTagDetails := Details{
				Format: "gguf", Family: tc.family, Families: tc.families,
				ParameterSize: tc.parameterSize, QuantizationLevel: tc.quantization,
				ContextLength: tc.context, EmbeddingLength: tc.embd,
			}
			if !reflect.DeepEqual(tagged.Details, wantTagDetails) {
				t.Errorf("/api/tags details = %#v, want %#v", tagged.Details, wantTagDetails)
			}

			assertStringInfo := func(key, want string) {
				t.Helper()
				if got := resp.ModelInfo[key]; got != want {
					t.Errorf("model_info[%q] = %v, want %v", key, got, want)
				}
			}
			assertIntInfo := func(key string, want int) {
				t.Helper()
				got, ok := resp.ModelInfo[key].(float64)
				if !ok || int(got) != want {
					t.Errorf("model_info[%q] = %v, want %d", key, resp.ModelInfo[key], want)
				}
			}
			assertStringInfo("general.architecture", tc.architecture)
			assertIntInfo(tc.architecture+".block_count", tc.blocks)
			assertIntInfo(tc.architecture+".context_length", tc.context)
			assertIntInfo(tc.architecture+".embedding_length", tc.embd)
			assertIntInfo(tc.architecture+".feed_forward_length", tc.ffn)
			assertIntInfo(tc.architecture+".vocab_size", tc.vocab)

			if len(resp.Tensors) != tc.tensorCount {
				t.Errorf("tensor count = %d, want independently specified %d",
					len(resp.Tensors), tc.tensorCount)
			}
			tensors := make(map[string]tensor, len(resp.Tensors))
			textBlocks := make(map[string]bool, tc.blocks)
			hasVisionTensor := false
			for _, candidate := range resp.Tensors {
				if _, duplicate := tensors[candidate.Name]; duplicate {
					t.Errorf("duplicate tensor %q", candidate.Name)
				}
				tensors[candidate.Name] = candidate
				for _, dimension := range candidate.Shape {
					if dimension <= 0 {
						t.Errorf("tensor %q has non-positive shape %v", candidate.Name, candidate.Shape)
					}
				}
				if strings.HasPrefix(candidate.Name, "blk.") {
					parts := strings.Split(candidate.Name, ".")
					textBlocks[parts[1]] = true
				}
				if strings.HasPrefix(candidate.Name, "v.") || strings.HasPrefix(candidate.Name, "mm.") {
					hasVisionTensor = true
				}
			}
			if len(textBlocks) != tc.blocks {
				t.Errorf("text blocks = %d, want %d", len(textBlocks), tc.blocks)
			}
			wantTensors := []tensor{
				{Name: "token_embd.weight", Type: "Q4_K", Shape: []int{tc.embd, tc.vocab}},
				{Name: "blk.0.attn_k.weight", Type: "Q4_K", Shape: []int{tc.embd, tc.kvWidth}},
				{Name: "blk.0.ffn_down.weight", Type: "Q6_K", Shape: []int{tc.ffn, tc.embd}},
				{Name: "output_norm.weight", Type: "F32", Shape: []int{tc.embd}},
				{Name: "output.weight", Type: "Q6_K", Shape: []int{tc.embd, tc.vocab}},
			}
			if tc.vision {
				wantTensors = append(wantTensors,
					tensor{Name: "v.position_embd.weight", Type: "F16", Shape: []int{1024, 577}},
					tensor{Name: "v.blk.23.ffn_down.weight", Type: "F16", Shape: []int{4096, 1024}},
				)
			}
			for _, want := range wantTensors {
				if got, ok := tensors[want.Name]; !ok {
					t.Errorf("tensor %q missing", want.Name)
				} else if !reflect.DeepEqual(got, want) {
					t.Errorf("tensor %q = %#v, want %#v", want.Name, got, want)
				}
			}
			if tc.vision != hasVisionTensor {
				t.Errorf("vision profile = %t but vision tensors present = %t", tc.vision, hasVisionTensor)
			}
			hasVisionCapability := false
			for _, capability := range resp.Capabilities {
				hasVisionCapability = hasVisionCapability || capability == "vision"
			}
			if tc.vision != hasVisionCapability {
				t.Errorf("vision profile = %t but vision capability present = %t", tc.vision, hasVisionCapability)
			}
			if resp.License != "" || resp.Template != "" || resp.System != "" || resp.Parameters != "" {
				t.Error("ungrounded license/template/system/parameters must be omitted, not invented")
			}
			if strings.Contains(resp.Modelfile, "TEMPLATE") {
				t.Error("ungrounded generated Modelfile must not claim a template")
			}
			var raw map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("decode raw generated response: %v", err)
			}
			details := raw["details"].(map[string]any)
			if len(details) != 6 {
				t.Errorf("details keys = %d, want exactly six show fields without tags-only dimensions", len(details))
			}
			if _, ok := details["context_length"]; ok {
				t.Error("generated /api/show details must omit context_length")
			}
			if _, ok := details["embedding_length"]; ok {
				t.Error("generated /api/show details must omit embedding_length")
			}
		})
	}
}

// /api/pull is observed in prod from three distinct IPs pulling llama3.2:1b. It must stream
// progress and leave the model listed, so the attacker goes on to use it.
func TestPullStreamsAndRegistersModel(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const name = "llama3.2:1b"
	t.Cleanup(func() { models.remove(httptest.NewRequest("GET", "/", nil), name) })

	rec := do(t, "POST", "/api/pull", `{"name":"`+name+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-ndjson" {
		t.Errorf("content-type %q, want application/x-ndjson", got)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected a progress stream, got %d lines", len(lines))
	}
	if !strings.Contains(lines[0], "pulling manifest") {
		t.Errorf("first line %q, want pulling manifest", lines[0])
	}
	if !strings.Contains(lines[len(lines)-1], `"success"`) {
		t.Errorf("last line %q, want success", lines[len(lines)-1])
	}
	// Every line must be valid JSON: a client streaming NDJSON will choke otherwise.
	for i, ln := range lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(ln), &v); err != nil {
			t.Fatalf("line %d is not JSON: %q", i, ln)
		}
	}
	if !models.has(httptest.NewRequest("GET", "/", nil), name) {
		t.Fatal("pulled model did not appear in the catalog")
	}
	// ...and is now servable and listed, which is the point of the divergence.
	if rec := do(t, "POST", "/api/generate", `{"model":"`+name+`","prompt":"hi","stream":false}`); rec.Code != http.StatusOK {
		t.Errorf("pulled model not servable: status %d", rec.Code)
	}
	if !strings.Contains(do(t, "GET", "/api/tags", "").Body.String(), name) {
		t.Error("pulled model missing from /api/tags")
	}
	showRec := do(t, "POST", "/api/show", `{"model":"`+name+`"}`)
	if showRec.Code != http.StatusOK {
		t.Fatalf("pulled model /api/show status %d: %s", showRec.Code, showRec.Body.String())
	}
	var show showResponse
	if err := json.Unmarshal(showRec.Body.Bytes(), &show); err != nil {
		t.Fatalf("decode pulled model /api/show: %v", err)
	}
	wantInfo := map[string]any{
		"general.architecture":                   "llama",
		"general.basename":                       "llama3.2",
		"general.file_type":                      float64(15),
		"general.parameter_count":                float64(1981647492),
		"general.quantization_version":           float64(2),
		"general.type":                           "model",
		"llama.attention.head_count":             float64(16),
		"llama.attention.head_count_kv":          float64(4),
		"llama.attention.layer_norm_rms_epsilon": 1e-05,
		"llama.block_count":                      float64(16),
		"llama.context_length":                   float64(32768),
		"llama.embedding_length":                 float64(2048),
		"llama.feed_forward_length":              float64(8192),
		"llama.rope.dimension_count":             float64(128),
		"llama.rope.freq_base":                   float64(10000),
		"llama.vocab_size":                       float64(32000),
		"tokenizer.ggml.bos_token_id":            float64(1),
		"tokenizer.ggml.eos_token_id":            float64(2),
		"tokenizer.ggml.model":                   "llama",
		"tokenizer.ggml.pre":                     "default",
	}
	if !reflect.DeepEqual(show.ModelInfo, wantInfo) {
		t.Errorf("pulled-model metadata diverged from the explicit fallback profile:\n got=%#v\nwant=%#v",
			show.ModelInfo, wantInfo)
	}
	wantDetails := showDetails{
		Format: "gguf", Family: "llama", Families: []string{"llama"},
		ParameterSize: "1.2B", QuantizationLevel: "Q4_K_M",
	}
	if !reflect.DeepEqual(show.Details, wantDetails) {
		t.Errorf("pulled-model details = %#v, want %#v", show.Details, wantDetails)
	}
	if !reflect.DeepEqual(show.Capabilities, []string{"completion", "tools"}) {
		t.Errorf("pulled-model capabilities = %v, want completion+tools", show.Capabilities)
	}
	if len(show.Tensors) != 147 {
		t.Errorf("pulled-model tensor count = %d, want 147", len(show.Tensors))
	}
	tensors := make(map[string]tensor, len(show.Tensors))
	blocks := make(map[string]bool, 16)
	for _, candidate := range show.Tensors {
		tensors[candidate.Name] = candidate
		if strings.HasPrefix(candidate.Name, "blk.") {
			blocks[strings.Split(candidate.Name, ".")[1]] = true
		}
	}
	if len(blocks) != 16 {
		t.Errorf("pulled-model text blocks = %d, want 16", len(blocks))
	}
	wantTensors := []tensor{
		{Name: "token_embd.weight", Type: "Q4_K", Shape: []int{2048, 32000}},
		{Name: "blk.0.attn_k.weight", Type: "Q4_K", Shape: []int{2048, 512}},
		{Name: "blk.15.ffn_down.weight", Type: "Q6_K", Shape: []int{8192, 2048}},
		{Name: "output_norm.weight", Type: "F32", Shape: []int{2048}},
		{Name: "output.weight", Type: "Q6_K", Shape: []int{2048, 32000}},
	}
	for _, want := range wantTensors {
		if got, ok := tensors[want.Name]; !ok {
			t.Errorf("pulled-model tensor %q missing", want.Name)
		} else if !reflect.DeepEqual(got, want) {
			t.Errorf("pulled-model tensor %q = %#v, want %#v", want.Name, got, want)
		}
	}
	if strings.Contains(show.License, "MIT License") || strings.Contains(show.Template, "<|start_header_id|>") {
		t.Error("pulled-model fallback reused the removed invented license/template")
	}
}

// /v1/responses is probed in prod by open-router-cli using models we advertise. Real modern
// Ollama implements it, so a 404 fails a validator the honeypot should pass.
func TestResponsesAPI(t *testing.T) {
	rec := do(t, "POST", "/v1/responses",
		`{"model":"mistral:latest","input":"Reply with OK.","temperature":0,"max_output_tokens":1,"stream":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var resp struct {
		Object string `json:"object"`
		Status string `json:"status"`
		Output []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v — %s", err, rec.Body.String())
	}
	if resp.Object != "response" || resp.Status != "completed" {
		t.Errorf("object=%q status=%q", resp.Object, resp.Status)
	}
	if len(resp.Output) == 0 || len(resp.Output[0].Content) == 0 || resp.Output[0].Content[0].Text != "OK" {
		t.Errorf("echo probe not answered: %s", rec.Body.String())
	}
}

// Real: no model in the catalog has embedding support, so all three routes refuse — but not with
// the same status. Measured against a real Ollama 0.30.11 (threat_gg-5fb), 3 runs x 2 models
// (qwen2.5-coder:7b, gemma3:12b): /api/embed and /v1/embeddings answer 501, the legacy
// /api/embeddings answers 500, for byte-identical refusal bodies.
func TestEmbeddingsRefusalStatusPerRoute(t *testing.T) {
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/embed", http.StatusNotImplemented},
		{"/api/embeddings", http.StatusInternalServerError},
		{"/v1/embeddings", http.StatusNotImplemented},
	} {
		rec := do(t, "POST", tc.path, `{"model":"mistral:latest","input":"hi"}`)
		if rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.path, rec.Code, tc.want)
		}
		if !strings.Contains(rec.Body.String(), "does not support embeddings") {
			t.Errorf("%s: body %q", tc.path, rec.Body.String())
		}
	}
}

// Real bodies are marshalled directly, with no trailing newline; json.Encoder.Encode adds one
// and inflates Content-Length by a byte against every real server.
func TestNoTrailingNewlineInJSONBodies(t *testing.T) {
	for _, path := range []string{"/api/tags", "/api/version", "/api/ps", "/v1/models"} {
		if body := do(t, "GET", path, "").Body.String(); strings.HasSuffix(body, "\n") {
			t.Errorf("%s: body has a trailing newline", path)
		}
	}
}

// encoding/json sorts map keys alphabetically; real servers marshal structs, so the key order is
// declaration order. Building payloads from maps produced an ordering no Ollama emits.
func TestTagsKeyOrderMatchesReal(t *testing.T) {
	body := do(t, "GET", "/api/tags", "").Body.String()
	want := []string{`"name"`, `"model"`, `"modified_at"`, `"size"`, `"digest"`, `"details"`, `"capabilities"`}
	idx := 0
	for _, key := range want {
		i := strings.Index(body[idx:], key)
		if i < 0 {
			t.Fatalf("key %s missing or out of order in /api/tags; real order is %v", key, want)
		}
		idx += i
	}
	// details itself is ordered too.
	di := strings.Index(body, `"details"`)
	sub := body[di:]
	for _, key := range []string{`"parent_model"`, `"format"`, `"family"`, `"families"`, `"parameter_size"`, `"quantization_level"`} {
		i := strings.Index(sub, key)
		if i < 0 {
			t.Fatalf("details key %s missing or out of order", key)
		}
		sub = sub[i:]
	}
}

// Real: system_fingerprint "fp_ollama" on every /v1 response and every SSE chunk.
func TestSystemFingerprintPresent(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"hi"}]}`)
	if !strings.Contains(rec.Body.String(), `"system_fingerprint":"fp_ollama"`) {
		t.Errorf("missing system_fingerprint: %s", rec.Body.String())
	}
}

// Real: max_tokens=1 truncates and reports finish_reason "length", not "stop".
func TestMaxTokensProducesLengthFinish(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"Reply with OK."}],"max_tokens":1,"stream":false}`)
	if !strings.Contains(rec.Body.String(), `"finish_reason":"length"`) {
		t.Errorf("want finish_reason length: %s", rec.Body.String())
	}
	// Ollama's native knob is options.num_predict.
	rec = do(t, "POST", "/api/chat",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"Hello"}],"stream":false,"options":{"num_predict":2}}`)
	if !strings.Contains(rec.Body.String(), `"done_reason":"length"`) {
		t.Errorf("want done_reason length: %s", rec.Body.String())
	}
}

// The old implementation returned these five constants on every request, so two requests from
// one scanner produced byte-identical duration fields.
func TestDurationsAreNotConstant(t *testing.T) {
	const banned = `"total_duration":1234567890`
	body1 := do(t, "POST", "/api/generate", `{"model":"mistral:latest","prompt":"hi","stream":false}`).Body.String()
	body2 := do(t, "POST", "/api/generate", `{"model":"mistral:latest","prompt":"hi there friend","stream":false}`).Body.String()
	for _, b := range []string{body1, body2} {
		if strings.Contains(b, banned) {
			t.Fatalf("placeholder duration still present: %s", b)
		}
	}
	re := regexp.MustCompile(`"total_duration":(\d+)`)
	m1, m2 := re.FindStringSubmatch(body1), re.FindStringSubmatch(body2)
	if m1 == nil || m2 == nil {
		t.Fatalf("no total_duration in responses")
	}
	if m1[1] == m2[1] {
		t.Errorf("total_duration identical across two different requests: %s", m1[1])
	}
	if !strings.Contains(body1, `"prompt_eval_duration"`) || !strings.Contains(body1, `"context"`) {
		t.Errorf("/api/generate missing prompt_eval_duration or context: %s", body1)
	}
}

// Real streams advance created_at per chunk; ours reused one timestamp for the whole stream.
func TestStreamTimestampsAdvance(t *testing.T) {
	rec := do(t, "POST", "/api/generate",
		`{"model":"mistral:latest","prompt":"tell me about databases","stream":true}`)
	var stamps []string
	for _, ln := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
		var v struct {
			CreatedAt string `json:"created_at"`
		}
		if json.Unmarshal([]byte(ln), &v) == nil && v.CreatedAt != "" {
			stamps = append(stamps, v.CreatedAt)
		}
	}
	if len(stamps) < 3 {
		t.Fatalf("expected a multi-chunk stream, got %d chunks", len(stamps))
	}
	if stamps[0] == stamps[len(stamps)-1] {
		t.Errorf("created_at identical across the whole stream (%s)", stamps[0])
	}
}

// Real SSE terminates with a literal "data: [DONE]".
func TestSSETerminator(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"mistral:latest","messages":[{"role":"user","content":"say pong"}],"max_tokens":20,"stream":true}`)
	body := rec.Body.String()
	if !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Errorf("stream does not end with [DONE]: %q", body[max(0, len(body)-80):])
	}
	if !strings.Contains(body, `"system_fingerprint":"fp_ollama"`) {
		t.Errorf("SSE chunks missing system_fingerprint")
	}
}

// /api/ps should reflect a model that was just used, and fall off when keep_alive is 0.
func TestPsReflectsResidency(t *testing.T) {
	do(t, "POST", "/api/chat",
		`{"model":"gemma3:12b","messages":[{"role":"user","content":"hi"}],"stream":false}`)
	if !strings.Contains(do(t, "GET", "/api/ps", "").Body.String(), "gemma3:12b") {
		t.Error("/api/ps does not list a model that was just used")
	}
	do(t, "POST", "/api/chat",
		`{"model":"gemma3:12b","messages":[{"role":"user","content":"hi"}],"stream":false,"keep_alive":0}`)
	if strings.Contains(do(t, "GET", "/api/ps", "").Body.String(), "gemma3:12b") {
		t.Error("/api/ps still lists a model unloaded with keep_alive:0")
	}
}
