package ollama

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Security regression tests for threat_gg-9k2.
//
// The mutating routes (/api/pull, /api/delete, /api/copy) are unauthenticated on purpose — a real
// exposed Ollama has no auth, and adding some would be a fingerprint. The original implementation
// backed them with a single shared catalog while gating inference on catalog membership, so six
// anonymous DELETEs emptied /api/tags and made every completion 404 until the agent restarted.
// That was reproduced against a live production node before it was fixed.
//
// Mutations are now scoped per source IP: the base catalog is immutable, each requester sees their
// own divergence from it, and the overlay map is bounded in both size and age.

func doFrom(t *testing.T, ip, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.RemoteAddr = ip + ":54321"
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, r)
	return rec
}

func catalogOf(t *testing.T, ip string) []string {
	t.Helper()
	var resp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	body := doFrom(t, ip, "GET", "/api/tags", "").Body.Bytes()
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("tags for %s: %v — %s", ip, err, body)
	}
	out := make([]string, 0, len(resp.Models))
	for _, m := range resp.Models {
		out = append(out, m.Name)
	}
	return out
}

// The disarm that was live in production: delete every advertised model, then check whether the
// honeypot still works for anyone else.
func TestDeleteCannotDisarmTheHoneypot(t *testing.T) {
	const attacker, bystander = "203.0.113.7", "198.51.100.9"

	seeded := catalogOf(t, bystander)
	if len(seeded) != len(seedModels) {
		t.Fatalf("expected %d seeded models, got %v", len(seedModels), seeded)
	}

	for _, m := range seeded {
		rec := doFrom(t, attacker, "DELETE", "/api/delete", fmt.Sprintf(`{"name":%q}`, m))
		if rec.Code != http.StatusOK {
			t.Fatalf("delete %s: status %d, want 200 (must look like it worked)", m, rec.Code)
		}
	}

	// The attacker observes faithful behaviour: their catalog is empty and their inference 404s.
	if got := catalogOf(t, attacker); len(got) != 0 {
		t.Errorf("attacker should see an empty catalog after deleting everything, got %v", got)
	}
	rec := doFrom(t, attacker, "POST", "/api/generate", `{"model":"llama3.2:latest","prompt":"hi","stream":false}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("attacker inference after delete: status %d, want 404", rec.Code)
	}

	// Everyone else is untouched — this is the property whose absence was the vulnerability.
	if got := catalogOf(t, bystander); len(got) != len(seedModels) {
		t.Fatalf("HONEYPOT DISARMED: bystander sees %v, want all %d seed models", got, len(seedModels))
	}
	rec = doFrom(t, bystander, "POST", "/api/generate", `{"model":"llama3.2:latest","prompt":"hi","stream":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("HONEYPOT DISARMED: bystander inference status %d, want 200", rec.Code)
	}
}

// A model one attacker pulls must not appear in another attacker's catalog. This was also a
// fidelity bug: no real server shows you a model somebody else pulled a minute ago.
func TestPulledModelsDoNotLeakAcrossCallers(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const puller, other = "203.0.113.20", "198.51.100.30"
	const name = "attacker-payload:1b"

	if rec := doFrom(t, puller, "POST", "/api/pull", `{"name":"`+name+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("pull: status %d", rec.Code)
	}

	mine := catalogOf(t, puller)
	if !contains(mine, name) {
		t.Errorf("puller does not see their own pulled model: %v", mine)
	}
	if rec := doFrom(t, puller, "POST", "/api/generate", `{"model":"`+name+`","prompt":"hi","stream":false}`); rec.Code != http.StatusOK {
		t.Errorf("puller cannot use their own pulled model: status %d", rec.Code)
	}

	theirs := catalogOf(t, other)
	if contains(theirs, name) {
		t.Errorf("pulled model leaked to another caller: %v", theirs)
	}
	if rec := doFrom(t, other, "POST", "/api/generate", `{"model":"`+name+`","prompt":"hi","stream":false}`); rec.Code != http.StatusNotFound {
		t.Errorf("another caller could use a model they never pulled: status %d", rec.Code)
	}
}

func TestShowCacheUsesFullModelIdentity(t *testing.T) {
	const ip = "203.0.113.61"
	const name = "qwen2.5-coder:7b"

	if rec := doFrom(t, ip, http.MethodDelete, "/api/delete", `{"name":"`+name+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d", rec.Code)
	}

	// Install a same-name overlay with a different identity. This models a changed registry
	// manifest and pins the cache boundary independently of /api/pull's known-model restoration.
	overlay := synthesize("attacker-model:1b")
	overlay.Name = name
	overlay.Model = name
	overlay.Digest = strings.Repeat("b", 64)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	models.add(req, overlay)

	rec := doFrom(t, ip, http.MethodPost, "/api/show", `{"model":"`+name+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("show: status %d: %s", rec.Code, rec.Body.String())
	}
	var show showResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &show); err != nil {
		t.Fatalf("decode show: %v", err)
	}
	if !strings.Contains(show.Modelfile, strings.Repeat("b", 64)) {
		t.Errorf("show returned stale base Modelfile: %s", show.Modelfile)
	}
	if got := show.ModelInfo["general.architecture"]; got != "llama" {
		t.Errorf("same-name overlay architecture = %v, want its llama fallback", got)
	}
	if len(show.Tensors) == 339 {
		t.Error("same-name overlay received cached qwen2.5-coder tensor inventory")
	}
}

func TestAdvertisedShowPayloadCacheExcludesOverlays(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	base, ok := models.get(req, "qwen2.5-coder:7b")
	if !ok {
		t.Fatal("base seed model missing")
	}
	if !isImmutableSeedModel(base) {
		t.Fatal("base catalog model was not recognized as immutable")
	}
	first := showPayloadFor(base)
	second := showPayloadFor(base)
	if len(first.body) == 0 || len(second.body) == 0 || &first.body[0] != &second.body[0] {
		t.Error("immutable base model did not reuse its serialized /api/show payload")
	}

	overlay := synthesize("cache-probe:1b")
	if isImmutableSeedModel(overlay) {
		t.Fatal("pulled overlay was incorrectly recognized as an immutable seed")
	}
	first = showPayloadFor(overlay)
	second = showPayloadFor(overlay)
	if len(first.body) == 0 || len(second.body) == 0 {
		t.Fatal("pulled overlay produced an empty /api/show payload")
	}
	if &first.body[0] == &second.body[0] {
		t.Error("attacker-controlled overlay unexpectedly entered the process-lifetime cache")
	}
}

func TestPullingDeletedSeedRestoresRegistryIdentity(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const ip = "203.0.113.62"
	const name = "qwen2.5-coder:7b"

	if rec := doFrom(t, ip, http.MethodDelete, "/api/delete", `{"name":"`+name+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d", rec.Code)
	}
	if rec := doFrom(t, ip, http.MethodPost, "/api/pull", `{"name":"`+name+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("pull: status %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	restored, ok := models.get(req, name)
	if !ok {
		t.Fatal("re-pulled seed model missing")
	}
	var seeded CatalogModel
	for _, candidate := range seedModels {
		if candidate.Name == name {
			seeded = candidate
			break
		}
	}
	if restored.Digest != seeded.Digest || !reflect.DeepEqual(restored.Details, seeded.Details) ||
		!reflect.DeepEqual(restored.Capabilities, seeded.Capabilities) {
		t.Errorf("re-pulled identity differs from registry seed:\n restored=%#v\n seed=%#v", restored, seeded)
	}
	if isImmutableSeedModel(restored) {
		t.Error("re-pulled seed overlay must not enter the immutable base payload cache")
	}

	rec := doFrom(t, ip, http.MethodPost, "/api/show", `{"model":"`+name+`"}`)
	var show showResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &show); err != nil {
		t.Fatalf("decode show: %v", err)
	}
	if len(show.ModelInfo) != 33 || len(show.Tensors) != 339 {
		t.Errorf("re-pulled seed did not restore grounded profile: model_info=%d tensors=%d",
			len(show.ModelInfo), len(show.Tensors))
	}
}

// Repeated pulls from one address must not grow memory without bound.
func TestAddedModelsAreCappedPerCaller(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const ip = "203.0.113.40"
	for i := 0; i < maxAddedPerView*3; i++ {
		doFrom(t, ip, "POST", "/api/pull", fmt.Sprintf(`{"name":"flood-%d:1b"}`, i))
	}
	got := catalogOf(t, ip)
	if max := len(seedModels) + maxAddedPerView; len(got) > max {
		t.Errorf("catalog grew to %d entries, cap is %d", len(got), max)
	}
}

// Rotating source addresses must not grow the overlay map without bound.
func TestOverlayMapIsBounded(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	for i := 0; i < maxViews+64; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		doFrom(t, ip, "POST", "/api/pull", `{"name":"x:1b"}`)
	}
	models.mu.Lock()
	n := len(models.views)
	models.mu.Unlock()
	if n > maxViews {
		t.Errorf("overlay map holds %d entries, cap is %d", n, maxViews)
	}
}

// The base catalog itself must never be mutated, whatever callers do.
func TestBaseCatalogIsImmutable(t *testing.T) {
	const ip = "203.0.113.50"
	for _, m := range seedModels {
		doFrom(t, ip, "DELETE", "/api/delete", fmt.Sprintf(`{"name":%q}`, m.Name))
	}
	models.mu.Lock()
	n := len(models.base)
	models.mu.Unlock()
	if n != len(seedModels) {
		t.Fatalf("base catalog mutated: %d entries, want %d", n, len(seedModels))
	}
	// A brand-new caller therefore always starts from the full catalog.
	if got := catalogOf(t, "198.51.100.77"); len(got) != len(seedModels) {
		t.Errorf("fresh caller sees %v, want all seed models", got)
	}
}

// X-Forwarded-For is attacker-controlled on a directly-addressed honeypot; honouring it would let
// one caller pollute or impersonate another caller's view.
func TestForwardedHeaderDoesNotKeyTheOverlay(t *testing.T) {
	const victim = "198.51.100.88"
	before := catalogOf(t, victim)

	r := httptest.NewRequest("DELETE", "/api/delete", strings.NewReader(`{"name":"llama3.2:latest"}`))
	r.RemoteAddr = "203.0.113.99:1111"
	r.Header.Set("X-Forwarded-For", victim)
	buildHandler().ServeHTTP(httptest.NewRecorder(), r)

	if after := catalogOf(t, victim); len(after) != len(before) {
		t.Errorf("X-Forwarded-For let one caller mutate another's view: %v -> %v", before, after)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
