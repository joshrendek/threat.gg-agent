package ollama

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	base, ok := models.get(req, name)
	if !ok {
		t.Fatal("base qwen model missing")
	}
	// Prime the immutable payload before replacing this caller's view with a same-name overlay.
	// A cache keyed only by name would now return this stale qwen response.
	if payload := showPayloadFor(base); len(payload.body) == 0 {
		t.Fatal("base qwen payload was empty")
	}

	if rec := doFrom(t, ip, http.MethodDelete, "/api/delete", `{"name":"`+name+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d", rec.Code)
	}

	// Install a same-name overlay with a different identity. This models a changed registry
	// manifest and pins the cache boundary independently of /api/pull's known-model restoration.
	overlay := buildModelForName("attacker-model:1b")
	overlay.Name = name
	overlay.Model = name
	overlay.Digest = strings.Repeat("b", 64)
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

	overlay := buildModelForName("cache-probe:1b")
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
	first := showPayloadFor(restored)
	second := showPayloadFor(restored)
	if len(first.body) == 0 || len(second.body) == 0 {
		t.Fatal("re-pulled seed produced an empty /api/show payload")
	}
	if &first.body[0] == &second.body[0] {
		t.Error("re-pulled seed reused a process-lifetime cached payload")
	}
	firstBody := showBodyForRequest(req, restored)
	secondBody := showBodyForRequest(req, restored)
	if &firstBody[0] != &secondBody[0] {
		t.Error("re-pulled seed did not reuse its bounded per-view payload")
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

func TestCopiedModelUsesSourceIdentityAndClearsBaseMarker(t *testing.T) {
	const ip = "203.0.113.63"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"

	const copiedName = "qwen-copy:latest"
	copyRec := doFrom(t, ip, http.MethodPost, "/api/copy",
		`{"source":"qwen2.5-coder:7b","destination":"`+copiedName+`"}`)
	if copyRec.Code != http.StatusOK {
		t.Fatalf("copy through public endpoint: status %d: %s", copyRec.Code, copyRec.Body.String())
	}
	copied, ok := models.get(req, copiedName)
	if !ok {
		t.Fatal("copied overlay missing")
	}
	if isImmutableSeedModel(copied) || copied.immutableBase {
		t.Error("copy of a base model retained the immutable cache marker")
	}
	first := showBodyForRequest(req, copied)
	second := showBodyForRequest(req, copied)
	if &first[0] != &second[0] {
		t.Error("copied overlay did not reuse its bounded per-view payload")
	}
	var copiedShow showResponse
	if err := json.Unmarshal(first, &copiedShow); err != nil {
		t.Fatalf("decode copied show payload: %v", err)
	}
	if len(copiedShow.ModelInfo) != 33 || len(copiedShow.Tensors) != 339 {
		t.Errorf("copied qwen lost source profile: model_info=%d tensors=%d",
			len(copiedShow.ModelInfo), len(copiedShow.Tensors))
	}

	const advertisedName = "llama3.2:latest"
	if rec := doFrom(t, ip, http.MethodDelete, "/api/delete", `{"name":"`+advertisedName+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("delete advertised destination: status %d", rec.Code)
	}
	source := buildModelForName("foo:1b")
	source.Name = advertisedName
	source.Model = advertisedName
	models.add(req, source)

	rec := doFrom(t, ip, http.MethodPost, "/api/show", `{"model":"`+advertisedName+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("show same-name copy: status %d: %s", rec.Code, rec.Body.String())
	}
	var show showResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &show); err != nil {
		t.Fatalf("decode same-name copy: %v", err)
	}
	if got := show.ModelInfo["llama.embedding_length"]; got != float64(2048) {
		t.Errorf("same-name copy embedding length = %v, want source fallback 2048", got)
	}
	if got := show.ModelInfo["llama.block_count"]; got != float64(16) {
		t.Errorf("same-name copy block count = %v, want source fallback 16", got)
	}
	if show.Details.ParameterSize != "1.2B" || len(show.Tensors) != 147 {
		t.Errorf("same-name copy used destination profile: details=%#v tensors=%d",
			show.Details, len(show.Tensors))
	}
}

func TestOverlayShowCacheInvalidatesAfterDeleteAndReplacement(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const ip = "203.0.113.64"
	const destination = "cache-swap:1b"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"

	if rec := doFrom(t, ip, http.MethodPost, "/api/pull", `{"name":"`+destination+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("pull initial model: status %d", rec.Code)
	}
	initial, ok := models.get(req, destination)
	if !ok {
		t.Fatal("initial overlay missing")
	}
	initialPayload := showBodyForRequest(req, initial)
	var initialShow showResponse
	if err := json.Unmarshal(initialPayload, &initialShow); err != nil {
		t.Fatalf("decode initial show payload: %v", err)
	}
	if got := initialShow.ModelInfo["llama.embedding_length"]; got != float64(2048) {
		t.Fatalf("initial embedding length = %v, want 2048", got)
	}
	const source = "cache-source:70b"
	if rec := doFrom(t, ip, http.MethodPost, "/api/pull", `{"name":"`+source+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("pull replacement source: status %d", rec.Code)
	}
	if rec := doFrom(t, ip, http.MethodPost, "/api/copy",
		`{"source":"`+source+`","destination":"`+destination+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("copy replacement: status %d", rec.Code)
	}
	replacement, ok := models.get(req, destination)
	if !ok {
		t.Fatal("replacement overlay missing")
	}
	replacementPayload := showBodyForRequest(req, replacement)
	if &initialPayload[0] == &replacementPayload[0] {
		t.Error("replacement reused the deleted overlay's serialized payload")
	}
	var replacementShow showResponse
	if err := json.Unmarshal(replacementPayload, &replacementShow); err != nil {
		t.Fatalf("decode replacement show payload: %v", err)
	}
	if got := replacementShow.ModelInfo["llama.embedding_length"]; got != float64(8192) {
		t.Errorf("replacement embedding length = %v, want 8192", got)
	}
	if got := replacementShow.ModelInfo["llama.block_count"]; got != float64(80) {
		t.Errorf("replacement block count = %v, want 80", got)
	}
}

func TestCopyReplacesVisibleBaseDestination(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const ip = "203.0.113.70"
	const source = "base-replacement:1b"
	const destination = "llama3.2:latest"
	if rec := doFrom(t, ip, http.MethodPost, "/api/pull", `{"name":"`+source+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("pull source: status %d", rec.Code)
	}
	if rec := doFrom(t, ip, http.MethodPost, "/api/copy",
		`{"source":"`+source+`","destination":"`+destination+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("replace base destination: status %d: %s", rec.Code, rec.Body.String())
	}

	count := 0
	for _, name := range catalogOf(t, ip) {
		if name == destination {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("catalog contains %d copies of replaced base destination, want 1", count)
	}
	rec := doFrom(t, ip, http.MethodPost, "/api/show", `{"model":"`+destination+`"}`)
	var show showResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &show); err != nil {
		t.Fatalf("decode replaced base show: %v", err)
	}
	if got := show.ModelInfo["llama.embedding_length"]; got != float64(2048) {
		t.Errorf("replaced base embedding length = %v, want copied 1B source value", got)
	}
	if got := show.ModelInfo["llama.block_count"]; got != float64(16) {
		t.Errorf("replaced base block count = %v, want copied 1B source value", got)
	}
}

func TestDeletedModelCannotRepopulateOverlayShowCache(t *testing.T) {
	const ip = "203.0.113.71"
	const name = "stale-show:1b"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	if !models.add(req, buildModelForName(name)) {
		t.Fatal("add stale-show fixture")
	}
	stale, ok := models.get(req, name)
	if !ok {
		t.Fatal("stale-show fixture missing")
	}
	v := models.viewForCachedShow(ip)
	if v == nil {
		t.Fatal("stale-show view missing")
	}
	buildLock := v.showLockFor(name)
	buildLock.Lock()
	built := buildShowPayload(stale)
	if !models.remove(req, name) {
		buildLock.Unlock()
		t.Fatal("delete stale-show fixture")
	}
	models.cacheShowPayloadIfCurrent(ip, v, stale, buildLock, built)
	buildLock.Unlock()

	v.showMu.Lock()
	_, payloadRetained := v.showPayloads[name]
	_, lockRetained := v.showLocks[name]
	v.showMu.Unlock()
	if payloadRetained || lockRetained {
		t.Errorf("deleted model repopulated view cache: payload=%v lock=%v",
			payloadRetained, lockRetained)
	}
}

func TestReplacedModelCannotCacheInFlightOldIdentity(t *testing.T) {
	const ip = "203.0.113.72"
	const name = "racing-replacement:latest"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"

	old := buildModelForName("old-source:1b")
	old.Name, old.Model = name, name
	if !models.add(req, old) {
		t.Fatal("add old replacement fixture")
	}
	v := models.viewForCachedShow(ip)
	buildLock := v.showLockFor(name)
	buildLock.Lock()
	oldBuilt := buildShowPayload(old)

	replacement := buildModelForName("new-source:70b")
	replacement.Name, replacement.Model = name, name
	replacement.ModifiedAt = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	if !models.replace(req, replacement) {
		buildLock.Unlock()
		t.Fatal("replace racing fixture")
	}
	models.cacheShowPayloadIfCurrent(ip, v, old, buildLock, oldBuilt)
	buildLock.Unlock()

	v.showMu.Lock()
	stale, staleCached := v.showPayloads[name]
	v.showMu.Unlock()
	if staleCached && stale.key == oldBuilt.key {
		t.Fatal("in-flight old identity was cached after replacement")
	}

	body := showBodyForRequest(req, replacement)
	var show showResponse
	if err := json.Unmarshal(body, &show); err != nil {
		t.Fatalf("decode replacement show: %v", err)
	}
	if got := show.ModelInfo["llama.embedding_length"]; got != float64(8192) {
		t.Errorf("replacement embedding length = %v, want 8192", got)
	}
	v.showMu.Lock()
	current := v.showPayloads[name]
	v.showMu.Unlock()
	wantKey := showCacheKey{
		name: replacement.Name, digest: replacement.Digest, modifiedAt: replacement.ModifiedAt,
	}
	if current.key != wantKey {
		t.Errorf("cache key = %#v, want replacement identity %#v", current.key, wantKey)
	}
}

func TestOverlayShowCacheHasPerViewByteBudget(t *testing.T) {
	const ip = "203.0.113.73"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	var v *view
	for i := 0; i < 3; i++ {
		m := buildModelForName(fmt.Sprintf("large-%d:1b", i))
		if !models.add(req, m) {
			t.Fatalf("add large cache fixture %d", i)
		}
		if v == nil {
			v = models.viewForCachedShow(ip)
		}
		lock := v.showLockFor(m.Name)
		lock.Lock()
		built := buildShowPayload(m)
		built.body = make([]byte, maxShowCacheBytesPerView/2+1)
		models.cacheShowPayloadIfCurrent(ip, v, m, lock, built)
		lock.Unlock()
	}
	v.showMu.Lock()
	bytes, entries := v.showBytes, len(v.showPayloads)
	v.showMu.Unlock()
	if bytes > maxShowCacheBytesPerView {
		t.Fatalf("view retained %d show bytes, budget is %d", bytes, maxShowCacheBytesPerView)
	}
	if entries != 1 {
		t.Errorf("byte budget retained %d large payloads, want FIFO eviction down to 1", entries)
	}

	oversized := buildModelForName("larger-than-cache:1b")
	if !models.add(req, oversized) {
		t.Fatal("add oversized cache fixture")
	}
	lock := v.showLockFor(oversized.Name)
	lock.Lock()
	built := buildShowPayload(oversized)
	built.body = make([]byte, maxShowCacheBytesPerView+1)
	models.cacheShowPayloadIfCurrent(ip, v, oversized, lock, built)
	lock.Unlock()

	v.showMu.Lock()
	_, retained := v.showPayloads[oversized.Name]
	orderRetained := false
	for _, name := range v.showOrder {
		orderRetained = orderRetained || name == oversized.Name
	}
	afterOversizedBytes := v.showBytes
	v.showMu.Unlock()
	if retained || orderRetained || afterOversizedBytes != bytes {
		t.Errorf("oversized body changed cache: retained=%v order=%v bytes=%d, want %d",
			retained, orderRetained, afterOversizedBytes, bytes)
	}

	validBody := showBodyForRequest(req, oversized)
	var validShow showResponse
	if err := json.Unmarshal(validBody, &validShow); err != nil {
		t.Fatalf("uncached oversized model did not return a valid response: %v", err)
	}
}

func TestPulledModelNameByteLimit(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const ip = "203.0.113.65"
	atLimit := strings.Repeat("a", maxModelNameBytes-len(":1b")) + ":1b"
	rec := doFrom(t, ip, http.MethodPost, "/api/pull", `{"name":"`+atLimit+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("boundary pull status %d: %s", rec.Code, rec.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	if !models.has(req, atLimit) {
		t.Error("model name exactly at the byte limit was not retained")
	}

	for _, tc := range []struct {
		name  string
		model string
	}{
		{name: "ASCII", model: strings.Repeat("a", maxModelNameBytes+1) + ":1b"},
		{name: "UTF-8", model: strings.Repeat("é", maxModelNameBytes/2+1) + ":1b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := doFrom(t, ip, http.MethodPost, "/api/pull",
				fmt.Sprintf(`{"name":%q}`, tc.model))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("oversized pull status %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if models.has(req, tc.model) {
				t.Error("oversized attacker-controlled model name was retained in the catalog")
			}
		})
	}
}

func TestConcurrentAddsDoNotCreateDuplicateModels(t *testing.T) {
	const ip = "203.0.113.66"
	const name = "concurrent:1b"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	model := buildModelForName(name)
	catalog := newCatalog()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !catalog.add(req, model) {
				t.Error("concurrent add did not leave the model visible")
			}
		}()
	}
	wg.Wait()

	count := 0
	for _, candidate := range catalog.list(req) {
		if candidate.Name == name {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent catalog contains %d copies of %q, want 1", count, name)
	}
}

func TestPullReportsStorageLimitInsteadOfSuccess(t *testing.T) {
	orig := pullStepDelay
	pullStepDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { pullStepDelay = orig })

	const ip = "203.0.113.67"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip + ":54321"
	for i := 0; i < maxAddedPerView; i++ {
		if !models.add(req, buildModelForName(fmt.Sprintf("full-%d:1b", i))) {
			t.Fatalf("fill overlay at index %d", i)
		}
	}

	const overflow = "one-too-many:1b"
	rec := doFrom(t, ip, http.MethodPost, "/api/pull", `{"name":"`+overflow+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("streaming pull status %d: %s", rec.Code, rec.Body.String())
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if got := lines[len(lines)-1]; !strings.Contains(got, `"error":"model storage limit reached"`) {
		t.Fatalf("last pull line %q, want storage-limit error", got)
	}
	if strings.Contains(rec.Body.String(), `"status":"success"`) {
		t.Error("storage-limited pull falsely reported success")
	}
	if models.has(req, overflow) {
		t.Error("storage-limited model was retained")
	}
}

func TestCopyRejectsInvalidOrFullDestination(t *testing.T) {
	t.Run("oversized destination", func(t *testing.T) {
		const ip = "203.0.113.68"
		destination := strings.Repeat("a", maxModelNameBytes+1) + ":copy"
		rec := doFrom(t, ip, http.MethodPost, "/api/copy",
			fmt.Sprintf(`{"source":"llama3.2:latest","destination":%q}`, destination))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("copy status %d, want 400: %s", rec.Code, rec.Body.String())
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":54321"
		if models.has(req, destination) {
			t.Error("oversized copy destination was retained")
		}
	})

	t.Run("full overlay", func(t *testing.T) {
		const ip = "203.0.113.69"
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":54321"
		for i := 0; i < maxAddedPerView; i++ {
			if !models.add(req, buildModelForName(fmt.Sprintf("copy-full-%d:1b", i))) {
				t.Fatalf("fill overlay at index %d", i)
			}
		}

		const destination = "copy-overflow:latest"
		rec := doFrom(t, ip, http.MethodPost, "/api/copy",
			`{"source":"llama3.2:latest","destination":"`+destination+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("copy status %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"error":"model storage limit reached"`) {
			t.Errorf("copy error body %q, want storage-limit error", rec.Body.String())
		}
		if models.has(req, destination) {
			t.Error("storage-limited copy destination was retained")
		}
	})
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
