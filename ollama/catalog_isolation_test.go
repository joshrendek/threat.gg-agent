package ollama

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
