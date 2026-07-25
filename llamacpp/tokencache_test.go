package llamacpp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression tests for the PR #33 review's per-source-IP scoping requirement on ERROR 2's fix
// (mirrors ollama/catalog_isolation_test.go's coverage of the same lesson from #32).

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
	newRouter().ServeHTTP(rec, r)
	return rec
}

func tokenizeIDs(t *testing.T, ip, content string) []int {
	t.Helper()
	var resp struct {
		Tokens []int `json:"tokens"`
	}
	body := doFrom(t, ip, "POST", "/tokenize", fmt.Sprintf(`{"content":%q}`, content)).Body.Bytes()
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("tokenize for %s: %v — %s", ip, err, body)
	}
	return resp.Tokens
}

func detokenizeFrom(t *testing.T, ip string, ids []int) string {
	t.Helper()
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		t.Fatalf("marshal ids: %v", err)
	}
	var resp struct {
		Content string `json:"content"`
	}
	body := doFrom(t, ip, "POST", "/detokenize", fmt.Sprintf(`{"tokens":%s}`, idsJSON)).Body.Bytes()
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("detokenize for %s: %v — %s", ip, err, body)
	}
	return resp.Content
}

// One attacker's tokenize/detokenize traffic must not let a different source reconstruct it —
// the cache is per-IP, not global, exactly as ollama/catalog.go's overlay views are.
func TestDetokenizeDoesNotLeakAcrossCallers(t *testing.T) {
	const owner, other = "203.0.113.7", "198.51.100.9"
	const secret = "the attacker's own prompt text"

	ids := tokenizeIDs(t, owner, secret)
	if len(ids) == 0 {
		t.Fatal("no tokens returned")
	}

	if got := detokenizeFrom(t, owner, ids); got != secret {
		t.Errorf("owner round trip failed: got %q, want %q", got, secret)
	}
	if got := detokenizeFrom(t, other, ids); got != "" {
		t.Errorf("a different source IP recovered another caller's text: %q", got)
	}
}

// X-Forwarded-For is attacker-controlled on a directly-addressed honeypot; honouring it would let
// one caller read another caller's cached pieces by spoofing their address.
func TestForwardedHeaderDoesNotKeyTheTokenCache(t *testing.T) {
	const victim = "198.51.100.88"
	const text = "victim only text"
	ids := tokenizeIDs(t, victim, text)

	r := httptest.NewRequest("POST", "/detokenize", strings.NewReader(fmt.Sprintf(`{"tokens":%s}`, mustJSON(t, ids))))
	r.RemoteAddr = "203.0.113.99:1111"
	r.Header.Set("X-Forwarded-For", victim)
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, r)

	var resp struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if resp.Content == text {
		t.Error("X-Forwarded-For let a spoofed caller read the victim's cached tokens")
	}
}

// Rotating source addresses must not grow the per-IP view map without bound.
func TestTokenCacheViewsAreBounded(t *testing.T) {
	for i := 0; i < maxTokenCacheViews+64; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
		tokenizeIDs(t, ip, "flood")
	}
	tokenMemory.mu.Lock()
	n := len(tokenMemory.views)
	tokenMemory.mu.Unlock()
	if n > maxTokenCacheViews {
		t.Errorf("token cache holds %d views, cap is %d", n, maxTokenCacheViews)
	}
}

// Tokenizing far more content than one IP's piece budget must not grow that IP's cache entry
// without bound — old pieces are evicted to make room, which is why an extreme volume degrades
// to partial reconstruction rather than failing outright (see tokencache.go's trade-off comment).
func TestTokenCachePiecesPerViewAreBounded(t *testing.T) {
	const ip = "203.0.113.40"
	// Needs high piece-to-piece variety, not just length: splitIntoChunks slices contiguously, so
	// a short repeating pattern (e.g. "word word word...") cycles through only a handful of
	// distinct 4-char windows and would never actually exercise eviction. A long run of
	// concatenated increasing integers has no short period, so its contiguous windows are
	// overwhelmingly distinct.
	var b strings.Builder
	for i := 0; i < maxPiecesPerView*8; i++ {
		fmt.Fprintf(&b, "%d", i)
	}
	tokenizeIDs(t, ip, b.String())

	tokenMemory.mu.Lock()
	n := len(tokenMemory.views[ip].byID)
	tokenMemory.mu.Unlock()
	if n > maxPiecesPerView {
		t.Errorf("view holds %d cached pieces, cap is %d", n, maxPiecesPerView)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
