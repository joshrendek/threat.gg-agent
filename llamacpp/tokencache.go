package llamacpp

import (
	"hash/fnv"
	"net"
	"net/http"
	"sync"
	"time"
)

// PR #33 review (ERROR 2): /detokenize used to answer every request with "" — including a
// straight tokenize-then-detokenize probe of content it had itself just tokenized, which is
// both a clean tell and simply wrong. /tokenize's ids used to be pure math/rand output
// (llmcore.PseudoTokens), which cannot be reversed: nothing durable tied an id back to the text
// it came from.
//
// The fix makes tokenization deterministic (idForPiece hashes the piece's own text, so identical
// content always produces identical ids — a real tokenizer's property too) and remembers each
// id -> piece mapping in a bounded, per-source-IP cache so /detokenize can look the pieces back
// up and reconstruct the original text. Determinism alone would not be enough: a hash is one-way,
// so recovering the text still requires *something* to have recorded it — this cache is that
// something.
//
// Scoped and bounded per source IP for the same reason ollama/catalog.go's per-IP catalog views
// are (#32, threat_gg-b57-adjacent): this honeypot is public and unauthenticated, so a single
// shared, unbounded cache would let one attacker's flood of unique /tokenize calls evict another
// attacker's just-issued tokens before they can be detokenized, and would grow without bound as
// distinct callers arrive. Both axes are capped: distinct IPs tracked (maxTokenCacheViews) and
// pieces remembered per IP (maxPiecesPerView), each evicted oldest-first.
//
// Trade-off: an attacker who tokenizes far more than maxPiecesPerView pieces in one call (or in
// many calls without ever detokenizing) will find the earliest pieces already evicted by the time
// they detokenize — the round trip degrades to partial reconstruction rather than failing
// outright. That only affects pathological, unrealistic volumes; the realistic probe pattern this
// fix targets is "tokenize a prompt, then immediately detokenize the ids it returned," which is
// comfortably within the per-IP budget.

const (
	// maxTokenCacheViews caps how many distinct source IPs hold cached pieces, mirroring
	// ollama/catalog.go's maxViews — without it, an attacker rotating source addresses could grow
	// this map indefinitely.
	maxTokenCacheViews = 256
	// maxPiecesPerView caps how many token->piece mappings one IP can accumulate. A realistic
	// tokenize/detokenize probe is a handful of calls over a few hundred tokens at most; this
	// leaves generous headroom above that while still bounding memory per attacker.
	maxPiecesPerView = 4096
	// tokenCacheViewTTL expires an IP's cache entirely after this long without traffic from it.
	tokenCacheViewTTL = time.Hour
)

// tokenCache is the per-source-IP id -> piece store described above.
type tokenCache struct {
	mu    sync.Mutex
	views map[string]*tokenView
}

type tokenView struct {
	byID  map[int]string
	order []int // insertion order, oldest first, for bounded FIFO eviction
	seen  time.Time
}

var tokenMemory = &tokenCache{views: map[string]*tokenView{}}

// clientIP extracts the source address used to key the cache. Deliberately ignores
// X-Forwarded-For, same reasoning as ollama/catalog.go's clientIP: this honeypot is addressed
// directly, so an attacker-supplied header would let one caller read or evict another's cache.
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// remember records that id decodes to piece for this source IP, evicting the oldest entry (view
// or, within a view, piece) when a bound would otherwise be exceeded.
func (c *tokenCache) remember(ip string, id int, piece string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, v := range c.views {
		if now.Sub(v.seen) > tokenCacheViewTTL {
			delete(c.views, k)
		}
	}

	v, ok := c.views[ip]
	if !ok {
		if len(c.views) >= maxTokenCacheViews {
			var oldestKey string
			var oldest time.Time
			for k, vv := range c.views {
				if oldestKey == "" || vv.seen.Before(oldest) {
					oldestKey, oldest = k, vv.seen
				}
			}
			delete(c.views, oldestKey)
		}
		v = &tokenView{byID: map[int]string{}}
		c.views[ip] = v
	}
	v.seen = now

	if _, exists := v.byID[id]; !exists {
		if len(v.order) >= maxPiecesPerView {
			oldestID := v.order[0]
			v.order = v.order[1:]
			delete(v.byID, oldestID)
		}
		v.order = append(v.order, id)
	}
	v.byID[id] = piece
}

// lookup returns the piece previously remembered for id under this source IP, if any is still
// cached.
func (c *tokenCache) lookup(ip string, id int) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.views[ip]
	if !ok {
		return "", false
	}
	piece, ok := v.byID[id]
	return piece, ok
}

// tokenCountFor mirrors llmcore's private estTokens heuristic (~4 chars/token, floor 1) — not
// shared, since llama.cpp needs the count without llmcore.PseudoTokens' random values or its
// Ollama-flavoured BOS handling.
func tokenCountFor(content string) int {
	n := len(content) / 4
	if n < 1 {
		n = 1
	}
	return n
}

// idForPiece derives a stable, plausible-looking token id from a piece's own text: the same piece
// text always hashes to the same id (so two different requests that happen to tokenize the same
// substring, e.g. a common word, land on the same id — as a real shared vocabulary would too),
// and the range matches what llmcore.PseudoTokens already advertises elsewhere on this surface.
func idForPiece(piece string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(piece))
	return 1000 + int(h.Sum32()%126000)
}

// deterministicTokens splits content the same way with_pieces already did (splitIntoChunks),
// derives each piece's id, and records the id -> piece mapping for ip so a later /detokenize call
// from the same source can reconstruct it. Returns the ids and their corresponding piece texts in
// order; concatenating pieces reproduces content exactly (splitIntoChunks partitions the input
// without gaps or overlap).
func deterministicTokens(content string, ip string) (ids []int, pieces []string) {
	n := tokenCountFor(content)
	pieces = splitIntoChunks(content, n)
	ids = make([]int, n)
	for i, piece := range pieces {
		id := idForPiece(piece)
		ids[i] = id
		tokenMemory.remember(ip, id, piece)
	}
	return ids, pieces
}
