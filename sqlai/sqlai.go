// Package sqlai is the agent half of AI answers for the SQL honeypots: when to
// ask the server, how long to wait, how a session learns that AI is live, and
// making server text safe for the wire. Spec §8 item 7 and §15.
package sqlai

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Generate has persistence.GenerateResponse's signature.
type Generate func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error)

const (
	// FirstBudget is what a session's first query waits, the same as the
	// legacy lookup, so a server without AI costs an attacker nothing new.
	FirstBudget = 500 * time.Millisecond
	// LiveBudget is what a query waits once the server showed AI is live.
	LiveBudget = 3 * time.Second
	// DegradedLookup replaces the legacy lookup deadline after a slow or
	// unreachable generate call, bounding the attacker's total wait.
	DegradedLookup = 600 * time.Millisecond
	// MaxQueryBytes caps the raw query sent to the server. A longer query is
	// never sent; the caller uses the legacy path.
	MaxQueryBytes = 4096
)

// State is what a session has learned about AI.
type State int

const (
	Unknown State = iota // nothing asked yet
	Live                 // the server answers this session with AI: ask with LiveBudget
	Off                  // no AI for this session: never ask again
)

// Outcome is one ask. ResultSet is non-nil only for an answered reply.
type Outcome struct {
	ResultSet    *proto.ResultSet
	Source       string // "ai", "ai_cached" or "local" when answered
	GenerationID string
	State        State // the session's state after this ask
	Degraded     bool  // the server was slow or unreachable: use DegradedLookup
}

var answeredSources = map[proto.GenerateSource]string{
	proto.GenerateSource_GENERATE_SOURCE_AI:        "ai",
	proto.GenerateSource_GENERATE_SOURCE_AI_CACHED: "ai_cached",
	proto.GenerateSource_GENERATE_SOURCE_LOCAL:     "local",
}

// Ask asks the server once and returns what the session learned. A first
// reply that is answered, or a NONE carrying a ledger id (the server has AI on
// for this protocol), makes the session live; a first NONE without an id, or
// any first-call error, turns AI off for the session, so a user without AI
// pays exactly one fast RPC per session. A blank or oversized query makes no
// call and leaves the state unchanged.
func Ask(gen Generate, protocol, guid, query string, st State) Outcome {
	out := Outcome{State: st}
	if gen == nil || st == Off || len(query) > MaxQueryBytes || strings.TrimSpace(query) == "" {
		return out
	}
	budget := FirstBudget
	if st == Live {
		budget = LiveBudget
	}
	reply, err := gen(&proto.GenerateRequest{
		Guid: guid, Protocol: protocol, Input: query, DeadlineMs: int32(budget / time.Millisecond),
	}, budget)
	if err != nil {
		out.Degraded = IsServerSlow(err)
		if st == Unknown {
			out.State = Off
		}
		return out
	}
	source, answered := answeredSources[reply.GetSource()]
	switch {
	case answered || reply.GetGenerationId() != "":
		out.State = Live
	case st == Unknown:
		out.State = Off
	}
	if answered && reply.GetResultSet() != nil {
		out.ResultSet, out.Source, out.GenerationID = reply.GetResultSet(), source, reply.GetGenerationId()
	}
	return out
}

// IsServerSlow reports a generate failure that means the server is slow or
// unreachable, as opposed to Unimplemented or a reply-level error.
func IsServerSlow(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable:
		return true
	}
	return false
}

// Clean makes server-supplied text safe to put on the wire to an attacker's
// client: invalid UTF-8 is repaired, and ESC, DEL and every other C0 or C1
// control is dropped, except newline and tab in cell values. Unicode format
// characters (category Cf: bidi overrides and isolates, zero-width marks, BOM)
// and the line and paragraph separators U+2028/U+2029 are dropped too, since
// cells reach psql and sqlcmd terminals. The server rejects such text already;
// this is the agent's own guarantee.
func Clean(s string, cell bool) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.Map(func(r rune) rune {
		if cell && (r == '\n' || r == '\t') {
			return r
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// Sessions remembers each session's State, bounded in size and age.
type Sessions struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	now   func() time.Time
	items map[string]sessionEntry
}

type sessionEntry struct {
	state State
	seen  time.Time
}

// DefaultSessionTTL is used when NewSessions is given a ttl of zero or less.
const DefaultSessionTTL = 30 * time.Minute

// NewSessions returns a Sessions holding at most bound entries (minimum 1),
// each forgotten after ttl without use. A ttl of zero or less is replaced by
// DefaultSessionTTL.
func NewSessions(bound int, ttl time.Duration) *Sessions {
	if bound < 1 {
		bound = 1
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &Sessions{max: bound, ttl: ttl, now: time.Now, items: map[string]sessionEntry{}}
}

// Get returns the session's state, or Unknown when it is absent or expired.
// A hit refreshes the entry's age, so a live session that keeps querying
// never expires mid-session.
func (s *Sessions) Get(id string) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e, ok := s.items[id]
	if !ok || now.Sub(e.seen) > s.ttl {
		delete(s.items, id)
		return Unknown
	}
	e.seen = now
	s.items[id] = e
	return e.state
}

// Set records the session's state and refreshes its age. Past the bound the
// least recently used entry is evicted (ties go to the smaller key, so the
// choice is deterministic); the scan is O(n) at the bound, which is acceptable
// for the configured bound.
func (s *Sessions) Set(id string, st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.items[id] = sessionEntry{state: st, seen: now}
	if len(s.items) <= s.max {
		return
	}
	oldest, oldestAt := "", time.Time{}
	for k, e := range s.items {
		if k == id {
			continue // never evict the entry just written
		}
		if now.Sub(e.seen) > s.ttl {
			delete(s.items, k)
			continue
		}
		if oldest == "" || e.seen.Before(oldestAt) || (e.seen.Equal(oldestAt) && k < oldest) {
			oldest, oldestAt = k, e.seen
		}
	}
	if len(s.items) > s.max && oldest != "" {
		delete(s.items, oldest)
	}
}

// Reset forgets every session (tests).
func (s *Sessions) Reset() {
	s.mu.Lock()
	s.items = map[string]sessionEntry{}
	s.mu.Unlock()
}
