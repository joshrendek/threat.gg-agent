package promptrules

import (
	"os"
	"sort"
	"sync/atomic"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "promptrules").Logger()

// Bundle is an immutable, pre-sorted, pre-compiled corpus. Nothing mutates one
// after Load returns: refreshing the corpus builds a whole new Bundle and swaps the
// pointer, so a reader either sees the entire old corpus or the entire new one and
// never a half-applied edit. This is the first shared mutable state on the LLM
// request path, which is why the torn-read guard is an explicit -race test rather
// than an assumption.
type Bundle struct {
	version string
	pre     []Rule
	post    []Rule

	// disabled is the set of builtin ids the corpus suppresses. Never contains
	// SafetyDenylistBuiltinID: compileRule refuses that row outright.
	disabled map[string]bool

	// dropped counts rules the load-time validator refused, for the log line and for
	// the admin-visible "my rule is not firing" question.
	dropped int
}

// current holds the live bundle. A nil pointer means "no corpus" -- the compiled
// floor -- and every method below is nil-safe so that the no-bundle case needs no
// branch at the call site. That matters: the branch that is never written is the
// branch that cannot be forgotten during an outage.
var current atomic.Pointer[Bundle]

// Current returns the live bundle, or nil when none has ever loaded.
func Current() *Bundle { return current.Load() }

// Store publishes a bundle to every honeypot goroutine at once. Passing nil drops
// the fleet back to the compiled floor, which is what a global corpus kill switch
// (UPDATE llm_prompt_rules SET enabled = false) produces one poll later.
func Store(b *Bundle) { current.Store(b) }

// Version reports the loaded bundle's ETag, or "" for no bundle.
func (b *Bundle) Version() string {
	if b == nil {
		return ""
	}
	return b.version
}

// Len reports how many rules survived load-time validation.
func (b *Bundle) Len() int {
	if b == nil {
		return 0
	}
	return len(b.pre) + len(b.post)
}

// Dropped reports how many rules the load-time validator refused.
func (b *Bundle) Dropped() int {
	if b == nil {
		return 0
	}
	return b.dropped
}

// BuiltinDisabled reports whether the corpus suppresses a compiled group.
//
// It answers false for SafetyDenylistBuiltinID unconditionally, by construction
// rather than by a special case: a builtin_disable rule naming it never survives
// compileRule, so it can never be in the set. The safety test asserts this against a
// bundle that was fed exactly such a row.
func (b *Bundle) BuiltinDisabled(id string) bool {
	if b == nil || b.disabled == nil {
		return false
	}
	return b.disabled[id]
}

// DisabledBuiltins lists the suppressed builtin ids, sorted, for logging and tests.
// Mirrors the server's function of the same name.
func (b *Bundle) DisabledBuiltins() []string {
	if b == nil || len(b.disabled) == 0 {
		return nil
	}
	out := make([]string, 0, len(b.disabled))
	for id := range b.disabled {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// stageRules returns the rules for a stage, already in evaluation order.
func (b *Bundle) stageRules(stage string) []Rule {
	if b == nil {
		return nil
	}
	if stage == StagePreBuiltin {
		return b.pre
	}
	return b.post
}

// Load compiles a wire bundle. Invalid rules are dropped INDIVIDUALLY and logged;
// only two conditions fail the whole load:
//
//   - more than MaxBundleRules rules, which is a refusal rather than a truncation
//     for the same reason the server refuses to assemble one: a silently short
//     corpus is a fleet answering differently from what the admin list shows; and
//   - a nil reply, which is a caller bug.
//
// A failed Load leaves the previously loaded bundle in place, because the poller
// only calls Store on success. That is the fail-open floor: no bundle, a stale
// bundle and a compiled-only agent are three points on the same safe spectrum.
func Load(reply *proto.LlmBundleReply) (*Bundle, error) {
	if reply == nil {
		return nil, ErrNilReply
	}
	rules := reply.GetRules()
	if len(rules) > MaxBundleRules {
		return nil, ErrTooManyRules
	}

	bundle := &Bundle{version: reply.GetVersion(), disabled: map[string]bool{}}
	compiled := make([]Rule, 0, len(rules))
	for _, in := range rules {
		rule, err := compileRule(in)
		if err != nil {
			bundle.dropped++
			// Log the id and the reason but NOT the pattern: a pattern is admin-authored
			// and benign, but this logger's output is the same stdout a honeypot operator
			// tails, and there is no reason to widen what lands there.
			logger.Warn().
				Str("rule_id", in.GetId()).
				Str("match_kind", in.GetMatchKind()).
				Err(err).
				Msg("dropping invalid llm prompt rule")
			continue
		}
		compiled = append(compiled, rule)
	}

	sortRules(compiled)
	for _, rule := range compiled {
		if rule.MatchKind == MatchBuiltinDisable {
			bundle.disabled[rule.Pattern] = true
			// A builtin_disable rule never matches a prompt, so it does not belong in a
			// stage slice: leaving it there would spend match budget on every request
			// forever. The server's Match skips it for the same reason; dropping it here
			// is the same decision made once at load instead of once per request.
			continue
		}
		if rule.Stage == StagePreBuiltin {
			bundle.pre = append(bundle.pre, rule)
		} else {
			bundle.post = append(bundle.post, rule)
		}
	}
	return bundle, nil
}

// sortRules orders rules exactly as the server's BundleOrderSQL does:
//
//	CASE stage WHEN 'pre_builtin' THEN 0 ELSE 1 END, priority, id
//
// The bundle arrives in that order already, but re-sorting locally is deliberate:
// the agent must not be the component that assumes an ordering it did not compute.
// A server that grows a second bundle assembly path, a test that hand-builds a
// reply, or a proxy that reorders repeated fields would otherwise silently change
// which rule wins.
func sortRules(rules []Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if ra, rb := stageRank(a.Stage), stageRank(b.Stage); ra != rb {
			return ra < rb
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		// Lexicographic on the canonical lowercase uuid text is byte-identical to
		// Postgres's ordering of the uuid column: the hyphens sit at fixed positions in
		// both operands, and for hex digits ASCII order ('0'<'9'<'a'<'f') agrees with
		// nibble order, so a text compare and a memcmp of the 16 bytes cannot disagree.
		return a.ID < b.ID
	})
}

// stageRank mirrors BundleOrderSQL's CASE expression.
//
// The CASE is not decoration and neither is this function. 'post_builtin' sorts
// BEFORE 'pre_builtin' alphabetically, so ordering on the stage STRING would run
// every broad catch-all ahead of the narrow pre_builtin rules it was authored to sit
// behind -- and every test that used a single stage would still pass. The server has
// a regression test forbidding a naive `ORDER BY stage`; TestStageOrderingIsNotAlphabetical
// is its counterpart here.
func stageRank(stage string) int {
	if stage == StagePreBuiltin {
		return 0
	}
	return 1
}
