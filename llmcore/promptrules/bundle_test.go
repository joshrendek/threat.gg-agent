package promptrules

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// TestOneBadRuleNeverCostsTheGoodOnes is the load-time half of PRD 034 safety
// invariant 5. Every row here is a way a rule can be wrong; each must be dropped
// individually, and the valid rule alongside it must survive.
func TestOneBadRuleNeverCostsTheGoodOnes(t *testing.T) {
	bad := []struct {
		name string
		rule *proto.LlmPromptRule
	}{
		{"no id", rule("", MatchContains, "probe-a")},
		{"unknown match_kind", rule(id(1), "startswith", "probe-b")},
		{"unknown reply_kind", rule(id(2), MatchContains, "probe-c", replyKind("engine:shell"))},
		{"unknown stage", rule(id(3), MatchContains, "probe-d", stage("mid_builtin"))},
		{"unknown telemetry_kind", rule(id(4), MatchContains, "probe-e", telemetry("exfiltration"))},
		{"negative priority", rule(id(5), MatchContains, "probe-f", priority(-1))},
		{"priority over the cap", rule(id(6), MatchContains, "probe-g", priority(MaxPriority+1))},
		{"empty pattern", rule(id(7), MatchContains, "")},
		{"oversized pattern", rule(id(8), MatchContains, strings.Repeat("a", MaxPatternBytes+1))},
		{"pattern with a newline", rule(id(9), MatchContains, "probe\nh")},
		{"pattern with a NUL", rule(id(10), MatchContains, "probe\x00i")},
		{"pattern is not valid utf-8", rule(id(11), MatchContains, "probe-\xff")},
		{"pattern is not normalized", rule(id(12), MatchContains, "Probe J")},
		{"uncompilable regex", rule(id(13), MatchRegex, "^answer (only")},
		{"regex program too large", rule(id(14), MatchRegex, "(?:abcdef){900}")},
		{"builtin_disable naming an unknown builtin", rule(id(15), MatchBuiltinDisable, "builtin.nope")},
		{"builtin_disable naming the safety denylist", rule(id(16), MatchBuiltinDisable, SafetyDenylistBuiltinID)},
		{"static with no reply_text", rule(id(17), MatchContains, "probe-k", replyText(""))},
		{"engine kind with a reply_text", rule(id(18), MatchContains, "probe-l",
			replyKind(ReplyEngineEchoLiteral), replyText("i will never be served"))},
		{"oversized reply_text", rule(id(19), MatchContains, "probe-m", replyText(strings.Repeat("x", MaxReplyTextBytes+1)))},
		{"reply_text with a control byte", rule(id(20), MatchContains, "probe-n", replyText("ok\x07"))},
		{"reply_text is not valid utf-8", rule(id(21), MatchContains, "probe-o", replyText("ok\xff"))},
		{"regex reply_text references a capture group", rule(id(22), MatchRegex, "^say (.+)$", replyText("you said $1"))},
		{"language too long", rule(id(23), MatchContains, "probe-p", func(r *proto.LlmPromptRule) {
			r.Language = strings.Repeat("e", MaxLanguageBytes+1)
		})},
	}

	good := rule(id(999), MatchContains, "survivor", replyText("still here"))
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			bundle := mustLoad(t, tc.rule, good)
			if bundle.Dropped() != 1 {
				t.Fatalf("dropped %d rules, want exactly 1", bundle.Dropped())
			}
			if bundle.Len() != 1 {
				t.Fatalf("bundle carries %d rules, want only the good one", bundle.Len())
			}
			if got := bundle.Matcher().Match(StagePreBuiltin, "survivor"); got == nil || got.ReplyText != "still here" {
				t.Fatalf("the valid rule did not survive alongside %q", tc.name)
			}
			// Whatever the bad rule was for, it must not answer -- neither by matching a
			// prompt nor, for a builtin_disable row, by suppressing a compiled group.
			if pattern := tc.rule.GetPattern(); pattern != "" {
				if got := bundle.Matcher().Match(StagePreBuiltin, Normalize(pattern)); got != nil && got.ID == tc.rule.GetId() {
					t.Fatalf("dropped rule %q still matched", tc.name)
				}
				if bundle.BuiltinDisabled(pattern) {
					t.Fatalf("dropped rule %q still disabled a builtin", tc.name)
				}
			}
		})
	}
}

// TestNonRegexPatternsMustArriveNormalized: the server normalizes them at write
// time, so an unnormalized one did not come through the API -- and could never match
// anything anyway, since it is compared against a normalized prompt.
func TestNonRegexPatternsMustArriveNormalized(t *testing.T) {
	for _, kind := range []string{MatchContains, MatchPrefix, MatchExact} {
		bundle := mustLoad(t, rule(id(1), kind, "Reply With Exactly One Word:"))
		if bundle.Len() != 0 || bundle.Dropped() != 1 {
			t.Fatalf("%s: an unnormalized pattern was kept", kind)
		}
	}
	// A regex pattern is NOT normalized -- "^Answer" is a legitimate case-sensitive
	// anchor an operator may have authored knowing the prompt is lowercased.
	bundle := mustLoad(t, rule(id(1), MatchRegex, "^answer (only|with) X"))
	if bundle.Len() != 1 {
		t.Fatal("a regex pattern must not be subject to the normalization check")
	}
}

func TestBundleRefusesRatherThanTruncates(t *testing.T) {
	rules := make([]*proto.LlmPromptRule, 0, MaxBundleRules+1)
	for i := 0; i <= MaxBundleRules; i++ {
		rules = append(rules, rule(id(i), MatchExact, fmt.Sprintf("probe %d", i)))
	}
	if _, err := Load(&proto.LlmBundleReply{Rules: rules}); err != ErrTooManyRules {
		t.Fatalf("Load(%d rules) err = %v, want ErrTooManyRules", len(rules), err)
	}
	// Exactly at the cap is fine.
	if _, err := Load(&proto.LlmBundleReply{Rules: rules[:MaxBundleRules]}); err != nil {
		t.Fatalf("Load at the cap: %v", err)
	}
	if _, err := Load(nil); err != ErrNilReply {
		t.Fatalf("Load(nil) err = %v, want ErrNilReply", err)
	}
}

func TestLoadPreservesRuleFields(t *testing.T) {
	bundle := mustLoad(t, &proto.LlmPromptRule{
		Id: id(1), MatchKind: MatchPrefix, Pattern: "responde solo con la palabra:",
		ReplyKind: ReplyEngineEchoLiteral, TelemetryKind: "literal_echo",
		Stage: StagePreBuiltin, Priority: 13, Language: "es",
	})
	got := bundle.Matcher().Match(StagePreBuiltin, "responde solo con la palabra: ok")
	if got == nil {
		t.Fatal("no match")
	}
	want := Rule{
		ID: id(1), MatchKind: MatchPrefix, Pattern: "responde solo con la palabra:",
		ReplyKind: ReplyEngineEchoLiteral, TelemetryKind: "literal_echo",
		Stage: StagePreBuiltin, Priority: 13, Language: "es",
	}
	if got.ID != want.ID || got.MatchKind != want.MatchKind || got.Pattern != want.Pattern ||
		got.ReplyKind != want.ReplyKind || got.ReplyText != "" || got.TelemetryKind != want.TelemetryKind ||
		got.Stage != want.Stage || got.Priority != want.Priority || got.Language != want.Language {
		t.Fatalf("rule round-trip = %#v, want %#v", *got, want)
	}
}

// TestConcurrentReadersDuringASwap is the torn-read guard. The bundle is the first
// shared mutable state on the LLM request path, so this must be run under -race:
// readers must observe either the whole old corpus or the whole new one.
func TestConcurrentReadersDuringASwap(t *testing.T) {
	t.Cleanup(func() { Store(nil) })

	first := mustLoad(t, rule(id(1), MatchContains, "probe", replyText("first")))
	second := mustLoad(t,
		rule(id(1), MatchContains, "probe", replyText("second")),
		rule(id(2), MatchBuiltinDisable, BuiltinEchoLiteral, replyKind(ReplyEngineEchoLiteral)),
	)
	Store(first)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				bundle := Current()
				got := bundle.Matcher().Match(StagePreBuiltin, "probe")
				if got == nil {
					t.Error("reader saw a bundle with no rules mid-swap")
					return
				}
				// A reader must never see the new reply text alongside the old disabled set,
				// or vice versa: the two always travel together.
				if (got.ReplyText == "second") != bundle.BuiltinDisabled(BuiltinEchoLiteral) {
					t.Errorf("torn read: reply %q with echo_literal disabled=%v",
						got.ReplyText, bundle.BuiltinDisabled(BuiltinEchoLiteral))
					return
				}
				_ = bundle.Version()
			}
		}()
	}
	for i := 0; i < 500; i++ {
		if i%2 == 0 {
			Store(second)
		} else {
			Store(first)
		}
	}
	close(stop)
	wg.Wait()
}

func TestStoreAndCurrentRoundTrip(t *testing.T) {
	t.Cleanup(func() { Store(nil) })
	Store(nil)
	if Current() != nil {
		t.Fatal("Current should be nil with no bundle stored")
	}
	bundle := mustLoad(t, rule(id(1), MatchContains, "probe"))
	Store(bundle)
	if Current() != bundle || Current().Version() != "v" {
		t.Fatal("Store/Current round trip failed")
	}
	// A global kill switch (UPDATE llm_prompt_rules SET enabled = false) arrives as an
	// empty rule list, not as an error: the fleet must go quiet, not stay stale.
	empty, err := Load(&proto.LlmBundleReply{Version: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	Store(empty)
	if Current().Len() != 0 || Current().Matcher().Match(StagePreBuiltin, "probe") != nil {
		t.Fatal("an empty bundle must match nothing")
	}
}
