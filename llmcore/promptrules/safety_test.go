package promptrules

// Load-time safety invariants. The ReplyFor-level half of PRD 034's safety story --
// that the compiled denylist beats a priority-0 pre_builtin rule, and that
// engine:* routes still pass their sanitizers -- lives in llmcore, next to the
// denylist and the sanitizers themselves (llmcore/corpus_test.go). What can be
// asserted HERE is everything that must be true before a rule is ever consulted.

import (
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// TestSafetyDenylistCanNeverBeDisabled is the invariant this package exists to
// enforce as the last of four layers. The write-time validator, a DB CHECK and the
// server's bundle assembly all refuse this row; if a bundle reaches a honeypot by
// any route those three did not cover, this is what still stands between a jailbreak
// probe and an answer.
func TestSafetyDenylistCanNeverBeDisabled(t *testing.T) {
	// Every shape the row could take, including ones the admin API would never emit.
	rows := []*proto.LlmPromptRule{
		rule(id(1), MatchBuiltinDisable, SafetyDenylistBuiltinID),
		rule(id(2), MatchBuiltinDisable, SafetyDenylistBuiltinID, stage(StagePostBuiltin)),
		rule(id(3), MatchBuiltinDisable, SafetyDenylistBuiltinID, priority(0), replyKind(ReplyEngineEchoLiteral)),
	}
	for _, row := range rows {
		bundle := mustLoad(t, row)
		if bundle.BuiltinDisabled(SafetyDenylistBuiltinID) {
			t.Fatal("the safety denylist was disabled by a corpus rule")
		}
		if len(bundle.DisabledBuiltins()) != 0 {
			t.Fatalf("DisabledBuiltins = %v, want none", bundle.DisabledBuiltins())
		}
		if bundle.Dropped() != 1 {
			t.Fatalf("the row was not dropped: dropped = %d", bundle.Dropped())
		}
	}

	// And it is not merely dropped from the disabled set -- it cannot reach the set
	// through the normal path either, because compileRule refuses it outright.
	if _, err := compileRule(rule(id(1), MatchBuiltinDisable, SafetyDenylistBuiltinID)); err == nil {
		t.Fatal("compileRule accepted a builtin_disable naming the safety denylist")
	} else if !strings.Contains(err.Error(), "can never be disabled") {
		t.Fatalf("error = %v, want the explicit 'can never be disabled' message", err)
	}

	// Every OTHER builtin, including one adjacent in the list, remains disableable --
	// this is a targeted refusal, not a broken feature.
	bundle := mustLoad(t, rule(id(1), MatchBuiltinDisable, BuiltinValidationFact))
	if !bundle.BuiltinDisabled(BuiltinValidationFact) || bundle.Dropped() != 0 {
		t.Fatal("disabling an ordinary builtin regressed")
	}
}

// TestSafetyDenylistSurvivesAMixedBundle: the refusal must be per-rule, so a
// malicious or corrupt row cannot take a legitimate corpus down with it (which would
// be its own kind of win -- a fleet on the compiled floor stops improving).
func TestSafetyDenylistSurvivesAMixedBundle(t *testing.T) {
	bundle := mustLoad(t,
		rule(id(1), MatchBuiltinDisable, SafetyDenylistBuiltinID, priority(0)),
		rule(id(2), MatchBuiltinDisable, BuiltinEchoLiteral, priority(1)),
		rule(id(3), MatchContains, "who built you", priority(2), replyText("I'm a local model.")),
	)
	if bundle.BuiltinDisabled(SafetyDenylistBuiltinID) {
		t.Fatal("safety denylist disabled")
	}
	if !bundle.BuiltinDisabled(BuiltinEchoLiteral) {
		t.Fatal("the legitimate builtin_disable was lost")
	}
	if got := bundle.Matcher().Match(StagePreBuiltin, "who built you"); got == nil {
		t.Fatal("the legitimate matching rule was lost")
	}
}

// TestReplyTextIsNeverInterpolated pins PRD 034 safety invariant 2 at the only place
// reply_text is stored. Nothing in this package or in llmcore expands it; a rule
// authored in the expectation that it would be is refused rather than shipped as a
// literal "$1" to attackers.
func TestReplyTextIsNeverInterpolated(t *testing.T) {
	for _, ref := range []string{"you said $1", "you said ${1}", "you said ${name}", `you said \1`} {
		bundle := mustLoad(t, rule(id(1), MatchRegex, "^say (.+)$", replyText(ref)))
		if bundle.Len() != 0 {
			t.Errorf("regex rule with reply_text %q was accepted", ref)
		}
	}
	// On a non-regex rule there are no capture groups, so "$1" is unambiguously
	// literal text (a price, a shell positional) and banning it would be superstition.
	bundle := mustLoad(t, rule(id(1), MatchContains, "how much", replyText("It costs $1.")))
	if bundle.Len() != 1 {
		t.Fatal("a literal $1 in a contains-rule's reply must be allowed")
	}
	got := bundle.Matcher().Match(StagePreBuiltin, "how much is it")
	if got == nil || got.ReplyText != "It costs $1." {
		t.Fatalf("reply_text = %#v, want the authored literal unchanged", got)
	}
}

// TestBoundsMirrorTheServer is the constant-drift guard. Each value here is
// duplicated in the server's internal/promptrules and in the migration's CHECK
// constraints; a change on one side without the others is how a rule becomes
// authorable but unservable.
func TestBoundsMirrorTheServer(t *testing.T) {
	bounds := map[string]int{
		"MaxPatternBytes":      MaxPatternBytes,
		"MaxReplyTextBytes":    MaxReplyTextBytes,
		"MaxPriority":          MaxPriority,
		"MaxLanguageBytes":     MaxLanguageBytes,
		"MaxBundleRules":       MaxBundleRules,
		"MaxRegexProgramInsts": MaxRegexProgramInsts,
	}
	want := map[string]int{
		"MaxPatternBytes":      512,
		"MaxReplyTextBytes":    8192,
		"MaxPriority":          10000,
		"MaxLanguageBytes":     32,
		"MaxBundleRules":       5000,
		"MaxRegexProgramInsts": 1000,
	}
	for name, got := range bounds {
		if got != want[name] {
			t.Errorf("%s = %d, want %d (server internal/promptrules must agree)", name, got, want[name])
		}
	}
}

// TestAllowlistsMirrorTheServer pins the four vocabularies the two repositories
// share. A label the agent rejects but the server accepts is a rule that looks
// enabled in the admin UI and is silently absent from the fleet.
func TestAllowlistsMirrorTheServer(t *testing.T) {
	assertKeys(t, "MatchKinds", MatchKinds,
		"contains", "prefix", "exact", "regex", "builtin_disable")
	assertKeys(t, "ReplyKinds", ReplyKinds,
		"static", "engine:echo_literal", "engine:arithmetic")
	assertKeys(t, "Stages", Stages, "pre_builtin", "post_builtin")
	assertKeys(t, "TelemetryKinds", TelemetryKinds,
		"static_endpoint", "ollama_description", "model_intro_en", "model_intro_zh",
		"arithmetic", "literal_echo", "validation_fact", "generic_safe", "error",
		"code_validation", "constrained_prose", "arithmetic_nonce", "model_lifecycle",
		"safety_refusal", "corpus_rule")
	assertKeys(t, "BuiltinIDs", BuiltinIDs,
		"builtin.safety_denylist", "builtin.ollama_description", "builtin.intro_zh",
		"builtin.code_validation", "builtin.prose_lighthouse", "builtin.prose_rain",
		"builtin.poem_ocean", "builtin.intro_en", "builtin.arith_nonce",
		"builtin.arith_symbolic", "builtin.arith_wordform", "builtin.validation_fact",
		"builtin.echo_literal")
}

func assertKeys(t *testing.T, name string, got map[string]bool, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s has %d entries, want %d", name, len(got), len(want))
	}
	for _, key := range want {
		if !got[key] {
			t.Errorf("%s is missing %q", name, key)
		}
	}
	for key := range got {
		found := false
		for _, w := range want {
			if key == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s has unexpected entry %q; the server must agree", name, key)
		}
	}
}
