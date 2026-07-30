package llmcore

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/joshrendek/threat.gg-agent/llmcore/promptrules"
)

// TestReplyForIsByteIdenticalWithAnEmptyCorpus is PRD 034 Phase 1's no-flag-day
// guarantee, and the PRD requires it to be a hard gate rather than an argument:
// "the corpus starts with zero rows, so ReplyFor behaves byte-identically to today.
// Guaranteed by a golden equivalence test, not by inspection."
//
// testdata/golden_replies.json was captured by running the PRE-PRD-034 build (commit
// 8b9c77f, before llmcore/promptrules existed) over 208 prompts x 4 models = 832
// cases spanning every compiled group, both sanitizer-rejection paths, the FNV
// generic pool, the jailbreak denylist and the degenerate inputs. Every entry is
// that build's exact ReplyResult.
//
// There is deliberately no -update flag. The file's entire value is that it predates
// the corpus engine; a regeneration switch would turn this gate into a tautology the
// first time someone ran it to make a red test green. If an entry legitimately must
// change, that is a change to the compiled floor and belongs in its own reviewed
// commit that says why.
func TestReplyForIsByteIdenticalWithAnEmptyCorpus(t *testing.T) {
	withCorpus(t, nil)

	var golden struct {
		Entries []struct {
			Prompt string `json:"prompt"`
			Model  string `json:"model"`
			Text   string `json:"text"`
			Kind   string `json:"kind"`
		} `json:"entries"`
	}
	body, err := os.ReadFile("testdata/golden_replies.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if err := json.Unmarshal(body, &golden); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(golden.Entries) < 800 {
		t.Fatalf("golden corpus has only %d entries; it is meant to be broad", len(golden.Entries))
	}

	var mismatches int
	for _, want := range golden.Entries {
		got := ReplyFor(want.Prompt, want.Model)
		if got.Text != want.Text || string(got.Kind) != want.Kind {
			mismatches++
			if mismatches <= 20 {
				t.Errorf("ReplyFor(%q, %q):\n  got  text=%q kind=%q\n  want text=%q kind=%q",
					want.Prompt, want.Model, got.Text, got.Kind, want.Text, want.Kind)
			}
		}
		// A compiled reply is never attributed to a corpus rule: rule_id must stay empty
		// or the admin fire counts would credit rules that did not fire.
		if got.RuleID != "" {
			t.Fatalf("ReplyFor(%q) reported rule_id %q with no corpus loaded", want.Prompt, got.RuleID)
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d of %d golden entries changed; the compiled floor must not move in Phase 1",
			mismatches, len(golden.Entries))
	}
}

// TestGoldenEquivalenceHoldsWithACorpusThatMatchesNothing separates two things the
// single golden run above cannot: "an absent bundle changes nothing" and "a PRESENT
// bundle that happens not to match changes nothing". The second is the one that
// would break if a stage lookup had a side effect, or if a loaded bundle altered the
// builtin gating by accident.
func TestGoldenEquivalenceHoldsWithACorpusThatMatchesNothing(t *testing.T) {
	inert := mustBundle(t,
		corpusRule("aaaaaaaa-0000-4000-8000-000000000001", promptrules.MatchExact,
			"zzzz-no-prompt-in-the-golden-corpus-is-this", promptrules.StagePreBuiltin, 0),
		corpusRule("aaaaaaaa-0000-4000-8000-000000000002", promptrules.MatchExact,
			"zzzz-nor-is-this-one", promptrules.StagePostBuiltin, 0),
	)

	var golden struct {
		Entries []struct {
			Prompt string `json:"prompt"`
			Model  string `json:"model"`
			Text   string `json:"text"`
			Kind   string `json:"kind"`
		} `json:"entries"`
	}
	body, err := os.ReadFile("testdata/golden_replies.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if err := json.Unmarshal(body, &golden); err != nil {
		t.Fatalf("parse golden: %v", err)
	}
	if len(golden.Entries) < 800 {
		t.Fatalf("golden corpus has only %d entries", len(golden.Entries))
	}

	withCorpus(t, nil)
	var nonEmpty int
	for _, want := range golden.Entries {
		promptrules.Store(inert)
		got := ReplyFor(want.Prompt, want.Model)
		// Compared against the RECORDED value, not against a second live call. Comparing
		// two live calls would pass trivially if the fixture had failed to unmarshal and
		// every prompt were the empty string.
		if got.Text != want.Text || string(got.Kind) != want.Kind || got.RuleID != "" {
			t.Fatalf("ReplyFor(%q, %q) changed under an inert corpus:\n  got  %#v\n  want text=%q kind=%q rule_id=\"\"",
				want.Prompt, want.Model, got, want.Text, want.Kind)
		}
		if want.Prompt != "" {
			nonEmpty++
		}
	}
	if nonEmpty < 800 {
		t.Fatalf("only %d golden prompts were non-empty; the fixture did not load properly", nonEmpty)
	}
}
