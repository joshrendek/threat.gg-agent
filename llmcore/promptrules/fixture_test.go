package promptrules

// Shared-fixture plumbing for the agent's matcher tests.
//
// testdata/llm_prompt_rules_preview.json is a COPY of the server's
// ~/dev/threat_gg/fixtures/llm_prompt_rules_preview.json and MUST STAY IN SYNC WITH
// IT. The two files existing is not duplication for its own sake: the server's
// preview endpoint promises an operator "this rule will win", and the fleet has to
// keep that promise. This file is the executable half of that contract on the agent
// side, and internal/handler/llm_prompt_rules_preview_test.go is the other half.
//
// A change to either copy without the other silently removes the only
// cross-repository check either suite has, so TestSharedFixtureMatchesTheServerCopy
// diffs them whenever a server checkout is available.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

type fixture struct {
	Rules []fixtureRule `json:"rules"`
	Cases []fixtureCase `json:"cases"`
}

type fixtureRule struct {
	MatchKind     string `json:"match_kind"`
	Pattern       string `json:"pattern"`
	ReplyKind     string `json:"reply_kind"`
	ReplyText     string `json:"reply_text"`
	TelemetryKind string `json:"telemetry_kind"`
	Stage         string `json:"stage"`
	Priority      int32  `json:"priority"`
	Language      string `json:"language"`
	Note          string `json:"note"`
}

type fixtureCase struct {
	Name                string  `json:"name"`
	Prompt              string  `json:"prompt"`
	Normalized          string  `json:"normalized"`
	ExpectSafetyRefusal bool    `json:"expect_safety_refusal"`
	ExpectPreBuiltin    *string `json:"expect_pre_builtin"`
	ExpectPostBuiltin   *string `json:"expect_post_builtin"`
}

const fixturePath = "testdata/llm_prompt_rules_preview.json"

func loadFixture(t *testing.T) fixture {
	t.Helper()
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(f.Rules) == 0 || len(f.Cases) == 0 {
		t.Fatal("fixture must carry both rules and cases")
	}
	return f
}

// fixtureID assigns a deterministic uuid per rule index. The fixture has none
// because the server mints them on insert; the agent needs one because a rule with
// no id cannot be attributed in telemetry. Ids ascend with index so that if two
// fixture rules ever share a (stage, priority), the tie-break still matches the
// order they are written in.
func fixtureID(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

// fixtureReply turns the fixture into the wire bundle the server would have sent.
func fixtureReply(f fixture) *proto.LlmBundleReply {
	reply := &proto.LlmBundleReply{Version: "fixture-v1"}
	for i, r := range f.Rules {
		reply.Rules = append(reply.Rules, &proto.LlmPromptRule{
			Id:            fixtureID(i),
			MatchKind:     r.MatchKind,
			Pattern:       r.Pattern,
			ReplyKind:     r.ReplyKind,
			ReplyText:     r.ReplyText,
			TelemetryKind: r.TelemetryKind,
			Stage:         r.Stage,
			Priority:      r.Priority,
			Language:      r.Language,
		})
	}
	return reply
}

func loadFixtureBundle(t *testing.T) *Bundle {
	t.Helper()
	bundle, err := Load(fixtureReply(loadFixture(t)))
	if err != nil {
		t.Fatalf("load fixture bundle: %v", err)
	}
	return bundle
}

// TestFixtureRulesAllSurviveLoad is the standing assertion that every rule in the
// shared fixture is one the fleet would actually serve. The server's copy of this
// check seeds the fixture THROUGH the admin API so a rule that cannot be authored
// fails there; this is the mirror-image check at the other end of the wire.
func TestFixtureRulesAllSurviveLoad(t *testing.T) {
	f := loadFixture(t)
	bundle := loadFixtureBundle(t)
	if bundle.Dropped() != 0 {
		t.Fatalf("load dropped %d fixture rules; every fixture rule must be servable", bundle.Dropped())
	}
	// builtin_disable rules live in the disabled set, not a stage slice.
	wantMatchable := 0
	for _, r := range f.Rules {
		if r.MatchKind != MatchBuiltinDisable {
			wantMatchable++
		}
	}
	if bundle.Len() != wantMatchable {
		t.Fatalf("bundle carries %d matchable rules, want %d", bundle.Len(), wantMatchable)
	}
}

// TestFixtureCasesMatchTheServerPreview replays every fixture case through the
// agent's matcher and requires the same winner the server's preview endpoint
// reports, per stage. This is THE test that says the two matchers agree.
func TestTheAgentMatcherAgreesWithTheServerPreviewFixture(t *testing.T) {
	f := loadFixture(t)
	bundle := loadFixtureBundle(t)

	for _, tc := range f.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			// Normalization is the contract every pattern is matched against; a drift here
			// breaks every rule at once, so it is asserted before the winners.
			if got := Normalize(tc.Prompt); got != tc.Normalized {
				t.Fatalf("Normalize(%q) = %q, want %q", tc.Prompt, got, tc.Normalized)
			}

			if tc.ExpectSafetyRefusal {
				// The compiled safety denylist claims this prompt before the matcher is ever
				// consulted, which is why the fixture records no winner in either stage even
				// though the post_builtin catch-all would otherwise match it. That gate is
				// llmcore's -- it holds the authoritative denylist -- so the assertion lives
				// there too, in TestReplyForFollowsTheSharedPreviewFixture. Asserting anything
				// about the raw matcher here would be asserting about code the request never
				// reaches.
				return
			}

			matcher := bundle.Matcher()
			assertWinner(t, StagePreBuiltin, matcher.Match(StagePreBuiltin, tc.Normalized), tc.ExpectPreBuiltin)
			assertWinner(t, StagePostBuiltin, matcher.Match(StagePostBuiltin, tc.Normalized), tc.ExpectPostBuiltin)
		})
	}
}

func assertWinner(t *testing.T, stage string, got *Rule, want *string) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Fatalf("%s: matched %q, want no match", stage, got.Pattern)
	case want == nil:
		return
	case got == nil:
		t.Fatalf("%s: no match, want %q", stage, *want)
	case got.Pattern != *want:
		t.Fatalf("%s: matched %q, want %q", stage, got.Pattern, *want)
	case got.Stage != stage:
		t.Fatalf("%s: winner reports stage %q", stage, got.Stage)
	}
}

// TestSharedFixtureMatchesTheServerCopy diffs the agent's copy against the server's
// whenever a server checkout is present, and skips otherwise so the suite stays
// hermetic in CI. Only `rules` and `cases` are compared: the `_comment` block
// legitimately differs, because the agent copy carries the sync warning.
func TestSharedFixtureMatchesTheServerCopy(t *testing.T) {
	candidates := []string{os.Getenv("THREATGG_SERVER_REPO")}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "dev", "threat_gg"))
	}
	var serverPath string
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		path := filepath.Join(dir, "fixtures", "llm_prompt_rules_preview.json")
		if _, err := os.Stat(path); err == nil {
			serverPath = path
			break
		}
	}
	if serverPath == "" {
		t.Skip("no server checkout found; set THREATGG_SERVER_REPO to enable the cross-repository fixture check")
	}

	body, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatalf("read server fixture: %v", err)
	}
	var server fixture
	if err := json.Unmarshal(body, &server); err != nil {
		t.Fatalf("parse server fixture: %v", err)
	}
	local := loadFixture(t)
	if !reflect.DeepEqual(server.Rules, local.Rules) {
		t.Errorf("fixture rules have drifted from %s; update %s to match", serverPath, fixturePath)
	}
	if !reflect.DeepEqual(server.Cases, local.Cases) {
		t.Errorf("fixture cases have drifted from %s; update %s to match", serverPath, fixturePath)
	}
}
