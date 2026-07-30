// Package promptrules is the agent half of PRD 034's server-pushed LLM prompt-rule
// corpus: the allowlists, the load-time validator, the prompt normalization the
// matcher is contracted to use, and the immutable compiled bundle the inference
// path reads through an atomic.Pointer.
//
// It is a mirror of the server's internal/promptrules, and the mirroring is the
// point. The admin preview endpoint tells an operator which rule will win for a
// candidate prompt; if this matcher and that one disagree, an operator authoring a
// regex against 28 internet-exposed honeypots is flying blind. Everything here that
// has a server counterpart names it in a comment, and the shared fixture
// (testdata/llm_prompt_rules_preview.json) is the executable half of the contract.
//
// Three properties this package exists to guarantee, in priority order:
//
//  1. It NEVER runs on the request path's critical section for network I/O. The
//     bundle is polled in the background and swapped atomically; ReplyFor reads a
//     pointer. See poller.go for why a per-request lookup was rejected.
//  2. It validates rather than trusts. The admin handler validated at write time and
//     the DB has CHECK constraints, but a row can reach the table another way (a
//     hand-run psql INSERT, a restored dump), so every rule is checked again here
//     and a bad one is dropped individually -- one bad row never costs the fleet the
//     good ones. This is PRD 034 safety invariant 5, and the agent is the last of
//     the four layers that enforce it.
//  3. It cannot widen what the honeypot is willing to SAY. A rule selects a stored
//     literal or routes to a COMPILED primitive (llmcore's cleanLiteralEcho /
//     computeArith) that keeps its own caps and denylists. There is no template
//     expansion and no capture-group interpolation anywhere in this package.
//
// The package deliberately does not import llmcore: llmcore imports it, and the
// engine primitives stay on that side of the boundary where their sanitizers live.
package promptrules

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// Bounds on authored content. Every one of these mirrors a constant of the same
// name in the server's internal/promptrules, which in turn mirrors a CHECK
// constraint in migrations/20260729210000_add_llm_prompt_rules.sql. A rule that
// exceeds one of them cannot be authored through the admin API at all; the copies
// here exist for the rows that arrive some other way.
const (
	// MaxPatternBytes bounds the pattern.
	MaxPatternBytes = 512
	// MaxReplyTextBytes bounds a static reply.
	MaxReplyTextBytes = 8192
	// MaxPriority bounds priority; 0 is the highest precedence and is legal.
	MaxPriority = 10000
	// MaxLanguageBytes bounds the informational BCP-47-ish tag.
	MaxLanguageBytes = 32
	// MaxBundleRules caps how many rules a bundle may carry. Exceeding it is a
	// REFUSAL, not a truncation: the server refuses to assemble an oversized bundle
	// for the same reason, because a silently short corpus is a fleet answering
	// differently from what the admin list shows.
	MaxBundleRules = 5000
	// MaxRegexProgramInsts bounds a regex rule's compiled program. The byte cap on
	// the pattern does not bound this by itself -- `(?:abcdef){900}` is fifteen bytes
	// and compiles to 5402 instructions -- and RE2's match cost is O(len(input) *
	// program size), so the program size is the quantity that needs the ceiling.
	MaxRegexProgramInsts = 1000
	// MaxMatchEvaluations is the per-REQUEST match budget (PRD 034: "a per-request
	// match budget (default 2,000 rule evaluations)"). It is shared across both
	// stages of one ReplyFor call via Bundle.Matcher, so a pathological corpus
	// degrades to the compiled floor instead of turning elapsed_ms into a
	// fingerprint. MaxBundleRules is deliberately larger: the rule cap bounds
	// memory, this bounds per-request latency, and they are not the same concern.
	MaxMatchEvaluations = 2000
)

// SafetyDenylistBuiltinID names the compiled jailbreak/unsafe-prompt group. It is
// the ONE builtin that can never be disabled: it runs before any corpus rule, and a
// row switching it off would make the honeypot answer jailbreak probes.
//
// The server rejects such a row at write time, the DB has a CHECK for it, and
// grpc_server drops it at bundle-assembly time. This package is the fourth and last
// layer, and it is the one that matters, because it is the only one still standing
// if a bundle reaches a honeypot by any route the other three did not cover.
const SafetyDenylistBuiltinID = "builtin.safety_denylist"

// Stage names. A pre_builtin rule is evaluated before the compiled groups and wins
// outright; a post_builtin rule fires only if no compiled group claimed the prompt.
const (
	StagePreBuiltin  = "pre_builtin"
	StagePostBuiltin = "post_builtin"
)

// Match kinds. All four prompt-matching kinds compare against the NORMALIZED
// prompt; builtin_disable never matches a prompt at all and instead suppresses one
// compiled group.
const (
	MatchContains       = "contains"
	MatchPrefix         = "prefix"
	MatchExact          = "exact"
	MatchRegex          = "regex"
	MatchBuiltinDisable = "builtin_disable"
)

// Reply kinds. "static" serves the authored literal verbatim; the engine:* kinds
// route to a compiled primitive in llmcore that keeps its own sanitizers. A corpus
// rule can widen what we RECOGNIZE, never what we are willing to SAY (PRD 034
// safety invariant 3).
const (
	ReplyStatic            = "static"
	ReplyEngineEchoLiteral = "engine:echo_literal"
	ReplyEngineArithmetic  = "engine:arithmetic"
)

// TelemetryKindCorpusRule is the fallback LlmReplyKind label for a rule that does
// not declare a more specific one.
const TelemetryKindCorpusRule = "corpus_rule"

// MatchKinds mirrors the server's allowlist of the same name.
var MatchKinds = map[string]bool{
	MatchContains:       true,
	MatchPrefix:         true,
	MatchExact:          true,
	MatchRegex:          true,
	MatchBuiltinDisable: true,
}

// ReplyKinds mirrors the server's allowlist of the same name.
var ReplyKinds = map[string]bool{
	ReplyStatic:            true,
	ReplyEngineEchoLiteral: true,
	ReplyEngineArithmetic:  true,
}

// Stages mirrors the server's allowlist of the same name.
var Stages = map[string]bool{
	StagePreBuiltin:  true,
	StagePostBuiltin: true,
}

// TelemetryKinds is the LlmReplyKind label set a rule may report. It mirrors the
// server's allowlist, which is itself the proto LlmReplyKind label set and the same
// set internal/handler/attack_payload.go applies on read.
//
// The agent accepts every label the server accepts, on purpose. Being STRICTER here
// than the write path would mean a rule the admin UI shows as valid and enabled is
// silently not served by the fleet -- the exact invisible divergence the shared
// fixture exists to prevent. Strictness belongs at author time; the agent's job is
// to drop the incoherent, not to second-guess the merely unusual.
var TelemetryKinds = map[string]bool{
	"static_endpoint":       true,
	"ollama_description":    true,
	"model_intro_en":        true,
	"model_intro_zh":        true,
	"arithmetic":            true,
	"literal_echo":          true,
	"validation_fact":       true,
	"generic_safe":          true,
	"error":                 true,
	"code_validation":       true,
	"constrained_prose":     true,
	"arithmetic_nonce":      true,
	"model_lifecycle":       true,
	"safety_refusal":        true,
	TelemetryKindCorpusRule: true,
}

// Builtin ids for the compiled groups in llmcore's ReplyFor cascade. A
// builtin_disable rule's pattern names one of these.
//
// Two of them do not map one-to-one onto a single `if` in generate.go, and the
// difference is documented rather than papered over:
//
//   - BuiltinArithSymbolic and BuiltinArithWordform are one function
//     (findArithmetic) iterating three regexes. The split is honoured by selecting
//     which regexes that function is handed, so disabling one id really does leave
//     the other working.
//   - BuiltinIntroEN covers BOTH the English and the Spanish self-introduction
//     branches. The Spanish branch already reports the English reply kind
//     (separating them needs a proto enum value), and the server's BuiltinIDs table
//     has no builtin.intro_es to name it with, so folding it in is the only mapping
//     that does not invent an id the admin UI would reject.
const (
	BuiltinOllamaDescription = "builtin.ollama_description"
	BuiltinIntroZH           = "builtin.intro_zh"
	BuiltinCodeValidation    = "builtin.code_validation"
	BuiltinProseLighthouse   = "builtin.prose_lighthouse"
	BuiltinProseRain         = "builtin.prose_rain"
	BuiltinPoemOcean         = "builtin.poem_ocean"
	BuiltinIntroEN           = "builtin.intro_en"
	BuiltinArithNonce        = "builtin.arith_nonce"
	BuiltinArithSymbolic     = "builtin.arith_symbolic"
	BuiltinArithWordform     = "builtin.arith_wordform"
	BuiltinValidationFact    = "builtin.validation_fact"
	BuiltinEchoLiteral       = "builtin.echo_literal"
)

// BuiltinIDs mirrors the server's table of the same name. The safety denylist is
// listed so that "unknown builtin" and "cannot be disabled" stay distinguishable;
// it is still refused everywhere it could be acted on.
var BuiltinIDs = map[string]bool{
	SafetyDenylistBuiltinID:  true,
	BuiltinOllamaDescription: true,
	BuiltinIntroZH:           true,
	BuiltinCodeValidation:    true,
	BuiltinProseLighthouse:   true,
	BuiltinProseRain:         true,
	BuiltinPoemOcean:         true,
	BuiltinIntroEN:           true,
	BuiltinArithNonce:        true,
	BuiltinArithSymbolic:     true,
	BuiltinArithWordform:     true,
	BuiltinValidationFact:    true,
	BuiltinEchoLiteral:       true,
}

// normalizeTrimCutset is the edge-punctuation set trimmed after lowercasing and
// collapsing whitespace. It includes the CJK full-width forms because the corpus is
// explicitly multilingual.
const normalizeTrimCutset = " .!?。！？"

// Normalize is the prompt normalization every pattern is matched against: trim,
// lowercase, collapse each whitespace run to a single space, then trim edge
// punctuation.
//
// It is byte-for-byte the server's promptrules.Normalize, and it is also the ONLY
// copy of this logic in the agent -- llmcore/generate.go's ReplyFor calls it rather
// than keeping the inline version it used to have. Three implementations of one
// contract (server validator, server preview, agent matcher) is already one more
// than is comfortable; a fourth inside llmcore would be the one that drifted.
func Normalize(prompt string) string {
	lower := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(prompt)), " "))
	return strings.Trim(lower, normalizeTrimCutset)
}

// Rule is one compiled corpus rule. It is immutable once a Bundle holds it: the
// inference path reads rules concurrently from many honeypot goroutines with no
// lock, and safety rests on nothing ever writing to one after the atomic swap.
type Rule struct {
	// ID is the llm_prompt_rules row uuid, reported back as LlmRequest.rule_id so a
	// capture can be attributed to the rule that answered it.
	ID            string
	MatchKind     string
	Pattern       string
	ReplyKind     string
	ReplyText     string
	TelemetryKind string
	Stage         string
	Priority      int32
	Language      string

	// re is the pattern compiled once at load time. *regexp.Regexp is safe for
	// concurrent use, which is why compiling here rather than per request is sound.
	re *regexp.Regexp
}

// Telemetry returns the LlmReplyKind label to report for a capture this rule
// answered, defaulting to corpus_rule.
func (r *Rule) Telemetry() string {
	if r == nil || r.TelemetryKind == "" {
		return TelemetryKindCorpusRule
	}
	return r.TelemetryKind
}

// matches reports whether the rule claims an already-normalized prompt.
// builtin_disable never matches a prompt -- it suppresses a compiled group instead
// -- which mirrors the skip at the top of the server's Match loop.
func (r *Rule) matches(normalized string) bool {
	switch r.MatchKind {
	case MatchContains:
		return strings.Contains(normalized, r.Pattern)
	case MatchPrefix:
		return strings.HasPrefix(normalized, r.Pattern)
	case MatchExact:
		return normalized == r.Pattern
	case MatchRegex:
		// re is non-nil for every regex rule that survived compileRule; the guard is
		// for the zero value, not for an expected condition.
		return r.re != nil && r.re.MatchString(normalized)
	}
	return false
}

// ErrTooManyRules is returned by Load when a bundle exceeds MaxBundleRules. It is a
// bundle-level refusal, unlike a per-rule validation failure: see Load.
var ErrTooManyRules = errors.New("llm bundle exceeds the maximum rule count")

// ErrNilReply is returned by Load for a nil reply. The poller cannot produce one --
// it treats a nil reply as a transport failure before it gets here -- so this is a
// caller bug, reported rather than papered over with an empty bundle.
var ErrNilReply = errors.New("nil llm bundle reply")

// captureGroupRef matches the interpolation forms an operator might reach for out of
// habit ($1, ${1}, ${name}, \1). Mirrors the server check; see compileRule for why
// it applies only to regex rules.
var captureGroupRef = regexp.MustCompile(`\$\{?[0-9A-Za-z_]|\\[1-9]`)

// compileRule validates one wire rule and compiles it, or explains why it was
// dropped. Every check mirrors the server's promptrules.Validate plus its Enabled
// filter; the ordering of the checks matches too, so a dropped-rule log line reads
// the same as the 400 an operator would have got at author time.
func compileRule(in *proto.LlmPromptRule) (Rule, error) {
	if in == nil {
		return Rule{}, errors.New("nil rule")
	}
	rule := Rule{
		ID:            in.GetId(),
		MatchKind:     in.GetMatchKind(),
		Pattern:       in.GetPattern(),
		ReplyKind:     in.GetReplyKind(),
		ReplyText:     in.GetReplyText(),
		TelemetryKind: in.GetTelemetryKind(),
		Stage:         in.GetStage(),
		Priority:      in.GetPriority(),
		Language:      in.GetLanguage(),
	}

	// A rule with no id cannot be attributed in telemetry (the server parses rule_id
	// as a uuid and drops anything else) and cannot be found by an operator reading
	// the answered-rate panel. The server always sets it, so an empty one means the
	// row did not come from the server's own assembly path.
	if rule.ID == "" {
		return Rule{}, errors.New("rule id is required")
	}
	if !MatchKinds[rule.MatchKind] {
		return Rule{}, fmt.Errorf("invalid match_kind %q", rule.MatchKind)
	}
	if !ReplyKinds[rule.ReplyKind] {
		return Rule{}, fmt.Errorf("invalid reply_kind %q", rule.ReplyKind)
	}
	if !Stages[rule.Stage] {
		return Rule{}, fmt.Errorf("invalid stage %q", rule.Stage)
	}
	if !TelemetryKinds[rule.Telemetry()] {
		return Rule{}, fmt.Errorf("invalid telemetry_kind %q", rule.TelemetryKind)
	}
	if rule.Priority < 0 || rule.Priority > MaxPriority {
		return Rule{}, fmt.Errorf("priority %d out of range", rule.Priority)
	}
	if len(rule.Language) > MaxLanguageBytes {
		return Rule{}, errors.New("language is too long")
	}
	if err := validatePattern(&rule); err != nil {
		return Rule{}, err
	}
	if err := validateReplyText(&rule); err != nil {
		return Rule{}, err
	}
	return rule, nil
}

func validatePattern(rule *Rule) error {
	if rule.Pattern == "" {
		return errors.New("pattern is required")
	}
	if len(rule.Pattern) > MaxPatternBytes {
		return fmt.Errorf("pattern exceeds %d bytes", MaxPatternBytes)
	}
	if strings.ContainsAny(rule.Pattern, "\x00\r\n") {
		return errors.New("pattern contains NUL, CR or LF")
	}
	if !utf8.ValidString(rule.Pattern) {
		return errors.New("pattern is not valid UTF-8")
	}

	switch rule.MatchKind {
	case MatchBuiltinDisable:
		// SAFETY INVARIANT. This is the load-time half of "builtin.safety_denylist can
		// never be disabled" and the reason this check is duplicated four times across
		// two repositories: "should have been impossible" is not a property you want
		// standing between a jailbreak probe and an answer.
		if rule.Pattern == SafetyDenylistBuiltinID {
			return fmt.Errorf("%s can never be disabled", SafetyDenylistBuiltinID)
		}
		if !BuiltinIDs[rule.Pattern] {
			return fmt.Errorf("unknown builtin id %q", rule.Pattern)
		}
	case MatchRegex:
		re, err := compilePattern(rule.Pattern)
		if err != nil {
			return err
		}
		rule.re = re
	default:
		// contains / prefix / exact are compared against the normalized prompt, so the
		// server normalizes the pattern at write time. A pattern that is NOT already in
		// normalized form therefore did not come through the API, and could never match
		// anything anyway -- shipping it would only spend match budget. This mirrors the
		// `candidate.Pattern == rule.Pattern` tail of the server's Enabled.
		if Normalize(rule.Pattern) != rule.Pattern {
			return errors.New("pattern is not in normalized form")
		}
	}
	return nil
}

// compilePattern is the load-time regex gate, mirroring the server's function of the
// same name: it must parse, it must compile, and its compiled program must fit under
// MaxRegexProgramInsts.
func compilePattern(pattern string) (*regexp.Regexp, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("pattern does not parse: %w", err)
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return nil, fmt.Errorf("pattern does not compile: %w", err)
	}
	if len(prog.Inst) > MaxRegexProgramInsts {
		return nil, fmt.Errorf("pattern compiles to %d instructions, limit %d", len(prog.Inst), MaxRegexProgramInsts)
	}
	// regexp.Compile is the compiler whose acceptance actually matters at serve time.
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("pattern is not a valid regular expression: %w", err)
	}
	return re, nil
}

func validateReplyText(rule *Rule) error {
	if rule.ReplyKind == ReplyStatic {
		if rule.ReplyText == "" {
			return errors.New("reply_text is required when reply_kind is static")
		}
	} else if rule.ReplyText != "" {
		// An engine:* rule supplies the TRIGGER phrasing only; the reply comes from the
		// compiled primitive. Serving the reply_text anyway would be exactly the bypass
		// PRD 034 safety invariant 3 forbids, and silently ignoring it would leave an
		// operator believing they had authored a reply that is never served.
		return fmt.Errorf("reply_text must be empty when reply_kind is %s", rule.ReplyKind)
	}
	if len(rule.ReplyText) > MaxReplyTextBytes {
		return fmt.Errorf("reply_text exceeds %d bytes", MaxReplyTextBytes)
	}
	if !utf8.ValidString(rule.ReplyText) {
		return errors.New("reply_text is not valid UTF-8")
	}
	for _, r := range rule.ReplyText {
		if r == '\n' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return errors.New("reply_text contains control characters other than tab and newline")
		}
	}
	// PRD 034 safety invariant 2: no capture-group interpolation. Nothing in this
	// repository expands reply_text -- it is served verbatim -- and this check stops a
	// rule authored in the expectation that it would be. Regex rules only: without
	// capture groups there is nothing to interpolate, so "$1" in a contains-rule's
	// reply is unambiguously literal text.
	if rule.MatchKind == MatchRegex && captureGroupRef.MatchString(rule.ReplyText) {
		return errors.New("reply_text references a capture group; interpolation is not supported")
	}
	return nil
}
