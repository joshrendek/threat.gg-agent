package llmcore

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// Model is one entry in an OpenAI /v1/models listing.
type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// replyPool holds benign, plausible assistant completions. They look like a real model
// reply but never actually help the attacker; the value is capturing the request, not
// producing useful output.
// A small pool is itself a fingerprint: a scanner that sends a handful of varied prompts and
// gets the same few sentences back knows it is not talking to a model.
var replyPool = []string{
	"Hello! I'm here to help. Could you tell me a bit more about what you're trying to do?",
	"Sure — I can help with that. Let me know the specifics and I'll walk you through it.",
	"That's an interesting question. Here's a high-level overview to get you started.",
	"I understand what you're asking. Let me break this down step by step.",
	"Happy to help! Here are a few things to consider before we begin.",
	"Good question. The short answer is that it depends on the context you're working in.",
	"There are a couple of ways to approach this. I'll start with the most common one.",
	"Let me make sure I've got this right before I answer in detail.",
	"I can outline the general idea, and we can go deeper wherever it's useful.",
	"From what you've described, the usual starting point is to narrow down the scope.",
	"That's a broad topic, so let's focus on the part that matters most to you.",
	"Here's how I'd think about it, along with the trade-offs involved.",
	"I'd approach that in stages rather than all at once — it's easier to verify that way.",
	"Sure thing. A quick summary first, then the details if you want them.",
	"I've seen this come up a lot. The answer usually hinges on one or two details.",
	"Let's work through it together. What's the outcome you're aiming for?",
	"It's worth separating the general principle from the specific case here.",
	"Absolutely — here's a straightforward explanation without too much jargon.",
	"I can give you a practical answer, though the exact details vary by setup.",
	"That depends on a few factors, so let me cover the main ones.",
	"Interesting — I'll explain the reasoning rather than just the conclusion.",
	"Happy to dig into that. Here's the essential background first.",
	"Let me summarise what's involved, then you can tell me where to expand.",
	"There's a simple version of this answer and a more complete one. Here's the simple version.",
}

// refusalPool answers prompt-injection and jailbreak attempts. A real assistant refuses; handing
// back cheerful helper prose to "ignore all previous instructions" is a tell on its own.
//
// They report ReplyKindSafetyRefusal so jailbreak volume is measurable separately from prompts
// we simply did not recognize. The server must know the value first: shapeLlmResponse validates
// reply_kind against an allowlist and silently drops anything unlisted.
var refusalPool = []string{
	"I can't help with that. Is there something else I can do for you?",
	"Sorry, I can't share the internal configuration I run under.",
	"I'm not able to do that. Happy to help with something else, though.",
	"That's not something I can provide. Let me know if there's another way I can help.",
	"I can't override the guidelines I operate under, but I'm glad to help with a normal request.",
	"I won't be able to do that one. Ask me something else and I'll do my best.",
	"Sorry — I cannot reveal internal details about how I'm set up.",
	"I'm unable to comply with that request. Is there another topic I can help with?",
	"I can't act on instructions that ask me to disregard my own guidelines.",
	"I cannot take that on, though I'm happy to answer an ordinary question.",
}

// ReplyKind is a bounded description of why a response was selected. The values deliberately
// match the server-side telemetry enum so response fidelity can be measured without retaining
// generated text.
type ReplyKind string

const (
	ReplyKindOllamaDescription ReplyKind = "ollama_description"
	ReplyKindModelIntroEN      ReplyKind = "model_intro_en"
	ReplyKindModelIntroZH      ReplyKind = "model_intro_zh"
	ReplyKindArithmetic        ReplyKind = "arithmetic"
	ReplyKindLiteralEcho       ReplyKind = "literal_echo"
	ReplyKindValidationFact    ReplyKind = "validation_fact"
	ReplyKindGenericSafe       ReplyKind = "generic_safe"
	ReplyKindSafetyRefusal     ReplyKind = "safety_refusal"
	ReplyKindCodeValidation    ReplyKind = "code_validation"
	ReplyKindConstrainedProse  ReplyKind = "constrained_prose"
	ReplyKindArithmeticNonce   ReplyKind = "arithmetic_nonce"
)

// ReplyResult carries the safe response and its bounded classification.
type ReplyResult struct {
	Text string
	Kind ReplyKind
}

func pickFrom(pool []string, prompt, model string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(prompt))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(model))
	return pool[int(h.Sum32())%len(pool)]
}

func pickReplyFor(prompt, model string) string { return pickFrom(replyPool, prompt, model) }

var (
	// echoRe gates the echo rule: the liveness probes scanners use to confirm an endpoint really
	// runs a model open with an instruction verb. Only the verb is matched here — the token the
	// scanner actually wants is extracted from the tail by echoTarget, because the surrounding
	// filler ("with exactly one word:", "exactly this text and nothing else:") is composed too
	// freely to enumerate as literal phrasings.
	echoRe = regexp.MustCompile(`(?i)^\s*(?:say|repeat|reply|respond|answer|return|output|print|echo` +
		`|responde|contesta|escribe|repite|devuelve|imprime|di)\b[:,\s]+(.+)$`)
	// arithRe locates a trivial arithmetic liveness check ("what is 2+2", "10 * 3") anywhere in
	// the prompt. Anchoring it to the whole prompt missed every probe that wrapped the
	// expression in instruction text or spread it over lines. Operand width is bounded by the
	// caller, not the pattern, so an over-wide operand is rejected rather than partially matched.
	arithRe = regexp.MustCompile(`(\d+)\s*([-+*/])\s*(\d+)`)
	// crossArithRe treats "x" as multiplication only when it is spaced: "1024x768" is a screen
	// resolution, not a probe.
	crossArithRe = regexp.MustCompile(`(\d+)\s+([xX])\s+(\d+)`)
	// wordArithRe covers natural-language probes seen in production, such as "2 plus 2".
	wordArithRe = regexp.MustCompile(`(?i)(\d+)\s+(plus|minus|times|multiplied\s+by|divided\s+by)\s+(\d+)`)
	// arithNonceRe covers validators that require both a computed value and a bounded nonce.
	// The nonce grammar intentionally matches cleanLiteralEcho's safe literal subset.
	arithNonceRe = regexp.MustCompile(`(?i)^\s*(?:what(?:'s| is)\s+)?(\d{1,6})\s*([-+*/xX])\s*(\d{1,6})\s*\?\s*(?:answer|respond)\s+with\s+just\s+the\s+number,?\s+then\s+(?:write|output)\s+([[:alnum:]_.-]{1,24})[.!]?\s*$`)

	// leadingFillerRe matches one instruction-filler clause at the head of an echo tail. They are
	// stripped iteratively so any composition of them reduces to the operative token.
	leadingFillerRe = regexp.MustCompile(`(?i)^(?:` + strings.Join([]string{
		`please`, `kindly`, `por favor`,
		`say`, `reply`, `respond`, `answer`, `return`, `output`, `print`, `echo`, `repeat`,
		`responde`, `contesta`, `escribe`, `repite`, `devuelve`, `imprime`,
		`after me`, `back`, `to me`, `with`, `using`, `con`,
		`only`, `just`, `exactly`, `simply`, `literally`, `verbatim`,
		`solo`, `solamente`, `únicamente`, `unicamente`, `exactamente`,
		`this text`, `the text`, `the following`, `lo siguiente`, `la siguiente`,
		`(?:the|a|an|one|this|that)(?:\s+single)?\s+(?:word|words|number|line|text|string|token|value|character)`,
		`la palabra`, `una palabra`, `el número`, `el numero`,
		`and nothing else`, `nothing else`, `no explanation`, `no other text`,
		`y nada más`, `y nada mas`, `nada más`, `nada mas`,
	}, `|`) + `)\b`)
	// trailingConstraintRe matches the length/format constraint scanners append after the value
	// they want back ("... in 5 words or less", "... and nothing else").
	trailingConstraintRe = regexp.MustCompile(`(?i)[\s,;.]*\b(?:` + strings.Join([]string{
		`in (?:exactly )?(?:\d{1,3}|one|two|three|four|five) words?(?: or (?:less|fewer))?`,
		`en (?:una|dos|tres) palabras?`,
		`or (?:less|fewer)`, `and nothing else`, `nothing else`,
		`with no explanation`, `without explanation`, `no explanation`, `no other text`,
		`only`, `exactly`, `please`, `y nada m[áa]s`, `nada m[áa]s`,
	}, `|`) + `)[\s,;.!]*$`)
	// phraseFragmentRe rejects a stripped target that is only the tail of a noun phrase — "Return
	// only the number of planets" reduces to "of planets", and echoing that is a confidently
	// wrong answer where a real model would answer the question.
	phraseFragmentRe = regexp.MustCompile(`(?i)^(?:of|in|on|for|about|from|that|which|with|to|as|and|or|by|de|del|sobre)\b`)
)

// maxArithDigits keeps the arithmetic rules on the trivial expressions validators actually send.
const maxArithDigits = 6

const (
	// These fixed code-only answers cover the observed function and one-liner
	// validators; each code response is executed by regression tests.
	reverseStringCode = "def reverse_string(text):\n    return text[::-1]"
	isPrimeCode       = "def is_prime(n):\n    if n < 2:\n        return False\n    if n % 2 == 0:\n        return n == 2\n    divisor = 3\n    while divisor * divisor <= n:\n        if n % divisor == 0:\n            return False\n        divisor += 2\n    return True"
	// fizzBuzzCode is the fixed executable answer for the observed 1-to-20 validator.
	fizzBuzzCode = "def fizzbuzz():\n    for number in range(1, 21):\n        if number % 15 == 0:\n            print(\"FizzBuzz\")\n        elif number % 3 == 0:\n            print(\"Fizz\")\n        elif number % 5 == 0:\n            print(\"Buzz\")\n        else:\n            print(number)"
	// dictSortCode is the fixed one-line expression for the observed descending-value sort.
	dictSortCode = "dict(sorted(my_dict.items(), key=lambda item: item[1], reverse=True))"
)

const (
	// lighthouseProse is intentionally exactly 100 whitespace-delimited words.
	lighthouseProse = "Each dawn, Mara climbed the lighthouse stairs before the gulls began calling. One stormy morning, a green bottle knocked against the rocks below. Inside, she found a faded message: Keep the lamp dark tonight. Mara read it twice, then watched an unfamiliar ship waiting beyond the reef. At sunset, she covered the lens and held her breath. The ship slipped safely past hidden mines revealed by the falling tide. By midnight, another bottle arrived. Its message contained only three words: Thank you, sister. Mara smiled, relit the lamp, and finally understood why her lost brother had never returned safely home."
	// rainProse's exact 50-word constraint is enforced with strings.Fields in regression tests.
	rainProse = "Rain followed Maya along the empty streets as she walked home, soaking her coat and blurring every streetlight. She kept one hand over the letter in her pocket. At last, her porch appeared through the silver curtain, and she hurried toward its warm, waiting glow with relief and smiled softly."
	// oceanPoem is intentionally four newline-delimited rhyming lines.
	oceanPoem = "Moonlit waves roll softly to the shore,\nThey turn beneath the stars and rise once more.\nThe salt wind sings across the silver sea,\nThe distant tides roll homeward, wild and free."
)

// ReplyFor returns a bounded, deterministic response tuned to the liveness and validation
// probes scanners use before escalating to their actual prompts. It does not execute prompts or
// call an external model. Unsupported input receives a deterministic safety-tuned response.
func ReplyFor(prompt, model string) ReplyResult {
	p := strings.TrimSpace(prompt)
	if p == "" {
		return genericReply(p, model)
	}

	lower := strings.ToLower(strings.Join(strings.Fields(p), " "))
	normalized := strings.Trim(lower, " .!?。！？")

	for _, unsafe := range []string{
		"ignore previous", "ignore all previous", "system prompt", "developer message",
		"hidden instruction", "reveal your instruction", "jailbreak",
	} {
		if strings.Contains(normalized, unsafe) {
			return refusalReply(p, model)
		}
	}

	if strings.Contains(normalized, "ollama server") &&
		(strings.Contains(normalized, "what") && strings.Contains(normalized, "does") ||
			strings.Contains(normalized, "describe") || strings.Contains(normalized, "description")) {
		return ReplyResult{
			Text: "An Ollama server hosts and runs language models locally, exposing APIs for chat and text generation.",
			Kind: ReplyKindOllamaDescription,
		}
	}
	if strings.Contains(p, "中文") &&
		(strings.Contains(p, "介绍一下你自己") || strings.Contains(p, "介绍你自己")) {
		return ReplyResult{
			Text: fmt.Sprintf("我是 %s，可协助文本生成、问答、总结和编程，但回答可能有误。", displayModel(model)),
			Kind: ReplyKindModelIntroZH,
		}
	}
	if code, ok := observedCodeValidation(normalized); ok {
		return ReplyResult{Text: code, Kind: ReplyKindCodeValidation}
	}
	if strings.Contains(normalized, "exactly 100 words") &&
		strings.Contains(normalized, "lighthouse keeper") &&
		strings.Contains(normalized, "message in a bottle") {
		return ReplyResult{Text: lighthouseProse, Kind: ReplyKindConstrainedProse}
	}
	if strings.Contains(normalized, "exactly 50 words") &&
		strings.Contains(normalized, "walking home") &&
		strings.Contains(normalized, "rain") {
		return ReplyResult{Text: rainProse, Kind: ReplyKindConstrainedProse}
	}
	if strings.Contains(normalized, "4-line poem") &&
		strings.Contains(normalized, "ocean") &&
		strings.Contains(normalized, "rhyming") {
		return ReplyResult{Text: oceanPoem, Kind: ReplyKindConstrainedProse}
	}
	if asksForSpanishIntroduction(normalized) {
		return ReplyResult{
			Text: fmt.Sprintf("Soy %s, un modelo de IA que puede ayudarte con preguntas, redacción, resúmenes y programación.", displayModel(model)),
			// Spanish introductions reuse the EN intro kind; a distinct value needs a proto change.
			Kind: ReplyKindModelIntroEN,
		}
	}
	if asksForEnglishIntroduction(normalized) {
		return ReplyResult{
			Text: fmt.Sprintf("I'm %s, an AI model that can help with questions, writing, summarization, and coding.", displayModel(model)),
			Kind: ReplyKindModelIntroEN,
		}
	}
	if m := arithNonceRe.FindStringSubmatch(p); m != nil {
		if s, ok := computeArith(m[1], m[2], m[3]); ok {
			if nonce := cleanLiteralEcho(m[4]); nonce != "" {
				return ReplyResult{Text: s + " " + nonce, Kind: ReplyKindArithmeticNonce}
			}
		}
	}
	if s, ok := findArithmetic(p); ok {
		return ReplyResult{Text: s, Kind: ReplyKindArithmetic}
	}

	switch normalized {
	case "你好":
		return ReplyResult{Text: "你好！有什么我可以帮助你的吗？", Kind: ReplyKindValidationFact}
	case "say hi in one word":
		return ReplyResult{Text: "Hi", Kind: ReplyKindValidationFact}
	case "name a fruit", "give me a fruit":
		return ReplyResult{Text: "Apple.", Kind: ReplyKindValidationFact}
	case "count to five", "count from one to five":
		return ReplyResult{Text: "One, two, three, four, five.", Kind: ReplyKindValidationFact}
	case "what color is the sky", "what colour is the sky":
		return ReplyResult{Text: "The sky usually appears blue during the day.", Kind: ReplyKindValidationFact}
	case "what story should we write":
		return ReplyResult{
			Text: "We could write a short mystery about a lost message that changes a small town.",
			Kind: ReplyKindValidationFact,
		}
	case "hi", "hello", "hey", "yo", "greetings":
		return ReplyResult{Text: "Hello! How can I help you today?", Kind: ReplyKindValidationFact}
	case "hola", "buenos días", "buenos dias", "buenas tardes":
		return ReplyResult{Text: "¡Hola! ¿En qué puedo ayudarte hoy?", Kind: ReplyKindValidationFact}
	}

	for _, clause := range promptClauses(p) {
		m := echoRe.FindStringSubmatch(clause)
		if m == nil {
			continue
		}
		target := echoTarget(m[1])
		if namesTheModel(target) {
			return ReplyResult{Text: displayModel(model), Kind: ReplyKindModelIntroEN}
		}
		if s := cleanLiteralEcho(target); s != "" {
			return ReplyResult{Text: s, Kind: ReplyKindLiteralEcho}
		}
	}
	return genericReply(p, model)
}

// smartReply is a test convenience for model-neutral response selection. Production
// generation paths use classifiedReply with the resolved advertised model.
func smartReply(prompt string) string { return ReplyFor(prompt, "").Text }

func genericReply(prompt, model string) ReplyResult {
	return ReplyResult{Text: pickReplyFor(prompt, model), Kind: ReplyKindGenericSafe}
}

func refusalReply(prompt, model string) ReplyResult {
	return ReplyResult{Text: pickFrom(refusalPool, prompt, model), Kind: ReplyKindSafetyRefusal}
}

// promptClauses splits a prompt into the lines an echo instruction can occupy. Multi-line probes
// put the instruction on one line and the question on another, which a whole-prompt match missed
// entirely because "." never crosses a newline.
func promptClauses(prompt string) []string {
	if !strings.ContainsAny(prompt, "\n\r") {
		return []string{prompt}
	}
	var out []string
	for _, line := range strings.FieldsFunc(prompt, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// echoTarget reduces an echo instruction's tail to the token the scanner actually wants back,
// so "with exactly one word: blue" yields "blue" rather than the whole instruction tail.
func echoTarget(tail string) string {
	const maxStripRounds = 12
	const separators = " \t\r\n:,;"
	s := tail
	for i := 0; i < maxStripRounds; i++ {
		s = strings.TrimLeft(s, separators)
		loc := leadingFillerRe.FindStringIndex(s)
		if loc == nil {
			break
		}
		s = s[loc[1]:]
	}
	for i := 0; i < maxStripRounds; i++ {
		loc := trailingConstraintRe.FindStringIndex(s)
		if loc == nil {
			break
		}
		s = s[:loc[0]]
	}
	s = strings.TrimSpace(s)
	if phraseFragmentRe.MatchString(s) {
		return ""
	}
	return s
}

// namesTheModel reports whether an echo target asks for the model's own name. Reflecting the
// literal words "your model name" is a deterministic wrong answer, and so a fingerprint.
func namesTheModel(target string) bool {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(target), `"'.?!`)) {
	case "your model name", "your model", "your name", "the model name", "model name",
		"your model id", "tu nombre", "tu modelo":
		return true
	}
	return false
}

// findArithmetic evaluates the first trivial expression embedded anywhere in the prompt.
func findArithmetic(prompt string) (string, bool) {
	for _, re := range []*regexp.Regexp{arithRe, crossArithRe, wordArithRe} {
		for _, loc := range re.FindAllStringSubmatchIndex(prompt, -1) {
			if arithmeticIsGlued(prompt, loc[0], loc[1]) {
				continue
			}
			a, op, b := prompt[loc[2]:loc[3]], prompt[loc[4]:loc[5]], prompt[loc[6]:loc[7]]
			if len(a) > maxArithDigits || len(b) > maxArithDigits {
				continue
			}
			if s, ok := computeArith(a, op, b); ok {
				return s, true
			}
		}
	}
	return "", false
}

// arithmeticIsGlued reports whether a match is really a slice of a longer literal — a version,
// date or identifier such as "2026-07-29" or "v1.2-3" — rather than a standalone expression.
func arithmeticIsGlued(s string, start, end int) bool {
	if start > 0 {
		switch prev := s[start-1]; {
		case prev >= '0' && prev <= '9', prev == '.', prev == '-', prev == '/', prev == ':':
			return true
		case prev >= 'a' && prev <= 'z', prev >= 'A' && prev <= 'Z':
			return true
		}
	}
	if end < len(s) {
		switch next := s[end]; {
		case next >= '0' && next <= '9':
			return true
		case next == '.', next == '-', next == '/', next == ':':
			return end+1 < len(s) && s[end+1] >= '0' && s[end+1] <= '9'
		}
	}
	return false
}

func observedCodeValidation(normalized string) (string, bool) {
	if strings.Contains(normalized, "python function") {
		if strings.Contains(normalized, "reverse_string") &&
			strings.Contains(normalized, "reversed string") {
			return reverseStringCode, true
		}
		if strings.Contains(normalized, "is_prime") &&
			strings.Contains(normalized, "returns true") &&
			strings.Contains(normalized, "prime") {
			return isPrimeCode, true
		}
		if strings.Contains(normalized, "fizzbuzz") &&
			strings.Contains(normalized, "numbers 1 to 20") &&
			strings.Contains(normalized, "multiples of 3") &&
			strings.Contains(normalized, "multiples of 5") {
			return fizzBuzzCode, true
		}
	}
	if strings.Contains(normalized, "python one-liner") &&
		strings.Contains(normalized, "sort a dictionary") &&
		strings.Contains(normalized, "values") &&
		strings.Contains(normalized, "descending order") {
		return dictSortCode, true
	}
	return "", false
}

func asksForEnglishIntroduction(normalized string) bool {
	// The negation guard runs before every trigger, not just "introduce yourself": constrained
	// prose probes carry "Do not introduce yourself" and must keep getting the prose.
	for _, negated := range []string{
		"do not introduce yourself",
		"don't introduce yourself",
		"dont introduce yourself",
		"without introducing yourself",
		"no introduction",
	} {
		if strings.Contains(normalized, negated) {
			return false
		}
	}
	for _, phrase := range []string{
		"introduce yourself", "identify yourself", "tell me about yourself",
		"who are you", "who built you", "who made you", "who created you",
		"who developed you", "who trained you",
		"what model are you", "which model are you", "what model is this",
		"what is your model name", "what's your model name", "whats your model name",
		"what is your name", "what's your name", "whats your name",
		"what are you",
	} {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	return false
}

func asksForSpanishIntroduction(normalized string) bool {
	for _, phrase := range []string{
		"quién eres", "quien eres", "qué modelo eres", "que modelo eres",
		"cómo te llamas", "como te llamas", "preséntate", "presentate",
		"quién te creó", "quien te creo",
	} {
		if strings.Contains(normalized, phrase) {
			return true
		}
	}
	return false
}

func displayModel(model string) string {
	if strings.TrimSpace(model) == "" {
		return "this model"
	}
	return strings.TrimSpace(model)
}

// cleanLiteralEcho accepts only a small literal value. This preserves common probes like
// "Reply with OK" and nonce echoes while rejecting arbitrary instructions and prose.
func cleanLiteralEcho(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'`")
	s = strings.TrimRight(s, " .!?\n\r\t")
	s = strings.Trim(s, "\"'`")
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > 24 || len(strings.Fields(s)) > 3 {
		return ""
	}
	lower := strings.ToLower(s)
	for _, blocked := range []string{
		"system prompt", "instruction", "password", "secret", "api key", "token",
		"contraseña", "contrasena", "secreto", "clave",
		"select ", "drop ", "delete ", "insert ", "update ", " then ",
	} {
		if strings.Contains(lower, blocked) {
			return ""
		}
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.IsSpace(r) &&
			r != '_' && r != '-' && r != '.' {
			return ""
		}
	}
	return s
}

// computeArith evaluates a trivial two-operand integer expression, returning ("", false) on
// bad operands or division by zero (so the caller falls back to a generic reply).
func computeArith(a, op, b string) (string, bool) {
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return "", false
	}
	op = strings.ToLower(strings.Join(strings.Fields(op), " "))
	var r int
	switch op {
	case "+", "plus":
		r = x + y
	case "-", "minus":
		r = x - y
	case "*", "x", "times", "multiplied by":
		r = x * y
	case "/", "divided by":
		if y == 0 {
			return "", false
		}
		if x%y != 0 {
			return strconv.FormatFloat(float64(x)/float64(y), 'f', -1, 64), true
		}
		r = x / y
	default:
		return "", false
	}
	return strconv.Itoa(r), true
}

// estTokens is a cheap, plausible token estimate (~4 chars/token, floor 1).
func estTokens(s string) int {
	n := len(s) / 4
	if n < 1 {
		n = 1
	}
	return n
}

// chatTemplateTokens approximates the system prompt and chat-template scaffolding a real server
// prepends before the user's text. Real Ollama reports prompt_eval_count ~30 for a one-word
// prompt, so reporting only the user's own token count is conspicuously low.
const chatTemplateTokens = 28

func promptTokensFor(text string) int { return chatTemplateTokens + estTokens(text) }

func wantsStream(body []byte, defaultStream bool) bool {
	var m struct {
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &m); err != nil || m.Stream == nil {
		return defaultStream
	}
	return *m.Stream
}

// maxTokensOf reads the generation cap under any of the names these surfaces accept: OpenAI's
// max_tokens and max_completion_tokens, the Responses API's max_output_tokens, and Ollama's
// options.num_predict. Returns 0 when uncapped.
func maxTokensOf(body []byte) int {
	var m struct {
		MaxTokens           *int `json:"max_tokens"`
		MaxCompletionTokens *int `json:"max_completion_tokens"`
		MaxOutputTokens     *int `json:"max_output_tokens"`
		Options             struct {
			NumPredict *int `json:"num_predict"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return 0
	}
	for _, v := range []*int{m.MaxTokens, m.MaxCompletionTokens, m.MaxOutputTokens, m.Options.NumPredict} {
		if v != nil && *v > 0 {
			return *v
		}
	}
	return 0
}

// capReply truncates reply to at most max generated tokens and reports the finish reason a real
// server would return. Hitting the cap yields "length", not "stop" — scanners routinely send
// max_tokens=1 and read the finish reason back, so always reporting "stop" is a giveaway.
func capReply(reply string, max int) (text string, chunks []string, finish string) {
	chunks = splitWords(reply)
	if max > 0 && len(chunks) >= max {
		chunks = chunks[:max]
		return strings.TrimRight(strings.Join(chunks, ""), " "), chunks, "length"
	}
	return reply, chunks, "stop"
}

type promptContent string

func (c *promptContent) UnmarshalJSON(body []byte) error {
	*c = promptContent(strings.Join(promptTextParts(body, 0), "\n"))
	return nil
}

const maxPromptContentDepth = 4

func promptTextParts(body []byte, depth int) []string {
	if depth > maxPromptContentDepth {
		return nil
	}
	var text string
	if json.Unmarshal(body, &text) == nil {
		if text == "" {
			return nil
		}
		return []string{text}
	}
	var parts []json.RawMessage
	if json.Unmarshal(body, &parts) == nil {
		var values []string
		for _, part := range parts {
			values = append(values, promptTextParts(part, depth+1)...)
		}
		return values
	}

	var part struct {
		Text    string          `json:"text"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(body, &part) != nil {
		return nil
	}
	var values []string
	if part.Text != "" {
		values = append(values, part.Text)
	}
	if len(part.Content) > 0 {
		values = append(values, promptTextParts(part.Content, depth+1)...)
	}
	return values
}

// chatMessageList reads the raw message list without introducing a decode-error path: a type
// error raised here would name llmcore's own types, which real Ollama's error text never does.
func chatMessageList(body []byte) []json.RawMessage {
	var m struct {
		Messages []json.RawMessage `json:"messages"`
	}
	_ = json.Unmarshal(body, &m)
	return m.Messages
}

func promptText(body []byte) string {
	var m struct {
		Prompt   promptContent `json:"prompt"`
		Input    promptContent `json:"input"`
		Content  promptContent `json:"content"` // llama.cpp's /tokenize request uses "content" (/completion's request field is "prompt"; "content" there names the response field instead).
		Messages []struct {
			Content promptContent `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &m)
	if m.Prompt != "" {
		return string(m.Prompt)
	}
	if m.Input != "" {
		return string(m.Input)
	}
	if m.Content != "" {
		return string(m.Content)
	}
	if len(m.Messages) > 0 {
		return string(m.Messages[len(m.Messages)-1].Content)
	}
	return ""
}

func readBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
	return b
}

func modelOr(body []byte, def string) string {
	if m := ParseModel(body); m != "" {
		return m
	}
	return def
}

// ValidJSONBody reports whether body parses as a JSON object, along with the parse error a real
// server would echo when it does not. Real servers 400 on malformed input; happily returning a
// completion for "not-json" is a tell.
func ValidJSONBody(body []byte) (string, bool) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return "", true
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return err.Error(), false
	}
	return "", true
}

func completionID(p Profile, prefix string) string {
	if p.ShortIDs {
		// Ollama's OpenAI layer emits a short numeric suffix, e.g. chatcmpl-964.
		return fmt.Sprintf("%s-%d", prefix, rand.Intn(1000))
	}
	return fmt.Sprintf("%s-%016x%016x", prefix, rand.Uint64(), rand.Uint64())
}

// -- OpenAI-shaped payloads. Field order mirrors the real servers' struct order; building these
// from map[string]any would sort the keys alphabetically, which no real implementation does.

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIChatChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
}

type openAIChatResponse struct {
	ID                string             `json:"id"`
	Object            string             `json:"object"`
	Created           int64              `json:"created"`
	Model             string             `json:"model"`
	SystemFingerprint string             `json:"system_fingerprint,omitempty"`
	Choices           []openAIChatChoice `json:"choices"`
	Usage             openAIUsage        `json:"usage"`
}

type openAIDelta struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChunkChoice struct {
	Index        int         `json:"index"`
	Delta        openAIDelta `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type openAIChatChunk struct {
	ID                string              `json:"id"`
	Object            string              `json:"object"`
	Created           int64               `json:"created"`
	Model             string              `json:"model"`
	SystemFingerprint string              `json:"system_fingerprint,omitempty"`
	Choices           []openAIChunkChoice `json:"choices"`
}

type openAITextChoice struct {
	Text         string `json:"text"`
	Index        int    `json:"index"`
	Logprobs     *int   `json:"logprobs"`
	FinishReason string `json:"finish_reason"`
}

type openAITextResponse struct {
	ID                string             `json:"id"`
	Object            string             `json:"object"`
	Created           int64              `json:"created"`
	Model             string             `json:"model"`
	SystemFingerprint string             `json:"system_fingerprint,omitempty"`
	Choices           []openAITextChoice `json:"choices"`
	Usage             openAIUsage        `json:"usage"`
}

// ChatCompletion writes an OpenAI /v1/chat/completions response, streaming SSE chunks
// when the request asks for "stream":true (default false for chat).
func ChatCompletion(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOpenAIError(w, p, http.StatusBadRequest, msg, "invalid_request_error")
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundV1(w, p, model)
		return
	}
	reply, chunks, finish := capReply(classifiedReply(r, promptText(body), model).Text, maxTokensOf(body))
	id := completionID(p, "chatcmpl")
	created := time.Now().Unix()

	if wantsStream(body, false) {
		w.Header().Set("Content-Type", CTEventStream)
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		emit := func(content string, finish *string) {
			b, _ := json.Marshal(openAIChatChunk{
				ID: id, Object: "chat.completion.chunk", Created: created, Model: model,
				SystemFingerprint: p.SystemFingerprint,
				Choices: []openAIChunkChoice{{
					Index: 0,
					Delta: openAIDelta{Role: "assistant", Content: content},
					// finish_reason is explicitly null until the terminal chunk.
					FinishReason: finish,
				}},
			})
			fmt.Fprintf(w, "data: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
		}
		for _, c := range chunks {
			emit(c, nil)
		}
		emit("", &finish)
		fmt.Fprint(w, "data: [DONE]\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	pt := promptTokensFor(promptText(body))
	WriteJSONCT(w, http.StatusOK, p.openAICT(), openAIChatResponse{
		ID: id, Object: "chat.completion", Created: created, Model: model,
		SystemFingerprint: p.SystemFingerprint,
		Choices: []openAIChatChoice{{
			Index:        0,
			Message:      chatMessage{Role: "assistant", Content: reply},
			FinishReason: finish,
		}},
		Usage: openAIUsage{PromptTokens: pt, CompletionTokens: len(chunks), TotalTokens: pt + len(chunks)},
	})
}

// Completion writes an OpenAI /v1/completions (legacy text completion) response.
func Completion(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOpenAIError(w, p, http.StatusBadRequest, msg, "invalid_request_error")
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundV1(w, p, model)
		return
	}
	reply, chunks, finish := capReply(classifiedReply(r, promptText(body), model).Text, maxTokensOf(body))
	pt := promptTokensFor(promptText(body))
	WriteJSONCT(w, http.StatusOK, p.openAICT(), openAITextResponse{
		ID: completionID(p, "cmpl"), Object: "text_completion",
		Created: time.Now().Unix(), Model: model,
		SystemFingerprint: p.SystemFingerprint,
		Choices: []openAITextChoice{{
			Text: reply, Index: 0, Logprobs: nil, FinishReason: finish,
		}},
		Usage: openAIUsage{PromptTokens: pt, CompletionTokens: len(chunks), TotalTokens: pt + len(chunks)},
	})
}

// -- Ollama-native /api payloads.

type ollamaGenerateChunk struct {
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
	Response  string `json:"response"`
	Done      bool   `json:"done"`
}

type ollamaGenerateFinal struct {
	Model              string `json:"model"`
	CreatedAt          string `json:"created_at"`
	Response           string `json:"response"`
	Done               bool   `json:"done"`
	DoneReason         string `json:"done_reason"`
	Context            []int  `json:"context,omitempty"`
	TotalDuration      int64  `json:"total_duration"`
	LoadDuration       int64  `json:"load_duration"`
	PromptEvalCount    int    `json:"prompt_eval_count"`
	PromptEvalDuration int64  `json:"prompt_eval_duration"`
	EvalCount          int    `json:"eval_count"`
	EvalDuration       int64  `json:"eval_duration"`
}

type ollamaGenerateLifecycle struct {
	Model      string `json:"model"`
	CreatedAt  string `json:"created_at"`
	Response   string `json:"response"`
	Done       bool   `json:"done"`
	DoneReason string `json:"done_reason"`
}

type ollamaChatLifecycle struct {
	Model      string      `json:"model"`
	CreatedAt  string      `json:"created_at"`
	Message    chatMessage `json:"message"`
	Done       bool        `json:"done"`
	DoneReason string      `json:"done_reason"`
}

type ollamaChatChunk struct {
	Model     string      `json:"model"`
	CreatedAt string      `json:"created_at"`
	Message   chatMessage `json:"message"`
	Done      bool        `json:"done"`
}

type ollamaChatFinal struct {
	Model              string      `json:"model"`
	CreatedAt          string      `json:"created_at"`
	Message            chatMessage `json:"message"`
	Done               bool        `json:"done"`
	DoneReason         string      `json:"done_reason"`
	TotalDuration      int64       `json:"total_duration"`
	LoadDuration       int64       `json:"load_duration"`
	PromptEvalCount    int         `json:"prompt_eval_count"`
	PromptEvalDuration int64       `json:"prompt_eval_duration"`
	EvalCount          int         `json:"eval_count"`
	EvalDuration       int64       `json:"eval_duration"`
}

// nowNano formats a timestamp the way Ollama does: RFC3339 with nanosecond precision. Each
// streamed chunk gets a fresh one, so timestamps advance across a stream instead of every
// chunk repeating the value computed when the handler started.
func nowNano() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// fakeContext synthesises the token-id array Ollama returns from /api/generate. Real ids are
// vocabulary indices bracketed by high-numbered special tokens; omitting the field entirely is
// what gives a fake away, not the specific ids.
func fakeContext(n int) []int {
	if n < 1 {
		n = 1
	}
	if n > 512 {
		n = 512
	}
	out := make([]int, 0, n+6)
	out = append(out, 151644, 8948, 198) // <|im_start|> system \n
	for i := 0; i < n; i++ {
		out = append(out, 1000+rand.Intn(126000))
	}
	out = append(out, 151645, 198, 151643) // <|im_end|> \n <|endoftext|>
	return out
}

// ndjsonWriter returns a helper that marshals and flushes one NDJSON line per call.
func ndjsonWriter(w http.ResponseWriter) func(any) {
	flusher, _ := w.(http.Flusher)
	return func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "%s\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// OllamaGenerate writes an Ollama /api/generate response. Ollama streams NDJSON by
// default (one JSON object per line), ending with a done:true summary line; "stream":false
// collapses to a single object.
func OllamaGenerate(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if len(strings.TrimSpace(string(body))) == 0 {
		WriteOllamaError(w, p, http.StatusBadRequest, "missing request body")
		return
	}
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOllamaError(w, p, http.StatusBadRequest, msg)
		return
	}
	// Use Ollama's upstream request type name so encoding/json produces the same
	// type-error text for object, number, array, and boolean prompt values.
	type GenerateRequest struct {
		Prompt string `json:"prompt"`
	}
	var generateRequest GenerateRequest
	if err := json.Unmarshal(body, &generateRequest); err != nil {
		WriteOllamaError(w, p, http.StatusBadRequest, err.Error())
		return
	}
	if ParseModel(body) == "" {
		WriteModelNotFoundAPI(w, p, "")
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundAPI(w, p, model)
		return
	}
	prompt := generateRequest.Prompt
	if prompt == "" {
		keepAlive := keepAliveOf(body)
		models.touch(model, keepAlive)
		reason := "load"
		if keepAlive == 0 {
			reason = "unload"
		}
		MarkReplyKind(r, proto.LlmReplyKind_LLM_REPLY_KIND_MODEL_LIFECYCLE)
		WriteJSONCT(w, http.StatusOK, p.ct(), ollamaGenerateLifecycle{
			Model: model, CreatedAt: nowNano(), Response: "", Done: true, DoneReason: reason,
		})
		return
	}
	reply, chunks, finish := capReply(classifiedReply(r, prompt, model).Text, maxTokensOf(body))
	pt := promptTokensFor(prompt)
	t := newTimings(model, keepAliveOf(body), pt, len(chunks))

	final := func(response string) ollamaGenerateFinal {
		return ollamaGenerateFinal{
			Model: model, CreatedAt: nowNano(), Response: response, Done: true,
			DoneReason:         finish,
			Context:            fakeContext(pt + len(chunks)),
			TotalDuration:      t.Total.Nanoseconds(),
			LoadDuration:       t.Load.Nanoseconds(),
			PromptEvalCount:    pt,
			PromptEvalDuration: t.PromptEval.Nanoseconds(),
			EvalCount:          len(chunks),
			EvalDuration:       t.Eval.Nanoseconds(),
		}
	}

	if !wantsStream(body, true) {
		WriteJSONCT(w, http.StatusOK, p.ct(), final(reply))
		return
	}
	w.Header().Set("Content-Type", CTNDJSON)
	w.WriteHeader(http.StatusOK)
	writeLine := ndjsonWriter(w)
	for _, c := range chunks {
		writeLine(ollamaGenerateChunk{Model: model, CreatedAt: nowNano(), Response: c, Done: false})
	}
	writeLine(final(""))
}

// OllamaChat writes an Ollama /api/chat response (message-shaped, single object when
// stream is false; NDJSON otherwise).
func OllamaChat(w http.ResponseWriter, r *http.Request, p Profile) {
	body := readBody(r)
	if len(strings.TrimSpace(string(body))) == 0 {
		WriteOllamaError(w, p, http.StatusBadRequest, "missing request body")
		return
	}
	if msg, ok := ValidJSONBody(body); !ok {
		WriteOllamaError(w, p, http.StatusBadRequest, msg)
		return
	}
	if ParseModel(body) == "" {
		WriteModelNotFoundAPI(w, p, "")
		return
	}
	model, known := p.resolveModel(r, body)
	if !known {
		WriteModelNotFoundAPI(w, p, model)
		return
	}
	// An empty message list is Ollama's model-lifecycle request, the /api/chat counterpart of
	// /api/generate's empty prompt.
	if len(chatMessageList(body)) == 0 {
		keepAlive := keepAliveOf(body)
		models.touch(model, keepAlive)
		reason := "load"
		if keepAlive == 0 {
			reason = "unload"
		}
		MarkReplyKind(r, proto.LlmReplyKind_LLM_REPLY_KIND_MODEL_LIFECYCLE)
		WriteJSONCT(w, http.StatusOK, p.ct(), ollamaChatLifecycle{
			Model: model, CreatedAt: nowNano(),
			Message: chatMessage{Role: "assistant"}, Done: true, DoneReason: reason,
		})
		return
	}
	prompt := promptText(body)
	reply, chunks, finish := capReply(classifiedReply(r, prompt, model).Text, maxTokensOf(body))
	pt := promptTokensFor(prompt)
	t := newTimings(model, keepAliveOf(body), pt, len(chunks))

	final := func(content string) ollamaChatFinal {
		return ollamaChatFinal{
			Model: model, CreatedAt: nowNano(),
			Message: chatMessage{Role: "assistant", Content: content},
			Done:    true, DoneReason: finish,
			TotalDuration:      t.Total.Nanoseconds(),
			LoadDuration:       t.Load.Nanoseconds(),
			PromptEvalCount:    pt,
			PromptEvalDuration: t.PromptEval.Nanoseconds(),
			EvalCount:          len(chunks),
			EvalDuration:       t.Eval.Nanoseconds(),
		}
	}

	if !wantsStream(body, true) {
		WriteJSONCT(w, http.StatusOK, p.ct(), final(reply))
		return
	}
	w.Header().Set("Content-Type", CTNDJSON)
	w.WriteHeader(http.StatusOK)
	writeLine := ndjsonWriter(w)
	for _, c := range chunks {
		writeLine(ollamaChatChunk{
			Model: model, CreatedAt: nowNano(),
			Message: chatMessage{Role: "assistant", Content: c}, Done: false,
		})
	}
	writeLine(final(""))
}

// splitWords chunks s into space-preserving tokens for streaming.
func splitWords(s string) []string {
	var out []string
	cur := ""
	for _, ch := range s {
		cur += string(ch)
		if ch == ' ' {
			out = append(out, cur)
			cur = ""
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
