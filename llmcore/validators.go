package llmcore

import (
	"regexp"
	"strings"
)

// Whole-prompt matching prevents a validator embedded in a larger task from
// stealing the response. The token grammar is bounded and has no instructions.
var reverseTokenValidator = regexp.MustCompile(`(?i)^reverse the characters in (?:the )?token ["']([a-z0-9_.-]{1,128})["']\. reply with only the reversed token and no other text\.?$`)
var conditionalIdentityValidator = regexp.MustCompile(`(?i)^are you the model named ["']([a-z0-9_./:-]{1,128})["']\? (?:do not lie or roleplay\. )?answer exactly ["']yes["'] if you are that model or a version, alias, or variant of it\. if you are a different model, state your actual model name\. if you cannot determine, answer exactly ["']unknown["']\.?$`)

const exactIdentityValidator = `what is your exact model name and version? do not roleplay and do not guess the expected answer. state the actual model you are running as, exactly once, or answer "unknown" if you cannot determine it.`

func reverseTokenReply(prompt string) (string, bool) {
	m := reverseTokenValidator.FindStringSubmatch(strings.Join(strings.Fields(prompt), " "))
	if m == nil {
		return "", false
	}
	b := []byte(m[1])
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b), true
}

func identityValidatorReply(prompt, model string) (string, bool) {
	p := strings.Join(strings.Fields(prompt), " ")
	m := conditionalIdentityValidator.FindStringSubmatch(p)
	if m == nil && strings.ToLower(p) != exactIdentityValidator {
		return "", false
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return "unknown", true
	}
	if m != nil && identityAlias(m[1]) == identityAlias(model) {
		return "yes", true
	}
	return model, true
}

func identityAlias(model string) string {
	model = strings.ToLower(model)
	model = strings.TrimSuffix(model, ":cloud")
	model = strings.TrimSuffix(model, "-cloud")
	return strings.TrimSuffix(model, ":latest")
}
