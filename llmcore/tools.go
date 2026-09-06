package llmcore

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// Tool support is a deterministic protocol simulation, not an execution engine.
// A client may execute emitted calls, so arguments are bounded benign values:
// weather locations and a constant database connectivity query only. Never emit
// attacker SQL, shell commands, paths, URLs, or instructions from descriptions.
// See docs/tool-response-policy.md for the intentionally supported schema subset.
type toolFunction struct {
	Index     *int   `json:"index,omitempty"` // native Ollama stream index
	Name      string `json:"name"`
	Arguments any    `json:"arguments"`
}

type toolCall struct {
	Index    *int         `json:"index,omitempty"` // OpenAI stream index
	ID       string       `json:"id,omitempty"`
	Type     string       `json:"type,omitempty"`
	Function toolFunction `json:"function"`
}

type requestedTool struct {
	Type     string `json:"type"`
	Function struct {
		Name       string          `json:"name"`
		Parameters json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type toolPlan struct {
	call  *toolCall
	text  string
	kind  proto.LlmReplyKind
	error string
}

func planToolReply(body []byte, base ReplyResult) *toolPlan {
	var request struct {
		Tools      []requestedTool `json:"tools"`
		ToolChoice json.RawMessage `json:"tool_choice"`
		Messages   []struct {
			Role    string        `json:"role"`
			Content promptContent `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &request) != nil || len(request.Tools) == 0 {
		return nil
	}
	choice, named := "auto", ""
	if len(request.ToolChoice) != 0 && string(request.ToolChoice) != "null" {
		if json.Unmarshal(request.ToolChoice, &choice) != nil {
			var option struct {
				Type     string `json:"type"`
				Function struct {
					Name string `json:"name"`
				} `json:"function"`
			}
			if json.Unmarshal(request.ToolChoice, &option) != nil || option.Type != "function" || option.Function.Name == "" {
				return &toolPlan{error: "invalid tool_choice"}
			}
			choice, named = "required", option.Function.Name
		}
	}
	if choice == "none" {
		return nil
	}
	if choice != "auto" && choice != "required" {
		return &toolPlan{error: "invalid tool_choice"}
	}
	refuse := &toolPlan{text: "I can't make that tool call. I can help with a weather lookup or a read-only database connectivity check.", kind: proto.LlmReplyKind_LLM_REPLY_KIND_SAFETY_REFUSAL}
	if len(request.Tools) > 32 || len(request.Messages) == 0 {
		return refuse
	}
	// The text responder's safety gate must also win over tool selection. Inspect
	// every message here because a tool-capable conversation includes system text.
	for _, message := range request.Messages {
		p := strings.ToLower(strings.Join(strings.Fields(string(message.Content)), " "))
		for _, denied := range safetyDenylistTerms {
			if strings.Contains(p, denied) {
				return refuse
			}
		}
	}
	last := request.Messages[len(request.Messages)-1]
	if last.Role == "tool" {
		// Terminate the tool turn instead of issuing the same call in a loop. The
		// server has not executed it and does not assert that it succeeded.
		return &toolPlan{text: "The tool result has been received.", kind: proto.LlmReplyKind_LLM_REPLY_KIND_VALIDATION_FACT}
	}
	if last.Role != "user" || base.Kind == ReplyKindSafetyRefusal {
		return nil
	}
	if choice == "auto" && base.Kind != ReplyKindGenericSafe {
		return nil // authored replies and ordinary validators retain precedence
	}
	prompt := promptText(body)
	lower := strings.ToLower(prompt)
	for _, tool := range request.Tools {
		if tool.Type != "function" || (named != "" && named != tool.Function.Name) {
			continue
		}
		args := map[string]any{}
		switch tool.Function.Name {
		case "get_weather":
			if !strings.Contains(lower, "weather") && !strings.Contains(prompt, "天气") {
				continue
			}
			location := weatherLocation(lower)
			if location == "" {
				continue
			}
			unit := "celsius"
			if strings.Contains(lower, "fahrenheit") {
				unit = "fahrenheit"
			}
			args = map[string]any{"location": location, "city": location, "unit": unit}
		case "query_database":
			if !strings.Contains(lower, "sql") && !strings.Contains(lower, "database") && !strings.Contains(lower, "query_database") {
				continue
			}
			// Even requests for user records only get an inert connection probe.
			args = map[string]any{"sql": "SELECT 1", "query": "SELECT 1", "read_only": true}
		default:
			continue
		}
		args, ok := toolArguments(tool.Function.Parameters, args)
		if !ok {
			continue
		}
		encoded, _ := json.Marshal(args)
		if max := maxTokensOf(body); max > 0 && estTokens(string(encoded)) > max {
			return nil // use the normal length-limited text path, never partial JSON
		}
		return &toolPlan{call: &toolCall{Function: toolFunction{Name: tool.Function.Name, Arguments: args}}, kind: proto.LlmReplyKind_LLM_REPLY_KIND_VALIDATION_FACT}
	}
	return refuse
}

func weatherLocation(prompt string) string {
	words := " " + strings.Join(strings.FieldsFunc(prompt, func(r rune) bool { return !unicode.IsLetter(r) }), " ") + " "
	location := ""
	for _, city := range []string{"Paris", "London", "Tokyo", "New York", "San Francisco", "Berlin", "Beijing", "Shanghai", "Shenzhen", "北京", "上海", "深圳", "巴黎"} {
		matches := strings.Contains(words, " "+strings.ToLower(city)+" ")
		if len(city) > 0 && city[0] >= 0x80 {
			matches = strings.Contains(prompt, city)
		}
		if matches {
			if location != "" {
				return "" // a single-call policy must not silently choose between cities
			}
			location = city
		}
	}
	return location
}

// Support flat primitive schemas only. Unknown required properties or schema
// constraints are declined, not filled with guessed values or copied defaults.
func toolArguments(raw json.RawMessage, candidates map[string]any) (map[string]any, bool) {
	var schema struct {
		Type       string                                `json:"type"`
		Properties map[string]map[string]json.RawMessage `json:"properties"`
		Required   []string                              `json:"required"`
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &schema) != nil || json.Unmarshal(raw, &keys) != nil || schema.Type != "object" || len(schema.Properties) == 0 || len(schema.Properties) > 16 {
		return nil, false
	}
	for key := range keys {
		if key != "type" && key != "properties" && key != "required" && key != "additionalProperties" && key != "description" {
			return nil, false
		}
	}
	out := map[string]any{}
	for name, property := range schema.Properties {
		value, known := candidates[name]
		if !known {
			continue
		}
		for key := range property {
			if key != "type" && key != "description" && key != "enum" {
				return nil, false
			}
		}
		var typ string
		if json.Unmarshal(property["type"], &typ) != nil {
			return nil, false
		}
		if _, isString := value.(string); isString && typ != "string" || !isString && typ != "boolean" {
			return nil, false
		}
		if enum, present := property["enum"]; present {
			var values []any
			if json.Unmarshal(enum, &values) != nil {
				return nil, false
			}
			matched := false
			for _, v := range values {
				if encoded, _ := json.Marshal(v); string(encoded) == string(mustJSON(value)) {
					matched = true
				}
			}
			if !matched {
				return nil, false
			}
		}
		out[name] = value
	}
	for _, required := range schema.Required {
		if _, ok := out[required]; !ok {
			return nil, false
		}
	}
	_, location := out["location"]
	_, city := out["city"]
	_, sql := out["sql"]
	_, query := out["query"]
	return out, location || city || sql || query
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func applyToolPlan(r *http.Request, plan *toolPlan) {
	MarkReplyKind(r, plan.kind)
	// Tool plans never claim a corpus rule fired.
	if metadata, _ := r.Context().Value(responseMetadataKey{}).(*responseMetadata); metadata != nil {
		metadata.mu.Lock()
		metadata.ruleID = ""
		metadata.mu.Unlock()
	}
}
