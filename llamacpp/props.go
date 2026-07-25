package llamacpp

import (
	"net/http"

	"github.com/joshrendek/threat.gg-agent/llmcore"
)

// threat_gg-5g1: /props previously advertised chat_template as "{{ .System }}\n{{ .Prompt }}" —
// Go text/template syntax, i.e. Ollama Modelfile format, on a llama.cpp endpoint. Real llama.cpp
// surfaces the model's own chat template (read from the GGUF's tokenizer.chat_template
// metadata), which for any GGUF converted from a Hugging Face chat model is Jinja2. The
// replacement below is the actual published Llama-2-chat template from
// meta-llama/Llama-2-7b-chat-hf's tokenizer_config.json, matching the model this honeypot
// advertises (llama-2-7b-chat.Q4_K_M.gguf).
//
// The rest of the key set is verified against the current server docs:
//
//	github.com/ggml-org/llama.cpp tools/server/README.md, "GET /props: Get server global
//	properties" — documents default_generation_settings{id,id_task,n_ctx,speculative,
//	is_processing,params,prompt,next_token}, total_slots, model_path, chat_template,
//	chat_template_caps, modalities, media_marker, build_info, is_sleeping. The default `params`
//	values below are copied verbatim from that section's example response, since they are the
//	server's stock sampling defaults rather than per-request state.
//
// (The current source additionally emits model_alias, model_ftype, endpoint_slots/props/metrics,
// ui, ui_settings, bos_token, eos_token, cors_proxy_enabled — fields added after the README
// section above was last written. They are left out here rather than guessed at; the README's
// documented set is the citable, verified subset.)

// slotNCtx is the per-slot context size advertised consistently across /props'
// default_generation_settings, /completion's generation_settings, and /slots — a real server
// would not contradict itself between these three endpoints.
const slotNCtx = 4096

// llama2ChatTemplate is copied from meta-llama/Llama-2-7b-chat-hf's tokenizer_config.json
// "chat_template" field (the template Hugging Face's transformers and, downstream, llama.cpp's
// GGUF conversion embed for this model family).
const llama2ChatTemplate = `{% if messages[0]['role'] == 'system' %}{% set loop_messages = messages[1:] %}{% set system_message = messages[0]['content'] %}{% else %}{% set loop_messages = messages %}{% set system_message = false %}{% endif %}{% for message in loop_messages %}{% if (message['role'] == 'user') != (loop.index0 % 2 == 0) %}{{ raise_exception('Conversation roles must alternate user/assistant/user/assistant/...') }}{% endif %}{% if loop.index0 == 0 and system_message != false %}{% set content = '<<SYS>>\n' + system_message + '\n<</SYS>>\n\n' + message['content'] %}{% else %}{% set content = message['content'] %}{% endif %}{% if message['role'] == 'user' %}{{ bos_token + '[INST] ' + content.strip() + ' [/INST]' }}{% elif message['role'] == 'assistant' %}{{ ' '  + content.strip() + ' ' + eos_token }}{% endif %}{% endfor %}`

// propsSamplingParams is the server's stock sampling defaults, field order and values copied
// from the README's example response. Seed is int64: the documented default (4294967295, i.e.
// uint32 max used as "no seed") overflows a 32-bit int, which this agent cross-compiles for
// (armv6l/armv7l) — see the Makefile's arm targets.
type propsSamplingParams struct {
	NPredict            int      `json:"n_predict"`
	Seed                int64    `json:"seed"`
	Temperature         float64  `json:"temperature"`
	DynatempRange       float64  `json:"dynatemp_range"`
	DynatempExponent    float64  `json:"dynatemp_exponent"`
	TopK                int      `json:"top_k"`
	TopP                float64  `json:"top_p"`
	MinP                float64  `json:"min_p"`
	XTCProbability      float64  `json:"xtc_probability"`
	XTCThreshold        float64  `json:"xtc_threshold"`
	TypicalP            float64  `json:"typical_p"`
	RepeatLastN         int      `json:"repeat_last_n"`
	RepeatPenalty       float64  `json:"repeat_penalty"`
	PresencePenalty     float64  `json:"presence_penalty"`
	FrequencyPenalty    float64  `json:"frequency_penalty"`
	DryMultiplier       float64  `json:"dry_multiplier"`
	DryBase             float64  `json:"dry_base"`
	DryAllowedLength    int      `json:"dry_allowed_length"`
	DryPenaltyLastN     int      `json:"dry_penalty_last_n"`
	DrySequenceBreakers []string `json:"dry_sequence_breakers"`
	Mirostat            int      `json:"mirostat"`
	MirostatTau         float64  `json:"mirostat_tau"`
	MirostatEta         float64  `json:"mirostat_eta"`
	Stop                []string `json:"stop"`
	MaxTokens           int      `json:"max_tokens"`
	NKeep               int      `json:"n_keep"`
	NDiscard            int      `json:"n_discard"`
	IgnoreEOS           bool     `json:"ignore_eos"`
	Stream              bool     `json:"stream"`
	NProbs              int      `json:"n_probs"`
	MinKeep             int      `json:"min_keep"`
	Grammar             string   `json:"grammar"`
	Samplers            []string `json:"samplers"`
	SpeculativeNMax     int      `json:"speculative.n_max"`
	SpeculativeNMin     int      `json:"speculative.n_min"`
	SpeculativePMin     float64  `json:"speculative.p_min"`
	TimingsPerToken     bool     `json:"timings_per_token"`
}

func defaultSamplingParams() propsSamplingParams {
	return propsSamplingParams{
		NPredict: -1, Seed: 4294967295, Temperature: 0.800000011920929,
		DynatempRange: 0, DynatempExponent: 1,
		TopK: 40, TopP: 0.949999988079071, MinP: 0.05000000074505806,
		XTCProbability: 0, XTCThreshold: 0.10000000149011612,
		TypicalP: 1, RepeatLastN: 64, RepeatPenalty: 1,
		PresencePenalty: 0, FrequencyPenalty: 0,
		DryMultiplier: 0, DryBase: 1.75, DryAllowedLength: 2, DryPenaltyLastN: -1,
		DrySequenceBreakers: []string{"\n", ":", "\"", "*"},
		Mirostat:            0, MirostatTau: 5, MirostatEta: 0.10000000149011612,
		Stop: []string{}, MaxTokens: -1, NKeep: 0, NDiscard: 0,
		IgnoreEOS: false, Stream: true, NProbs: 0, MinKeep: 0, Grammar: "",
		Samplers:        []string{"dry", "top_k", "typ_p", "top_p", "min_p", "xtc", "temperature"},
		SpeculativeNMax: 16, SpeculativeNMin: 5, SpeculativePMin: 0.8999999761581421,
		TimingsPerToken: false,
	}
}

type propsNextToken struct {
	HasNextToken bool   `json:"has_next_token"`
	HasNewLine   bool   `json:"has_new_line"`
	NRemain      int    `json:"n_remain"`
	NDecoded     int    `json:"n_decoded"`
	StoppingWord string `json:"stopping_word"`
}

type propsGenerationSettings struct {
	ID           int                 `json:"id"`
	IDTask       int                 `json:"id_task"`
	NCtx         int                 `json:"n_ctx"`
	Speculative  bool                `json:"speculative"`
	IsProcessing bool                `json:"is_processing"`
	Params       propsSamplingParams `json:"params"`
	Prompt       string              `json:"prompt"`
	NextToken    propsNextToken      `json:"next_token"`
}

// propsModalities intentionally carries only "vision": that is the field the README documents.
// Current source also reports "video"/"audio", added after this section was last documented;
// left out rather than guessed at.
type propsModalities struct {
	Vision bool `json:"vision"`
}

type propsResponse struct {
	DefaultGenerationSettings propsGenerationSettings `json:"default_generation_settings"`
	TotalSlots                int                     `json:"total_slots"`
	ModelPath                 string                  `json:"model_path"`
	ChatTemplate              string                  `json:"chat_template"`
	ChatTemplateCaps          struct{}                `json:"chat_template_caps"`
	Modalities                propsModalities         `json:"modalities"`
	MediaMarker               string                  `json:"media_marker"`
	BuildInfo                 string                  `json:"build_info"`
	IsSleeping                bool                    `json:"is_sleeping"`
}

func handleProps(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSONCT(w, http.StatusOK, llmcore.CTJSONCharset, propsResponse{
		DefaultGenerationSettings: propsGenerationSettings{
			ID: 0, IDTask: -1, NCtx: slotNCtx, Speculative: false, IsProcessing: false,
			Params: defaultSamplingParams(),
			Prompt: "",
			NextToken: propsNextToken{
				HasNextToken: true, HasNewLine: false, NRemain: -1, NDecoded: 0, StoppingWord: "",
			},
		},
		TotalSlots:       1,
		ModelPath:        "models/" + defaultModel,
		ChatTemplate:     llama2ChatTemplate,
		ChatTemplateCaps: struct{}{},
		Modalities:       propsModalities{Vision: false},
		MediaMarker:      "<__media__>",
		BuildInfo:        "b4620-3f8e2a1",
		IsSleeping:       false,
	})
}
