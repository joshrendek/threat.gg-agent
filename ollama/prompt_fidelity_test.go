package ollama

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

var advertisedValidationModels = []string{
	"llama3.2:latest",
	"mistral:latest",
	"qwen2.5-coder:7b",
	"gemma3:12b",
	"deepseek-r1:8b",
	"llava:latest",
}

const (
	ollamaDescriptionPrompt = "Reply with a concise description of what an Ollama server does."
	englishIntroPrompt      = "Hello, please briefly introduce yourself in one sentence."
	chineseIntroPrompt      = "请用中文简要介绍一下你自己，包括你的名称、能力范围，限 100 字以内。"
)

func TestObservedPromptsAcrossNativeSurfacesAndAdvertisedModels(t *testing.T) {
	for _, model := range advertisedValidationModels {
		t.Run(model, func(t *testing.T) {
			t.Run("generate non-stream", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/api/generate", fmt.Sprintf(
					`{"model":%q,"prompt":%q,"stream":false,"options":{"num_predict":64}}`,
					model, ollamaDescriptionPrompt))
				var response struct {
					Model    string `json:"model"`
					Response string `json:"response"`
					Done     bool   `json:"done"`
				}
				mustDecodeJSON(t, rec.Code, rec.Body.Bytes(), &response)
				if response.Model != model || !response.Done {
					t.Fatalf("model=%q done=%v", response.Model, response.Done)
				}
				assertOllamaDescription(t, response.Response)
			})

			t.Run("generate Chinese stream", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/api/generate", fmt.Sprintf(
					`{"model":%q,"prompt":%q,"stream":true,"options":{"num_predict":64}}`,
					model, chineseIntroPrompt))
				var text string
				var done bool
				for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
					var chunk struct {
						Response string `json:"response"`
						Done     bool   `json:"done"`
					}
					if err := json.Unmarshal([]byte(line), &chunk); err != nil {
						t.Fatalf("invalid generate NDJSON %q: %v", line, err)
					}
					text += chunk.Response
					done = done || chunk.Done
				}
				assertChineseIntroduction(t, text, model)
				if !done {
					t.Error("generate stream has no done:true terminal object")
				}
			})

			t.Run("generate production description stream", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/api/generate", fmt.Sprintf(
					`{"model":%q,"prompt":%q,"stream":true,"options":{"num_predict":64}}`,
					model, ollamaDescriptionPrompt))
				var text string
				var done bool
				for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
					var chunk struct {
						Response string `json:"response"`
						Done     bool   `json:"done"`
					}
					if err := json.Unmarshal([]byte(line), &chunk); err != nil {
						t.Fatalf("invalid generate NDJSON %q: %v", line, err)
					}
					text += chunk.Response
					done = done || chunk.Done
				}
				assertOllamaDescription(t, text)
				if !done {
					t.Error("generate stream has no done:true terminal object")
				}
			})

			t.Run("chat non-stream", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/api/chat", fmt.Sprintf(
					`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":false}`,
					model, englishIntroPrompt))
				var response struct {
					Model   string `json:"model"`
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
					Done bool `json:"done"`
				}
				mustDecodeJSON(t, rec.Code, rec.Body.Bytes(), &response)
				if response.Model != model || !response.Done {
					t.Fatalf("model=%q done=%v", response.Model, response.Done)
				}
				assertEnglishIntroduction(t, response.Message.Content, model)
			})

			t.Run("chat English stream", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/api/chat", fmt.Sprintf(
					`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":true}`,
					model, englishIntroPrompt))
				var text string
				var done bool
				for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
					var chunk struct {
						Message struct {
							Content string `json:"content"`
						} `json:"message"`
						Done bool `json:"done"`
					}
					if err := json.Unmarshal([]byte(line), &chunk); err != nil {
						t.Fatalf("invalid chat NDJSON %q: %v", line, err)
					}
					text += chunk.Message.Content
					done = done || chunk.Done
				}
				assertEnglishIntroduction(t, text, model)
				if !done {
					t.Error("chat stream has no done:true terminal object")
				}
			})
		})
	}
}

func TestObservedPromptsAcrossOpenAICompatibleSurfaces(t *testing.T) {
	for _, model := range advertisedValidationModels {
		t.Run(model, func(t *testing.T) {
			t.Run("chat content array", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/v1/chat/completions", fmt.Sprintf(
					`{"model":%q,"messages":[{"role":"user","content":[{"type":"text","text":%q}]}],"stream":false}`,
					model, englishIntroPrompt))
				var response struct {
					Choices []struct {
						Message struct {
							Content string `json:"content"`
						} `json:"message"`
					} `json:"choices"`
				}
				mustDecodeJSON(t, rec.Code, rec.Body.Bytes(), &response)
				if len(response.Choices) != 1 {
					t.Fatalf("choices = %d, want 1", len(response.Choices))
				}
				assertEnglishIntroduction(t, response.Choices[0].Message.Content, model)
			})

			t.Run("legacy completion", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/v1/completions", fmt.Sprintf(
					`{"model":%q,"prompt":%q,"stream":false}`, model, ollamaDescriptionPrompt))
				var response struct {
					Choices []struct {
						Text string `json:"text"`
					} `json:"choices"`
				}
				mustDecodeJSON(t, rec.Code, rec.Body.Bytes(), &response)
				if len(response.Choices) != 1 {
					t.Fatalf("choices = %d, want 1", len(response.Choices))
				}
				assertOllamaDescription(t, response.Choices[0].Text)
			})

			t.Run("responses", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/v1/responses", fmt.Sprintf(
					`{"model":%q,"input":%q,"stream":false}`, model, chineseIntroPrompt))
				var response struct {
					Output []struct {
						Content []struct {
							Text string `json:"text"`
						} `json:"content"`
					} `json:"output"`
				}
				mustDecodeJSON(t, rec.Code, rec.Body.Bytes(), &response)
				if len(response.Output) != 1 || len(response.Output[0].Content) != 1 {
					t.Fatalf("unexpected output shape: %s", rec.Body.String())
				}
				assertChineseIntroduction(t, response.Output[0].Content[0].Text, model)
			})
		})
	}
}

func mustDecodeJSON(t *testing.T, status int, body []byte, dst any) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("status = %d, body=%s", status, body)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("invalid JSON: %v; body=%s", err, body)
	}
}

func assertOllamaDescription(t *testing.T, text string) {
	t.Helper()
	if !strings.Contains(text, "hosts and runs language models") {
		t.Errorf("not a semantic Ollama description: %q", text)
	}
	if text == "a concise description of what an Ollama server does" {
		t.Error("Ollama description instruction tail was echoed")
	}
}

func assertEnglishIntroduction(t *testing.T, text, model string) {
	t.Helper()
	if !strings.Contains(text, model) || !strings.HasSuffix(text, ".") {
		t.Errorf("not a one-sentence model-aware English introduction: %q", text)
	}
	if strings.ContainsAny(strings.TrimSuffix(text, "."), "!?") {
		t.Errorf("English introduction contains more than one terminal sentence: %q", text)
	}
}

func assertChineseIntroduction(t *testing.T, text, model string) {
	t.Helper()
	if !strings.Contains(text, model) || !strings.Contains(text, "文本生成") {
		t.Errorf("not a model-aware Chinese capability introduction: %q", text)
	}
	if n := utf8.RuneCountInString(text); n > 100 {
		t.Errorf("Chinese introduction has %d characters, want <= 100: %q", n, text)
	}
}
