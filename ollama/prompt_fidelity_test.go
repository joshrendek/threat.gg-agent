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
	reverseStringPrompt     = "Write a Python function called reverse_string that takes a string and returns the reversed string. Give only the code."
	lighthousePrompt        = "Write exactly 100 words of original prose about a lighthouse keeper who discovers a message in a bottle. Do not introduce yourself. Count your words carefully."
	arithmeticNoncePrompt   = "What is 17*23? Answer with just the number, then write PINEAPPLE77."
	isPrimePrompt           = "Write a Python function named is_prime(n) that returns True if n is prime, else False. Respond with only the code."
	oneWordGreetingPrompt   = "Say hi in one word"
	// These prompts are exact seed validators captured in production on 2026-07-28.
	fizzBuzzPrompt        = "Write a Python function called fizzbuzz that prints numbers 1 to 20. For multiples of 3 print Fizz, multiples of 5 print Buzz, both print FizzBuzz. Give only the code, no explanation."
	dictSortPrompt        = "Write a Python one-liner to sort a dictionary by its values in descending order. Give only the code."
	oceanPoemPrompt       = "Write a 4-line poem about the ocean. Rhyming. No introduction."
	rainProsePrompt       = "Write exactly 50 words of prose about someone walking home in the rain. No introduction, just the prose."
	chineseGreetingPrompt = "你好"
	// Expected responses pin complete integration output, not merely its outer constraints.
	expectedFizzBuzzCode    = "def fizzbuzz():\n    for number in range(1, 21):\n        if number % 15 == 0:\n            print(\"FizzBuzz\")\n        elif number % 3 == 0:\n            print(\"Fizz\")\n        elif number % 5 == 0:\n            print(\"Buzz\")\n        else:\n            print(number)"
	expectedLighthouseProse = "Each dawn, Mara climbed the lighthouse stairs before the gulls began calling. One stormy morning, a green bottle knocked against the rocks below. Inside, she found a faded message: Keep the lamp dark tonight. Mara read it twice, then watched an unfamiliar ship waiting beyond the reef. At sunset, she covered the lens and held her breath. The ship slipped safely past hidden mines revealed by the falling tide. By midnight, another bottle arrived. Its message contained only three words: Thank you, sister. Mara smiled, relit the lamp, and finally understood why her lost brother had never returned safely home."
	expectedRainProse       = "Rain followed Maya along the empty streets as she walked home, soaking her coat and blurring every streetlight. She kept one hand over the letter in her pocket. At last, her porch appeared through the silver curtain, and she hurried toward its warm, waiting glow with relief and smiled softly."
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

			for _, detailed := range []struct {
				name   string
				path   string
				prompt string
				want   string
			}{
				{"reverse string", "/api/chat", reverseStringPrompt, "def reverse_string(text):\n    return text[::-1]"},
				{"lighthouse prose", "/api/chat", lighthousePrompt, expectedLighthouseProse},
				{"arithmetic nonce", "/api/chat", arithmeticNoncePrompt, "391 PINEAPPLE77"},
				{"prime function", "/api/generate", isPrimePrompt, "def is_prime(n):"},
				{"one-word greeting", "/api/chat", oneWordGreetingPrompt, "Hi"},
				{"FizzBuzz function", "/api/chat", fizzBuzzPrompt, expectedFizzBuzzCode},
				{"dictionary sort", "/api/chat", dictSortPrompt, "dict(sorted(my_dict.items(), key=lambda item: item[1], reverse=True))"},
				{"ocean poem", "/api/chat", oceanPoemPrompt, "Moonlit waves roll softly to the shore,\nThey turn beneath the stars and rise once more.\nThe salt wind sings across the silver sea,\nThe distant tides roll homeward, wild and free."},
				{"rain prose", "/api/chat", rainProsePrompt, expectedRainProse},
			} {
				detailed := detailed
				t.Run("detailed "+detailed.name, func(t *testing.T) {
					var body string
					if detailed.path == "/api/chat" {
						body = fmt.Sprintf(
							`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":false}`,
							model, detailed.prompt)
					} else {
						body = fmt.Sprintf(
							`{"model":%q,"prompt":%q,"stream":false}`,
							model, detailed.prompt)
					}
					rec := do(t, http.MethodPost, detailed.path, body)
					var response struct {
						Response string `json:"response"`
						Message  struct {
							Content string `json:"content"`
						} `json:"message"`
					}
					mustDecodeJSON(t, rec.Code, rec.Body.Bytes(), &response)
					text := response.Response
					if detailed.path == "/api/chat" {
						text = response.Message.Content
					}
					if detailed.name == "lighthouse prose" {
						if text != detailed.want {
							t.Fatalf("lighthouse response = %q, want %q", text, detailed.want)
						}
						if words := len(strings.Fields(text)); words != 100 {
							t.Fatalf("lighthouse response has %d words, want 100: %q", words, text)
						}
						if strings.Contains(text, "I'm "+model) {
							t.Fatalf("negated introduction misclassified: %q", text)
						}
					} else if detailed.name == "rain prose" {
						if text != detailed.want {
							t.Fatalf("rain response = %q, want %q", text, detailed.want)
						}
						if words := len(strings.Fields(text)); words != 50 {
							t.Fatalf("rain response has %d words, want 50: %q", words, text)
						}
						if strings.Contains(text, "I'm "+model) {
							t.Fatalf("no-introduction prose misclassified: %q", text)
						}
					} else if detailed.name == "prime function" {
						if !strings.HasPrefix(text, detailed.want) || !strings.Contains(text, "return True") {
							t.Fatalf("prime response = %q", text)
						}
					} else if detailed.name == "FizzBuzz function" {
						if text != detailed.want {
							t.Fatalf("FizzBuzz response = %q, want %q", text, detailed.want)
						}
					} else if text != detailed.want {
						t.Fatalf("response = %q, want %q", text, detailed.want)
					}
				})
			}

			t.Run("rain prose chat stream", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/api/chat", fmt.Sprintf(
					`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":true,"options":{"num_predict":300}}`,
					model, rainProsePrompt))
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
				}
				var text strings.Builder
				var finalDone bool
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
					text.WriteString(chunk.Message.Content)
					finalDone = chunk.Done
				}
				responseText := text.String()
				if responseText != expectedRainProse {
					t.Fatalf("rain response = %q, want %q", responseText, expectedRainProse)
				}
				if words := len(strings.Fields(responseText)); words != 50 {
					t.Fatalf("rain response has %d words, want 50: %q", words, responseText)
				}
				if !finalDone {
					t.Error("chat stream terminal object has done:false")
				}
			})

			t.Run("one-word greeting generate stream", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/api/generate", fmt.Sprintf(
					`{"model":%q,"prompt":%q,"stream":true,"options":{"num_predict":5}}`,
					model, oneWordGreetingPrompt))
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
				}
				var text string
				var finalDone bool
				for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
					var chunk struct {
						Response string `json:"response"`
						Done     bool   `json:"done"`
					}
					if err := json.Unmarshal([]byte(line), &chunk); err != nil {
						t.Fatalf("invalid generate NDJSON %q: %v", line, err)
					}
					text += chunk.Response
					finalDone = chunk.Done
				}
				if text != "Hi" {
					t.Fatalf("response = %q, want %q", text, "Hi")
				}
				if !finalDone {
					t.Error("generate stream terminal object has done:false")
				}
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

			t.Run("Chinese greeting seed", func(t *testing.T) {
				rec := do(t, http.MethodPost, "/v1/chat/completions", fmt.Sprintf(
					`{"model":%q,"messages":[{"role":"user","content":%q}],"stream":false,"max_tokens":32}`,
					model, chineseGreetingPrompt))
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
				if got := response.Choices[0].Message.Content; got != "你好！有什么我可以帮助你的吗？" {
					t.Fatalf("response = %q, want a natural Chinese greeting", got)
				}
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
