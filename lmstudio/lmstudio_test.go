package lmstudio

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/stretchr/testify/require"
)

func resetState(t *testing.T) {
	t.Helper()
	oldModels := models
	models = newCatalog()
	t.Cleanup(func() { models = oldModels })
}

func request(t *testing.T, handler http.Handler, method, path, body, ip string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://lmstudio:1234"+path, strings.NewReader(body))
	r.RemoteAddr = ip + ":43210"
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestIdentityAndCatalogMatchLMStudioShape(t *testing.T) {
	resetState(t)
	h := newRouter()

	w := request(t, identityHeaders(h), http.MethodGet, "/", "", "198.51.100.1")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "Express", w.Header().Get("X-Powered-By"))
	require.JSONEq(t, `{"error":"Unexpected endpoint or method. (GET /)"}`, w.Body.String())

	w = request(t, h, http.MethodGet, "/api/v1/models", "", "198.51.100.1")
	require.Equal(t, http.StatusOK, w.Code)
	var native struct {
		Models []model `json:"models"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &native))
	require.Len(t, native.Models, 3)
	require.Equal(t, defaultModel, native.Models[0].Key)
	require.Len(t, native.Models[0].LoadedInstances, 1)
	require.Equal(t, embeddingModel, native.Models[2].Key)

	w = request(t, h, http.MethodGet, "/v1/models", "", "198.51.100.1")
	require.Contains(t, w.Body.String(), `"owned_by": "organization_owner"`)
	require.Contains(t, w.Body.String(), defaultModel)
}

func TestCatalogMutationsAreScopedAndBounded(t *testing.T) {
	resetState(t)
	h := newRouter()
	modelKey := "attacker/interesting-model"

	w := request(t, h, http.MethodPost, "/api/v1/models/download", `{"model":"`+modelKey+`"}`, "198.51.100.10")
	require.Equal(t, http.StatusOK, w.Code)
	var started struct {
		JobID string `json:"job_id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &started))
	require.NotEmpty(t, started.JobID)

	w = request(t, h, http.MethodGet, "/api/v1/models/download/status/"+started.JobID, "", "198.51.100.10")
	require.Contains(t, w.Body.String(), `"status": "completed"`)

	w = request(t, h, http.MethodGet, "/api/v1/models", "", "198.51.100.10")
	require.Contains(t, w.Body.String(), modelKey)
	w = request(t, h, http.MethodGet, "/api/v1/models", "", "198.51.100.11")
	require.NotContains(t, w.Body.String(), modelKey)

	w = request(t, h, http.MethodPost, "/api/v1/models/load", `{"model":"`+modelKey+`","echo_load_config":true}`, "198.51.100.10")
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"status": "loaded"`)
	w = request(t, h, http.MethodPost, "/api/v1/models/unload", `{"instance_id":"`+modelKey+`"}`, "198.51.100.10")
	require.Equal(t, http.StatusOK, w.Code)

	for i := 0; i < maxDownloadsPerView+3; i++ {
		w = request(t, h, http.MethodPost, "/api/v1/models/download", `{"model":"overflow/model-`+string(rune('a'+i))+`"}`, "198.51.100.20")
		if i < maxDownloadsPerView {
			require.Equal(t, http.StatusOK, w.Code)
		} else {
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, w.Body.String(), `"code": "invalid_model_identifier"`)
		}
	}
	viewRequest := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	viewRequest.RemoteAddr = "198.51.100.20:43210"
	require.LessOrEqual(t, len(models.view(viewRequest).downloaded), maxDownloadsPerView)
}

func TestNativeChatAndAnthropicStreaming(t *testing.T) {
	resetState(t)
	h := newRouter()

	w := request(t, h, http.MethodPost, "/api/v1/chat", `{"model":"`+defaultModel+`","input":"Reply with exactly OK","store":true}`, "198.51.100.30")
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), `"model_instance_id": "`+defaultModel+`"`)
	require.Contains(t, w.Body.String(), `"content": "OK"`)
	require.Contains(t, w.Body.String(), `"response_id": "resp_`)

	w = request(t, h, http.MethodPost, "/api/v1/chat", `{"model":"`+defaultModel+`","input":"Reply with pong","stream":true}`, "198.51.100.30")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
	require.Contains(t, w.Body.String(), "event: chat.start")
	require.Contains(t, w.Body.String(), "event: message.delta")
	require.Contains(t, w.Body.String(), "event: chat.end")

	w = request(t, h, http.MethodPost, "/v1/messages", `{"model":"`+defaultModel+`","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"Reply with blue"}]}`, "198.51.100.30")
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "event: message_start")
	require.Contains(t, w.Body.String(), "event: content_block_delta")
	require.Contains(t, w.Body.String(), "event: message_stop")
}

func TestEmbeddingsHaveExpectedDimension(t *testing.T) {
	resetState(t)
	w := request(t, newRouter(), http.MethodPost, "/v1/embeddings", `{"model":"`+embeddingModel+`","input":"hello"}`, "198.51.100.40")
	require.Equal(t, http.StatusOK, w.Code)
	var body struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(t, body.Data, 1)
	require.Len(t, body.Data[0].Embedding, 768)
}

func TestEmbeddingsBatchReturnsOneDeterministicVectorPerInput(t *testing.T) {
	resetState(t)
	h := newRouter()
	body := `{"model":"` + embeddingModel + `","input":["hello","world"]}`
	first := request(t, h, http.MethodPost, "/v1/embeddings", body, "198.51.100.41")
	second := request(t, h, http.MethodPost, "/v1/embeddings", body, "198.51.100.41")
	require.Equal(t, http.StatusOK, first.Code)
	var got struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &got))
	require.Len(t, got.Data, 2)
	require.Equal(t, []int{0, 1}, []int{got.Data[0].Index, got.Data[1].Index})
	require.NotEqual(t, got.Data[0].Embedding, got.Data[1].Embedding)
	require.JSONEq(t, first.Body.String(), second.Body.String())
}

func TestStructuredPromptExtractionAndStrictJSONBoundary(t *testing.T) {
	for _, raw := range []string{
		`[{"role":"user","content":[{"type":"input_text","text":"Reply with exactly OK"}]}]`,
		`[{"role":"user","content":[{"type":"text","text":"Reply with exactly OK"}]}]`,
	} {
		require.Equal(t, "Reply with exactly OK", promptFromRaw(json.RawMessage(raw)))
	}
	bad := request(t, newRouter(), http.MethodPost, "/api/v1/chat",
		`{"model":"`+defaultModel+`","input":"hello"}{"extra":true}`, "198.51.100.42")
	require.Equal(t, http.StatusBadRequest, bad.Code)
	require.Contains(t, bad.Body.String(), "invalid_json")
}

func TestCaptureRetainsMCPMetadata(t *testing.T) {
	resetState(t)
	got := make(chan *proto.LlmRequest, 1)
	oldSave := saveLmstudioRequest
	saveLmstudioRequest = func(in *proto.LlmRequest) error { got <- in; return nil }
	t.Cleanup(func() { saveLmstudioRequest = oldSave })

	server := buildHandler()
	w := request(t, server, http.MethodPost, "/api/v1/chat", `{"model":"`+defaultModel+`","input":"hello","integrations":[{"type":"ephemeral_mcp","server_label":"probe","server_url":"https://example.invalid/mcp"}]}`, "203.0.113.50")
	require.Equal(t, http.StatusOK, w.Code)
	select {
	case captured := <-got:
		require.Equal(t, "/api/v1/chat", captured.Path)
		require.Equal(t, defaultModel, captured.Model)
		require.Contains(t, captured.Body, "ephemeral_mcp")
		require.Contains(t, captured.Body, "server_url")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for LM Studio capture")
	}
}

func TestOpenAICLICompatibility(t *testing.T) {
	openai, err := exec.LookPath("openai")
	if err != nil {
		t.Skip("OpenAI CLI is not installed")
	}
	resetState(t)
	oldSave := saveLmstudioRequest
	saveLmstudioRequest = func(*proto.LlmRequest) error { return nil }
	t.Cleanup(func() { saveLmstudioRequest = oldSave })

	ts := httptest.NewServer(buildHandler())
	t.Cleanup(ts.Close)
	env := append(os.Environ(), "OPENAI_API_KEY=lm-studio", "OPENAI_BASE_URL="+ts.URL+"/v1")
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(openai, args...)
		cmd.Env = env
		out, runErr := cmd.CombinedOutput()
		require.NoError(t, runErr, "openai %s failed: %s", strings.Join(args, " "), out)
		return string(out)
	}

	require.Contains(t, run("api", "models.list"), defaultModel)
	chat := run("api", "chat.completions.create", "-m", defaultModel, "-g", "user", "Reply with exactly OK")
	require.Contains(t, chat, "OK")
}

func TestOpenAIResponsesStreamEvents(t *testing.T) {
	resetState(t)
	w := request(t, newRouter(), http.MethodPost, "/v1/responses", `{"model":"`+defaultModel+`","input":"Reply with OK","stream":true}`, "198.51.100.60")
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "event: response.created")
	require.Contains(t, w.Body.String(), "event: response.output_text.delta")
	require.Contains(t, w.Body.String(), "event: response.completed")

	res := w.Result()
	_, _ = io.ReadAll(res.Body)
	require.NoError(t, res.Body.Close())
}
