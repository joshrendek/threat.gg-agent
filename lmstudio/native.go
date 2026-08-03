package lmstudio

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/llmcore"
	uuid "github.com/satori/go.uuid"
)

type nativeError struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Param   string `json:"param,omitempty"`
		Code    string `json:"code,omitempty"`
	} `json:"error"`
}

func writeCompactJSON(w http.ResponseWriter, status int, value any) {
	body, _ := json.Marshal(value)
	w.Header().Set("Content-Type", llmcore.CTJSONCharset)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writePrettyJSON(w http.ResponseWriter, status int, value any) {
	body, _ := json.MarshalIndent(value, "", "  ")
	w.Header().Set("Content-Type", llmcore.CTJSONCharset)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeNativeError(w http.ResponseWriter, status int, errType, message, param, code string) {
	payload := nativeError{}
	payload.Error.Message = message
	payload.Error.Type = errType
	payload.Error.Param = param
	payload.Error.Code = code
	writePrettyJSON(w, status, payload)
}

func decodeJSON(r *http.Request, target any) bool {
	if r.Body == nil {
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, llmcore.MaxBodySize+1))
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return true
}

func handleNativeModels(w http.ResponseWriter, r *http.Request) {
	writePrettyJSON(w, http.StatusOK, struct {
		Models []model `json:"models"`
	}{Models: models.list(r)})
}

type openAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

func handleOpenAIModels(w http.ResponseWriter, r *http.Request) {
	available := models.list(r)
	data := make([]openAIModel, 0, len(available))
	for _, candidate := range available {
		data = append(data, openAIModel{ID: candidate.Key, Object: "model", OwnedBy: "organization_owner"})
	}
	writePrettyJSON(w, http.StatusOK, struct {
		Data   []openAIModel `json:"data"`
		Object string        `json:"object"`
	}{Data: data, Object: "list"})
}

func handleLoad(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Model               string `json:"model"`
		ContextLength       int    `json:"context_length"`
		EvalBatchSize       int    `json:"eval_batch_size"`
		Parallel            int    `json:"parallel"`
		FlashAttention      bool   `json:"flash_attention"`
		OffloadKVCacheToGPU bool   `json:"offload_kv_cache_to_gpu"`
		EchoLoadConfig      bool   `json:"echo_load_config"`
	}
	if !decodeJSON(r, &request) {
		writeCompactJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{
			"message": "Invalid body: failed to parse JSON value. Please check the value to ensure it is valid JSON",
			"type":    "invalid_request", "code": "invalid_json",
		}})
		return
	}
	cfg := loadConfig{
		ContextLength: request.ContextLength, EvalBatchSize: request.EvalBatchSize,
		Parallel: request.Parallel, FlashAttention: request.FlashAttention,
		OffloadKVCacheToGPU: request.OffloadKVCacheToGPU,
	}
	candidate, ok := models.load(r, request.Model, cfg)
	if !ok {
		writeNativeError(w, http.StatusNotFound, "model_not_found",
			fmt.Sprintf("Model %s not found in downloaded models", request.Model), "", "")
		return
	}
	response := struct {
		Type            string      `json:"type"`
		InstanceID      string      `json:"instance_id"`
		LoadTimeSeconds float64     `json:"load_time_seconds"`
		Status          string      `json:"status"`
		LoadConfig      *loadConfig `json:"load_config,omitempty"`
	}{Type: candidate.Type, InstanceID: candidate.Key, LoadTimeSeconds: 2.431, Status: "loaded"}
	if request.EchoLoadConfig {
		response.LoadConfig = &cfg
		if listed := models.list(r); len(listed) > 0 {
			for _, item := range listed {
				if item.Key == candidate.Key && len(item.LoadedInstances) > 0 {
					response.LoadConfig = &item.LoadedInstances[0].Config
				}
			}
		}
	}
	writePrettyJSON(w, http.StatusOK, response)
}

func handleUnload(w http.ResponseWriter, r *http.Request) {
	var request struct {
		InstanceID string `json:"instance_id"`
	}
	if !decodeJSON(r, &request) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "\"instance_id\" is required", "instance_id", "missing_required_parameter")
		return
	}
	if !models.unload(r, request.InstanceID) {
		writeNativeError(w, http.StatusNotFound, "model_not_found",
			fmt.Sprintf("Model with instance identifier '%s' is not loaded.", request.InstanceID), "", "")
		return
	}
	writePrettyJSON(w, http.StatusOK, struct {
		InstanceID string `json:"instance_id"`
	}{InstanceID: request.InstanceID})
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Model string `json:"model"`
	}
	if !decodeJSON(r, &request) {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "\"model\" is required", "model", "missing_required_parameter")
		return
	}
	job, ok := models.download(r, request.Model)
	if !ok {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "Model identifier is invalid or the download limit was reached", "model", "invalid_model_identifier")
		return
	}
	writePrettyJSON(w, http.StatusOK, job)
}

func handleDownloadStatus(w http.ResponseWriter, r *http.Request) {
	id := muxVars(r, "job")
	job, ok := models.job(r, id)
	if !ok {
		writeNativeError(w, http.StatusNotFound, "job_not_found", fmt.Sprintf("Download job with id '%s' not found", id), "", "")
		return
	}
	writePrettyJSON(w, http.StatusOK, job)
}

func muxVars(r *http.Request, key string) string {
	// Kept behind a helper so handlers do not retain the whole attacker-controlled
	// mux variable map beyond the request.
	return mux.Vars(r)[key]
}

type nativeOutput struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

type nativeStats struct {
	InputTokens             int     `json:"input_tokens"`
	TotalOutputTokens       int     `json:"total_output_tokens"`
	ReasoningOutputTokens   int     `json:"reasoning_output_tokens"`
	TokensPerSecond         float64 `json:"tokens_per_second"`
	TimeToFirstTokenSeconds float64 `json:"time_to_first_token_seconds"`
	ModelLoadTimeSeconds    float64 `json:"model_load_time_seconds,omitempty"`
}

type nativeChatResult struct {
	ModelInstanceID string         `json:"model_instance_id"`
	Output          []nativeOutput `json:"output"`
	Stats           nativeStats    `json:"stats"`
	ResponseID      string         `json:"response_id,omitempty"`
}

func handleNativeChat(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Model           string          `json:"model"`
		Input           json.RawMessage `json:"input"`
		Stream          bool            `json:"stream"`
		Store           *bool           `json:"store"`
		MaxOutputTokens int             `json:"max_output_tokens"`
	}
	if !decodeJSON(r, &request) {
		writeCompactJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{
			"message": "Invalid body: failed to parse JSON value. Please check the value to ensure it is valid JSON",
			"type":    "invalid_request", "code": "invalid_json",
		}})
		return
	}
	if request.Model == "" {
		writeNativeError(w, http.StatusBadRequest, "invalid_request", "\"model\" is required", "model", "missing_required_parameter")
		return
	}
	candidate, ok := models.get(r, request.Model)
	if !ok || candidate.Type != "llm" {
		writeNativeError(w, http.StatusNotFound, "invalid_request",
			fmt.Sprintf("Invalid model identifier %q. Please specify a valid downloaded model.", request.Model), "model", "model_not_found")
		return
	}
	_, _ = models.load(r, candidate.Key, loadConfig{}) // Native API JIT-loads a downloaded model.
	prompt := promptFromRaw(request.Input)
	reply := llmcore.ClassifiedReply(r, prompt, candidate.Key).Text
	words := strings.Fields(reply)
	if request.MaxOutputTokens > 0 && len(words) > request.MaxOutputTokens {
		words = words[:request.MaxOutputTokens]
		reply = strings.Join(words, " ")
	}
	result := nativeChatResult{
		ModelInstanceID: candidate.Key,
		Output:          []nativeOutput{{Type: "message", Content: reply}},
		Stats: nativeStats{
			InputTokens: 28 + max(1, len(prompt)/4), TotalOutputTokens: max(1, len(words)),
			TokensPerSecond: 34.72, TimeToFirstTokenSeconds: 0.184,
		},
	}
	if request.Store == nil || *request.Store {
		result.ResponseID = "resp_" + strings.ReplaceAll(uuid.NewV4().String(), "-", "")
	}
	if request.Stream {
		streamNativeChat(w, candidate.Key, words, result)
		return
	}
	writePrettyJSON(w, http.StatusOK, result)
}

func promptFromRaw(raw json.RawMessage) string {
	var direct string
	if json.Unmarshal(raw, &direct) == nil {
		return direct
	}
	var items []struct {
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	_ = json.Unmarshal(raw, &items)
	parts := make([]string, 0, len(items))
	for _, item := range items {
		if item.Content != "" {
			parts = append(parts, item.Content)
		}
	}
	return strings.Join(parts, "\n")
}

func streamNativeChat(w http.ResponseWriter, model string, words []string, result nativeChatResult) {
	w.Header().Set("Content-Type", llmcore.CTEventStream)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	emit := func(event string, value any) {
		body, _ := json.Marshal(value)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body)
		if flusher != nil {
			flusher.Flush()
		}
	}
	emit("chat.start", map[string]any{"type": "chat.start", "model_instance_id": model})
	emit("prompt_processing.start", map[string]string{"type": "prompt_processing.start"})
	emit("prompt_processing.end", map[string]string{"type": "prompt_processing.end"})
	emit("message.start", map[string]string{"type": "message.start"})
	for i, word := range words {
		if i+1 < len(words) {
			word += " "
		}
		emit("message.delta", map[string]string{"type": "message.delta", "content": word})
	}
	emit("message.end", map[string]string{"type": "message.end"})
	emit("chat.end", map[string]any{"type": "chat.end", "result": result})
}
