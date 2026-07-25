package comfyui

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/llmcore"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const defaultPort = "8188"

var _ honeypots.Honeypot = &honeypot{}
var saveComfyuiRequest = persistence.SaveComfyuiRequest

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "comfyui").Logger()}
}

func (h *honeypot) Name() string { return "comfyui" }

func (h *honeypot) Start() {
	port := os.Getenv("COMFYUI_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	handler := llmcore.Capture(saveComfyuiRequest)(cmdresp.MuxMiddleware("comfyui")(newRouter()))
	h.logger.Info().Str("port", port).Msg("starting comfyui honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), handler)).Msg("failed to start")
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/system_stats", handleSystemStats).Methods("GET")
	r.HandleFunc("/object_info", handleObjectInfo).Methods("GET")
	r.HandleFunc("/queue", handleQueue).Methods("GET")
	r.HandleFunc("/prompt", handlePrompt).Methods("POST")
	r.HandleFunc("/prompt", handlePromptGet).Methods("GET")
	// threat_gg-3kd: verified 404 on the live fleet. Every real client polls /history after
	// submitting a workflow via /prompt. Response shape verified against the current source
	// (github.com/comfyanonymous/ComfyUI execution.py, PromptQueue.get_history): this honeypot
	// never actually executes a submitted workflow, so both the collection and any specific
	// prompt_id are always the "nothing recorded yet" case, which real ComfyUI also renders as
	// an empty JSON object — not a guess, the literal return value of that code path.
	r.HandleFunc("/history", handleHistory).Methods("GET")
	r.HandleFunc("/history/{prompt_id}", handleHistory).Methods("GET")
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
	return r
}

// handleHistory serves both GET /history and GET /history/{prompt_id}. Real ComfyUI's
// PromptQueue.get_history returns {} for the no-argument case on a fresh instance (self.history
// starts empty) and {} for any prompt_id not present in self.history — which, since nothing this
// honeypot "runs" via /prompt ever actually completes, is every prompt_id it will ever be asked
// about. Both routes are therefore the same response.
func handleHistory(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{})
}

func handleSystemStats(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"system": map[string]any{
			"os": "posix", "python_version": "3.11.6", "embedded_python": false,
			"comfyui_version": "0.2.2",
		},
		"devices": []map[string]any{{
			"name": "cuda:0 NVIDIA GeForce RTX 4090", "type": "cuda",
			"vram_total": int64(25757220864), "vram_free": int64(24000000000),
		}},
	})
}

func handleObjectInfo(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"KSampler": map[string]any{
			"input":        map[string]any{"required": map[string]any{}},
			"output":       []string{"LATENT"},
			"category":     "sampling",
			"display_name": "KSampler",
		},
		"CheckpointLoaderSimple": map[string]any{
			"input":        map[string]any{"required": map[string]any{}},
			"output":       []string{"MODEL", "CLIP", "VAE"},
			"category":     "loaders",
			"display_name": "Load Checkpoint",
		},
	})
}

func handleQueue(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{"queue_running": []any{}, "queue_pending": []any{}})
}

// handlePrompt captures the submitted workflow (custom-node RCE surface) and returns a
// plausible prompt_id.
func handlePrompt(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"prompt_id": uuid.NewV4().String(), "number": 1, "node_errors": map[string]any{},
	})
}

func handlePromptGet(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{"exec_info": map[string]any{"queue_remaining": 0}})
}

func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404: Not Found")
}
