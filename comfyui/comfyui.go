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
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
	return r
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
