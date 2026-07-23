package ray

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

const defaultPort = "8265"

var _ honeypots.Honeypot = &honeypot{}
var saveRayRequest = persistence.SaveRayRequest

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "ray").Logger()}
}

func (h *honeypot) Name() string { return "ray" }

func (h *honeypot) Start() {
	port := os.Getenv("RAY_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	handler := llmcore.Capture(saveRayRequest)(cmdresp.MuxMiddleware("ray")(newRouter()))
	h.logger.Info().Str("port", port).Msg("starting ray honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), handler)).Msg("failed to start")
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/api/version", handleVersion).Methods("GET")
	r.HandleFunc("/api/cluster_status", handleClusterStatus).Methods("GET")
	r.HandleFunc("/nodes", handleNodes).Methods("GET")
	r.HandleFunc("/api/jobs/", handleJobSubmit).Methods("POST")
	r.HandleFunc("/api/jobs/", handleJobList).Methods("GET")
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
	return r
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"version": "2.9.0", "ray_version": "2.9.0",
		"ray_commit": "cfbf98c31577d3e2f3f9e9d0a0b1c2d3e4f5a6b7",
	})
}

func handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"result": true, "msg": "",
		"data": map[string]any{"clusterStatus": map[string]any{
			"autoscalingStatus": "", "loadMetricsReport": map[string]any{"usage": map[string]any{}},
		}},
	})
}

func handleNodes(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{
		"result": true, "msg": "",
		"data": map[string]any{"summary": []map[string]any{{
			"hostname": "ray-head", "ip": "10.0.0.5", "state": "ALIVE",
			"raylet": map[string]any{"numWorkers": 4, "state": "ALIVE"},
		}}},
	})
}

// handleJobSubmit is the ShadowRay (CVE-2023-48022) endpoint. We capture the entrypoint
// (the attacker's command) via the capture middleware and return a plausible submission id.
func handleJobSubmit(w http.ResponseWriter, r *http.Request) {
	id := "raysubmit_" + uuid.NewV4().String()[:12]
	llmcore.WriteJSON(w, http.StatusOK, map[string]any{"job_id": id, "submission_id": id})
}

func handleJobList(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusOK, []any{})
}

func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	llmcore.WriteJSON(w, http.StatusNotFound, map[string]any{"result": false, "msg": "Not Found"})
}
