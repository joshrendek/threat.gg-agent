// Package kubelet emulates the authenticated HTTPS API exposed by a Kubernetes
// node agent. It returns a small, coherent node/pod persona and records bounded
// request metadata. Bearer tokens are fingerprinted and redacted, but are
// never validated against an external control plane.
package kubelet

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/internal/kubetls"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort       = "10250"
	maxBodyBytes      = 64 << 10
	maxPathBytes      = 8 << 10
	maxQueryBytes     = 16 << 10
	maxUserAgentBytes = 4 << 10
	maxCommands       = 64
	maxCommandBytes   = 4 << 10
	persistSlotsN     = 32
)

var (
	saveRequest  = persistence.SaveKubeletRequest
	persistSlots = make(chan struct{}, persistSlotsN)
)

var labeledSecretPattern = regexp.MustCompile(`(?i)(?:access[_-]?token|token|secret|password|authorization|api[_-]?key|cookie)\s*[:=]\s*["']?[^&,;\s"']+["']?`)

var _ honeypots.Honeypot = (*honeypot)(nil)

type honeypot struct{ logger zerolog.Logger }

// New constructs a Kubelet HTTPS honeypot.
func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "kubelet").Logger()}
}

func (h *honeypot) Name() string { return "kubelet" }

func (h *honeypot) Start() {
	port := os.Getenv("KUBELET_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	cert, err := selfSignedCertForNode()
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to generate kubelet TLS certificate")
	}
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           newHandler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	h.logger.Info().Str("port", port).Msg("starting Kubelet HTTPS honeypot")
	h.logger.Fatal().Err(server.ListenAndServeTLS("", "")).Msg("failed to start Kubelet honeypot")
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", textHandler("ok", "text/plain; charset=utf-8"))
	mux.HandleFunc("/pods", jsonHandler(podList))
	mux.HandleFunc("/runningPods/", jsonHandler(podList))
	mux.HandleFunc("/stats/summary", jsonHandler(statsSummary))
	mux.HandleFunc("/metrics", textHandler(metrics, "text/plain; version=0.0.4; charset=utf-8"))
	mux.HandleFunc("/metrics/", textHandler(metrics, "text/plain; version=0.0.4; charset=utf-8"))
	mux.HandleFunc("/logs/", logsHandler)
	mux.HandleFunc("/containerLogs/", containerLogsHandler)
	mux.HandleFunc("/exec/", commandHandler)
	mux.HandleFunc("/run/", commandHandler)
	mux.HandleFunc("/configz", jsonHandler(configz))
	mux.HandleFunc("/spec/", jsonHandler(machineSpec))
	mux.HandleFunc("/", notFoundHandler)
	return captureMiddleware(cmdresp.MuxMiddleware("kubelet")(mux))
}

func captureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guid := uuid.NewV4().String()
		body, tooLarge, err := readBoundedBody(r.Body, maxBodyBytes)
		if err != nil {
			http.Error(w, "unable to read request body", http.StatusBadRequest)
			return
		}
		if tooLarge {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			persist(r, guid, body)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		persist(r, guid, body)
		next.ServeHTTP(w, r)
	})
}

func persist(r *http.Request, guid string, body []byte) {
	authScheme, tokenFingerprint := authorizationMetadata(r.Header.Get("Authorization"))
	query := r.URL.Query()
	commands := boundedCommands(query["command"])
	req := &proto.KubeletRequest{
		RemoteAddr:       bounded(r.RemoteAddr, 4096),
		Guid:             guid,
		Method:           bounded(r.Method, 16),
		Path:             bounded(r.URL.EscapedPath(), maxPathBytes),
		Query:            bounded(redactedQuery(query).Encode(), maxQueryBytes),
		AuthScheme:       authScheme,
		TokenFingerprint: tokenFingerprint,
		UserAgent:        bounded(r.UserAgent(), maxUserAgentBytes),
		Body:             redactedBody(body),
		Commands:         commands,
	}
	select {
	case persistSlots <- struct{}{}:
		save := saveRequest
		go func() {
			defer func() { <-persistSlots }()
			_ = save(req)
		}()
	default:
	}
}

func authorizationMetadata(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "anonymous", ""
	}
	parts := strings.Fields(value)
	scheme := strings.ToLower(parts[0])
	if len(parts) < 2 {
		return bounded(scheme, 32), ""
	}
	sum := sha256.Sum256([]byte(strings.Join(parts[1:], " ")))
	return bounded(scheme, 32), "sha256:" + hex.EncodeToString(sum[:8])
}

func redactedQuery(values url.Values) url.Values {
	out := make(url.Values, len(values))
	for key, vals := range values {
		if isSecretKey(key) {
			out[key] = []string{"[REDACTED]"}
			continue
		}
		for _, value := range vals {
			out[key] = append(out[key], bounded(value, maxCommandBytes))
		}
	}
	return out
}

func isSecretKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	return strings.Contains(normalized, "token") || strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "password") || strings.Contains(normalized, "authorization") ||
		normalized == "api_key" || strings.Contains(normalized, "cookie")
}

func redactedBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		raw := bounded(string(body), maxBodyBytes)
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			return "[REDACTED_MALFORMED_JSON_BODY]"
		}
		if strings.Contains(raw, "=") {
			if values, err := url.ParseQuery(raw); err == nil {
				return redactedQuery(values).Encode()
			}
		}
		return labeledSecretPattern.ReplaceAllString(raw, "[REDACTED]")
	}
	redactJSONSecrets(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return bounded(string(encoded), maxBodyBytes)
}

func redactJSONSecrets(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isSecretKey(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			redactJSONSecrets(child)
		}
	case []any:
		for _, child := range typed {
			redactJSONSecrets(child)
		}
	}
}

func boundedCommands(commands []string) []string {
	if len(commands) > maxCommands {
		commands = commands[:maxCommands]
	}
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, bounded(command, maxCommandBytes))
	}
	return out
}

func bounded(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func readBoundedBody(r io.Reader, limit int64) ([]byte, bool, error) {
	if r == nil {
		return nil, false, nil
	}
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		return body[:limit], true, nil
	}
	return body, false, nil
}

func jsonHandler(payload string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, payload)
	}
}

func textHandler(payload, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = io.WriteString(w, payload)
	}
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<pre><a href="pods/">pods/</a>\n<a href="kubelet.log">kubelet.log</a>\n<a href="containerd.log">containerd.log</a>\n</pre>`)
}

func containerLogsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if strings.Contains(r.URL.Path, "node-exporter") {
		_, _ = io.WriteString(w, "ts=2026-08-02T00:00:00Z caller=node_exporter.go:193 level=info msg=\"Listening on\" address=:9100\n")
		return
	}
	_, _ = io.WriteString(w, "10.244.0.1 - - [02/Aug/2026:00:00:00 +0000] \"GET /healthz HTTP/1.1\" 200 2\n")
}

func commandHandler(w http.ResponseWriter, r *http.Request) {
	commands := boundedCommands(r.URL.Query()["command"])
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if len(commands) == 0 {
		http.Error(w, "command is required", http.StatusBadRequest)
		return
	}
	command := strings.Join(commands, " ")
	switch command {
	case "id", "/usr/bin/id":
		_, _ = io.WriteString(w, "uid=0(root) gid=0(root) groups=0(root)\n")
	case "whoami", "/usr/bin/whoami":
		_, _ = io.WriteString(w, "root\n")
	case "uname -a", "/bin/uname -a":
		_, _ = io.WriteString(w, "Linux worker-01 6.8.0-60-generic #63-Ubuntu SMP x86_64 GNU/Linux\n")
	default:
		_, _ = io.WriteString(w, "")
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind": "Status", "apiVersion": "v1", "status": "Failure",
		"message": "no kubelet handler for " + bounded(r.URL.Path, 1024), "reason": "NotFound", "code": 404,
	})
}

func selfSignedCertForNode() (tls.Certificate, error) {
	return kubetls.GenerateSelfSigned("worker-01", "worker-01", "localhost")
}

var podList = `{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"web-7d9b4f8d6b-k2x7m","namespace":"default","uid":"3d6f6c19-1f44-4dcb-b429-5adef468ace1"},"spec":{"nodeName":"worker-01","containers":[{"name":"nginx","image":"nginx:1.27.5"}]},"status":{"phase":"Running","podIP":"10.244.1.12","hostIP":"10.0.0.21","containerStatuses":[{"name":"nginx","ready":true,"restartCount":0,"image":"nginx:1.27.5","containerID":"containerd://7be42af60a37"}]}},{"metadata":{"name":"node-exporter-4jm8n","namespace":"monitoring","uid":"85930444-4dad-46df-96fe-aef842baf8b0"},"spec":{"nodeName":"worker-01","containers":[{"name":"node-exporter","image":"quay.io/prometheus/node-exporter:v1.8.2"}]},"status":{"phase":"Running","podIP":"10.244.1.8","hostIP":"10.0.0.21"}}]}`

var statsSummary = `{"node":{"nodeName":"worker-01","systemContainers":[],"startTime":"2026-07-15T08:12:00Z","cpu":{"time":"2026-08-02T00:00:00Z","usageNanoCores":184220000,"usageCoreNanoSeconds":380414650000000},"memory":{"time":"2026-08-02T00:00:00Z","availableBytes":12884901888,"usageBytes":4294967296,"workingSetBytes":3758096384},"network":{"time":"2026-08-02T00:00:00Z","name":"eth0","rxBytes":981233821,"txBytes":443298812}},"pods":[{"podRef":{"name":"web-7d9b4f8d6b-k2x7m","namespace":"default","uid":"3d6f6c19-1f44-4dcb-b429-5adef468ace1"},"startTime":"2026-07-28T14:05:00Z","containers":[{"name":"nginx","startTime":"2026-07-28T14:05:02Z","cpu":{"usageNanoCores":12200000},"memory":{"workingSetBytes":35651584}}]}]}`

var metrics = "# HELP kubernetes_build_info A metric with a constant '1' value labeled by version.\n# TYPE kubernetes_build_info gauge\nkubernetes_build_info{git_version=\"v1.32.4\",go_version=\"go1.23.6\",platform=\"linux/amd64\"} 1\n# HELP kubelet_running_pods Number of pods currently running.\n# TYPE kubelet_running_pods gauge\nkubelet_running_pods 2\n# HELP kubelet_running_containers Number of containers currently running.\n# TYPE kubelet_running_containers gauge\nkubelet_running_containers{container_state=\"running\"} 2\n"
var configz = `{"kubeletconfig":{"enableServer":true,"address":"0.0.0.0","port":10250,"readOnlyPort":0,"authentication":{"anonymous":{"enabled":true},"webhook":{"enabled":true}},"authorization":{"mode":"AlwaysAllow"},"clusterDomain":"cluster.local","clusterDNS":["10.96.0.10"]}}`
var machineSpec = `{"num_cores":8,"cpu_frequency_khz":3192000,"memory_capacity":17179869184,"machine_id":"f1d2d2f924e986ac86fdf7b36c94bcdf","system_uuid":"42091e4c-47db-4707-9c8e-3e2f1af91e37"}`
