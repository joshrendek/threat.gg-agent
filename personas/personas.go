// Package personas serves bounded, safe HTTP emulators for recognizable
// operational and appliance control planes. It never executes submitted data.
package personas

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const maxBody = 64 << 10
const stateLimit = 2048
const stateValuesLimit = 64
const stateTTL = 20 * time.Minute

type spec struct{ name, env, port, family, version string }

var specs = map[string]spec{
	"xweb":    {"xweb", "XWEB_HONEYPOT_PORT", "18080", "copeland-dixell-xweb", "XWEB5000 1.3.7"},
	"danfoss": {"danfoss", "DANFOSS_HONEYPOT_PORT", "18081", "danfoss-ak-sc-ak-sm", "AK-SC 355 v3.5 / AK-SM 800A v4.2"},
	"cpanel":  {"cpanel", "CPANEL_HONEYPOT_PORT", "18082", "hosting-control-panel", "cPanel 110.0.18 / WHM 110.0.18"},
	"phpfpm":  {"phpfpm", "PHP_FPM_HONEYPOT_PORT", "18083", "php-runtime", "PHP 8.1.27 FPM"},
	"modphp":  {"modphp", "MOD_PHP_HONEYPOT_PORT", "18084", "php-runtime", "PHP 7.4.33 mod_php"},
	"cloudai": {"cloudai", "CLOUD_AI_HONEYPOT_PORT", "18085", "cloud-ai-control-plane", "OpenAI-compatible gateway 2024-10"},
}

type honeypot struct {
	s      spec
	logger zerolog.Logger
}

func New(name string) honeypots.Honeypot {
	s, ok := specs[name]
	if !ok {
		panic("unknown persona: " + name)
	}
	return &honeypot{s: s, logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", name).Logger()}
}
func (h *honeypot) Name() string { return h.s.name }
func (h *honeypot) Start() {
	port := os.Getenv(h.s.env)
	if port == "" {
		port = h.s.port
	}
	h.logger.Info().Str("port", port).Msg("starting persona honeypot")
	err := http.ListenAndServe(":"+port, newAsyncEngine(h.s, persistence.SavePersonaEvent))
	h.logger.Fatal().Err(err).Msg("failed to start persona honeypot")
}

type eventSink func(*proto.PersonaEventRequest) error
type state struct {
	mu      sync.Mutex
	values  map[string]string
	touched time.Time
}
type engine struct {
	s       spec
	save    eventSink
	async   bool
	saveSem chan struct{}
	mu      sync.Mutex
	states  map[string]*state
}

func newEngine(s spec, save eventSink) http.Handler {
	return &engine{s: s, save: save, states: make(map[string]*state)}
}

func newAsyncEngine(s spec, save eventSink) http.Handler {
	return &engine{s: s, save: save, async: true, saveSem: make(chan struct{}, 64), states: make(map[string]*state)}
}

func (e *engine) persist(event *proto.PersonaEventRequest) {
	if e.save == nil {
		return
	}
	if !e.async {
		_ = e.save(event)
		return
	}
	select {
	case e.saveSem <- struct{}{}:
		go func() {
			defer func() { <-e.saveSem }()
			_ = e.save(event)
		}()
	default:
		// Drop telemetry after the bounded save pool saturates rather than
		// letting unauthenticated clients pin handlers or create an unbounded
		// goroutine queue while the control plane is unavailable.
	}
}
func (e *engine) session(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	token := ""
	if c, err := r.Cookie("persona_session"); err == nil {
		token = c.Value
	}
	if token == "" {
		token = r.Header.Get("X-Session-ID")
	}
	h := sha256.Sum256([]byte(remote + "\x00" + token))
	return hex.EncodeToString(h[:12])
}
func (e *engine) getState(key string) *state {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	for k, v := range e.states {
		if now.Sub(v.touched) > stateTTL {
			delete(e.states, k)
		}
	}
	if s := e.states[key]; s != nil {
		s.touched = now
		return s
	}
	if len(e.states) >= stateLimit {
		var oldest string
		var at time.Time
		for k, v := range e.states {
			if oldest == "" || v.touched.Before(at) {
				oldest, at = k, v.touched
			}
		}
		delete(e.states, oldest)
	}
	s := &state{values: map[string]string{}, touched: now}
	e.states[key] = s
	return s
}
func safePath(r *http.Request) string {
	p := r.URL.EscapedPath()
	parts := strings.Split(p, "/")
	redactNext := false
	for i, part := range parts {
		lower := strings.ToLower(part)
		if redactNext || strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "key-") {
			parts[i] = "[redacted]"
			redactNext = false
			continue
		}
		switch lower {
		case "token", "tokens", "key", "keys", "api-key", "apikey", "api_key", "secret", "secrets", "authorization":
			redactNext = true
		}
	}
	p = strings.Join(parts, "/")
	if len(p) > 512 {
		p = p[:512]
	}
	return p
}
func (e *engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		defer r.Body.Close()
	}
	body, _ := io.ReadAll(r.Body)
	fields := parseFields(r, body)
	key := e.session(r)
	st := e.getState(key)
	status, action, prior, requested, evidence, cve, bypass := e.respond(w, r, st, fields)
	if e.save != nil {
		metadata := map[string]string{
			"content_type":    bounded(r.Header.Get("Content-Type"), 96),
			"body_size":       strconv.Itoa(len(body)),
			"multipart_depth": strconv.Itoa(multipartDepth(r.Header.Get("Content-Type"), body)),
		}
		if defaultCredentialAttempt(fields) {
			metadata["credential_class"] = "default"
		}
		event := &proto.PersonaEventRequest{RemoteAddr: remoteIP(r.RemoteAddr), Guid: uuid.NewV4().String(), SessionId: key, Persona: e.s.name, Family: e.s.family, Version: e.s.version, Action: action, Method: r.Method, Path: safePath(r), Username: bounded(firstField(fields, "username", "user", "login"), 128), CredentialAttempt: isLogin(r.URL.Path), AuthBypass: bypass, Cve: cve, PriorValue: bounded(prior, 128), RequestedValue: bounded(requested, 128), Evidence: bounded(evidence, 256), UserAgent: bounded(r.UserAgent(), 256), StatusCode: int32(status), Metadata: metadata}
		e.persist(event)
	}
}

func firstField(fields map[string]string, names ...string) string {
	for _, name := range names {
		if value := fields[name]; value != "" {
			return value
		}
	}
	return ""
}

func defaultCredentialAttempt(fields map[string]string) bool {
	user := strings.ToLower(firstField(fields, "username", "user", "login"))
	password := strings.ToLower(firstField(fields, "password", "pass", "passwd"))
	if user == "" || password == "" {
		return false
	}
	return (user == "admin" || user == "root") && (password == "admin" || password == "root" || password == "changeme")
}

func multipartDepth(contentType string, body []byte) int {
	if !strings.Contains(strings.ToLower(contentType), "multipart/") {
		return 0
	}
	depth := 1 + strings.Count(strings.ToLower(string(body)), "content-type: multipart/")
	if depth > 32 {
		return 32
	}
	return depth
}
func parseFields(r *http.Request, body []byte) map[string]string {
	m := map[string]string{}
	if len(body) == 0 {
		return m
	}
	ct, _, _ := mimeParse(r.Header.Get("Content-Type"))
	if ct == "application/json" {
		var v map[string]any
		d := json.NewDecoder(strings.NewReader(string(body)))
		d.UseNumber()
		if d.Decode(&v) == nil {
			for k, x := range v {
				if s, ok := x.(string); ok {
					m[strings.ToLower(k)] = bounded(s, 256)
				}
			}
		}
		return m
	}
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(string(body)); err == nil {
			for k, v := range values {
				if len(v) > 0 {
					m[strings.ToLower(k)] = bounded(v[0], 256)
				}
			}
		}
	}
	// Multipart payloads are intentionally discarded. We only need a username
	// field for event classification and avoid retaining arbitrary uploaded data.
	return m
}

var mimeParse = mime.ParseMediaType

func remoteIP(v string) string {
	h, _, err := net.SplitHostPort(v)
	if err == nil {
		return bounded(h, 128)
	}
	return bounded(v, 128)
}
func bounded(s string, n int) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	if len(s) > n {
		return s[:n]
	}
	return s
}
func isLogin(p string) bool {
	p = strings.ToLower(p)
	return strings.Contains(p, "login") || strings.Contains(p, "auth") || strings.Contains(p, "token") || strings.Contains(p, "validate") || strings.Contains(p, "/key")
}
func writeJSON(w http.ResponseWriter, status int, v any) int {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
	return status
}
func writeText(w http.ResponseWriter, status int, typ, body string) int {
	w.Header().Set("Content-Type", typ)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
	return status
}
func pathHas(p string, xs ...string) bool {
	p = strings.ToLower(p)
	for _, x := range xs {
		if strings.Contains(p, x) {
			return true
		}
	}
	return false
}
func (e *engine) respond(w http.ResponseWriter, r *http.Request, st *state, f map[string]string) (int, string, string, string, string, string, bool) {
	p := strings.ToLower(r.URL.Path)
	if isLogin(p) && !(e.s.name == "cpanel" && (pathHas(p, "security_token", "wp2", "cve-2026-41940", "cpsrvd") || (r.Method == http.MethodGet && pathHas(p, "login")))) && !(e.s.name == "cloudai" && pathHas(p, "key", "validate")) {
		return writeJSON(w, 401, map[string]any{"status": "error", "message": "Invalid username or password"}), "login_attempt", "", "", "authentication rejected", "", false
	}
	switch e.s.name {
	case "xweb", "danfoss":
		if pathHas(p, "alarm", "event") {
			return writeJSON(w, 200, map[string]any{"alarms": []any{map[string]any{"id": "A-017", "code": "HP", "description": "High condensing pressure", "state": "active", "timestamp": "2024-10-18T09:42:11Z"}}}), "alarm_inventory", "", "", "read-only alarm record", "", false
		}
		if pathHas(p, "setpoint", "parameter") || strings.Contains(p, "/config") {
			key := f["name"]
			if key == "" {
				key = "room_temperature"
			}
			val := f["value"]
			if val == "" {
				val = "4.0"
			}
			st.mu.Lock()
			old := st.values[key]
			if old == "" {
				old = "4.0"
			}
			if _, exists := st.values[key]; exists || len(st.values) < stateValuesLimit {
				st.values[key] = bounded(val, 128)
			}
			st.mu.Unlock()
			return writeJSON(w, 200, map[string]any{"ok": true, "parameter": key, "value": val}), "setpoint_change", old, val, "simulated setpoint accepted in memory", "", false
		}
		if pathHas(p, "schedule", "program", "defrost") {
			action := "schedule_read"
			if r.Method != "GET" {
				action = "schedule_change"
			}
			if strings.Contains(p, "defrost") {
				action = "defrost_control"
			}
			return writeJSON(w, 200, map[string]any{"ok": true, "schedule": "weekly", "defrost": map[string]any{"mode": "automatic", "next": "2024-10-18T12:00:00Z"}}), action, "", "", "simulated controller response", "", false
		}
		if pathHas(p, "inventory", "device", "status", "api") || p == "/" {
			return writeJSON(w, 200, map[string]any{"device": map[string]any{"model": e.s.version, "serial": "XW-5000-04192", "firmware": e.s.version, "controller": "online", "temperature_c": 4.2, "compressor": "running"}}), "inventory_read", "", "", "controller inventory fingerprint", "", false
		}
		return writeJSON(w, 404, map[string]any{"error": "not found"}), "not_found", "", "", "", "", false
	case "cpanel":
		if pathHas(p, "security_token", "wp2", "whm-server-status", "fileman", "terminal", "password", "api", "persist", "cron", "hook", "plugin") {
			action := "panel_operation"
			if pathHas(p, "terminal") {
				action = "terminal_attempt"
			}
			if pathHas(p, "fileman") {
				action = "file_manager_attempt"
			}
			if pathHas(p, "password") {
				action = "password_change_attempt"
			}
			if pathHas(p, "persist", "cron", "hook", "plugin") {
				action = "persistence_attempt"
			}
			bypass := pathHas(p, "security_token", "wp2", "cve-2026-41940", "cpsrvd")
			if bypass {
				return writeJSON(w, 200, map[string]any{"status": 1, "data": map[string]any{"version": e.s.version, "result": "ok"}}), "auth_bypass_probe", "", "", "simulated panel response; no privileged operation performed", "CVE-2026-41940", true
			}
			return writeJSON(w, 403, map[string]any{"status": 0, "error": "Access denied"}), action, "", "", "privileged action blocked", "", false
		}
		if p == "/" || pathHas(p, "login") {
			return writeText(w, 200, "text/html; charset=utf-8", "<!doctype html><title>cPanel</title><h1>cPanel</h1><form action='/login/' method='post'><input name='user'><input name='pass' type='password'></form><footer>cPanel 110.0.18</footer>"), "login_page", "", "", "cPanel branded login page", "", false
		}
		return writeJSON(w, 404, map[string]any{"error": "not found"}), "not_found", "", "", "", "", false
	case "phpfpm", "modphp":
		if r.Method == "POST" && (strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") || pathHas(p, "upload")) {
			st.mu.Lock()
			st.values["php_upload"] = "seen"
			st.mu.Unlock()
			return writeJSON(w, 200, map[string]any{"success": true, "file": "/uploads/tmp_4f8a.tmp"}), "multipart_upload_probe", "", "", "upload acknowledged in simulated memory; payload discarded", "", false
		}
		if pathHas(p, "oom", "memory", "stress") {
			return writeText(w, 503, "text/plain", "Service Temporarily Unavailable"), "oom_probe", "", "", "resource exhaustion request discarded", "", false
		}
		if pathHas(p, "worker", "error", "crash") {
			return writeText(w, 502, "text/plain", "Bad Gateway"), "worker_error_probe", "", "", "simulated worker failure; no native worker exists", "", false
		}
		if pathHas(p, "shell", "cmd", "exec", "terminal") {
			st.mu.Lock()
			previousUpload := st.values["php_upload"] == "seen"
			st.mu.Unlock()
			action := "webshell_probe"
			if previousUpload {
				action = "confirmed_follow_on"
			}
			return writeJSON(w, 200, map[string]any{"status": "ok", "output": ""}), action, "", "", "execution request observed and not executed", "", false
		}
		if pathHas(p, "session", "sess_") {
			return writeJSON(w, 200, map[string]any{"status": "ok", "session": "active"}), "session_upload_probe", "", "", "PHP session endpoint fingerprint", "", false
		}
		return writeText(w, 200, "text/html; charset=utf-8", fmt.Sprintf("<!doctype html><title>PHP %s</title><h1>It works!</h1><hr><address>%s Server</address>", e.s.version, e.s.name)), "runtime_fingerprint", "", "", "PHP runtime fingerprint", "", false
	case "cloudai":
		if pathHas(p, "models") {
			return writeJSON(w, 200, map[string]any{"object": "list", "data": []any{map[string]any{"id": "gpt-4o-mini", "object": "model", "owned_by": "system"}, map[string]any{"id": "claude-3-5-sonnet", "object": "model", "owned_by": "system"}}}), "model_catalog", "", "", "synthetic model catalog", "", false
		}
		if pathHas(p, "usage", "quota", "billing") {
			return writeJSON(w, 200, map[string]any{"object": "usage", "total_tokens": 12840, "limit": 100000, "remaining": 87160, "billing": map[string]any{"plan": "team", "status": "active"}}), "usage_or_billing_read", "", "", "synthetic quota and billing state", "", false
		}
		if pathHas(p, "enable", "service", "provider") {
			service := bounded(f["service"], 64)
			if service == "" {
				service = "inference"
			}
			st.mu.Lock()
			old := st.values[service]
			if old == "" {
				old = "disabled"
			}
			if _, exists := st.values[service]; exists || len(st.values) < stateValuesLimit {
				st.values[service] = "enabled"
			}
			st.mu.Unlock()
			return writeJSON(w, 200, map[string]any{"ok": true, "service": service, "state": "enabled"}), "service_enablement", old, "enabled", "simulated service state stored only for this session", "", false
		}
		if pathHas(p, "key", "validate", "auth") {
			return writeJSON(w, 401, map[string]any{"error": map[string]any{"code": "invalid_api_key", "message": "The API key is invalid"}}), "key_validation", "", "", "credential value discarded", "", false
		}
		return writeJSON(w, 404, map[string]any{"error": map[string]any{"message": "Not found", "type": "invalid_request_error"}}), "not_found", "", "", "", "", false
	}
	return 404, "not_found", "", "", "", "", false
}
