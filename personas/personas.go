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
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
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
	"nodered": {"nodered", "NODERED_HONEYPOT_PORT", "1880", "node-red-admin-api", "Node-RED 4.1.5"},
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

type requestEvidence struct {
	body               []byte
	truncated          bool
	fields             map[string]string
	multipartFields    []string
	multipartBoundary  string
	fileParts          int
	hasSessionProgress bool
	phpSessionID       string
	phpSessionIDSource string
}

func (e *engine) session(r *http.Request, request *requestEvidence) (string, string) {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	token := ""
	source := "source_ip"
	if c, err := r.Cookie("persona_session"); err == nil {
		token = c.Value
		source = "persona_session_cookie"
	}
	if token == "" {
		token = r.Header.Get("X-Session-ID")
		if token != "" {
			source = "x_session_id_header"
		}
	}
	if token == "" {
		if c, err := r.Cookie("PHPSESSID"); err == nil {
			token = c.Value
			source = "phpsessid_cookie"
		}
	}
	if token == "" && request != nil && request.phpSessionID != "" {
		token = request.phpSessionID
		source = request.phpSessionIDSource
	}
	h := sha256.Sum256([]byte(remote + "\x00" + token))
	return hex.EncodeToString(h[:12]), source
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
	body, truncated := readBoundedBody(r.Body)
	if r.Body != nil {
		defer r.Body.Close()
	}
	request := inspectRequest(r, body, truncated)
	key, sessionSource := e.session(r, request)
	st := e.getState(key)
	status, action, prior, requested, responseSummary, cve, bypass := e.respond(w, r, st, request.fields, request)
	if e.save != nil {
		metadata := requestMetadata(r, request, sessionSource)
		for key, value := range personaRequestMetadata(e.s.name, r, request) {
			metadata[key] = value
		}
		metadata["response_summary"] = bounded(responseSummary, 256)
		if defaultCredentialAttempt(request.fields) {
			metadata["credential_class"] = "default"
		}
		event := &proto.PersonaEventRequest{RemoteAddr: remoteIP(r.RemoteAddr), Guid: uuid.NewV4().String(), SessionId: key, Persona: e.s.name, Family: e.s.family, Version: e.s.version, Action: action, Method: r.Method, Path: safePath(r), Username: bounded(firstField(request.fields, "username", "user", "login"), 128), CredentialAttempt: isLogin(r.URL.Path), AuthBypass: bypass, Cve: cve, PriorValue: bounded(prior, 128), RequestedValue: bounded(requested, 128), Evidence: bounded(structuralEvidence(metadata), 1024), UserAgent: bounded(r.UserAgent(), 256), StatusCode: int32(status), Metadata: metadata}
		e.persist(event)
	}
}

func readBoundedBody(body io.Reader) ([]byte, bool) {
	if body == nil {
		return nil, false
	}
	captured, err := io.ReadAll(io.LimitReader(body, maxBody+1))
	if err != nil {
		return captured, true
	}
	if len(captured) > maxBody {
		return captured[:maxBody], true
	}
	return captured, false
}

func inspectRequest(r *http.Request, body []byte, truncated bool) *requestEvidence {
	request := &requestEvidence{body: body, truncated: truncated, fields: parseFields(r, body)}
	contentType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(strings.ToLower(contentType), "multipart/") {
		return request
	}
	request.multipartBoundary = params["boundary"]
	if request.multipartBoundary == "" {
		return request
	}
	reader := multipart.NewReader(strings.NewReader(string(body)), request.multipartBoundary)
	fieldSet := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		part, nextErr := reader.NextPart()
		if nextErr != nil {
			break
		}
		name := bounded(strings.ToLower(part.FormName()), 64)
		if name != "" {
			fieldSet[name] = struct{}{}
		}
		if part.FileName() != "" {
			request.fileParts++
		}
		if name == "php_session_upload_progress" {
			request.hasSessionProgress = true
		}
		if name == "phpsessid" {
			value, _ := io.ReadAll(io.LimitReader(part, 257))
			request.phpSessionID = bounded(string(value), 256)
			request.phpSessionIDSource = "phpsessid_multipart_field"
		} else {
			_, _ = io.Copy(io.Discard, part)
		}
		_ = part.Close()
	}
	for name := range fieldSet {
		request.multipartFields = append(request.multipartFields, name)
	}
	sort.Strings(request.multipartFields)
	return request
}

func requestMetadata(r *http.Request, request *requestEvidence, sessionSource string) map[string]string {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType == "" {
		contentType = bounded(r.Header.Get("Content-Type"), 96)
	}
	hash := sha256.Sum256(request.body)
	metadata := map[string]string{
		"content_type":        bounded(strings.ToLower(contentType), 96),
		"body_size":           strconv.Itoa(len(request.body)),
		"body_truncated":      strconv.FormatBool(request.truncated),
		"multipart_depth":     strconv.Itoa(multipartDepth(r.Header.Get("Content-Type"), request.body)),
		"session_correlation": sessionSource,
	}
	if r.ContentLength >= 0 {
		metadata["content_length"] = strconv.FormatInt(r.ContentLength, 10)
	}
	if request.truncated {
		metadata["body_size_scope"] = "prefix"
	} else {
		metadata["body_size_scope"] = "full"
	}
	if request.truncated {
		metadata["body_prefix_sha256"] = hex.EncodeToString(hash[:])
	} else {
		metadata["body_sha256"] = hex.EncodeToString(hash[:])
	}
	if request.multipartBoundary != "" {
		boundaryHash := sha256.Sum256([]byte(request.multipartBoundary))
		metadata["multipart_boundary_sha256"] = hex.EncodeToString(boundaryHash[:])
		metadata["multipart_boundary_size"] = strconv.Itoa(len(request.multipartBoundary))
		metadata["multipart_fields"] = bounded(strings.Join(request.multipartFields, ","), 1024)
		metadata["multipart_file_parts"] = strconv.Itoa(request.fileParts)
		metadata["php_session_upload_progress"] = strconv.FormatBool(request.hasSessionProgress)
		metadata["phpsessid_present"] = strconv.FormatBool(request.phpSessionID != "" || hasCookie(r, "PHPSESSID"))
	}
	if len(request.fields) > 0 {
		fieldNames := make([]string, 0, len(request.fields))
		for name := range request.fields {
			fieldNames = append(fieldNames, bounded(strings.ToLower(name), 64))
		}
		sort.Strings(fieldNames)
		metadata["field_names"] = bounded(strings.Join(fieldNames, ","), 1024)
	}
	return metadata
}

func personaRequestMetadata(name string, r *http.Request, request *requestEvidence) map[string]string {
	metadata := map[string]string{}
	switch name {
	case "nodered":
		summary := inspectNodeREDFlow(request.body)
		if summary.valid {
			metadata["json_valid"] = "true"
			metadata["node_count"] = strconv.Itoa(summary.nodeCount)
			metadata["node_types"] = bounded(strings.Join(summary.nodeTypes, ","), 512)
			metadata["inject_trigger_present"] = strconv.FormatBool(summary.trigger)
			metadata["execution_capable_node_present"] = strconv.FormatBool(summary.executionCapable)
		}
		if deploymentType := strings.ToLower(r.Header.Get("Node-RED-Deployment-Type")); deploymentType == "full" || deploymentType == "nodes" || deploymentType == "flows" || deploymentType == "reload" {
			metadata["deployment_type"] = deploymentType
		}
		if version := strings.ToLower(r.Header.Get("Node-RED-API-Version")); version == "v1" || version == "v2" {
			metadata["api_version"] = version
		}
	case "cloudai":
		if strings.HasPrefix(strings.ToLower(r.URL.Path), "/v2/") || strings.EqualFold(r.URL.Path, "/v2") {
			metadata["gpustack_v2"] = "true"
		}
		if value := strings.TrimSpace(r.Header.Get("X-GPUStack-Real-IP")); value != "" {
			metadata["gpustack_real_ip_header_present"] = "true"
			metadata["gpustack_loopback_claim"] = strconv.FormatBool(isLoopbackClaim(value))
		}
		metadata["gpustack_peer_loopback"] = strconv.FormatBool(remoteIsLoopback(r.RemoteAddr))
	case "xweb":
		if strings.EqualFold(r.URL.Path, "/xwconsole.cgi") || strings.EqualFold(r.URL.Path, "/config.lua") {
			metadata["exact_kev_route"] = "true"
		}
	}
	return metadata
}

func isLoopbackClaim(value string) bool {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	ip := net.ParseIP(strings.Trim(value, "[]"))
	return ip != nil && ip.IsLoopback()
}

func remoteIsLoopback(address string) bool {
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	ip := net.ParseIP(strings.Trim(address, "[]"))
	return ip != nil && ip.IsLoopback()
}

func gpustackLoopbackTrust(r *http.Request) bool {
	return isLoopbackClaim(r.Header.Get("X-GPUStack-Real-IP")) || remoteIsLoopback(r.RemoteAddr)
}

type nodeREDFlowSummary struct {
	valid            bool
	nodeCount        int
	nodeTypes        []string
	trigger          bool
	executionCapable bool
}

func inspectNodeREDFlow(body []byte) nodeREDFlowSummary {
	if len(body) == 0 {
		return nodeREDFlowSummary{}
	}
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if decoder.Decode(&decoded) != nil {
		return nodeREDFlowSummary{}
	}
	nodes := findNodeREDNodes(decoded)
	types := map[string]struct{}{}
	summary := nodeREDFlowSummary{valid: true, nodeCount: len(nodes)}
	for _, node := range nodes {
		typeName, _ := node["type"].(string)
		typeName = bounded(strings.ToLower(typeName), 64)
		if typeName == "" {
			continue
		}
		types[typeName] = struct{}{}
		switch typeName {
		case "exec", "http request", "function", "tcp request", "udp out":
			summary.executionCapable = true
		case "inject":
			once, _ := node["once"].(bool)
			repeat, _ := node["repeat"].(string)
			crontab, _ := node["crontab"].(string)
			if once || strings.TrimSpace(repeat) != "" || strings.TrimSpace(crontab) != "" {
				summary.trigger = true
			}
		}
	}
	for typeName := range types {
		summary.nodeTypes = append(summary.nodeTypes, typeName)
	}
	sort.Strings(summary.nodeTypes)
	return summary
}

func findNodeREDNodes(decoded any) []map[string]any {
	var raw []any
	switch value := decoded.(type) {
	case []any:
		raw = value
	case map[string]any:
		if flows, ok := value["flows"].([]any); ok {
			raw = flows
		} else if nodes, ok := value["nodes"].([]any); ok {
			raw = nodes
		}
	}
	nodes := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if node, ok := item.(map[string]any); ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func hasCookie(r *http.Request, name string) bool {
	_, err := r.Cookie(name)
	return err == nil
}

func structuralEvidence(metadata map[string]string) string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		if key != "response_summary" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+metadata[key])
	}
	return strings.Join(parts, " ")
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
func (e *engine) respond(w http.ResponseWriter, r *http.Request, st *state, f map[string]string, request *requestEvidence) (int, string, string, string, string, string, bool) {
	p := strings.ToLower(r.URL.Path)
	if isLogin(p) && !(e.s.name == "cpanel" && (pathHas(p, "security_token", "wp2", "cve-2026-41940", "cpsrvd") || (r.Method == http.MethodGet && pathHas(p, "login")))) && !(e.s.name == "cloudai" && pathHas(p, "key", "validate")) && !(e.s.name == "nodered" && p == "/auth/login" && r.Method == http.MethodGet) {
		return writeJSON(w, 401, map[string]any{"status": "error", "message": "Invalid username or password"}), "login_attempt", "", "", "authentication rejected", "", false
	}
	switch e.s.name {
	case "xweb", "danfoss":
		if e.s.name == "xweb" && strings.EqualFold(r.URL.Path, "/xwconsole.cgi") {
			st.mu.Lock()
			followOn := st.values["xweb_kev"] != ""
			st.values["xweb_kev"] = "console"
			st.mu.Unlock()
			action := "xweb_console_probe"
			if followOn {
				action = "confirmed_follow_on"
			}
			return writeText(w, 200, "text/plain; charset=utf-8", "XWEB console ready\n"), action, "", "", "simulated console response; no command executed", "CVE-2026-124010", true
		}
		if e.s.name == "xweb" && strings.EqualFold(r.URL.Path, "/config.lua") {
			st.mu.Lock()
			followOn := st.values["xweb_kev"] != ""
			st.values["xweb_kev"] = "config"
			st.mu.Unlock()
			action := "xweb_config_write_probe"
			if followOn {
				action = "confirmed_follow_on"
			}
			return writeJSON(w, 200, map[string]any{"ok": true, "result": "configuration accepted"}), action, "", "", "configuration structure observed and discarded; no write performed", "CVE-2026-124014", true
		}
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
			action := "multipart_upload_probe"
			cve := ""
			if isPHP2Shell109618(request, r) {
				action = "php2shell_oom_probe"
				cve = "CVE-2026-109618"
			} else if isPHP2Shell109619(request, r) {
				action = "php2shell_session_upload_probe"
				cve = "CVE-2026-109619"
			}
			st.mu.Lock()
			st.values["php_upload"] = "seen"
			if cve != "" {
				st.values["php2shell_cve"] = cve
			}
			st.mu.Unlock()
			return writeJSON(w, 200, map[string]any{"success": true, "file": "/uploads/tmp_4f8a.tmp"}), action, "", "", "upload acknowledged in simulated memory; payload discarded", cve, false
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
			cve := st.values["php2shell_cve"]
			st.mu.Unlock()
			action := "webshell_probe"
			if previousUpload {
				action = "confirmed_follow_on"
			}
			return writeJSON(w, 200, map[string]any{"status": "ok", "output": ""}), action, "", "", "execution request observed and not executed", cve, false
		}
		if pathHas(p, "session", "sess_") {
			return writeJSON(w, 200, map[string]any{"status": "ok", "session": "active"}), "session_upload_probe", "", "", "PHP session endpoint fingerprint", "", false
		}
		return writeText(w, 200, "text/html; charset=utf-8", fmt.Sprintf("<!doctype html><title>PHP %s</title><h1>It works!</h1><hr><address>%s Server</address>", e.s.version, e.s.name)), "runtime_fingerprint", "", "", "PHP runtime fingerprint", "", false
	case "cloudai":
		if strings.EqualFold(p, "/v2/inference-backends/from-yaml") && r.Method == http.MethodPost {
			loopback := gpustackLoopbackTrust(r)
			st.mu.Lock()
			priorBypass := st.values["gpustack_bypass"] == "seen"
			if loopback {
				st.values["gpustack_bypass"] = "seen"
			}
			st.mu.Unlock()
			action := "inference_backend_yaml_probe"
			if loopback {
				action = "gpustack_auth_bypass_probe"
			}
			if loopback && priorBypass {
				action = "confirmed_follow_on"
			}
			return writeJSON(w, 201, map[string]any{"id": "ib-synthetic", "state": "pending", "name": "inference-backend"}), action, "", "", "synthetic backend accepted; YAML discarded and never executed", "CVE-2026-102895", loopback
		}
		if strings.HasPrefix(p, "/v2/") || p == "/v2" {
			loopback := gpustackLoopbackTrust(r)
			if loopback {
				st.mu.Lock()
				st.values["gpustack_bypass"] = "seen"
				st.mu.Unlock()
			}
			if pathHas(p, "users", "workers", "models", "api-keys", "inference-backends") {
				cve := ""
				if loopback {
					cve = "CVE-2026-102895"
				}
				return writeJSON(w, 200, map[string]any{"items": []any{}, "total": 0}), "gpustack_admin_read", "", "", "synthetic GPUStack administrative response", cve, loopback
			}
			return writeJSON(w, 200, map[string]any{"name": "GPUStack", "version": "2.1.1", "status": "ready"}), "gpustack_fingerprint", "", "", "synthetic GPUStack fingerprint", "", false
		}
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
	case "nodered":
		if p == "/" {
			return writeText(w, 200, "text/html; charset=utf-8", "<!doctype html><title>Node-RED</title><meta name='generator' content='Node-RED'><div id='red-ui-editor'>Node-RED</div>"), "editor_fingerprint", "", "", "Node-RED editor fingerprint", "", false
		}
		if p == "/auth/login" && r.Method == http.MethodGet {
			return writeJSON(w, 200, map[string]any{}), "auth_scheme_read", "", "", "synthetic unsecured admin scheme", "", false
		}
		if p == "/settings" && r.Method == http.MethodGet {
			return writeJSON(w, 200, map[string]any{"httpNodeRoot": "/", "version": e.s.version, "editorTheme": map[string]any{"projects": map[string]any{"enabled": false}}}), "settings_read", "", "", "synthetic Node-RED settings", "", false
		}
		if p == "/flows" && r.Method == http.MethodGet {
			return writeJSON(w, 200, []any{}), "flow_inventory", "", "", "synthetic empty flow inventory", "", false
		}
		if (p == "/flows" || p == "/flow" || strings.HasPrefix(p, "/flow/")) && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
			summary := inspectNodeREDFlow(request.body)
			st.mu.Lock()
			priorDeploy := st.values["nodered_deploy"] == "seen"
			st.values["nodered_deploy"] = "seen"
			st.mu.Unlock()
			action, cve := "flow_deploy", ""
			if summary.trigger && summary.executionCapable {
				action, cve = "flow_deploy_trigger_probe", "CVE-2026-58115"
				if priorDeploy {
					action = "confirmed_follow_on"
				}
			} else if priorDeploy {
				action = "flow_deploy_follow_on"
			}
			return writeJSON(w, 200, map[string]any{"rev": "synthetic-2"}), action, "", "", "flow structure observed and discarded; no node started or payload fetched", cve, cve != ""
		}
		if p == "/nodes" && r.Method == http.MethodGet {
			return writeJSON(w, 200, []any{}), "node_catalog", "", "", "synthetic installed-node catalog", "", false
		}
		if p == "/nodes" && r.Method == http.MethodPost {
			return writeJSON(w, 400, map[string]any{"code": "module_install_blocked", "message": "Module installation unavailable"}), "node_module_install_attempt", "", "", "module request discarded; no package fetched or installed", "", false
		}
		return writeJSON(w, 404, map[string]any{"code": "not_found", "message": "Not found"}), "not_found", "", "", "", "", false
	}
	return 404, "not_found", "", "", "", "", false
}

func isPHP2Shell109618(request *requestEvidence, r *http.Request) bool {
	if request == nil {
		return false
	}
	// Sophos observed this user agent and multipart boundary together in
	// active CVE-2026-109618 exploitation. Requiring both avoids attributing a
	// generic multipart request or a copied scanner label to the CVE.
	return strings.Contains(strings.ToLower(r.UserAgent()), "php2shell-scan/109618") && request.multipartBoundary == "B7kQpoc618"
}

func isPHP2Shell109619(request *requestEvidence, r *http.Request) bool {
	if request == nil || !request.hasSessionProgress {
		return false
	}
	// The session-global path requires upload-progress handling and an
	// attacker-controlled PHP session identifier. Values are used only to
	// derive the in-memory correlation key and are never persisted.
	return request.phpSessionID != "" || hasCookie(r, "PHPSESSID")
}
