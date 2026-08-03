// Package consul emulates a bounded subset of the Consul HTTP API.
package consul

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort = "8500"
	maxBody     = 64 << 10
	maxClients  = 128
	maxKeys     = 128
	maxSessions = 64
	maxSaves    = 32
)

var saveRequest = persistence.SaveConsulRequest
var saveSlots = make(chan struct{}, maxSaves)
var labeledSecretPattern = regexp.MustCompile(`(?i)(?:access[_-]?token|token|secret|password|authorization|api[_-]?key|cookie)\s*[:=]\s*["']?[^&,;\s"']+["']?`)

type honeypot struct{ logger zerolog.Logger }

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "consul").Logger()}
}
func (h *honeypot) Name() string { return "consul" }
func (h *honeypot) Start() {
	port := os.Getenv("CONSUL_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	srv := &http.Server{Addr: ":" + port, Handler: newHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10}
	h.logger.Info().Str("port", port).Msg("starting Consul HTTP honeypot")
	h.logger.Fatal().Err(srv.ListenAndServe()).Msg("failed to start Consul honeypot")
}

type clientState struct {
	kv       map[string][]byte
	sessions map[string]session
	touched  time.Time
	index    uint64
}
type session struct{ ID, Name, Node, TTL, Behavior string }
type stateStore struct {
	mu      sync.Mutex
	clients map[string]*clientState
}

var states = &stateStore{clients: make(map[string]*clientState)}

func (s *stateStore) forClient(key string) *clientState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.clients[key]; state != nil {
		state.touched = time.Now()
		return state
	}
	if len(s.clients) >= maxClients {
		var oldest string
		var at time.Time
		for k, v := range s.clients {
			if oldest == "" || v.touched.Before(at) {
				oldest, at = k, v.touched
			}
		}
		delete(s.clients, oldest)
	}
	state := &clientState{kv: map[string][]byte{"config/database/host": []byte("postgres.service.consul"), "config/database/port": []byte("5432")}, sessions: make(map[string]session), touched: time.Now(), index: 42}
	s.clients[key] = state
	return state
}

func newHandler() http.Handler {
	return capture(cmdresp.MuxMiddleware("consul")(http.HandlerFunc(serveHTTP)))
}

func capture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		if len(body) > maxBody {
			body = body[:maxBody]
			http.Error(w, "request entity too large", 413)
			persist(r, body, 413)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		rw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		if rw.status == 0 {
			rw.status = http.StatusOK
		}
		persist(r, body, rw.status)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func persist(r *http.Request, body []byte, status int) {
	source, fp := tokenMetadata(r)
	q := redactedQuery(r.URL.Query()).Encode()
	in := &proto.ConsulRequest{RemoteAddr: bounded(r.RemoteAddr, 128), Guid: uuid.NewV4().String(), Method: bounded(r.Method, 16), Path: bounded(r.URL.EscapedPath(), 8192), Query: bounded(q, 16384), TokenSource: source, TokenFingerprint: fp, UserAgent: bounded(r.UserAgent(), 4096), Body: bounded(redactedBody(body), maxBody), ResponseStatus: int32(status)}
	select {
	case saveSlots <- struct{}{}:
		save := saveRequest
		go func() { defer func() { <-saveSlots }(); _ = save(in) }()
	default:
	}
}

func tokenMetadata(r *http.Request) (string, string) {
	token, source := r.Header.Get("X-Consul-Token"), "x-consul-token"
	if token == "" {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token, source = parts[1], "bearer"
		}
	}
	if token == "" {
		token, source = r.URL.Query().Get("token"), "query"
	}
	if token == "" {
		return "anonymous", ""
	}
	sum := sha256.Sum256([]byte(token))
	return source, "sha256:" + hex.EncodeToString(sum[:8])
}
func redactedQuery(q url.Values) url.Values {
	out := make(url.Values, len(q))
	for k, v := range q {
		if isSecretKey(k) {
			out[k] = []string{"[REDACTED]"}
		} else {
			out[k] = v
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
	var v any
	if json.Unmarshal(body, &v) != nil {
		raw := bounded(string(body), maxBody)
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
	redact(v)
	out, _ := json.Marshal(v)
	return string(out)
}
func redact(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			if isSecretKey(k) {
				x[k] = "[REDACTED]"
			} else {
				redact(c)
			}
		}
	case []any:
		for _, c := range x {
			redact(c)
		}
	}
}
func bounded(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Consul-Index", "42")
	w.Header().Set("X-Consul-KnownLeader", "true")
	w.Header().Set("X-Consul-LastContact", "0")
	state := states.forClient(clientKey(r))
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/v1/agent/self":
		jsonOut(w, agentSelf)
	case r.Method == "GET" && p == "/v1/agent/members":
		jsonOut(w, members)
	case r.Method == "GET" && p == "/v1/agent/services":
		jsonOut(w, agentServices)
	case r.Method == "GET" && p == "/v1/agent/checks":
		jsonOut(w, checks)
	case r.Method == "GET" && p == "/v1/catalog/datacenters":
		jsonOut(w, []string{"dc1"})
	case r.Method == "GET" && p == "/v1/catalog/nodes":
		jsonOut(w, nodes)
	case r.Method == "GET" && p == "/v1/catalog/services":
		jsonOut(w, map[string][]string{"consul": {}, "postgresql": {"primary"}, "redis": {"cache"}, "web": {"v1"}})
	case r.Method == "GET" && strings.HasPrefix(p, "/v1/catalog/service/"):
		jsonOut(w, catalogService(strings.TrimPrefix(p, "/v1/catalog/service/")))
	case r.Method == "GET" && strings.HasPrefix(p, "/v1/health/service/"):
		jsonOut(w, healthService(strings.TrimPrefix(p, "/v1/health/service/")))
	case r.Method == "GET" && p == "/v1/status/leader":
		jsonOut(w, "10.0.0.10:8300")
	case r.Method == "GET" && p == "/v1/status/peers":
		jsonOut(w, []string{"10.0.0.10:8300", "10.0.0.11:8300", "10.0.0.12:8300"})
	case strings.HasPrefix(p, "/v1/kv/"):
		handleKV(w, r, state, strings.TrimPrefix(p, "/v1/kv/"))
	case r.Method == "PUT" && p == "/v1/session/create":
		handleSessionCreate(w, r, state)
	case r.Method == "GET" && p == "/v1/session/list":
		stateList(w, state)
	case r.Method == "GET" && strings.HasPrefix(p, "/v1/session/info/"):
		stateInfo(w, state, strings.TrimPrefix(p, "/v1/session/info/"))
	case r.Method == "PUT" && strings.HasPrefix(p, "/v1/session/destroy/"):
		stateDestroy(w, state, strings.TrimPrefix(p, "/v1/session/destroy/"))
	default:
		http.Error(w, "404 page not found", 404)
	}
}

func handleKV(w http.ResponseWriter, r *http.Request, s *clientState, key string) {
	states.mu.Lock()
	defer states.mu.Unlock()
	switch r.Method {
	case "GET":
		if _, ok := r.URL.Query()["keys"]; ok {
			keys := make([]string, 0, len(s.kv))
			for k := range s.kv {
				if strings.HasPrefix(k, key) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			jsonOut(w, keys)
			return
		}
		value, ok := s.kv[key]
		if !ok {
			http.Error(w, "", 404)
			return
		}
		if _, ok := r.URL.Query()["raw"]; ok {
			_, _ = w.Write(value)
			return
		}
		jsonOut(w, []map[string]any{{"LockIndex": 0, "Key": key, "Flags": 0, "Value": base64.StdEncoding.EncodeToString(value), "CreateIndex": 1, "ModifyIndex": s.index}})
	case "PUT":
		if _, exists := s.kv[key]; !exists && len(s.kv) >= maxKeys {
			http.Error(w, "KV limit reached", 429)
			return
		}
		body, _ := io.ReadAll(r.Body)
		s.index++
		s.kv[key] = append([]byte(nil), body...)
		jsonOut(w, true)
	case "DELETE":
		delete(s.kv, key)
		s.index++
		jsonOut(w, true)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
func handleSessionCreate(w http.ResponseWriter, r *http.Request, s *clientState) {
	var in struct{ Name, Node, TTL, Behavior string }
	_ = json.NewDecoder(r.Body).Decode(&in)
	states.mu.Lock()
	defer states.mu.Unlock()
	if len(s.sessions) >= maxSessions {
		http.Error(w, "session limit reached", 429)
		return
	}
	id := uuid.NewV4().String()
	if in.Node == "" {
		in.Node = "consul-server-01"
	}
	if in.Behavior == "" {
		in.Behavior = "release"
	}
	s.sessions[id] = session{ID: id, Name: bounded(in.Name, 256), Node: bounded(in.Node, 256), TTL: bounded(in.TTL, 32), Behavior: bounded(in.Behavior, 32)}
	jsonOut(w, map[string]string{"ID": id})
}
func stateList(w http.ResponseWriter, s *clientState) {
	states.mu.Lock()
	defer states.mu.Unlock()
	out := make([]session, 0, len(s.sessions))
	for _, v := range s.sessions {
		out = append(out, v)
	}
	jsonOut(w, out)
}
func stateInfo(w http.ResponseWriter, s *clientState, id string) {
	states.mu.Lock()
	defer states.mu.Unlock()
	if v, ok := s.sessions[id]; ok {
		jsonOut(w, []session{v})
	} else {
		jsonOut(w, []session{})
	}
}
func stateDestroy(w http.ResponseWriter, s *clientState, id string) {
	states.mu.Lock()
	defer states.mu.Unlock()
	delete(s.sessions, id)
	jsonOut(w, true)
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

var agentSelf = map[string]any{"Config": map[string]any{"Datacenter": "dc1", "NodeName": "consul-server-01", "NodeID": "2f4e5668-58bb-4d20-a7d4-8698af62a5f4", "Server": true, "Version": "1.21.2", "Revision": "75a8c3f"}, "Member": map[string]any{"Name": "consul-server-01", "Addr": "10.0.0.10", "Port": 8301, "Status": 1, "Tags": map[string]string{"dc": "dc1", "role": "consul", "port": "8300", "build": "1.21.2"}}}
var members = []map[string]any{{"Name": "consul-server-01", "Addr": "10.0.0.10", "Port": 8301, "Status": 1, "Tags": map[string]string{"dc": "dc1", "role": "consul"}}, {"Name": "worker-01", "Addr": "10.0.0.21", "Port": 8301, "Status": 1, "Tags": map[string]string{"dc": "dc1", "role": "node"}}}
var agentServices = map[string]any{"consul": map[string]any{"ID": "consul", "Service": "consul", "Port": 8300}, "postgresql-primary": map[string]any{"ID": "postgresql-primary", "Service": "postgresql", "Tags": []string{"primary"}, "Address": "10.0.0.31", "Port": 5432}, "redis-cache": map[string]any{"ID": "redis-cache", "Service": "redis", "Tags": []string{"cache"}, "Address": "10.0.0.32", "Port": 6379}, "web-v1": map[string]any{"ID": "web-v1", "Service": "web", "Tags": []string{"v1"}, "Address": "10.0.0.41", "Port": 8080}}
var checks = map[string]any{"serfHealth": map[string]any{"Node": "consul-server-01", "CheckID": "serfHealth", "Name": "Serf Health Status", "Status": "passing", "Output": "Agent alive and reachable"}}
var nodes = []map[string]any{{"ID": "2f4e5668-58bb-4d20-a7d4-8698af62a5f4", "Node": "consul-server-01", "Address": "10.0.0.10", "Datacenter": "dc1"}, {"ID": "8b61f9ad-c903-4266-a9d4-315a0890bf78", "Node": "worker-01", "Address": "10.0.0.21", "Datacenter": "dc1"}}

func catalogService(name string) []map[string]any {
	ports := map[string]int{"consul": 8300, "postgresql": 5432, "redis": 6379, "web": 8080}
	port, ok := ports[name]
	if !ok {
		return []map[string]any{}
	}
	return []map[string]any{{"Node": "worker-01", "Address": "10.0.0.21", "Datacenter": "dc1", "ServiceID": name + "-01", "ServiceName": name, "ServiceAddress": fmt.Sprintf("10.0.0.%d", 30+port%10), "ServicePort": port}}
}
func healthService(name string) []map[string]any {
	out := []map[string]any{}
	for _, v := range catalogService(name) {
		out = append(out, map[string]any{"Node": map[string]any{"Node": v["Node"], "Address": v["Address"], "Datacenter": "dc1"}, "Service": map[string]any{"ID": v["ServiceID"], "Service": name, "Address": v["ServiceAddress"], "Port": v["ServicePort"]}, "Checks": []map[string]any{{"CheckID": "service:" + name + "-01", "Name": "Service health status", "Status": "passing", "Output": "HTTP GET http://localhost:health: 200 OK"}}})
	}
	return out
}
