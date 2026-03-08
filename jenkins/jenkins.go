package jenkins

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const defaultPort = "8080"

var _ honeypots.Honeypot = &honeypot{}

type saveFunc func(*pb.JenkinsRequest) error

type honeypot struct {
	logger zerolog.Logger
	save   saveFunc
}

func New() honeypots.Honeypot {
	return &honeypot{
		logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "jenkins").Logger(),
		save:   persistence.SaveJenkinsRequest,
	}
}

func (h *honeypot) Name() string {
	return "jenkins"
}

func (h *honeypot) Start() {
	port := os.Getenv("JENKINS_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleRequest)
	mux.HandleFunc("/login", h.handleRequest)
	mux.HandleFunc("/j_spring_security_check", h.handleRequest)
	mux.HandleFunc("/script", h.handleRequest)
	mux.HandleFunc("/scriptText", h.handleRequest)
	mux.HandleFunc("/api/json", h.handleRequest)

	h.logger.Fatal().Err(http.ListenAndServe(":"+port, mux)).Str("port", port).Msg("failed to start jenkins honeypot")
}

func (h *honeypot) handleRequest(w http.ResponseWriter, r *http.Request) {
	guid := uuid.NewV4().String()
	body, _ := readBody(r)
	remoteAddr := remoteIP(r.RemoteAddr)
	username, password := extractCredentials(r, body)

	req := &pb.JenkinsRequest{
		RemoteAddr: remoteAddr,
		Guid:       guid,
		Method:     r.Method,
		Path:       r.URL.Path,
		Username:   username,
		Password:   password,
		Script:     extractScript(r.URL.Path, body),
		Data:       string(body),
	}
	if err := h.save(req); err != nil {
		h.logger.Error().Err(err).Str("guid", guid).Str("path", r.URL.Path).Msg("failed to persist jenkins request")
	}

	w.Header().Set("Server", "Jetty(10.0.18)")
	w.Header().Set("X-Jenkins", "2.426.3")
	w.Header().Set("X-Jenkins-Session", "ad9f8d49")

	switch r.URL.Path {
	case "/script", "/scriptText":
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		_, _ = io.WriteString(w, "Result: Script execution completed\n")
	case "/j_spring_security_check":
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusFound)
	default:
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = io.WriteString(w, dashboardHTML)
	}
}

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func extractCredentials(r *http.Request, body []byte) (string, string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}

	values := parseForm(body)
	username := firstNonEmpty(values.Get("j_username"), values.Get("username"), values.Get("user"))
	password := firstNonEmpty(values.Get("j_password"), values.Get("password"), values.Get("pass"))
	return username, password
}

func extractScript(path string, body []byte) string {
	if path != "/script" && path != "/scriptText" {
		return ""
	}
	values := parseForm(body)
	return values.Get("script")
}

func parseForm(body []byte) url.Values {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return url.Values{}
	}
	return values
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

const dashboardHTML = `<!doctype html>
<html>
  <head>
    <title>Dashboard [Jenkins]</title>
  </head>
  <body>
    <h1>Welcome to Jenkins 2.426.3 LTS</h1>
    <ul>
      <li>build-web</li>
      <li>deploy-api</li>
      <li>backup-nightly</li>
      <li>security-scan</li>
    </ul>
  </body>
</html>`
