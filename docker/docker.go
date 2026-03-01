package docker

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort    = "2375"
	maxBodySize    = 1 << 20 // 1MB
	serverVersion  = "24.0.7"
	apiVersion     = "1.43"
	fakeContainerID = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	fakeExecID      = "e1f2a3b4c5d6e1f2a3b4c5d6e1f2a3b4c5d6e1f2a3b4c5d6e1f2a3b4c5d6e1f2"
)

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "docker").Logger()

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "docker").Logger()}
}

func (h *honeypot) Name() string {
	return "docker"
}

func (h *honeypot) Start() {
	port := os.Getenv("DOCKER_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	r := mux.NewRouter()
	registerRoutes(r)

	h.logger.Info().Str("port", port).Msg("starting docker api honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), r)).Msg("failed to start")
}

func registerRoutes(r *mux.Router) {
	r.HandleFunc("/_ping", handlePing).Methods("GET", "HEAD")
	r.HandleFunc("/version", handleVersion).Methods("GET")
	r.HandleFunc("/info", handleInfo).Methods("GET")
	r.HandleFunc("/containers/json", handleContainerList).Methods("GET")
	r.HandleFunc("/containers/create", handleContainerCreate).Methods("POST")
	r.HandleFunc("/containers/{id}/start", handleContainerStart).Methods("POST")
	r.HandleFunc("/containers/{id}/json", handleContainerInspect).Methods("GET")
	r.HandleFunc("/containers/{id}/exec", handleExecCreate).Methods("POST")
	r.HandleFunc("/exec/{id}/start", handleExecStart).Methods("POST")
	r.HandleFunc("/images/json", handleImageList).Methods("GET")
	r.HandleFunc("/images/create", handleImageCreate).Methods("POST")
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
}

func captureAndSave(r *http.Request) {
	guid := uuid.NewV4()

	var body string
	if r.Body != nil && (r.Method == "POST" || r.Method == "PUT") {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err == nil {
			body = string(data)
		}
		r.Body.Close()
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	req := &proto.DockerRequest{
		RemoteAddr: ip,
		Headers:    persistence.HttpToMap(map[string][]string(r.Header)),
		Path:       r.URL.Path,
		Method:     r.Method,
		Body:       body,
		Guid:       guid.String(),
		Hostname:   r.Host,
		UserAgent:  r.UserAgent(),
	}

	user, pass, ok := r.BasicAuth()
	if ok {
		req.Username = user
		req.Password = pass
	}

	go func(in *proto.DockerRequest) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Interface("panic", r).Msg("panic saving docker request")
			}
		}()
		if err := persistence.SaveDockerRequest(in); err != nil {
			logger.Error().Err(err).Msg("error saving docker request")
		}
	}(req)
}
