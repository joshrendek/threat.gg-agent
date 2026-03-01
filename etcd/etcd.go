package etcd

import (
	"encoding/json"
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
	defaultPort = "2379"
	maxBodySize = 1 << 20 // 1MB
	etcdVersion = "3.5.12"
)

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "etcd").Logger()

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "etcd").Logger()}
}

func (h *honeypot) Name() string {
	return "etcd"
}

func (h *honeypot) Start() {
	port := os.Getenv("ETCD_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}

	r := mux.NewRouter()
	registerRoutes(r)

	h.logger.Info().Str("port", port).Msg("starting etcd honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), r)).Msg("failed to start")
}

type requestData struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

func captureAndSave(r *http.Request) {
	guid := uuid.NewV4()

	var body string
	if r.Body != nil && (r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE") {
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

	reqData := requestData{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: persistence.HttpToMap(map[string][]string(r.Header)),
		Body:    body,
	}

	jsonBytes, err := json.Marshal(reqData)
	if err != nil {
		logger.Error().Err(err).Msg("error marshaling request data")
		return
	}

	req := &proto.EtcdRequest{
		RemoteAddr: ip,
		Guid:       guid.String(),
		Data:       string(jsonBytes),
	}

	go func(in *proto.EtcdRequest) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Interface("panic", r).Msg("panic saving etcd request")
			}
		}()
		if err := persistence.SaveEtcdRequest(in); err != nil {
			logger.Error().Err(err).Msg("error saving etcd request")
		}
	}(req)
}

func registerRoutes(r *mux.Router) {
	r.HandleFunc("/version", handleVersion).Methods("GET")
	r.HandleFunc("/health", handleHealth).Methods("GET")
	r.HandleFunc("/v2/keys/{path:.*}", handleKeysWrite).Methods("PUT")
	r.HandleFunc("/v2/keys/{path:.*}", handleKeysDelete).Methods("DELETE")
	r.HandleFunc("/v2/keys/{path:.*}", handleKeysRead).Methods("GET")
	r.HandleFunc("/v2/keys/", handleKeysRoot).Methods("GET")
	r.HandleFunc("/v2/keys", handleKeysRoot).Methods("GET")
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
}
