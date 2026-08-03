package kubernetes

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/joshrendek/hnypots-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/internal/kubetls"
	"github.com/rs/zerolog"
	"net/http"
	"os"
	"time"
)

const defaultPort = "6443"

var _ honeypots.Honeypot = &honeypot{}

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	h := &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "kubernetes").Logger()}
	return h
}

func (h *honeypot) Name() string {
	return "kubernetes"
}

func resolvePort() string {
	port := os.Getenv("KUBERNETES_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	return port
}

func (h *honeypot) Start() {
	port := resolvePort()
	fmt.Println("----------- START K8s")
	router := mux.NewRouter()
	router.Use(h.LoggingMiddleware)
	// Server-authored response override (admin-editable command_responses, scoped to
	// command_type="kubernetes"), keyed by "METHOD /path". Intercepts before the routes
	// below (including the catch-all); on a miss/error it falls through unchanged.
	router.Use(cmdresp.MuxMiddleware("kubernetes"))

	// Handle /version for cluster-info
	router.HandleFunc("/version", h.versionHandler).Methods("GET")
	router.HandleFunc("/version/", h.versionHandler).Methods("GET")

	router.HandleFunc("/openapi/v2", h.openapiHandler).Methods("GET")

	// Handle /api and /api/v1
	router.HandleFunc("/api", h.apiHandler).Methods("GET")
	router.HandleFunc("/api/v1", h.apiV1Handler).Methods("GET")

	// Handle /apis and related endpoints
	router.HandleFunc("/apis", h.apisHandler).Methods("GET")
	router.HandleFunc("/apis/apps", h.apiAppsHandler).Methods("GET")
	router.HandleFunc("/apis/apps/v1", h.apiAppsV1Handler).Methods("GET")
	// /apis/apps/v1/namespaces/default/deployments/test-deployment
	router.HandleFunc("/apis/apps/v1/namespaces/{namespace}/deployments", h.deploymentsHandler).Methods("GET", "POST")
	router.HandleFunc("/apis/apps/v1/namespaces/{namespace}/daemonsets", h.daemonSetsHandler).Methods("GET", "POST")
	router.HandleFunc("/apis/apps/v1/namespaces/{namespace}/deployments/{name}", h.deploymentHandler).Methods("GET")

	// Handle /api/v1/namespaces
	router.HandleFunc("/api/v1/namespaces", h.namespacesHandler).Methods("GET", "POST")
	router.HandleFunc("/api/v1/namespaces/{namespace}", h.namespaceHandler).Methods("GET")

	// Handle /api/v1/namespaces/{namespace}/pods
	router.HandleFunc("/api/v1/namespaces/{namespace}/pods", h.podsHandler).Methods("GET", "POST")

	router.HandleFunc("/apis/rbac.authorization.k8s.io", h.apiRBACHandler).Methods("GET")
	router.HandleFunc("/apis/rbac.authorization.k8s.io/v1", h.apiRBACV1Handler).Methods("GET")
	router.HandleFunc("/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles", h.rolesHandler).Methods("GET", "POST")

	// Record unmatched reconnaissance without reflecting attacker input.
	router.PathPrefix("/").HandlerFunc(h.catchAllHandler)

	// Generate the TLS certificate
	cert, err := kubetls.GenerateSelfSigned("localhost", "localhost")
	if err != nil {
		h.logger.Fatal().Err(err).Msg("failed to generate Kubernetes API TLS certificate")
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		//ClientAuth:   tls.RequestClientCert,
	}

	// Create a custom server to use TLS
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	// Start the server
	fmt.Println("Starting mock Kubernetes API server on :" + port)
	h.logger.Fatal().Err(server.ListenAndServeTLS("", "")).Msg("failed to start k8s")
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.statusCode != 0 {
		return
	}
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (h *honeypot) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Start timer
		start := time.Now()

		// Wrap the ResponseWriter to capture the status code
		rw := &responseWriter{ResponseWriter: w}

		// Process the request
		next.ServeHTTP(rw, r)
		if rw.statusCode == 0 {
			rw.statusCode = http.StatusOK
		}

		// Calculate duration
		duration := time.Since(start)

		// Log the details
		h.logger.Info().
			Str("method", r.Method).
			Str("path", r.URL.EscapedPath()).
			Str("remote_addr", r.RemoteAddr).
			Str("user_agent", r.UserAgent()).
			Int("status", rw.statusCode).
			Dur("duration", duration).
			Msg("HTTP request processed")
	})
}
