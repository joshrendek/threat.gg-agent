package kubernetes

import (
  "crypto/rand"
  "crypto/rsa"
  "crypto/tls"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "fmt"
  "github.com/gorilla/mux"
  "github.com/joshrendek/hnypots-agent/honeypots"
  "github.com/rs/zerolog"
  "math/big"
  "net/http"
  "os"
  "time"
)

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

func (h *honeypot) Start() {
	fmt.Println("----------- START K8s")
	router := mux.NewRouter()
	router.Use(h.LoggingMiddleware)

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

	// Generate the TLS certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		h.logger.Fatal().AnErr("Failed to generate TLS certificate: %v", err).Msg("failed to start k8s")
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		//ClientAuth:   tls.RequestClientCert,
	}

	// Create a custom server to use TLS
	server := &http.Server{
		Addr:      ":6443",
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	// Start the server
	fmt.Println("Starting mock Kubernetes API server on :6443")
	h.logger.Fatal().Err(server.ListenAndServeTLS("", "")).Msg("failed to start k8s")
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (h *honeypot) LoggingMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // Start timer
    start := time.Now()

    // Wrap the ResponseWriter to capture the status code
    rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

    // Process the request
    next.ServeHTTP(rw, r)

    // Calculate duration
    duration := time.Since(start)

    // Log the details
    h.logger.Info().
      Str("method", r.Method).
      Str("url", r.URL.String()).
      Str("remote_addr", r.RemoteAddr).
      Str("user_agent", r.UserAgent()).
      Int("status", rw.statusCode).
      Dur("duration", duration).
      Msg("HTTP request processed")
  })
}

// Function to generate a self-signed TLS certificate and key
func generateSelfSignedCert() (tls.Certificate, error) {
	// Set up the certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Valid for one year

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode the certificate and key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})

	// Load the certificate and key into tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, err
}
