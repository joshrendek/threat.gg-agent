package kubernetes

import (
  "crypto/rand"
  "crypto/rsa"
  "crypto/tls"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/json"
  "encoding/pem"
  "fmt"
  "github.com/gorilla/mux"
  "github.com/joshrendek/hnypots-agent/honeypots"
  "github.com/rs/zerolog"
  "log"
  "math/big"
  "net/http"
  "os"
  "time"
)

type honeypot struct {
  logger zerolog.Logger
}

func init() {
  honeypots.Register(&honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "kubernetes").Logger()})
}

func (h *honeypot) Name() string {
  return "kubernetes"
}

// Namespace represents a Kubernetes Namespace object
type Namespace struct {
  Kind       string            `json:"kind"`
  APIVersion string            `json:"apiVersion"`
  Metadata   map[string]string `json:"metadata"`
}

// Pod represents a Kubernetes Pod object
type Pod struct {
  Kind       string            `json:"kind"`
  APIVersion string            `json:"apiVersion"`
  Metadata   map[string]string `json:"metadata"`
  Spec       map[string]string `json:"spec"`
}

// Middleware to log every request, including credentials and certificates
func loggingMiddleware(logger zerolog.Logger) func(next http.Handler) http.Handler {
  return func(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      // Log HTTP method and URL
      logger.Printf("Received request: %s %s", r.Method, r.URL.Path)

      // Log headers (excluding sensitive ones)
      for name, values := range r.Header {
        for _, value := range values {
          // Exclude logging of Authorization header content
          if name == "Authorization" {
            logger.Printf("Header: %s: [REDACTED]", name)
          } else {
            logger.Printf("Header: %s: %s", name, value)
          }
        }
      }

      // Log Authorization header presence
      if authHeader := r.Header.Get("Authorization"); authHeader != "" {
        logger.Printf("Authorization header is present")
      }

      // Log client certificates if provided
      if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
        for i, cert := range r.TLS.PeerCertificates {
          logger.Printf("Client Certificate %d:", i+1)
          logger.Printf("\tSubject: %s", cert.Subject.String())
          logger.Printf("\tIssuer: %s", cert.Issuer.String())
        }
      }

      // Call the next handler
      next.ServeHTTP(w, r)
    })
  }
}

func namespacesHandler(w http.ResponseWriter, r *http.Request) {
  // Return a list of namespaces
  namespaces := []Namespace{
    {
      Kind:       "Namespace",
      APIVersion: "v1",
      Metadata: map[string]string{
        "name": "default",
      },
    },
    {
      Kind:       "Namespace",
      APIVersion: "v1",
      Metadata: map[string]string{
        "name": "kube-system",
      },
    },
  }

  response := map[string]interface{}{
    "kind":       "NamespaceList",
    "apiVersion": "v1",
    "items":      namespaces,
  }

  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

func namespaceHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  namespaceName := vars["namespace"]

  // Return the namespace
  namespace := Namespace{
    Kind:       "Namespace",
    APIVersion: "v1",
    Metadata: map[string]string{
      "name": namespaceName,
    },
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(namespace)
}

func podsHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  namespaceName := vars["namespace"]

  if r.Method == http.MethodGet {
    // Return a list of pods in the namespace
    pods := []Pod{
      {
        Kind:       "Pod",
        APIVersion: "v1",
        Metadata: map[string]string{
          "name":      "pod-1",
          "namespace": namespaceName,
        },
        Spec: map[string]string{
          "containers": "[]",
        },
      },
    }

    response := map[string]interface{}{
      "kind":       "PodList",
      "apiVersion": "v1",
      "items":      pods,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
  } else if r.Method == http.MethodPost {
    // Create a pod (mock)
    var pod Pod
    err := json.NewDecoder(r.Body).Decode(&pod)
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }
    pod.Metadata["namespace"] = namespaceName
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(pod)
  }
}

func (h *honeypot) Start() {
  router := mux.NewRouter()

  // Apply the logging middleware to all routes
  router.Use(loggingMiddleware(h.logger))

  // Handle /api/v1/namespaces
  router.HandleFunc("/api/v1/namespaces", namespacesHandler).Methods("GET")

  // Handle /api/v1/namespaces/{namespace}
  router.HandleFunc("/api/v1/namespaces/{namespace}", namespaceHandler).Methods("GET")

  // Handle /api/v1/namespaces/{namespace}/pods
  router.HandleFunc("/api/v1/namespaces/{namespace}/pods", podsHandler).Methods("GET", "POST")

  // Generate the TLS certificate
  cert, err := generateSelfSignedCert()
  if err != nil {
    log.Fatalf("Failed to generate TLS certificate: %v", err)
  }

  // Configure TLS settings
  tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientAuth:   tls.RequestClientCert,
  }

  // Create a custom server to use TLS
  server := &http.Server{
    Addr:      ":6443",
    Handler:   router,
    TLSConfig: tlsConfig,
  }

  // generate the .crt and .key files

  // Start the server
  fmt.Println("Starting mock Kubernetes API server on :6443")
  h.logger.Fatal().Err(server.ListenAndServeTLS("server.crt", "server.key")).Msg("failed to start k8s")
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
