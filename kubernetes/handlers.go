package kubernetes

import (
  _ "embed"
  "encoding/json"
  "fmt"
  "github.com/gorilla/mux"
  "log"
  "net/http"
  "os"
)

//go:embed swagger.json
var openAPISpec string

// kubectl proxy --port=8001
//
//	curl -s \
//	 -H "Accept: application/com.github.proto-openapi.spec.v2@v1.0+protobuf" \
//	 http://127.0.0.1:8001/openapi/v2 \
//	 -o openapi.pb
func (h *honeypot) openapiHandler(w http.ResponseWriter, r *http.Request) {
  // Attempt to read the openapi.pb file
  data, err := os.ReadFile("kubernetes/openapi.pb")
  if err != nil {
    log.Printf("Failed to read openapi.pb: %v", err) // Log the specific error
    http.Error(w, "Internal Server Error: Could not read openapi.pb", http.StatusInternalServerError)
    return
  }

  // Set the Content-Type to Protobuf
  w.Header().Set("Content-Type", "application/vnd.kubernetes.protobuf")
  w.WriteHeader(http.StatusOK)

  // Write the data to the response
  _, writeErr := w.Write(data)
  if writeErr != nil {
    log.Printf("Failed to write response: %v", writeErr) // Log the write error
    http.Error(w, "Internal Server Error: Could not write response", http.StatusInternalServerError)
  }
}

// Handler for /version (cluster-info)
func (h *honeypot) versionHandler(w http.ResponseWriter, r *http.Request) {
  response := map[string]string{
    "major":        "1",
    "minor":        "28",
    "gitVersion":   "v1.28.11",
    "gitCommit":    "f25b321b9ae42cb1bfaa00b3eec9a12566a15d91",
    "gitTreeState": "clean",
    "buildDate":    "2024-06-11T20:11:29Z",
    "goVersion":    "go1.21.11",
    "compiler":     "gc",
    "platform":     "linux/amd64",
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

// Handler for /api
func (h *honeypot) apiHandler(w http.ResponseWriter, r *http.Request) {
  response := map[string]interface{}{
    "kind":                       "APIVersions",
    "apiVersion":                 "v1",
    "versions":                   []string{"v1"},
    "serverAddressByClientCIDRs": []interface{}{},
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

func (h *honeypot) catchAllHandler(w http.ResponseWriter, r *http.Request) {
  body := make([]byte, r.ContentLength)
  _, _ = r.Body.Read(body)
  h.logger.Info().Str("path", r.URL.Path).Str("method", r.Method).Bytes("body", body).Msg("Request received")
}

// Handler for /api/v1
func (h *honeypot) apiV1Handler(w http.ResponseWriter, r *http.Request) {
  response := map[string]interface{}{
    "kind":         "APIResourceList",
    "apiVersion":   "v1",
    "groupVersion": "v1",
    "resources": []map[string]interface{}{
      {
        "name":               "pods",
        "namespaced":         true,
        "kind":               "Pod",
        "verbs":              []string{"get", "list", "create", "update", "delete"},
        "shortNames":         []string{"po"},
        "categories":         []string{"all"},
        "storageVersionHash": "abc123",
      },
      {
        "name":               "namespaces",
        "namespaced":         false,
        "kind":               "Namespace",
        "verbs":              []string{"get", "list", "create", "update", "delete"},
        "shortNames":         []string{"ns"},
        "storageVersionHash": "abc456",
      },
      // Add other resources as needed
    },
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

// Handler for /apis
func (h *honeypot) apisHandler(w http.ResponseWriter, r *http.Request) {
  response := map[string]interface{}{
    "kind":       "APIGroupList",
    "apiVersion": "v1",
    "groups": []map[string]interface{}{
      {
        "name": "apps",
        "versions": []map[string]string{
          {
            "groupVersion": "apps/v1",
            "version":      "v1",
          },
        },
        "preferredVersion": map[string]string{
          "groupVersion": "apps/v1",
          "version":      "v1",
        },
      },
      // Add other API groups as needed
    },
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

// Handler for /apis/apps
func (h *honeypot) apiAppsHandler(w http.ResponseWriter, r *http.Request) {
  response := map[string]interface{}{
    "kind":       "APIGroup",
    "apiVersion": "v1",
    "name":       "apps",
    "versions": []map[string]string{
      {
        "groupVersion": "apps/v1",
        "version":      "v1",
      },
    },
    "preferredVersion": map[string]string{
      "groupVersion": "apps/v1",
      "version":      "v1",
    },
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

// Handler for /apis/apps/v1
func (h *honeypot) apiAppsV1Handler(w http.ResponseWriter, r *http.Request) {
  // refresh with k get --raw /apis
  resp := `{"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"apiregistration.k8s.io","versions":[{"groupVersion":"apiregistration.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apiregistration.k8s.io/v1","version":"v1"}},{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},{"name":"events.k8s.io","versions":[{"groupVersion":"events.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"events.k8s.io/v1","version":"v1"}},{"name":"authentication.k8s.io","versions":[{"groupVersion":"authentication.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"authentication.k8s.io/v1","version":"v1"}},{"name":"authorization.k8s.io","versions":[{"groupVersion":"authorization.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"authorization.k8s.io/v1","version":"v1"}},{"name":"autoscaling","versions":[{"groupVersion":"autoscaling/v2","version":"v2"},{"groupVersion":"autoscaling/v1","version":"v1"}],"preferredVersion":{"groupVersion":"autoscaling/v2","version":"v2"}},{"name":"batch","versions":[{"groupVersion":"batch/v1","version":"v1"}],"preferredVersion":{"groupVersion":"batch/v1","version":"v1"}},{"name":"certificates.k8s.io","versions":[{"groupVersion":"certificates.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"certificates.k8s.io/v1","version":"v1"}},{"name":"networking.k8s.io","versions":[{"groupVersion":"networking.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"networking.k8s.io/v1","version":"v1"}},{"name":"policy","versions":[{"groupVersion":"policy/v1","version":"v1"}],"preferredVersion":{"groupVersion":"policy/v1","version":"v1"}},{"name":"rbac.authorization.k8s.io","versions":[{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"rbac.authorization.k8s.io/v1","version":"v1"}},{"name":"storage.k8s.io","versions":[{"groupVersion":"storage.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"storage.k8s.io/v1","version":"v1"}},{"name":"admissionregistration.k8s.io","versions":[{"groupVersion":"admissionregistration.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"admissionregistration.k8s.io/v1","version":"v1"}},{"name":"apiextensions.k8s.io","versions":[{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}},{"name":"scheduling.k8s.io","versions":[{"groupVersion":"scheduling.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"scheduling.k8s.io/v1","version":"v1"}},{"name":"coordination.k8s.io","versions":[{"groupVersion":"coordination.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"coordination.k8s.io/v1","version":"v1"}},{"name":"node.k8s.io","versions":[{"groupVersion":"node.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"node.k8s.io/v1","version":"v1"}},{"name":"discovery.k8s.io","versions":[{"groupVersion":"discovery.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"discovery.k8s.io/v1","version":"v1"}},{"name":"flowcontrol.apiserver.k8s.io","versions":[{"groupVersion":"flowcontrol.apiserver.k8s.io/v1beta3","version":"v1beta3"},{"groupVersion":"flowcontrol.apiserver.k8s.io/v1beta2","version":"v1beta2"}],"preferredVersion":{"groupVersion":"flowcontrol.apiserver.k8s.io/v1beta3","version":"v1beta3"}},{"name":"acme.cert-manager.io","versions":[{"groupVersion":"acme.cert-manager.io/v1","version":"v1"},{"groupVersion":"acme.cert-manager.io/v1beta1","version":"v1beta1"},{"groupVersion":"acme.cert-manager.io/v1alpha3","version":"v1alpha3"},{"groupVersion":"acme.cert-manager.io/v1alpha2","version":"v1alpha2"}],"preferredVersion":{"groupVersion":"acme.cert-manager.io/v1","version":"v1"}},{"name":"cert-manager.io","versions":[{"groupVersion":"cert-manager.io/v1","version":"v1"},{"groupVersion":"cert-manager.io/v1beta1","version":"v1beta1"},{"groupVersion":"cert-manager.io/v1alpha3","version":"v1alpha3"},{"groupVersion":"cert-manager.io/v1alpha2","version":"v1alpha2"}],"preferredVersion":{"groupVersion":"cert-manager.io/v1","version":"v1"}},{"name":"monitoring.coreos.com","versions":[{"groupVersion":"monitoring.coreos.com/v1","version":"v1"},{"groupVersion":"monitoring.coreos.com/v1alpha1","version":"v1alpha1"}],"preferredVersion":{"groupVersion":"monitoring.coreos.com/v1","version":"v1"}},{"name":"operators.coreos.com","versions":[{"groupVersion":"operators.coreos.com/v2","version":"v2"},{"groupVersion":"operators.coreos.com/v1","version":"v1"},{"groupVersion":"operators.coreos.com/v1alpha2","version":"v1alpha2"},{"groupVersion":"operators.coreos.com/v1alpha1","version":"v1alpha1"}],"preferredVersion":{"groupVersion":"operators.coreos.com/v2","version":"v2"}},{"name":"snapshot.storage.k8s.io","versions":[{"groupVersion":"snapshot.storage.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"snapshot.storage.k8s.io/v1","version":"v1"}},{"name":"px.dev","versions":[{"groupVersion":"px.dev/v1alpha1","version":"v1alpha1"}],"preferredVersion":{"groupVersion":"px.dev/v1alpha1","version":"v1alpha1"}},{"name":"cilium.io","versions":[{"groupVersion":"cilium.io/v2","version":"v2"},{"groupVersion":"cilium.io/v2alpha1","version":"v2alpha1"}],"preferredVersion":{"groupVersion":"cilium.io/v2","version":"v2"}},{"name":"metrics.k8s.io","versions":[{"groupVersion":"metrics.k8s.io/v1beta1","version":"v1beta1"}],"preferredVersion":{"groupVersion":"metrics.k8s.io/v1beta1","version":"v1beta1"}}]}`
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(http.StatusOK)
  w.Write([]byte(resp))
}

// Add RBAC structs
type Role struct {
  Kind       string       `json:"kind,omitempty"`
  APIVersion string       `json:"apiVersion,omitempty"`
  Metadata   ObjectMeta   `json:"metadata,omitempty"`
  Rules      []PolicyRule `json:"rules,omitempty"`
}

type PolicyRule struct {
  APIGroups     []string `json:"apiGroups,omitempty"`
  Resources     []string `json:"resources,omitempty"`
  Verbs         []string `json:"verbs,omitempty"`
  ResourceNames []string `json:"resourceNames,omitempty"`
}

// In-memory store for roles
var roleStore = make(map[string][]Role) // Keyed by namespace

func (h *honeypot) rolesHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  namespace := vars["namespace"]

  if r.Method == http.MethodGet {
    roles := roleStore[namespace]
    response := map[string]interface{}{
      "kind":       "RoleList",
      "apiVersion": "rbac.authorization.k8s.io/v1",
      "items":      roles,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
  } else if r.Method == http.MethodPost {
    var role Role
    err := json.NewDecoder(r.Body).Decode(&role)
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }
    roleStore[namespace] = append(roleStore[namespace], role)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(role)
  }
}

func (h *honeypot) apiRBACV1Handler(w http.ResponseWriter, r *http.Request) {
  response := map[string]interface{}{
    "kind":         "APIResourceList",
    "apiVersion":   "v1",
    "groupVersion": "rbac.authorization.k8s.io/v1",
    "resources": []map[string]interface{}{
      {
        "name":         "roles",
        "singularName": "",
        "namespaced":   true,
        "kind":         "Role",
        "verbs":        []string{"create", "delete", "get", "list", "patch", "update", "watch"},
      },
      {
        "name":         "rolebindings",
        "singularName": "",
        "namespaced":   true,
        "kind":         "RoleBinding",
        "verbs":        []string{"create", "delete", "get", "list", "patch", "update", "watch"},
      },
      {
        "name":         "clusterroles",
        "singularName": "",
        "namespaced":   false,
        "kind":         "ClusterRole",
        "verbs":        []string{"create", "delete", "get", "list", "patch", "update", "watch"},
      },
      {
        "name":         "clusterrolebindings",
        "singularName": "",
        "namespaced":   false,
        "kind":         "ClusterRoleBinding",
        "verbs":        []string{"create", "delete", "get", "list", "patch", "update", "watch"},
      },
      // Add more resources if needed
    },
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

func (h *honeypot) apiRBACHandler(w http.ResponseWriter, r *http.Request) {
  response := map[string]interface{}{
    "kind":       "APIGroup",
    "apiVersion": "v1",
    "name":       "rbac.authorization.k8s.io",
    "versions": []map[string]string{
      {
        "groupVersion": "rbac.authorization.k8s.io/v1",
        "version":      "v1",
      },
    },
    "preferredVersion": map[string]string{
      "groupVersion": "rbac.authorization.k8s.io/v1",
      "version":      "v1",
    },
  }
  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(response)
}

// In-memory store for namespaces
var namespaceStore = make(map[string]Namespace)

// Handler for /api/v1/namespaces
func (h *honeypot) namespacesHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method == http.MethodGet {
    // Return a list of namespaces
    var namespaces []Namespace
    for _, ns := range namespaceStore {
      namespaces = append(namespaces, ns)
    }
    response := map[string]interface{}{
      "kind":       "NamespaceList",
      "apiVersion": "v1",
      "items":      namespaces,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
  } else if r.Method == http.MethodPost {
    // Create a namespace
    var namespace Namespace
    err := json.NewDecoder(r.Body).Decode(&namespace)
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }
    name := namespace.Metadata["name"]
    namespaceStore[name.(string)] = namespace
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(namespace)
  }
}

// Handler for /api/v1/namespaces/{namespace}
func (h *honeypot) namespaceHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  namespaceName := vars["namespace"]

  namespace, exists := namespaceStore[namespaceName]
  if !exists {
    http.Error(w, "Namespace not found", http.StatusNotFound)
    return
  }

  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(namespace)
}

// In-memory store for pods, deployments, and daemonsets
var podStore = make(map[string][]Pod)               // Keyed by namespace
var deploymentStore = make(map[string][]Deployment) // Keyed by namespace
var daemonSetStore = make(map[string][]DaemonSet)   // Keyed by namespace

// Handler for /api/v1/namespaces/{namespace}/pods
func (h *honeypot) podsHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  namespaceName := vars["namespace"]

  if r.Method == http.MethodGet {
    // Return a list of pods in the namespace
    pods := podStore[namespaceName]
    response := map[string]interface{}{
      "kind":       "PodList",
      "apiVersion": "v1",
      "items":      pods,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
  } else if r.Method == http.MethodPost {
    // Create a pod
    var pod Pod
    err := json.NewDecoder(r.Body).Decode(&pod)
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }
    if pod.Metadata == nil {
      pod.Metadata = make(map[string]interface{})
    }
    pod.Metadata["namespace"] = namespaceName
    podStore[namespaceName] = append(podStore[namespaceName], pod)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(pod)
  }
}

func (h *honeypot) deploymentHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  namespaceName := vars["namespace"]
  deploymentName := vars["name"]

  deployments := deploymentStore[namespaceName]
  for _, deployment := range deployments {
    if deployment.Metadata.Name == deploymentName {
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(deployment)
      return
    }
  }

  http.Error(w, "Deployment not found", http.StatusNotFound)
}

// Handler for /apis/apps/v1/namespaces/{namespace}/deployments
func (h *honeypot) deploymentsHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Println("deployments handler")
  vars := mux.Vars(r)
  namespaceName := vars["namespace"]

  if r.Method == http.MethodGet {
    // Return a list of deployments in the namespace
    deployments := deploymentStore[namespaceName]
    response := map[string]interface{}{
      "kind":       "DeploymentList",
      "apiVersion": "apps/v1",
      "items":      deployments,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
  } else if r.Method == http.MethodPost {
    // Create a deployment
    var deployment Deployment
    err := json.NewDecoder(r.Body).Decode(&deployment)
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }
    if deployment.Metadata.Namespace == "" {
      deployment.Metadata.Namespace = namespaceName
    }
    h.logger.Info().Interface("deployment", deployment).Msg("Creating deployment")
    // Store the deployment
    deploymentStore[namespaceName] = append(deploymentStore[namespaceName], deployment)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(deployment)
  }
}

// Handler for /apis/apps/v1/namespaces/{namespace}/daemonsets
func (h *honeypot) daemonSetsHandler(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  namespaceName := vars["namespace"]

  if r.Method == http.MethodGet {
    // Return a list of daemonsets in the namespace
    daemonSets := daemonSetStore[namespaceName]
    response := map[string]interface{}{
      "kind":       "DaemonSetList",
      "apiVersion": "apps/v1",
      "items":      daemonSets,
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
  } else if r.Method == http.MethodPost {
    // Create a daemonset
    var daemonSet DaemonSet
    err := json.NewDecoder(r.Body).Decode(&daemonSet)
    if err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      return
    }
    if daemonSet.Metadata == nil {
      daemonSet.Metadata = make(map[string]interface{})
    }
    daemonSet.Metadata["namespace"] = namespaceName
    daemonSetStore[namespaceName] = append(daemonSetStore[namespaceName], daemonSet)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(daemonSet)
  }
}
