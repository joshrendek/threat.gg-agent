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
	resp := `{
  "kind": "APIResourceList",
  "groupVersion": "v1",
  "resources": [
    {
      "name": "bindings",
      "singularName": "binding",
      "namespaced": true,
      "kind": "Binding",
      "verbs": [
        "create"
      ]
    },
    {
      "name": "componentstatuses",
      "singularName": "componentstatus",
      "namespaced": false,
      "kind": "ComponentStatus",
      "verbs": [
        "get",
        "list"
      ],
      "shortNames": [
        "cs"
      ]
    },
    {
      "name": "configmaps",
      "singularName": "configmap",
      "namespaced": true,
      "kind": "ConfigMap",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "cm"
      ],
      "storageVersionHash": "qFsyl6wFWjQ="
    },
    {
      "name": "endpoints",
      "singularName": "endpoints",
      "namespaced": true,
      "kind": "Endpoints",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "ep"
      ],
      "storageVersionHash": "fWeeMqaN/OA="
    },
    {
      "name": "events",
      "singularName": "event",
      "namespaced": true,
      "kind": "Event",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "ev"
      ],
      "storageVersionHash": "r2yiGXH7wu8="
    },
    {
      "name": "limitranges",
      "singularName": "limitrange",
      "namespaced": true,
      "kind": "LimitRange",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "limits"
      ],
      "storageVersionHash": "EBKMFVe6cwo="
    },
    {
      "name": "namespaces",
      "singularName": "namespace",
      "namespaced": false,
      "kind": "Namespace",
      "verbs": [
        "create",
        "delete",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "ns"
      ],
      "storageVersionHash": "Q3oi5N2YM8M="
    },
    {
      "name": "namespaces/finalize",
      "singularName": "",
      "namespaced": false,
      "kind": "Namespace",
      "verbs": [
        "update"
      ]
    },
    {
      "name": "namespaces/status",
      "singularName": "",
      "namespaced": false,
      "kind": "Namespace",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "nodes",
      "singularName": "node",
      "namespaced": false,
      "kind": "Node",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "no"
      ],
      "storageVersionHash": "XwShjMxG9Fs="
    },
    {
      "name": "nodes/proxy",
      "singularName": "",
      "namespaced": false,
      "kind": "NodeProxyOptions",
      "verbs": [
        "create",
        "delete",
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "nodes/status",
      "singularName": "",
      "namespaced": false,
      "kind": "Node",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "persistentvolumeclaims",
      "singularName": "persistentvolumeclaim",
      "namespaced": true,
      "kind": "PersistentVolumeClaim",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "pvc"
      ],
      "storageVersionHash": "QWTyNDq0dC4="
    },
    {
      "name": "persistentvolumeclaims/status",
      "singularName": "",
      "namespaced": true,
      "kind": "PersistentVolumeClaim",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "persistentvolumes",
      "singularName": "persistentvolume",
      "namespaced": false,
      "kind": "PersistentVolume",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "pv"
      ],
      "storageVersionHash": "HN/zwEC+JgM="
    },
    {
      "name": "persistentvolumes/status",
      "singularName": "",
      "namespaced": false,
      "kind": "PersistentVolume",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "pods",
      "singularName": "pod",
      "namespaced": true,
      "kind": "Pod",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "po"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "xPOwRZ+Yhw8="
    },
    {
      "name": "pods/attach",
      "singularName": "",
      "namespaced": true,
      "kind": "PodAttachOptions",
      "verbs": [
        "create",
        "get"
      ]
    },
    {
      "name": "pods/binding",
      "singularName": "",
      "namespaced": true,
      "kind": "Binding",
      "verbs": [
        "create"
      ]
    },
    {
      "name": "pods/ephemeralcontainers",
      "singularName": "",
      "namespaced": true,
      "kind": "Pod",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "pods/eviction",
      "singularName": "",
      "namespaced": true,
      "group": "policy",
      "version": "v1",
      "kind": "Eviction",
      "verbs": [
        "create"
      ]
    },
    {
      "name": "pods/exec",
      "singularName": "",
      "namespaced": true,
      "kind": "PodExecOptions",
      "verbs": [
        "create",
        "get"
      ]
    },
    {
      "name": "pods/log",
      "singularName": "",
      "namespaced": true,
      "kind": "Pod",
      "verbs": [
        "get"
      ]
    },
    {
      "name": "pods/portforward",
      "singularName": "",
      "namespaced": true,
      "kind": "PodPortForwardOptions",
      "verbs": [
        "create",
        "get"
      ]
    },
    {
      "name": "pods/proxy",
      "singularName": "",
      "namespaced": true,
      "kind": "PodProxyOptions",
      "verbs": [
        "create",
        "delete",
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "pods/status",
      "singularName": "",
      "namespaced": true,
      "kind": "Pod",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "podtemplates",
      "singularName": "podtemplate",
      "namespaced": true,
      "kind": "PodTemplate",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "storageVersionHash": "LIXB2x4IFpk="
    },
    {
      "name": "replicationcontrollers",
      "singularName": "replicationcontroller",
      "namespaced": true,
      "kind": "ReplicationController",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "rc"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "Jond2If31h0="
    },
    {
      "name": "replicationcontrollers/scale",
      "singularName": "",
      "namespaced": true,
      "group": "autoscaling",
      "version": "v1",
      "kind": "Scale",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "replicationcontrollers/status",
      "singularName": "",
      "namespaced": true,
      "kind": "ReplicationController",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "resourcequotas",
      "singularName": "resourcequota",
      "namespaced": true,
      "kind": "ResourceQuota",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "quota"
      ],
      "storageVersionHash": "8uhSgffRX6w="
    },
    {
      "name": "resourcequotas/status",
      "singularName": "",
      "namespaced": true,
      "kind": "ResourceQuota",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "secrets",
      "singularName": "secret",
      "namespaced": true,
      "kind": "Secret",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "storageVersionHash": "S6u1pOWzb84="
    },
    {
      "name": "serviceaccounts",
      "singularName": "serviceaccount",
      "namespaced": true,
      "kind": "ServiceAccount",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "sa"
      ],
      "storageVersionHash": "pbx9ZvyFpBE="
    },
    {
      "name": "serviceaccounts/token",
      "singularName": "",
      "namespaced": true,
      "group": "authentication.k8s.io",
      "version": "v1",
      "kind": "TokenRequest",
      "verbs": [
        "create"
      ]
    },
    {
      "name": "services",
      "singularName": "service",
      "namespaced": true,
      "kind": "Service",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "svc"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "0/CO1lhkEBI="
    },
    {
      "name": "services/proxy",
      "singularName": "",
      "namespaced": true,
      "kind": "ServiceProxyOptions",
      "verbs": [
        "create",
        "delete",
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "services/status",
      "singularName": "",
      "namespaced": true,
      "kind": "Service",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    }
  ]
}`
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(resp))
}

// Handler for /apis
func (h *honeypot) apisHandler(w http.ResponseWriter, r *http.Request) {
	resp := `{
  "kind": "APIGroupList",
  "apiVersion": "v1",
  "groups": [
    {
      "name": "apps",
      "versions": [
        {
          "groupVersion": "apps/v1",
          "version": "v1"
        }
      ],
      "preferredVersion": {
        "groupVersion": "apps/v1",
        "version": "v1"
      }
    }
  ]
}`
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(resp))
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
	resp := `{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "apps/v1",
  "resources": [
    {
      "name": "controllerrevisions",
      "singularName": "controllerrevision",
      "namespaced": true,
      "kind": "ControllerRevision",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "storageVersionHash": "85nkx63pcBU="
    },
    {
      "name": "daemonsets",
      "singularName": "daemonset",
      "namespaced": true,
      "kind": "DaemonSet",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "ds"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "dd7pWHUlMKQ="
    },
    {
      "name": "daemonsets/status",
      "singularName": "",
      "namespaced": true,
      "kind": "DaemonSet",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "deployments",
      "singularName": "deployment",
      "namespaced": true,
      "kind": "Deployment",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "deploy"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "8aSe+NMegvE="
    },
    {
      "name": "deployments/scale",
      "singularName": "",
      "namespaced": true,
      "group": "autoscaling",
      "version": "v1",
      "kind": "Scale",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "deployments/status",
      "singularName": "",
      "namespaced": true,
      "kind": "Deployment",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "replicasets",
      "singularName": "replicaset",
      "namespaced": true,
      "kind": "ReplicaSet",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "rs"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "P1RzHs8/mWQ="
    },
    {
      "name": "replicasets/scale",
      "singularName": "",
      "namespaced": true,
      "group": "autoscaling",
      "version": "v1",
      "kind": "Scale",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "replicasets/status",
      "singularName": "",
      "namespaced": true,
      "kind": "ReplicaSet",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "statefulsets",
      "singularName": "statefulset",
      "namespaced": true,
      "kind": "StatefulSet",
      "verbs": [
        "create",
        "delete",
        "deletecollection",
        "get",
        "list",
        "patch",
        "update",
        "watch"
      ],
      "shortNames": [
        "sts"
      ],
      "categories": [
        "all"
      ],
      "storageVersionHash": "H+vl74LkKdo="
    },
    {
      "name": "statefulsets/scale",
      "singularName": "",
      "namespaced": true,
      "group": "autoscaling",
      "version": "v1",
      "kind": "Scale",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    },
    {
      "name": "statefulsets/status",
      "singularName": "",
      "namespaced": true,
      "kind": "StatefulSet",
      "verbs": [
        "get",
        "patch",
        "update"
      ]
    }
  ]
}`
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
		h.logger.Info().Interface("pod", pod).Msg("Creating pod")
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
