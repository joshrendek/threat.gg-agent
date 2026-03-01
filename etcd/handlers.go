package etcd

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func etcdHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Etcd-Cluster-Id", "cdf818194e3a8c32")
	w.Header().Set("X-Etcd-Index", "18432")
	w.Header().Set("X-Raft-Index", "29541")
	w.Header().Set("X-Raft-Term", "7")
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"etcdserver":"%s","etcdcluster":"3.5.0"}`, etcdVersion)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"health":"true"}`)
}

func handleKeysRoot(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	etcdHeaders(w)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{
  "action": "get",
  "node": {
    "key": "/",
    "dir": true,
    "nodes": [
      {"key": "/registry", "dir": true, "modifiedIndex": 2, "createdIndex": 2}
    ]
  }
}`)
}

func handleKeysRead(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	etcdHeaders(w)

	vars := mux.Vars(r)
	path := "/" + vars["path"]

	// Normalize trailing slash
	cleanPath := strings.TrimSuffix(path, "/")

	switch {
	case cleanPath == "/registry" || cleanPath == "/registry/":
		handleRegistryRoot(w, path)
	case strings.HasPrefix(cleanPath, "/registry/secrets"):
		handleRegistrySecrets(w, path)
	case strings.HasPrefix(cleanPath, "/registry/serviceaccounts"):
		handleRegistryServiceAccounts(w, path)
	case strings.HasPrefix(cleanPath, "/registry/pods"):
		handleRegistryPods(w, path)
	default:
		handleKeyNotFound(w, path)
	}
}

func handleKeysWrite(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	etcdHeaders(w)

	vars := mux.Vars(r)
	path := "/" + vars["path"]
	now := time.Now().UTC().Format(time.RFC3339Nano)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{
  "action": "set",
  "node": {
    "key": "%s",
    "value": "",
    "modifiedIndex": 18433,
    "createdIndex": 18433,
    "expiration": "%s"
  }
}`, path, now)
}

func handleKeysDelete(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	etcdHeaders(w)

	vars := mux.Vars(r)
	path := "/" + vars["path"]

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
  "action": "delete",
  "node": {
    "key": "%s",
    "modifiedIndex": 18434,
    "createdIndex": 18430
  },
  "prevNode": {
    "key": "%s",
    "value": "",
    "modifiedIndex": 18430,
    "createdIndex": 18430
  }
}`, path, path)
}

func handleCatchAll(w http.ResponseWriter, r *http.Request) {
	captureAndSave(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `{"message":"Not found"}`)
}

func handleRegistryRoot(w http.ResponseWriter, path string) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
  "action": "get",
  "node": {
    "key": "%s",
    "dir": true,
    "nodes": [
      {"key": "/registry/secrets", "dir": true, "modifiedIndex": 10, "createdIndex": 10},
      {"key": "/registry/serviceaccounts", "dir": true, "modifiedIndex": 11, "createdIndex": 11},
      {"key": "/registry/pods", "dir": true, "modifiedIndex": 12, "createdIndex": 12},
      {"key": "/registry/namespaces", "dir": true, "modifiedIndex": 13, "createdIndex": 13},
      {"key": "/registry/deployments", "dir": true, "modifiedIndex": 14, "createdIndex": 14},
      {"key": "/registry/services", "dir": true, "modifiedIndex": 15, "createdIndex": 15},
      {"key": "/registry/configmaps", "dir": true, "modifiedIndex": 16, "createdIndex": 16}
    ]
  }
}`, path)
}

func handleRegistrySecrets(w http.ResponseWriter, path string) {
	cleanPath := strings.TrimSuffix(path, "/")

	// Listing /registry/secrets or /registry/secrets/default
	if cleanPath == "/registry/secrets" || cleanPath == "/registry/secrets/default" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
  "action": "get",
  "node": {
    "key": "%s",
    "dir": true,
    "nodes": [
      {"key": "/registry/secrets/default/default-token-x4m2k", "value": "{\"kind\":\"Secret\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"default-token-x4m2k\",\"namespace\":\"default\"},\"data\":{\"ca.crt\":\"LS0tLS1CRUdJTi...\",\"namespace\":\"ZGVmYXVsdA==\",\"token\":\"ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklr...\"},\"type\":\"kubernetes.io/service-account-token\"}", "modifiedIndex": 100, "createdIndex": 100},
      {"key": "/registry/secrets/default/cloud-credentials", "value": "{\"kind\":\"Secret\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"cloud-credentials\",\"namespace\":\"default\"},\"data\":{\"access_key\":\"ZmFrZS1ob25leXBvdC1rZXktaWQ=\",\"secret_key\":\"ZmFrZS1ob25leXBvdC1zZWNyZXQta2V5\"},\"type\":\"Opaque\"}", "modifiedIndex": 101, "createdIndex": 101},
      {"key": "/registry/secrets/kube-system/admin-token-rz9nf", "value": "{\"kind\":\"Secret\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"admin-token-rz9nf\",\"namespace\":\"kube-system\"},\"data\":{\"token\":\"ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklr...\"},\"type\":\"kubernetes.io/service-account-token\"}", "modifiedIndex": 102, "createdIndex": 102}
    ]
  }
}`, path)
		return
	}

	// Specific secret key
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
  "action": "get",
  "node": {
    "key": "%s",
    "value": "{\"kind\":\"Secret\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"default-token-x4m2k\",\"namespace\":\"default\"},\"data\":{\"ca.crt\":\"LS0tLS1CRUdJTi...\",\"namespace\":\"ZGVmYXVsdA==\",\"token\":\"ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklr...\"},\"type\":\"kubernetes.io/service-account-token\"}",
    "modifiedIndex": 100,
    "createdIndex": 100
  }
}`, path)
}

func handleRegistryServiceAccounts(w http.ResponseWriter, path string) {
	cleanPath := strings.TrimSuffix(path, "/")

	if cleanPath == "/registry/serviceaccounts" || cleanPath == "/registry/serviceaccounts/default" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
  "action": "get",
  "node": {
    "key": "%s",
    "dir": true,
    "nodes": [
      {"key": "/registry/serviceaccounts/default/default", "value": "{\"kind\":\"ServiceAccount\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"default\",\"namespace\":\"default\"},\"secrets\":[{\"name\":\"default-token-x4m2k\"}]}", "modifiedIndex": 200, "createdIndex": 200},
      {"key": "/registry/serviceaccounts/kube-system/admin", "value": "{\"kind\":\"ServiceAccount\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"admin\",\"namespace\":\"kube-system\"},\"secrets\":[{\"name\":\"admin-token-rz9nf\"}]}", "modifiedIndex": 201, "createdIndex": 201}
    ]
  }
}`, path)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
  "action": "get",
  "node": {
    "key": "%s",
    "value": "{\"kind\":\"ServiceAccount\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"default\",\"namespace\":\"default\"},\"secrets\":[{\"name\":\"default-token-x4m2k\"}]}",
    "modifiedIndex": 200,
    "createdIndex": 200
  }
}`, path)
}

func handleRegistryPods(w http.ResponseWriter, path string) {
	cleanPath := strings.TrimSuffix(path, "/")

	if cleanPath == "/registry/pods" || cleanPath == "/registry/pods/default" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
  "action": "get",
  "node": {
    "key": "%s",
    "dir": true,
    "nodes": [
      {"key": "/registry/pods/default/nginx-deployment-6b474476c4-x2k9l", "value": "{\"kind\":\"Pod\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"nginx-deployment-6b474476c4-x2k9l\",\"namespace\":\"default\",\"labels\":{\"app\":\"nginx\"}},\"spec\":{\"containers\":[{\"name\":\"nginx\",\"image\":\"nginx:1.25\",\"ports\":[{\"containerPort\":80}]}]},\"status\":{\"phase\":\"Running\",\"podIP\":\"10.244.0.5\"}}", "modifiedIndex": 300, "createdIndex": 300},
      {"key": "/registry/pods/default/redis-master-0", "value": "{\"kind\":\"Pod\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"redis-master-0\",\"namespace\":\"default\",\"labels\":{\"app\":\"redis\"}},\"spec\":{\"containers\":[{\"name\":\"redis\",\"image\":\"redis:7-alpine\",\"ports\":[{\"containerPort\":6379}]}]},\"status\":{\"phase\":\"Running\",\"podIP\":\"10.244.0.7\"}}", "modifiedIndex": 301, "createdIndex": 301},
      {"key": "/registry/pods/kube-system/kube-apiserver-master", "value": "{\"kind\":\"Pod\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"kube-apiserver-master\",\"namespace\":\"kube-system\"},\"spec\":{\"containers\":[{\"name\":\"kube-apiserver\",\"image\":\"registry.k8s.io/kube-apiserver:v1.28.4\"}]},\"status\":{\"phase\":\"Running\",\"podIP\":\"172.31.24.6\"}}", "modifiedIndex": 302, "createdIndex": 302}
    ]
  }
}`, path)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
  "action": "get",
  "node": {
    "key": "%s",
    "value": "{\"kind\":\"Pod\",\"apiVersion\":\"v1\",\"metadata\":{\"name\":\"nginx-deployment-6b474476c4-x2k9l\",\"namespace\":\"default\",\"labels\":{\"app\":\"nginx\"}},\"spec\":{\"containers\":[{\"name\":\"nginx\",\"image\":\"nginx:1.25\"}]},\"status\":{\"phase\":\"Running\",\"podIP\":\"10.244.0.5\"}}",
    "modifiedIndex": 300,
    "createdIndex": 300
  }
}`, path)
}

func handleKeyNotFound(w http.ResponseWriter, path string) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `{
  "errorCode": 100,
  "message": "Key not found",
  "cause": "%s",
  "index": 18432
}`, path)
}
