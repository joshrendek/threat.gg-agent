package etcd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const maxV3RangeBodySize = 64 << 10

type v3RangeRequest struct {
	Key       string `json:"key"`
	RangeEnd  string `json:"range_end"`
	Limit     int64  `json:"limit"`
	KeysOnly  bool   `json:"keys_only"`
	CountOnly bool   `json:"count_only"`
}

type v3KV struct {
	Key            string `json:"key"`
	Value          string `json:"value,omitempty"`
	CreateRevision string `json:"create_revision"`
	ModRevision    string `json:"mod_revision"`
	Version        string `json:"version"`
}

type v3RangeResponse struct {
	Header struct {
		ClusterID string `json:"cluster_id"`
		MemberID  string `json:"member_id"`
		Revision  string `json:"revision"`
		RaftTerm  string `json:"raft_term"`
	} `json:"header"`
	KVs   []v3KV `json:"kvs,omitempty"`
	More  bool   `json:"more"`
	Count string `json:"count"`
}

var v3FakeKeyspace = map[string]string{
	"admin":       "true",
	"config":      `{"environment":"production","region":"us-east-1"}`,
	"credential":  "svc-honeypot:fake-password-not-valid",
	"credentials": "svc-honeypot:fake-password-not-valid",
	"env":         "production",
	"key":         "fake-key-id-honeypot",
	"mnemonic":    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
	"private":     "-----BEGIN PRIVATE KEY-----\nFAKE-HONEYPOT-MATERIAL\n-----END PRIVATE KEY-----",
	"private_key": "-----BEGIN PRIVATE KEY-----\nFAKE-HONEYPOT-MATERIAL\n-----END PRIVATE KEY-----",
	"secret":      "fake-secret-honeypot",
	"token":       "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJob25leXBvdCJ9.invalid",
	"wallet":      "0x00000000000000000000000000000000deadbeef",
}

func etcdHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Etcd-Cluster-Id", "cdf818194e3a8c32")
	w.Header().Set("X-Etcd-Index", "18432")
	w.Header().Set("X-Raft-Index", "29541")
	w.Header().Set("X-Raft-Term", "7")
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"etcdserver":"%s","etcdcluster":"3.5.0"}`, etcdVersion)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"health":"true"}`)
}

func handleV3Range(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, maxV3RangeBodySize+1))
	if err != nil {
		writeV3Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(body) > maxV3RangeBodySize {
		writeV3Error(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	var request v3RangeRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &request); err != nil {
			writeV3Error(w, http.StatusBadRequest, "invalid range request")
			return
		}
	}
	if request.Limit < 0 {
		writeV3Error(w, http.StatusBadRequest, "limit must not be negative")
		return
	}

	start := decodeV3Key(request.Key)
	end := decodeV3Key(request.RangeEnd)
	keys := selectV3Keys(start, end)
	total := len(keys)
	more := false
	if request.Limit > 0 && int64(len(keys)) > request.Limit {
		keys = keys[:request.Limit]
		more = true
	}

	response := v3RangeResponse{More: more, Count: fmt.Sprintf("%d", total)}
	response.Header.ClusterID = "14841639068965178418"
	response.Header.MemberID = "10276657743932975437"
	response.Header.Revision = "18432"
	response.Header.RaftTerm = "7"
	if !request.CountOnly {
		response.KVs = make([]v3KV, 0, len(keys))
		for _, key := range keys {
			createRevision, modRevision := v3KeyRevisions(key)
			kv := v3KV{
				Key:            base64.StdEncoding.EncodeToString([]byte(key)),
				CreateRevision: createRevision,
				ModRevision:    modRevision,
				Version:        "1",
			}
			if !request.KeysOnly {
				kv.Value = base64.StdEncoding.EncodeToString([]byte(v3FakeKeyspace[key]))
			}
			response.KVs = append(response.KVs, kv)
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

func v3KeyRevisions(key string) (string, string) {
	keys := make([]string, 0, len(v3FakeKeyspace))
	for candidate := range v3FakeKeyspace {
		keys = append(keys, candidate)
	}
	sort.Strings(keys)
	for index, candidate := range keys {
		if candidate == key {
			return fmt.Sprintf("%d", 17000+index), fmt.Sprintf("%d", 18300+index)
		}
	}
	return "17000", "18300"
}

func decodeV3Key(value string) string {
	if value == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil && printableV3Key(decoded) {
		return string(decoded)
	}
	return value
}

func printableV3Key(value []byte) bool {
	for _, b := range value {
		if b != 0 && (b < 0x20 || b > 0x7e) {
			return false
		}
	}
	return true
}

func selectV3Keys(start, end string) []string {
	keys := make([]string, 0, len(v3FakeKeyspace))
	for key := range v3FakeKeyspace {
		if start == "" || start == "\x00" {
			if end == "" || end == "\x00" || key < end {
				keys = append(keys, key)
			}
			continue
		}
		if end == "" {
			if key == start {
				keys = append(keys, key)
			}
			continue
		}
		if key >= start && key < end {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func writeV3Error(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    3,
		"error":   message,
		"message": message,
	})
}

func handleKeysRoot(w http.ResponseWriter, r *http.Request) {
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
