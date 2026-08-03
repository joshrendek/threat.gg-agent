package consul

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/stretchr/testify/require"
)

func resetState() { states = &stateStore{clients: make(map[string]*clientState)} }

func TestConsulReconPersona(t *testing.T) {
	resetState()
	server := httptest.NewServer(newHandler())
	defer server.Close()
	for path, want := range map[string]string{
		"/v1/agent/self": "consul-server-01", "/v1/agent/members": "worker-01",
		"/v1/catalog/services": "postgresql", "/v1/catalog/nodes": "dc1",
		"/v1/health/service/redis": "passing", "/v1/status/leader": "10.0.0.10:8300",
	} {
		resp, err := http.Get(server.URL + path)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, 200, resp.StatusCode, path)
		require.Contains(t, string(body), want, path)
		require.Equal(t, "true", resp.Header.Get("X-Consul-KnownLeader"))
	}
}

func TestKVStateIsBoundedAndScopedPerClient(t *testing.T) {
	resetState()
	h := newHandler()
	put := func(remote, key, value string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PUT", "http://consul/v1/kv/"+key, strings.NewReader(value))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	putResponse := put("192.0.2.1:1", "secret/key", "alpha")
	require.Equal(t, 200, putResponse.Code)
	require.Equal(t, "43", putResponse.Header().Get("X-Consul-Index"))
	get := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://consul/v1/kv/secret/key?raw", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	require.Equal(t, "alpha", get("192.0.2.1:2").Body.String())
	require.Equal(t, "43", get("192.0.2.1:2").Header().Get("X-Consul-Index"))
	require.Equal(t, 404, get("192.0.2.2:2").Code)
	state := states.forClient("198.51.100.1")
	for i := 0; i < maxKeys; i++ {
		state.kv[string(rune(i+1000))] = []byte("x")
	}
	require.Equal(t, 429, put("198.51.100.1:9", "overflow", "x").Code)
}

func TestKVEnvelopeKeysDeleteMissingAndUnsupportedMethod(t *testing.T) {
	resetState()
	h := newHandler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://consul"+path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.50:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	require.Equal(t, 200, request("PUT", "/v1/kv/app/z", "last").Code)
	require.Equal(t, 200, request("PUT", "/v1/kv/app/a", "first").Code)
	envelope := request("GET", "/v1/kv/app/a", "")
	require.Contains(t, envelope.Body.String(), base64.StdEncoding.EncodeToString([]byte("first")))
	require.Contains(t, envelope.Body.String(), `"ModifyIndex":44`)
	keys := request("GET", "/v1/kv/app/?keys", "")
	require.JSONEq(t, `["app/a","app/z"]`, keys.Body.String())
	require.Equal(t, 200, request("DELETE", "/v1/kv/app/a", "").Code)
	require.Equal(t, 404, request("GET", "/v1/kv/app/a", "").Code)
	require.Equal(t, 405, request("POST", "/v1/kv/app/z", "").Code)
}

func TestSessionsCreateListInfoAndDestroy(t *testing.T) {
	resetState()
	h := newHandler()
	remote := "203.0.113.8:1"
	req := httptest.NewRequest("PUT", "http://consul/v1/session/create", strings.NewReader(`{"Name":"deploy-lock","TTL":"15s"}`))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code)
	var created map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	require.NotEmpty(t, created["ID"])
	for _, path := range []string{"/v1/session/list", "/v1/session/info/" + created["ID"]} {
		req = httptest.NewRequest("GET", "http://consul"+path, nil)
		req.RemoteAddr = remote
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Contains(t, rec.Body.String(), "deploy-lock")
		require.Contains(t, rec.Body.String(), "consul-server-01")
		require.Contains(t, rec.Body.String(), "release")
	}
	req = httptest.NewRequest("PUT", "http://consul/v1/session/destroy/"+created["ID"], nil)
	req.RemoteAddr = remote
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Contains(t, rec.Body.String(), "true")
	req = httptest.NewRequest("GET", "http://consul/v1/session/info/"+created["ID"], nil)
	req.RemoteAddr = remote
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.JSONEq(t, `[]`, rec.Body.String())
}

func TestSessionStateIsBoundedAndFieldsAreBounded(t *testing.T) {
	resetState()
	h := newHandler()
	remote := "203.0.113.9:1"
	for i := 0; i < maxSessions; i++ {
		body := `{"Name":"` + strings.Repeat("n", 300) + `","TTL":"` + strings.Repeat("t", 50) + `"}`
		req := httptest.NewRequest("PUT", "http://consul/v1/session/create", strings.NewReader(body))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, 200, rec.Code)
	}
	req := httptest.NewRequest("PUT", "http://consul/v1/session/create", strings.NewReader(`{}`))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, 429, rec.Code)
	state := states.forClient("203.0.113.9")
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, session := range state.sessions {
		require.LessOrEqual(t, len(session.Name), 256)
		require.LessOrEqual(t, len(session.TTL), 32)
	}
}

func TestCaptureRedactsAndFingerprintsAllTokenForms(t *testing.T) {
	resetState()
	old := saveRequest
	captured := make(chan *proto.ConsulRequest, 3)
	saveRequest = func(in *proto.ConsulRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveRequest = old })
	cases := []struct{ header, value, url, source, token string }{{"X-Consul-Token", "header-secret", "http://consul/v1/agent/self", "x-consul-token", "header-secret"}, {"Authorization", "Bearer bearer-secret", "http://consul/v1/catalog/services", "bearer", "bearer-secret"}, {"", "", "http://consul/v1/kv/a?token=query-secret", "query", "query-secret"}}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", tc.url, nil)
		if tc.header != "" {
			req.Header.Set(tc.header, tc.value)
		}
		rec := httptest.NewRecorder()
		newHandler().ServeHTTP(rec, req)
		select {
		case got := <-captured:
			require.Equal(t, tc.source, got.TokenSource)
			sum := sha256.Sum256([]byte(tc.token))
			require.Equal(t, "sha256:"+hex.EncodeToString(sum[:8]), got.TokenFingerprint)
			require.NotContains(t, got.Query, "query-secret")
			require.NotContains(t, got.Body, "secret")
			require.Equal(t, int32(rec.Code), got.ResponseStatus)
		case <-time.After(time.Second):
			t.Fatal("capture timeout")
		}
	}
}

func TestOversizedBodyReturns413AndCaptureBodyRedactsJSONSecrets(t *testing.T) {
	resetState()
	old := saveRequest
	captured := make(chan *proto.ConsulRequest, 2)
	saveRequest = func(in *proto.ConsulRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveRequest = old })
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest("PUT", "http://consul/v1/kv/a", strings.NewReader(strings.Repeat("x", maxBody+1))))
	require.Equal(t, 413, rec.Code)
	require.Equal(t, "[REDACTED_KV_VALUE]", awaitCapture(t, captured).Body)
	rec = httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest("PUT", "http://consul/v1/session/create", strings.NewReader(`{"nested":[{"apiKey":"secret"},{"credentials":123}],"Name":"safe"}`)))
	got := awaitCapture(t, captured)
	require.NotContains(t, got.Body, "secret")
	require.NotContains(t, got.Body, "123")
	require.JSONEq(t, `{"Name":"safe"}`, got.Body)
}

func TestCaptureOmitsRawKVValues(t *testing.T) {
	req := httptest.NewRequest("PUT", "http://consul/v1/kv/config/database/password", strings.NewReader("bare-database-password"))
	require.Equal(t, "[REDACTED_KV_VALUE]", redactedCaptureBody(req, []byte("bare-database-password")))
}

func TestConsulCaptureRedactsSensitiveQueryAndNonJSONBodies(t *testing.T) {
	query := make(url.Values)
	query.Set("client-secret", "query-secret")
	query.Set("safe", "visible")
	encoded := redactedQuery(query).Encode()
	require.Contains(t, encoded, "client-secret=%5BREDACTED%5D")
	require.NotContains(t, encoded, "query-secret")

	require.Equal(t, "password=%5BREDACTED%5D&safe=visible", redactedBody([]byte("password=hunter2&safe=visible")))
	require.Equal(t, "[REDACTED_MALFORMED_JSON_BODY]", redactedBody([]byte(`{"password":"hunter2"`)))
	require.Equal(t, "[REDACTED]", redactedBody([]byte("Authorization: Bearer plaintext-secret")))
}

func TestStateStoreEvictsOldestClientAtCapacity(t *testing.T) {
	store := &stateStore{clients: make(map[string]*clientState)}
	for i := 0; i < maxClients; i++ {
		store.clients[fmt.Sprintf("client-%03d", i)] = &clientState{touched: time.Unix(int64(i), 0)}
	}
	store.forClient("new-client")
	require.Len(t, store.clients, maxClients)
	require.NotContains(t, store.clients, "client-000")
	require.Contains(t, store.clients, "new-client")
}

func TestStateStoreRejectsNewClientWhenEveryStateIsActive(t *testing.T) {
	store := &stateStore{clients: make(map[string]*clientState)}
	for i := 0; i < maxClients; i++ {
		store.clients[fmt.Sprintf("client-%03d", i)] = &clientState{touched: time.Unix(int64(i), 0), active: 1}
	}
	state, release, ok := store.acquireClient("new-client")
	require.False(t, ok)
	require.Nil(t, state)
	require.Nil(t, release)
	require.Len(t, store.clients, maxClients)
}

func TestPersistenceBackpressureDropsAndReleasesSlot(t *testing.T) {
	oldSave, oldSlots := saveRequest, saveSlots
	block := make(chan struct{})
	started := make(chan struct{}, 1)
	saveRequest = func(*proto.ConsulRequest) error { started <- struct{}{}; <-block; return nil }
	saveSlots = make(chan struct{}, 1)
	t.Cleanup(func() { saveRequest, saveSlots = oldSave, oldSlots })
	req := httptest.NewRequest("GET", "http://consul/v1/agent/self", nil)
	persist(req, nil, 200)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("save did not start")
	}
	persist(req, nil, 200)
	require.Len(t, saveSlots, 1)
	close(block)
	require.Eventually(t, func() bool { return len(saveSlots) == 0 }, time.Second, 10*time.Millisecond)
}

func awaitCapture(t *testing.T, ch <-chan *proto.ConsulRequest) *proto.ConsulRequest {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Consul capture")
		return nil
	}
}
