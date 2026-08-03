package consul

import (
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
	require.Equal(t, 200, put("192.0.2.1:1", "secret/key", "alpha").Code)
	get := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://consul/v1/kv/secret/key?raw", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	require.Equal(t, "alpha", get("192.0.2.1:2").Body.String())
	require.Equal(t, 404, get("192.0.2.2:2").Code)
	state := states.forClient("198.51.100.1")
	for i := 0; i < maxKeys; i++ {
		state.kv[string(rune(i+1000))] = []byte("x")
	}
	require.Equal(t, 429, put("198.51.100.1:9", "overflow", "x").Code)
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
	}
	req = httptest.NewRequest("PUT", "http://consul/v1/session/destroy/"+created["ID"], nil)
	req.RemoteAddr = remote
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Contains(t, rec.Body.String(), "true")
}

func TestCaptureRedactsAndFingerprintsAllTokenForms(t *testing.T) {
	resetState()
	old := saveRequest
	captured := make(chan *proto.ConsulRequest, 3)
	saveRequest = func(in *proto.ConsulRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveRequest = old })
	cases := []struct{ header, value, url, source string }{{"X-Consul-Token", "header-secret", "http://consul/v1/agent/self", "x-consul-token"}, {"Authorization", "Bearer bearer-secret", "http://consul/v1/catalog/services", "bearer"}, {"", "", "http://consul/v1/kv/a?token=query-secret", "query"}}
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
			require.Regexp(t, `^sha256:[0-9a-f]{16}$`, got.TokenFingerprint)
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
	require.Len(t, awaitCapture(t, captured).Body, maxBody)
	rec = httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest("PUT", "http://consul/v1/session/create", strings.NewReader(`{"Token":"secret","Name":"safe"}`)))
	got := awaitCapture(t, captured)
	require.NotContains(t, got.Body, "secret")
	require.Contains(t, got.Body, "[REDACTED]")
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
	require.NotContains(t, redactedBody([]byte("authorization: bearer-secret")), "bearer-secret")
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
