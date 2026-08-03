package kubelet

import (
	"crypto/x509"
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

func TestKubeletPersonaEndpointsAreCoherent(t *testing.T) {
	oldSave := saveRequest
	captured := make(chan *proto.KubeletRequest, 8)
	saveRequest = func(in *proto.KubeletRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveRequest = oldSave })

	server := httptest.NewServer(newHandler())
	t.Cleanup(server.Close)
	for _, path := range []string{"/pods", "/runningPods/", "/stats/summary", "/metrics/resource", "/logs/", "/containerLogs/default/web-7d9b4f8d6b-k2x7m/nginx"} {
		resp, err := http.Get(server.URL + path)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, path)
		require.NotEmpty(t, body, path)
	}

	resp, err := http.Get(server.URL + "/pods")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Contains(t, string(body), `"nodeName":"worker-01"`)
	require.Contains(t, string(body), `"name":"web-7d9b4f8d6b-k2x7m"`)
	require.Contains(t, string(body), `"name":"nginx"`)
}

func TestCaptureFingerprintsBearerAndPreservesCommandOrder(t *testing.T) {
	oldSave := saveRequest
	captured := make(chan *proto.KubeletRequest, 1)
	saveRequest = func(in *proto.KubeletRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveRequest = oldSave })

	req := httptest.NewRequest(http.MethodPost, "https://node/exec/default/web/nginx?command=/bin/sh&command=-c&command=id&token=secret-query", strings.NewReader("stdin-data"))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("User-Agent", "curl/8.10")
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	select {
	case got := <-captured:
		require.Equal(t, "bearer", got.AuthScheme)
		require.Regexp(t, `^sha256:[0-9a-f]{16}$`, got.TokenFingerprint)
		require.NotContains(t, got.TokenFingerprint, "super-secret")
		require.Equal(t, []string{"/bin/sh", "-c", "id"}, got.Commands)
		require.Contains(t, got.Query, "token=%5BREDACTED%5D")
		require.NotContains(t, got.Query, "secret-query")
		require.Equal(t, "stdin-data", got.Body)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Kubelet capture")
	}
}

func TestAnonymousCaptureAndOversizedBody(t *testing.T) {
	oldSave := saveRequest
	captured := make(chan *proto.KubeletRequest, 2)
	saveRequest = func(in *proto.KubeletRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveRequest = oldSave })

	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://node/healthz", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "anonymous", (<-captured).AuthScheme)

	rec = httptest.NewRecorder()
	newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://node/run/default/web/nginx?command=id", strings.NewReader(strings.Repeat("x", maxBodyBytes+1))))
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	got := <-captured
	require.Len(t, got.Body, maxBodyBytes)
}

func TestCaptureRedactsJSONSecrets(t *testing.T) {
	oldSave := saveRequest
	captured := make(chan *proto.KubeletRequest, 1)
	saveRequest = func(in *proto.KubeletRequest) error { captured <- in; return nil }
	t.Cleanup(func() { saveRequest = oldSave })

	rec := httptest.NewRecorder()
	body := `{"spec":{"token":"secret-value","password":"hunter2"},"command":"id"}`
	newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://node/run/default/web/nginx?command=id", strings.NewReader(body)))
	require.Equal(t, http.StatusOK, rec.Code)
	got := <-captured
	require.NotContains(t, got.Body, "secret-value")
	require.NotContains(t, got.Body, "hunter2")
	require.Contains(t, got.Body, `"token":"[REDACTED]"`)
	require.Contains(t, got.Body, `"command":"id"`)
}

func TestKubeletCertificateUsesNodePersona(t *testing.T) {
	cert, err := selfSignedCertForNode()
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, "worker-01", parsed.Subject.CommonName)
	require.Contains(t, parsed.DNSNames, "worker-01")
}

func TestCaptureBoundsAndRedactsNonJSONSecrets(t *testing.T) {
	values := make(url.Values)
	values.Set("client-secret", "query-secret")
	values.Set("safe", "visible")
	redacted := redactedQuery(values).Encode()
	require.Contains(t, redacted, "client-secret=%5BREDACTED%5D")
	require.NotContains(t, redacted, "query-secret")

	require.Equal(t, "password=%5BREDACTED%5D&safe=visible", redactedBody([]byte("password=hunter2&safe=visible")))
	require.Equal(t, "[REDACTED_MALFORMED_JSON_BODY]", redactedBody([]byte(`{"password":"hunter2"`)))
	require.NotContains(t, redactedBody([]byte("authorization: bearer-secret")), "bearer-secret")

	commands := make([]string, maxCommands+4)
	for i := range commands {
		commands[i] = strings.Repeat("x", maxCommandBytes+10)
	}
	got := boundedCommands(commands)
	require.Len(t, got, maxCommands)
	for _, command := range got {
		require.Len(t, command, maxCommandBytes)
	}
}

func TestCommandResponseShapes(t *testing.T) {
	for path, want := range map[string]string{
		"/exec/default/web/nginx?command=id":       "uid=0(root)",
		"/run/default/web/nginx?command=whoami":    "root\n",
		"/exec/default/web/nginx?command=uname+-a": "Linux worker-01",
	} {
		rec := httptest.NewRecorder()
		newHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "https://node"+path, nil))
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), want)
	}
}
