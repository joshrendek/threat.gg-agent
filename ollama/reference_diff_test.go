package ollama

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestAgainstReferenceServer diffs this honeypot against a real Ollama, so the fidelity claims
// in PRD 033 can be re-verified against a new upstream release rather than trusted forever.
//
// Skipped unless a reference server is pointed at:
//
//	OLLAMA_REFERENCE_URL=http://127.0.0.1:11434 go test ./ollama/ -run Reference -v
//
// It compares the observable properties a fingerprinting scanner can read without knowing which
// models the box happens to host: status code, content type, and the presence or absence of
// identifying headers. Body *values* legitimately differ (a real box lists its own models); body
// *shape* is covered by the fixtures in fidelity_test.go.
func TestAgainstReferenceServer(t *testing.T) {
	ref := os.Getenv("OLLAMA_REFERENCE_URL")
	if ref == "" {
		t.Skip("set OLLAMA_REFERENCE_URL to a real Ollama to run the reference diff")
	}
	ref = strings.TrimRight(ref, "/")

	srv := httptest.NewServer(buildHandler())
	defer srv.Close()

	cases := []struct {
		name, method, path, body string
		// unknownModel marks requests naming a model the reference box will not have either,
		// so both sides should produce the same not-found behaviour.
		unknownModel bool
	}{
		{name: "root", method: "GET", path: "/"},
		{name: "head root", method: "HEAD", path: "/"},
		{name: "version", method: "GET", path: "/api/version"},
		{name: "tags", method: "GET", path: "/api/tags"},
		{name: "ps", method: "GET", path: "/api/ps"},
		{name: "v1 models", method: "GET", path: "/v1/models"},
		{name: "404 props", method: "GET", path: "/props"},
		{name: "404 metrics", method: "GET", path: "/metrics"},
		{name: "404 random", method: "GET", path: "/nonexistent-xyz"},
		{name: "405 generate", method: "GET", path: "/api/generate"},
		{name: "show no model", method: "POST", path: "/api/show", body: `{}`},
		{name: "show unknown", method: "POST", path: "/api/show", body: `{"name":"nope:latest"}`, unknownModel: true},
		{name: "chat unknown model", method: "POST", path: "/api/chat",
			body: `{"model":"nope:latest","messages":[{"role":"user","content":"hi"}],"stream":false}`, unknownModel: true},
		{name: "v1 chat unknown model", method: "POST", path: "/v1/chat/completions",
			body: `{"model":"nope","messages":[{"role":"user","content":"hi"}]}`, unknownModel: true},
		{name: "generate malformed", method: "POST", path: "/api/generate", body: `not-json`},
		{name: "delete unknown", method: "DELETE", path: "/api/delete", body: `{"name":"nope:latest"}`, unknownModel: true},
		{name: "blob bad digest", method: "HEAD", path: "/api/blobs/sha256:0000"},
	}

	fetch := func(base string, c struct {
		name, method, path, body string
		unknownModel             bool
	}) (*http.Response, []byte, error) {
		var rdr io.Reader
		if c.body != "" {
			rdr = strings.NewReader(c.body)
		}
		req, err := http.NewRequest(c.method, base+c.path, rdr)
		if err != nil {
			return nil, nil, err
		}
		if c.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp, b, nil
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			realResp, realBody, err := fetch(ref, c)
			if err != nil {
				t.Fatalf("reference request failed: %v", err)
			}
			ourResp, ourBody, err := fetch(srv.URL, c)
			if err != nil {
				t.Fatalf("honeypot request failed: %v", err)
			}

			if realResp.StatusCode != ourResp.StatusCode {
				t.Errorf("status: honeypot %d, real %d", ourResp.StatusCode, realResp.StatusCode)
			}
			if r, o := realResp.Header.Get("Content-Type"), ourResp.Header.Get("Content-Type"); r != o {
				t.Errorf("content-type: honeypot %q, real %q", o, r)
			}
			if r, o := realResp.Header.Get("Server"), ourResp.Header.Get("Server"); r != o {
				t.Errorf("Server header: honeypot %q, real %q", o, r)
			}
			if r, o := realResp.Header.Get("Allow"), ourResp.Header.Get("Allow"); r != o {
				t.Errorf("Allow header: honeypot %q, real %q", o, r)
			}
			// For plain-text and not-found paths the bodies should match exactly; for
			// catalog-dependent endpoints they legitimately differ.
			if c.unknownModel || strings.HasPrefix(c.name, "404") || strings.HasPrefix(c.name, "405") ||
				c.name == "root" || c.name == "show no model" || c.name == "blob bad digest" {
				if !bytes.Equal(bytes.TrimSpace(realBody), bytes.TrimSpace(ourBody)) {
					t.Errorf("body mismatch:\n honeypot: %s\n real:     %s", ourBody, realBody)
				}
			}
		})
	}
}
