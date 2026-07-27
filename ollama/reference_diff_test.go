package ollama

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
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
	client := &http.Client{Timeout: 15 * time.Second}

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
		{name: "generate no model", method: "POST", path: "/api/generate", body: `{}`},
		{name: "generate invalid prompt", method: "POST", path: "/api/generate",
			body: `{"model":"qwen2.5-coder:7b","prompt":{}}`},
		{name: "delete unknown", method: "DELETE", path: "/api/delete", body: `{"name":"nope:latest"}`, unknownModel: true},
		{name: "blob bad digest", method: "HEAD", path: "/api/blobs/sha256:0000"},
		// threat_gg-5fb: the embeddings refusal status differs by route (501/500/501) even
		// though every model in both catalogs lacks embedding support. qwen2.5-coder:7b is
		// pulled on the reference box, so this exercises the real refusal, not a 404.
		{name: "embed", method: "POST", path: "/api/embed", body: `{"model":"qwen2.5-coder:7b","input":"hi"}`},
		{name: "embeddings legacy", method: "POST", path: "/api/embeddings", body: `{"model":"qwen2.5-coder:7b","prompt":"hi"}`},
		{name: "v1 embeddings", method: "POST", path: "/v1/embeddings", body: `{"model":"qwen2.5-coder:7b","input":"hi"}`},
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
		resp, err := client.Do(req)
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
			// Compare exact bodies for stable root/error responses. Catalog and generated
			// response bodies legitimately depend on local models, timestamps, or output.
			if c.unknownModel || strings.HasPrefix(c.name, "404") || strings.HasPrefix(c.name, "405") ||
				c.name == "root" || c.name == "show no model" || c.name == "generate no model" ||
				c.name == "generate invalid prompt" || c.name == "blob bad digest" {
				if !bytes.Equal(bytes.TrimSpace(realBody), bytes.TrimSpace(ourBody)) {
					t.Errorf("body mismatch:\n honeypot: %s\n real:     %s", ourBody, realBody)
				}
			}
		})
	}
}

// TestShowAgainstReferenceServer compares the fields a profiler uses to identify the underlying
// GGUF architecture. It runs only for models shared by the reference and honeypot catalogs, so a
// developer can point it at a smaller real installation without pulling every advertised model.
func TestShowAgainstReferenceServer(t *testing.T) {
	ref := os.Getenv("OLLAMA_REFERENCE_URL")
	if ref == "" {
		t.Skip("set OLLAMA_REFERENCE_URL to a real Ollama to run the reference diff")
	}
	ref = strings.TrimRight(ref, "/")
	client := &http.Client{Timeout: 15 * time.Second}

	srv := httptest.NewServer(buildHandler())
	defer srv.Close()

	fetchShow := func(base, model string) (*http.Response, []byte) {
		t.Helper()
		resp, err := client.Post(base+"/api/show", "application/json",
			strings.NewReader(`{"model":"`+model+`"}`))
		if err != nil {
			t.Fatalf("%s /api/show %s: %v", base, model, err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatalf("read %s /api/show %s: %v", base, model, err)
		}
		return resp, body
	}

	keys := func(body []byte) []string {
		t.Helper()
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("decode top-level response: %v", err)
		}
		out := make([]string, 0, len(raw))
		for key := range raw {
			out = append(out, key)
		}
		sort.Strings(out)
		return out
	}

	for _, model := range []string{"qwen2.5-coder:7b", "gemma3:12b"} {
		t.Run(model, func(t *testing.T) {
			realHTTP, realBody := fetchShow(ref, model)
			if realHTTP.StatusCode == http.StatusNotFound {
				t.Skipf("reference server does not have shared model %s", model)
			}
			if realHTTP.StatusCode != http.StatusOK {
				t.Fatalf("reference status %d: %s", realHTTP.StatusCode, realBody)
			}
			ourHTTP, ourBody := fetchShow(srv.URL, model)
			if ourHTTP.StatusCode != http.StatusOK {
				t.Fatalf("honeypot status %d: %s", ourHTTP.StatusCode, ourBody)
			}

			if realKeys, ourKeys := keys(realBody), keys(ourBody); !reflect.DeepEqual(realKeys, ourKeys) {
				t.Errorf("top-level keys:\n honeypot: %v\n real:     %v", ourKeys, realKeys)
			}

			var real, ours showResponse
			if err := json.Unmarshal(realBody, &real); err != nil {
				t.Fatalf("decode reference response: %v", err)
			}
			if err := json.Unmarshal(ourBody, &ours); err != nil {
				t.Fatalf("decode honeypot response: %v", err)
			}
			if !reflect.DeepEqual(ours.Details, real.Details) {
				t.Errorf("details:\n honeypot: %#v\n real:     %#v", ours.Details, real.Details)
			}
			if !reflect.DeepEqual(ours.Capabilities, real.Capabilities) {
				t.Errorf("capabilities:\n honeypot: %v\n real:     %v", ours.Capabilities, real.Capabilities)
			}
			if !reflect.DeepEqual(ours.ModelInfo, real.ModelInfo) {
				t.Error("model_info differs from real Ollama")
			}
			if !reflect.DeepEqual(ours.Tensors, real.Tensors) {
				t.Errorf("tensor inventory differs: honeypot=%d real=%d", len(ours.Tensors), len(real.Tensors))
			}
			if ours.License != real.License {
				t.Error("license differs from real Ollama")
			}
			if ours.Template != real.Template {
				t.Error("template differs from real Ollama")
			}
			if ours.System != real.System {
				t.Error("system prompt differs from real Ollama")
			}
			if ours.Parameters != real.Parameters {
				t.Error("parameters differ from real Ollama")
			}
		})
	}
}
