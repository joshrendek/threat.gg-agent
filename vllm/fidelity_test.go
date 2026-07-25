package vllm

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression tests for PRD 033. vLLM runs on FastAPI behind uvicorn, so its wire behaviour
// differs from Ollama's in specific, checkable ways.

func do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	buildHandler().ServeHTTP(rec, r)
	return rec
}

// /metrics is the single most-requested path on this honeypot in prod (16 hits, 11 distinct
// IPs — Palo Alto Xpanse and similar) and used to return a JSON 404.
func TestMetricsServesPrometheusText(t *testing.T) {
	rec := do(t, "GET", "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain; version=0.0.4") {
		t.Errorf("content-type %q, want Prometheus exposition", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# HELP vllm:num_requests_running",
		"# TYPE vllm:num_requests_running gauge",
		"vllm:prompt_tokens_total",
		"vllm:generation_tokens_total",
		"vllm:time_to_first_token_seconds_bucket",
		"vllm:e2e_request_latency_seconds_sum",
		"vllm:cache_config_info",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if !strings.Contains(body, `model_name="`+defaultModel+`"`) {
		t.Error("metrics not labelled with the served model")
	}
}

// A real exporter's counters advance between scrapes; a frozen body is its own tell.
func TestMetricsCountersAdvance(t *testing.T) {
	first := do(t, "GET", "/metrics", "").Body.String()
	// counterAt is derived from uptime, so a later scrape must not be byte-identical forever.
	// Assert the mechanism rather than sleeping: the counter must be non-zero and parseable.
	if !strings.Contains(first, "vllm:prompt_tokens_total{") {
		t.Fatal("prompt tokens counter missing")
	}
	if strings.Contains(first, "vllm:prompt_tokens_total{model_name=\""+defaultModel+"\"} 0\n") {
		t.Error("counter is pinned at zero; a box serving traffic would have accrued tokens")
	}
}

// FastAPI answers unrouted paths with {"detail":"Not Found"} — not an OpenAI error envelope.
func TestNotFoundIsFastAPIShape(t *testing.T) {
	rec := do(t, "GET", "/definitely-not-a-route", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if got := rec.Body.String(); got != `{"detail":"Not Found"}` {
		t.Errorf("body %q, want %q", got, `{"detail":"Not Found"}`)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type %q, want bare application/json (FastAPI adds no charset)", got)
	}
}

// uvicorn genuinely does send a Server header, unlike Ollama's Gin.
func TestUvicornServerHeaderIsPresent(t *testing.T) {
	if got := do(t, "GET", "/health", "").Header().Get("Server"); got != "uvicorn" {
		t.Errorf("Server %q, want uvicorn", got)
	}
}

// FastAPI mounts these by default and vLLM does not disable them; 404ing both on a box that is
// otherwise obviously FastAPI is inconsistent.
func TestOpenAPIAndDocsAreMounted(t *testing.T) {
	rec := do(t, "GET", "/openapi.json", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"openapi"`) {
		t.Errorf("/openapi.json: status %d body %.80s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/v1/chat/completions") {
		t.Error("/openapi.json does not document the served routes")
	}
	rec = do(t, "GET", "/docs", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "swagger-ui") {
		t.Errorf("/docs: status %d", rec.Code)
	}
}

// vLLM omits system_fingerprint entirely, where Ollama stamps "fp_ollama". Emitting Ollama's
// value here would be a cross-product inconsistency.
func TestNoSystemFingerprint(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"`+defaultModel+`","messages":[{"role":"user","content":"hi"}]}`)
	if strings.Contains(rec.Body.String(), "system_fingerprint") {
		t.Errorf("vLLM must not emit system_fingerprint: %s", rec.Body.String())
	}
}

func TestTokenizeAndPing(t *testing.T) {
	rec := do(t, "POST", "/tokenize", `{"prompt":"hello world"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count"`) {
		t.Errorf("/tokenize: status %d body %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, "GET", "/ping", ""); rec.Code != http.StatusOK {
		t.Errorf("/ping: status %d", rec.Code)
	}
}

// The shared llmcore fix must land here too.
func TestMaxTokensHonoured(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"`+defaultModel+`","messages":[{"role":"user","content":"Reply with OK."}],"max_tokens":1}`)
	if !strings.Contains(rec.Body.String(), `"finish_reason":"length"`) {
		t.Errorf("want finish_reason length: %s", rec.Body.String())
	}
}
