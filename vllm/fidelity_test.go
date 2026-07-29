package vllm

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
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

// -- threat_gg-tye part 1: vLLM serves exactly one model and 404s every other name.
//
// Probed live on the prod box, /v1/models advertised only the served model yet
// /v1/chat/completions returned 200 for "totally-fake-model-xyz", "../../etc/passwd" and
// "gpt-4", echoing each one back. Anyone who gets a completion for a model that does not exist
// knows the box is fake, and our own ollama honeypot 404s unknown models — so two of our boxes
// contradicted each other.

// notFoundBody is OpenAIServing._check_model's response. vLLM's ErrorResponse is a flat pydantic
// model (object/message/type/param/code in declaration order, code an int), not OpenAI's nested
// {"error":{…}} envelope with a null code that llmcore.WriteOpenAIError writes.
func notFoundBody(model string) string {
	return `{"object":"error","message":"The model ` + "`" + model + "`" +
		` does not exist.","type":"NotFoundError","param":null,"code":404}`
}

// Every route whose real counterpart calls _check_model as its first statement.
var modelRoutes = []string{"/v1/chat/completions", "/v1/completions", "/tokenize", "/detokenize"}

func TestUnknownModelIsRejected(t *testing.T) {
	// The three names probed on the live box, plus one that is a prefix of the served model (the
	// check is equality, not a substring or prefix match) and an explicitly empty name, which is
	// still a name this server does not have — distinct from omitting the field entirely.
	for _, model := range []string{
		"totally-fake-model-xyz", "../../etc/passwd", "gpt-4", "meta-llama", "",
	} {
		for _, path := range modelRoutes {
			body := `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}],"prompt":"hi","tokens":[1]}`
			rec := do(t, "POST", path, body)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s model=%q: status %d, want 404 (body %s)", path, model, rec.Code, rec.Body.String())
				continue
			}
			if got := rec.Body.String(); got != notFoundBody(model) {
				t.Errorf("%s model=%q:\n got %s\nwant %s", path, model, got, notFoundBody(model))
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("%s model=%q: content-type %q, want bare application/json", path, model, got)
			}
		}
	}
}

// A model name that differs from the served one only in case is still absent: vLLM compares the
// served model id exactly.
func TestModelMatchIsExact(t *testing.T) {
	upper := strings.ToUpper(defaultModel)
	rec := do(t, "POST", "/v1/chat/completions",
		`{"model":"`+upper+`","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("case-shifted model: status %d, want 404", rec.Code)
	}
}

// The advertised model must be the one that works, or /v1/models is a lie in the other direction.
func TestAdvertisedModelIsServed(t *testing.T) {
	for _, path := range modelRoutes {
		body := `{"model":"` + defaultModel + `","messages":[{"role":"user","content":"hi"}],"prompt":"hi","tokens":[1]}`
		if rec := do(t, "POST", path, body); rec.Code != http.StatusOK {
			t.Errorf("%s with the served model: status %d, want 200 (body %s)", path, rec.Code, rec.Body.String())
		}
	}
}

// A body naming no model falls back to the served model rather than 404ing, matching the shared
// generators' DefaultModel behaviour.
func TestAbsentModelUsesServedModel(t *testing.T) {
	rec := do(t, "POST", "/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"model":"`+defaultModel+`"`) {
		t.Errorf("body does not name the served model: %s", rec.Body.String())
	}
}

// The gate must not eat the body: the handler behind it still sees the prompt.
func TestModelGatePreservesBody(t *testing.T) {
	rec := do(t, "POST", "/tokenize", `{"model":"`+defaultModel+`","prompt":"hello world"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `"count":0`) {
		t.Errorf("prompt lost through the model gate: %s", rec.Body.String())
	}
}

// The profile's KnownModel is the backstop behind requireKnownModel: without it a future route
// wired straight to an llmcore generator would silently complete for any model again.
func TestProfileRejectsUnknownModel(t *testing.T) {
	if profile.KnownModel == nil {
		t.Fatal("profile.KnownModel is nil; the shared generators will accept any model")
	}
	if profile.KnownModel(nil, "totally-fake-model-xyz") {
		t.Error("profile accepts an unserved model")
	}
	if !profile.KnownModel(nil, defaultModel) {
		t.Error("profile rejects the model it advertises")
	}
}

// vLLM checks whether it can do embeddings at all before it validates the model — the "no
// embeddings" branch sits above _check_model — so an unknown model here is still a 400, and the
// envelope is vLLM's flat one rather than llmcore's nested OpenAI shape.
func TestEmbeddingsErrorIsVLLMShape(t *testing.T) {
	for _, model := range []string{defaultModel, "totally-fake-model-xyz"} {
		rec := do(t, "POST", "/v1/embeddings", `{"model":"`+model+`","input":"hi"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("model=%q: status %d, want 400", model, rec.Code)
		}
		want := `{"object":"error","message":"The model does not support Embeddings API",` +
			`"type":"BadRequestError","param":null,"code":400}`
		if got := rec.Body.String(); got != want {
			t.Errorf("model=%q:\n got %s\nwant %s", model, got, want)
		}
	}
}

// -- threat_gg-tye part 2: a routed path reached with the wrong verb is 405, not 404.
//
// Starlette's Route.handle raises HTTPException(405, headers={"Allow": …}) when the method is
// not registered, and FastAPI renders that as {"detail":"Method Not Allowed"}. Answering 404
// instead tells a scanner the endpoint does not exist.
func TestWrongMethodOnRoutedPathIs405(t *testing.T) {
	for _, tc := range []struct{ method, path, allow string }{
		{"GET", "/v1/chat/completions", "POST"},
		{"GET", "/v1/completions", "POST"},
		{"GET", "/v1/embeddings", "POST"},
		{"GET", "/tokenize", "POST"},
		{"GET", "/detokenize", "POST"},
		{"POST", "/v1/models", "GET, HEAD"},
		{"POST", "/health", "GET, HEAD"},
		{"POST", "/version", "GET, HEAD"},
		{"DELETE", "/docs", "GET, HEAD"},
		{"PUT", "/openapi.json", "GET, HEAD"},
	} {
		rec := do(t, tc.method, tc.path, "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status %d, want 405", tc.method, tc.path, rec.Code)
			continue
		}
		if got := rec.Body.String(); got != `{"detail":"Method Not Allowed"}` {
			t.Errorf("%s %s: body %q", tc.method, tc.path, got)
		}
		if got := rec.Header().Get("Allow"); got != tc.allow {
			t.Errorf("%s %s: Allow %q, want %q", tc.method, tc.path, got, tc.allow)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("%s %s: content-type %q, want bare application/json", tc.method, tc.path, got)
		}
	}
}

// The 404 and the 405 are different answers to different questions, and both have to stay right:
// an unrouted path must not start reporting 405 now that the catch-all route is gone.
func TestUnroutedPathStays404(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "HEAD"} {
		rec := do(t, method, "/definitely-not-a-route", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s /definitely-not-a-route: status %d, want 404", method, rec.Code)
		}
		if rec.Header().Get("Allow") != "" {
			t.Errorf("%s /definitely-not-a-route: unrouted 404 must not carry an Allow header", method)
		}
	}
}

// /metrics is a Mount of prometheus_client's ASGI app, not a path operation, and that app does
// not inspect the request method — so it must not 405.
func TestMetricsAcceptsAnyMethod(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST"} {
		if rec := do(t, method, "/metrics", ""); rec.Code != http.StatusOK {
			t.Errorf("%s /metrics: status %d, want 200", method, rec.Code)
		}
	}
}

// Rejecting a request must not make it invisible: a 404/405 is exactly the probe worth keeping,
// and the capture layer is expected to force reply_kind to ERROR on any status >= 400.
func TestRejectionsAreStillCaptured(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		wantStatus               int32
	}{
		{"unknown model", "POST", "/v1/chat/completions", `{"model":"gpt-4","messages":[]}`, 404},
		{"wrong method", "GET", "/v1/chat/completions", "", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captured := make(chan *proto.LlmRequest, 1)
			orig := saveVllmRequest
			saveVllmRequest = func(in *proto.LlmRequest) error {
				select {
				case captured <- in:
				default:
				}
				return nil
			}
			t.Cleanup(func() { saveVllmRequest = orig })

			do(t, tc.method, tc.path, tc.body)

			select {
			case in := <-captured:
				if in.ResponseStatus != tc.wantStatus {
					t.Errorf("captured status %d, want %d", in.ResponseStatus, tc.wantStatus)
				}
				if in.ReplyKind != proto.LlmReplyKind_LLM_REPLY_KIND_ERROR {
					t.Errorf("reply kind %v, want ERROR", in.ReplyKind)
				}
				if in.Path != tc.path {
					t.Errorf("captured path %q, want %q", in.Path, tc.path)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("rejected request was never captured")
			}
		})
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
