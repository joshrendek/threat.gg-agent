package cmdresp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/llmcore"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// stub swaps the gRPC seam for a test double and restores it on cleanup.
func stub(t *testing.T, fn func(*proto.CommandRequest) (*proto.CommandResponse, error)) {
	t.Helper()
	orig := GetCommandResponse
	GetCommandResponse = fn
	t.Cleanup(func() { GetCommandResponse = orig })
}

func stubWithin(t *testing.T, fn func(*proto.CommandRequest, time.Duration) (*proto.CommandResponse, error)) {
	t.Helper()
	original := GetCommandResponseWithin
	GetCommandResponseWithin = fn
	t.Cleanup(func() { GetCommandResponseWithin = original })
}

// TestLookup covers the shared gate every honeypot relies on: a Matched row returns
// (response, true); a miss, an error, and an oversized command all return ("", false) so
// the caller falls back to its hardcoded handler. The request carries the given
// command_type and command verbatim.
func TestLookup(t *testing.T) {
	// Matched.
	stub(t, func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "ftp" || in.Command != "SYST" {
			t.Fatalf("forwarded (%q,%q), want (ftp,SYST)", in.CommandType, in.Command)
		}
		return &proto.CommandResponse{Response: "215 UNIX Type: L8\r\n", Matched: true}, nil
	})
	if got, ok := Lookup("ftp", "SYST"); !ok || got != "215 UNIX Type: L8\r\n" {
		t.Fatalf("matched: (%q,%v), want the response,true", got, ok)
	}

	// Miss (Matched=false).
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "x", Matched: false}, nil
	})
	if got, ok := Lookup("ftp", "SYST"); ok || got != "" {
		t.Fatalf("miss: (%q,%v), want empty,false", got, ok)
	}

	// Error.
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return nil, errors.New("boom")
	})
	if _, ok := Lookup("ftp", "SYST"); ok {
		t.Fatal("error: ok=true, want false")
	}

	// Oversized → not forwarded.
	called := false
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		called = true
		return &proto.CommandResponse{Response: "x", Matched: true}, nil
	})
	if _, ok := Lookup("ftp", strings.Repeat("a", MaxServerLookupLen+1)); ok {
		t.Fatal("oversized: ok=true, want false")
	}
	if called {
		t.Fatal("oversized command must not be forwarded")
	}
}

func TestLookupAndRecordUsesTheExactLookupKey(t *testing.T) {
	originalSave := SaveResponseLookup
	defer func() { SaveResponseLookup = originalSave }()
	saved := make(chan *proto.ResponseLookupRequest, 1)
	SaveResponseLookup = func(request *proto.ResponseLookupRequest) error {
		saved <- request
		return nil
	}
	stub(t, func(request *proto.CommandRequest) (*proto.CommandResponse, error) {
		if request.CommandType != "mysql" || request.Command != "select @@version" {
			t.Fatalf("lookup request = %+v", request)
		}
		return &proto.CommandResponse{Matched: false}, nil
	})

	LookupAndRecord("mysql", "select @@version", "session-guid")
	select {
	case request := <-saved:
		if request.Guid != "session-guid" || request.CommandType != "mysql" || request.LookupKey != "select @@version" {
			t.Fatalf("saved request = %+v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("lookup telemetry was not saved")
	}
}

func TestLookupAndRecordSkipsOversizedKeys(t *testing.T) {
	originalSave := SaveResponseLookup
	originalLookup := GetCommandResponse
	defer func() {
		SaveResponseLookup = originalSave
		GetCommandResponse = originalLookup
	}()
	called := make(chan string, 2)
	SaveResponseLookup = func(*proto.ResponseLookupRequest) error { called <- "save"; return nil }
	GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		called <- "lookup"
		return &proto.CommandResponse{}, nil
	}
	LookupAndRecord("ftp", strings.Repeat("x", MaxServerLookupLen+1), "guid")
	select {
	case call := <-called:
		t.Fatalf("oversized key reached %s", call)
	case <-time.After(25 * time.Millisecond):
	}
}

// TestHTTPOverride: a Matched row for "METHOD /path" is written as the HTTP body and
// returns true; a miss returns false and writes nothing so the caller renders its default.
func TestHTTPOverride(t *testing.T) {
	stub(t, func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "elasticsearch" || in.Command != "GET /_cat/indices" {
			t.Fatalf("forwarded (%q,%q), want (elasticsearch,GET /_cat/indices)", in.CommandType, in.Command)
		}
		return &proto.CommandResponse{Response: `{"ok":true}`, Matched: true}, nil
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_cat/indices", nil)
	if !HTTPOverride(rec, req, "elasticsearch") {
		t.Fatal("matched: HTTPOverride returned false, want true")
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("matched body = %q, want the response", rec.Body.String())
	}

	// Miss → false, nothing written.
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Matched: false}, nil
	})
	rec = httptest.NewRecorder()
	if HTTPOverride(rec, httptest.NewRequest(http.MethodGet, "/", nil), "elasticsearch") {
		t.Fatal("miss: HTTPOverride returned true, want false")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("miss wrote %q, want nothing", rec.Body.String())
	}
}

func TestHTTPOverrideStructuredStatusAndHeaders(t *testing.T) {
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{
			Response: HTTPResponsePrefix + `{"status":201,"headers":{"Content-Type":"application/json","X-Etcd-Index":"18432"},"body":"{\"ok\":true}"}`,
			Matched:  true,
		}, nil
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v3/kv/range", nil)
	if !HTTPOverride(recorder, request, "etcd") {
		t.Fatal("structured response did not match")
	}
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	if got := recorder.Header().Get("X-Etcd-Index"); got != "18432" {
		t.Fatalf("X-Etcd-Index = %q", got)
	}
	if got := recorder.Body.String(); got != `{"ok":true}` {
		t.Fatalf("body = %q", got)
	}
}

func TestHTTPOverrideMalformedEnvelopeRemainsBodyOnly(t *testing.T) {
	value := HTTPResponsePrefix + `{"status":999,"body":"bad"}`
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: value, Matched: true}, nil
	})
	recorder := httptest.NewRecorder()
	if !HTTPOverride(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "docker") {
		t.Fatal("malformed envelope should remain a matched body-only row")
	}
	if recorder.Body.String() != value {
		t.Fatalf("body = %q, want original value", recorder.Body.String())
	}
}

func TestHTTPOverrideDropsUnsafeStructuredHeaders(t *testing.T) {
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{
			Response: HTTPResponsePrefix + `{"headers":{"Good":"yes","Bad":"one\r\nInjected: yes"},"body":"ok"}`,
			Matched:  true,
		}, nil
	})
	recorder := httptest.NewRecorder()
	HTTPOverride(recorder, httptest.NewRequest(http.MethodGet, "/", nil), "docker")
	if recorder.Header().Get("Good") != "yes" {
		t.Fatal("valid header was not written")
	}
	if recorder.Header().Get("Bad") != "" || recorder.Header().Get("Injected") != "" {
		t.Fatal("unsafe header was written")
	}
}

// TestMuxMiddleware: on a Matched row the wrapped handler is NOT called and the override
// body is written; on a miss the wrapped handler runs normally.
func TestMuxMiddleware(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.Write([]byte("DEFAULT"))
	})

	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "OVERRIDE", Matched: true}, nil
	})
	rec := httptest.NewRecorder()
	MuxMiddleware("docker")(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	if nextCalled {
		t.Fatal("matched: wrapped handler was called, want intercepted")
	}
	if rec.Body.String() != "OVERRIDE" {
		t.Fatalf("matched body = %q, want OVERRIDE", rec.Body.String())
	}

	nextCalled = false
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Matched: false}, nil
	})
	rec = httptest.NewRecorder()
	MuxMiddleware("docker")(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	if !nextCalled {
		t.Fatal("miss: wrapped handler was not called, want fallthrough")
	}
	if rec.Body.String() != "DEFAULT" {
		t.Fatalf("miss body = %q, want DEFAULT", rec.Body.String())
	}
}

func TestMuxMiddlewareMarksCapturedCommandResponseSource(t *testing.T) {
	stub(t, func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: `{"overridden":true}`, Matched: true}, nil
	})
	saved := make(chan *proto.LlmRequest, 1)
	handler := llmcore.Capture(func(request *proto.LlmRequest) error {
		saved <- request
		return nil
	})(MuxMiddleware("ollama")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("matched command response fell through")
	})))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/generate", nil))
	select {
	case request := <-saved:
		if request.ResponseSource != proto.LlmResponseSource_LLM_RESPONSE_SOURCE_COMMAND_RESPONSE {
			t.Fatalf("response source = %v, want command response", request.ResponseSource)
		}
		if request.ResponseStatus != http.StatusOK {
			t.Fatalf("response status = %d, want 200", request.ResponseStatus)
		}
	case <-time.After(time.Second):
		t.Fatal("captured command response was not saved")
	}
}

func TestLLMMuxMiddlewarePreservesFastOverridesAndFailsOpenConcurrently(t *testing.T) {
	t.Run("matched override", func(t *testing.T) {
		calls := 0
		stubWithin(t, func(in *proto.CommandRequest, timeout time.Duration) (*proto.CommandResponse, error) {
			calls++
			if timeout != LLMOverrideTimeout {
				t.Fatalf("timeout = %v, want %v", timeout, LLMOverrideTimeout)
			}
			if in.CommandType != "ollama" || in.Command != "GET /api/tags" {
				t.Fatalf("lookup = %+v", in)
			}
			return &proto.CommandResponse{Matched: true, Response: `{"models":[]}`}, nil
		})
		handler := LLMMuxMiddleware("ollama")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("matched override fell through")
		}))
		for i := 0; i < 2; i++ {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/tags", nil))
			if got := recorder.Body.String(); got != `{"models":[]}` {
				t.Fatalf("body = %q", got)
			}
		}
		if calls != 1 {
			t.Fatalf("matched control-plane lookups = %d, want one cached lookup", calls)
		}
	})

	t.Run("concurrent stalled lookups", func(t *testing.T) {
		var calls atomic.Int32
		stubWithin(t, func(_ *proto.CommandRequest, timeout time.Duration) (*proto.CommandResponse, error) {
			calls.Add(1)
			<-time.After(timeout)
			return nil, context.DeadlineExceeded
		})
		const callers = 16
		var wg sync.WaitGroup
		handler := LLMMuxMiddleware("ollama")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		started := time.Now()
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/tags", nil))
				if recorder.Code != http.StatusNoContent {
					t.Errorf("fallback status = %d, want 204", recorder.Code)
				}
			}()
		}
		wg.Wait()
		if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
			t.Fatalf("concurrent LLM fallbacks took %v, want close to one %v deadline", elapsed, LLMOverrideTimeout)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("control-plane lookups = %d, want one coalesced lookup", got)
		}
	})

	t.Run("caches bounded misses and retries after expiry", func(t *testing.T) {
		calls := 0
		stubWithin(t, func(*proto.CommandRequest, time.Duration) (*proto.CommandResponse, error) {
			calls++
			return &proto.CommandResponse{Matched: false}, nil
		})
		handler := llmMuxMiddleware("ollama", 20*time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		for i := 0; i < 2; i++ {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/tags", nil))
		}
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/version", nil))
		if calls != 2 {
			t.Fatalf("lookup calls = %d, want one per distinct key during miss TTL", calls)
		}
		time.Sleep(30 * time.Millisecond)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/tags", nil))
		if calls != 3 {
			t.Fatalf("lookup calls after expiry = %d, want expired route rechecked", calls)
		}
	})

	t.Run("caps concurrent distinct-route lookups", func(t *testing.T) {
		var active, peak, calls atomic.Int32
		entered := make(chan struct{}, maxConcurrentLLMLookups)
		release := make(chan struct{})
		stubWithin(t, func(*proto.CommandRequest, time.Duration) (*proto.CommandResponse, error) {
			calls.Add(1)
			current := active.Add(1)
			for {
				previous := peak.Load()
				if current <= previous || peak.CompareAndSwap(previous, current) {
					break
				}
			}
			entered <- struct{}{}
			<-release
			active.Add(-1)
			return nil, context.DeadlineExceeded
		})
		handler := LLMMuxMiddleware("ollama")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		var wg sync.WaitGroup
		for i := 0; i < maxConcurrentLLMLookups; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				path := fmt.Sprintf("/api/distinct/%d", i)
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
			}(i)
		}
		for i := 0; i < maxConcurrentLLMLookups; i++ {
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("lookup slots did not fill")
			}
		}

		saturatedStarted := time.Now()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/saturated", nil))
		if elapsed := time.Since(saturatedStarted); elapsed > 50*time.Millisecond {
			t.Fatalf("saturated request took %v, want immediate fail-open", elapsed)
		}
		if got := calls.Load(); got != maxConcurrentLLMLookups {
			t.Fatalf("calls while saturated = %d, want %d", got, maxConcurrentLLMLookups)
		}

		close(release)
		wg.Wait()
		if got := peak.Load(); got != maxConcurrentLLMLookups {
			t.Fatalf("peak control-plane lookups = %d, want %d", got, maxConcurrentLLMLookups)
		}

		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/saturated", nil))
		if got := calls.Load(); got != maxConcurrentLLMLookups+1 {
			t.Fatalf("calls after slots released = %d, want saturated route retried", got)
		}
	})

	t.Run("does not cache transient lookup errors", func(t *testing.T) {
		calls := 0
		stubWithin(t, func(*proto.CommandRequest, time.Duration) (*proto.CommandResponse, error) {
			calls++
			if calls == 1 {
				return nil, context.DeadlineExceeded
			}
			return &proto.CommandResponse{Matched: true, Response: "RECOVERED"}, nil
		})
		handler := LLMMuxMiddleware("ollama")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		first := httptest.NewRecorder()
		handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/tags", nil))
		if first.Code != http.StatusNoContent {
			t.Fatalf("first status = %d, want fail-open 204", first.Code)
		}
		second := httptest.NewRecorder()
		handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/tags", nil))
		if second.Body.String() != "RECOVERED" || calls != 2 {
			t.Fatalf("recovery body = %q, calls = %d", second.Body.String(), calls)
		}
	})

	t.Run("does not retain oversized cache keys", func(t *testing.T) {
		calls := 0
		stubWithin(t, func(*proto.CommandRequest, time.Duration) (*proto.CommandResponse, error) {
			calls++
			return &proto.CommandResponse{Matched: false}, nil
		})
		handler := LLMMuxMiddleware("ollama")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		path := "/" + strings.Repeat("x", MaxServerLookupLen+1)
		for i := 0; i < 2; i++ {
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
		}
		if calls != 0 {
			t.Fatalf("oversized path caused %d lookups, want none", calls)
		}
	})
}

func TestLLMOverrideCacheIsBounded(t *testing.T) {
	cache := &llmOverrideCache{entries: make(map[string]llmOverrideCacheEntry)}
	until := time.Now().Add(time.Minute)
	for i := 0; i < maxLLMOverrideCache+100; i++ {
		cache.mu.Lock()
		cache.rememberLocked(fmt.Sprintf("GET /attacker-path/%d", i), llmOverrideCacheEntry{until: until})
		cache.mu.Unlock()
	}
	if got := len(cache.entries); got != maxLLMOverrideCache {
		t.Fatalf("cache size = %d, want bounded at %d", got, maxLLMOverrideCache)
	}
}

// TestIsRowReturning: the SQL framing helper shared by the postgres-style binary honeypots
// (mysql). Row-returning verbs render as a data row; other statements render as an OK packet.
func TestIsRowReturning(t *testing.T) {
	for _, q := range []string{"select 1", "  SHOW databases", "with x as (select 1) select *", "values (1)", "table t"} {
		if !IsRowReturning(q) {
			t.Errorf("IsRowReturning(%q)=false, want true", q)
		}
	}
	for _, q := range []string{"set names utf8", "begin", "insert into t values (1)", "use mysql", ""} {
		if IsRowReturning(q) {
			t.Errorf("IsRowReturning(%q)=true, want false", q)
		}
	}
}
