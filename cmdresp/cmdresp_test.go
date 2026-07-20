package cmdresp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// stub swaps the gRPC seam for a test double and restores it on cleanup.
func stub(t *testing.T, fn func(*proto.CommandRequest) (*proto.CommandResponse, error)) {
	t.Helper()
	orig := GetCommandResponse
	GetCommandResponse = fn
	t.Cleanup(func() { GetCommandResponse = orig })
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
