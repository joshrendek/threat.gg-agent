package cmdresp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// TestHTTPOverrideDefaultsJSONContentType pins the fidelity fix: an admin-authored JSON body
// must be served as application/json (not Go-sniffed text/plain), while non-JSON bodies keep
// the default text/plain behavior.
func TestHTTPOverrideDefaultsJSONContentType(t *testing.T) {
	orig := GetCommandResponse
	defer func() { GetCommandResponse = orig }()

	cases := []struct {
		name, body, wantCT string
	}{
		{"json object", `{"object":"list","data":[]}`, "application/json"},
		{"json array", `[{"a":1}]`, "application/json"},
		{"leading whitespace json", "  \n{\"x\":1}", "application/json"},
		{"plain text banner", "Ollama is running", "text/plain; charset=utf-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
				return &proto.CommandResponse{Response: tc.body, Matched: true}, nil
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			if !HTTPOverride(rec, req, "vllm") {
				t.Fatal("expected override to handle the request")
			}
			if got := rec.Header().Get("Content-Type"); got != tc.wantCT {
				t.Fatalf("Content-Type = %q, want %q", got, tc.wantCT)
			}
			if rec.Body.String() != tc.body {
				t.Fatalf("body = %q, want %q", rec.Body.String(), tc.body)
			}
		})
	}
}

// TestHTTPOverridePreservesCallerContentType ensures a Content-Type the caller already set is
// never clobbered (backward-compat with honeypots that set their own).
func TestHTTPOverridePreservesCallerContentType(t *testing.T) {
	orig := GetCommandResponse
	defer func() { GetCommandResponse = orig }()
	GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: `{"a":1}`, Matched: true}, nil
	}
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/xml")
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	HTTPOverride(rec, req, "vllm")
	if got := rec.Header().Get("Content-Type"); got != "application/xml" {
		t.Fatalf("caller Content-Type not preserved: %q", got)
	}
}

// TestHTTPOverrideStructuredContentType: the @http structured form defaults JSON too when the
// author didn't set Content-Type, but an explicit author header wins.
func TestHTTPOverrideStructuredContentType(t *testing.T) {
	orig := GetCommandResponse
	defer func() { GetCommandResponse = orig }()

	GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: HTTPResponsePrefix + `{"status":200,"body":"{\"ok\":true}"}`, Matched: true}, nil
	}
	rec := httptest.NewRecorder()
	HTTPOverride(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil), "vllm")
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("structured JSON body Content-Type = %q, want application/json", got)
	}

	GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: HTTPResponsePrefix + `{"status":200,"headers":{"Content-Type":"text/yaml"},"body":"{\"ok\":true}"}`, Matched: true}, nil
	}
	rec = httptest.NewRecorder()
	HTTPOverride(rec, httptest.NewRequest(http.MethodGet, "/v1/models", nil), "vllm")
	if got := rec.Header().Get("Content-Type"); got != "text/yaml" {
		t.Fatalf("explicit author Content-Type = %q, want text/yaml (not overridden)", got)
	}
}
