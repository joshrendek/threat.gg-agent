package jenkins

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

// TestHandleRequest_ServerOverride proves the HTTPOverride wiring for a net/http honeypot:
// a Matched jenkins row (keyed by "METHOD /path") is written as the body while the common
// Jenkins headers are preserved; a miss falls through to the hardcoded dashboard. Scoped to
// command_type="jenkins".
func TestHandleRequest_ServerOverride(t *testing.T) {
	orig := cmdresp.GetCommandResponse
	defer func() { cmdresp.GetCommandResponse = orig }()
	cmdresp.GetCommandResponse = func(in *pb.CommandRequest) (*pb.CommandResponse, error) {
		if in.CommandType == "jenkins" && in.Command == "GET /secret" {
			return &pb.CommandResponse{Response: "CUSTOM-BODY", Matched: true}, nil
		}
		return &pb.CommandResponse{Matched: false}, nil
	}
	h := &honeypot{logger: zerolog.Nop(), save: func(*pb.JenkinsRequest) error { return nil }}

	// (a) Matched → override body, common headers preserved.
	rec := httptest.NewRecorder()
	h.handleRequest(rec, httptest.NewRequest(http.MethodGet, "/secret", nil))
	if rec.Body.String() != "CUSTOM-BODY" {
		t.Fatalf("matched body = %q, want CUSTOM-BODY", rec.Body.String())
	}
	if rec.Header().Get("X-Jenkins") == "" {
		t.Fatal("matched: expected X-Jenkins header to be preserved on an override")
	}

	// (b) Miss → hardcoded dashboard HTML.
	rec = httptest.NewRecorder()
	h.handleRequest(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() == "CUSTOM-BODY" {
		t.Fatal("miss: got the override body, want the hardcoded dashboard")
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("miss Content-Type = %q, want text/html", rec.Header().Get("Content-Type"))
	}
}
