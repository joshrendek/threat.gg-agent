package ray

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestBuildHandlerUsesRayLLMOverride(t *testing.T) {
	originalLookup, originalSave := cmdresp.GetCommandResponseWithin, saveRayRequest
	t.Cleanup(func() {
		cmdresp.GetCommandResponseWithin, saveRayRequest = originalLookup, originalSave
	})
	saveRayRequest = func(*proto.LlmRequest) error { return nil }
	cmdresp.GetCommandResponseWithin = func(in *proto.CommandRequest, timeout time.Duration) (*proto.CommandResponse, error) {
		if in.CommandType != "ray" || in.Command != "GET /api/version" || timeout != cmdresp.LLMOverrideTimeout {
			t.Fatalf("lookup = %+v, timeout = %v", in, timeout)
		}
		return &proto.CommandResponse{Matched: true, Response: `{"override":"ray"}`}, nil
	}

	recorder := httptest.NewRecorder()
	buildHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/version", nil))
	if got := recorder.Body.String(); got != `{"override":"ray"}` {
		t.Fatalf("body = %q", got)
	}
}
