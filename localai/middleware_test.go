package localai

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestBuildHandlerUsesLocalaiLLMOverride(t *testing.T) {
	originalLookup, originalSave := cmdresp.GetCommandResponseWithin, saveLocalaiRequest
	t.Cleanup(func() {
		cmdresp.GetCommandResponseWithin, saveLocalaiRequest = originalLookup, originalSave
	})
	saveLocalaiRequest = func(*proto.LlmRequest) error { return nil }
	cmdresp.GetCommandResponseWithin = func(in *proto.CommandRequest, timeout time.Duration) (*proto.CommandResponse, error) {
		if in.CommandType != "localai" || in.Command != "GET /v1/models" || timeout != cmdresp.LLMOverrideTimeout {
			t.Fatalf("lookup = %+v, timeout = %v", in, timeout)
		}
		return &proto.CommandResponse{Matched: true, Response: `{"override":"localai"}`}, nil
	}

	recorder := httptest.NewRecorder()
	buildHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	if got := recorder.Body.String(); got != `{"override":"localai"}` {
		t.Fatalf("body = %q", got)
	}
}
