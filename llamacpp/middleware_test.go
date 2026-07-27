package llamacpp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestBuildHandlerUsesLlamacppLLMOverride(t *testing.T) {
	originalLookup, originalSave := cmdresp.GetCommandResponseWithin, saveLlamacppRequest
	t.Cleanup(func() {
		cmdresp.GetCommandResponseWithin, saveLlamacppRequest = originalLookup, originalSave
	})
	saveLlamacppRequest = func(*proto.LlmRequest) error { return nil }
	cmdresp.GetCommandResponseWithin = func(in *proto.CommandRequest, timeout time.Duration) (*proto.CommandResponse, error) {
		if in.CommandType != "llamacpp" || in.Command != "GET /props" || timeout != cmdresp.LLMOverrideTimeout {
			t.Fatalf("lookup = %+v, timeout = %v", in, timeout)
		}
		return &proto.CommandResponse{Matched: true, Response: `{"override":"llamacpp"}`}, nil
	}

	recorder := httptest.NewRecorder()
	buildHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/props", nil))
	if got := recorder.Body.String(); got != `{"override":"llamacpp"}` {
		t.Fatalf("body = %q", got)
	}
}
