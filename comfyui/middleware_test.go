package comfyui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestBuildHandlerUsesComfyuiLLMOverride(t *testing.T) {
	originalLookup, originalSave := cmdresp.GetCommandResponseWithin, saveComfyuiRequest
	t.Cleanup(func() {
		cmdresp.GetCommandResponseWithin, saveComfyuiRequest = originalLookup, originalSave
	})
	saveComfyuiRequest = func(*proto.LlmRequest) error { return nil }
	cmdresp.GetCommandResponseWithin = func(in *proto.CommandRequest, timeout time.Duration) (*proto.CommandResponse, error) {
		if in.CommandType != "comfyui" || in.Command != "GET /system_stats" || timeout != cmdresp.LLMOverrideTimeout {
			t.Fatalf("lookup = %+v, timeout = %v", in, timeout)
		}
		return &proto.CommandResponse{Matched: true, Response: `{"override":"comfyui"}`}, nil
	}

	recorder := httptest.NewRecorder()
	buildHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/system_stats", nil))
	if got := recorder.Body.String(); got != `{"override":"comfyui"}` {
		t.Fatalf("body = %q", got)
	}
}
