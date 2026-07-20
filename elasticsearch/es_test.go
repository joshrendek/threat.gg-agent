package elasticsearch

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestServeHTTPPersistsMethodAndPathBeforeOverride(t *testing.T) {
	originalSave := saveElasticRequest
	originalLookup := cmdresp.GetCommandResponse
	defer func() {
		saveElasticRequest = originalSave
		cmdresp.GetCommandResponse = originalLookup
	}()
	saved := make(chan *proto.ElasticsearchRequest, 2)
	saveElasticRequest = func(request *proto.ElasticsearchRequest) error { saved <- request; return nil }
	cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Matched: true, Response: `{"seeded":true}`}, nil
	}

	request := httptest.NewRequest(http.MethodGet, "/_cat/indices", nil)
	request.RemoteAddr = "192.0.2.10:4231"
	recorder := httptest.NewRecorder()
	(&ES{}).ServeHTTP(recorder, request)

	select {
	case captured := <-saved:
		if captured.Method != http.MethodGet || captured.Path != "/_cat/indices" {
			t.Fatalf("captured request = %+v", captured)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not captured")
	}
	select {
	case duplicate := <-saved:
		t.Fatalf("request captured twice: %+v", duplicate)
	case <-time.After(25 * time.Millisecond):
	}
	if recorder.Body.String() != `{"seeded":true}` {
		t.Fatalf("override body = %q", recorder.Body.String())
	}
}
