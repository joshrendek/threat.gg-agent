package etcd

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveEtcdRequest = func(*proto.EtcdRequest) error { return nil }
	os.Exit(m.Run())
}

func TestHandleV3RangeObservedKeyProbes(t *testing.T) {
	for _, body := range []string{
		`{"key":"admin"}`,
		`{"key":"wallet"}`,
		`{"key":"c2VjcmV0"}`,
		`{"key":"token"}`,
		`{"key":"mnemonic"}`,
		`{"key":"private_key"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v3/kv/range", strings.NewReader(body))
		recorder := httptest.NewRecorder()
		handleV3Range(recorder, req)

		if recorder.Code != http.StatusOK {
			t.Fatalf("body %s: status = %d, body = %s", body, recorder.Code, recorder.Body.String())
		}
		var response v3RangeResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("body %s: invalid JSON: %v", body, err)
		}
		if response.Count != "1" || len(response.KVs) != 1 {
			t.Fatalf("body %s: count = %s, kvs = %d", body, response.Count, len(response.KVs))
		}
		if _, err := base64.StdEncoding.DecodeString(response.KVs[0].Value); err != nil {
			t.Fatalf("body %s: value is not base64: %v", body, err)
		}
	}
}

func TestHandleV3RangeAllKeysLimitAndCount(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v3/kv/range", strings.NewReader(`{"key":"AA==","range_end":"AA==","limit":2}`))
	recorder := httptest.NewRecorder()
	handleV3Range(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response v3RangeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.More || len(response.KVs) != 2 || response.Count != "12" {
		t.Fatalf("unexpected range response: %+v", response)
	}
}

func TestV3KeyMetadataIsStableAcrossQueryShapes(t *testing.T) {
	walletCreate, walletMod := v3KeyRevisions("wallet")
	request := httptest.NewRequest(http.MethodPost, "/v3/kv/range", strings.NewReader(`{"key":"wallet"}`))
	recorder := httptest.NewRecorder()
	handleV3Range(recorder, request)
	var response v3RangeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.KVs) != 1 || response.KVs[0].CreateRevision != walletCreate || response.KVs[0].ModRevision != walletMod {
		t.Fatalf("wallet metadata = %+v; want revisions %s/%s", response.KVs, walletCreate, walletMod)
	}
}

func TestHandleV3RangeRejectsMalformedAndOversizedBodies(t *testing.T) {
	for _, test := range []struct {
		body   string
		status int
	}{
		{body: `{`, status: http.StatusBadRequest},
		{body: `{"limit":-1}`, status: http.StatusBadRequest},
		{body: strings.Repeat("x", maxV3RangeBodySize+1), status: http.StatusRequestEntityTooLarge},
	} {
		req := httptest.NewRequest(http.MethodPost, "/v3/kv/range", strings.NewReader(test.body))
		recorder := httptest.NewRecorder()
		handleV3Range(recorder, req)
		if recorder.Code != test.status {
			t.Errorf("status = %d, want %d; body = %s", recorder.Code, test.status, recorder.Body.String())
		}
	}
}

func TestRegisterRoutesIncludesV3Range(t *testing.T) {
	router := newEtcdTestRouter()
	req := httptest.NewRequest(http.MethodPost, "/v3/kv/range", strings.NewReader(`{"key":"secret"}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestCaptureWrapsMatchedAndUnmatchedOverridesExactlyOnce(t *testing.T) {
	for _, matched := range []bool{true, false} {
		t.Run(map[bool]string{true: "matched", false: "unmatched"}[matched], func(t *testing.T) {
			saved := make(chan *proto.EtcdRequest, 2)
			originalSave := saveEtcdRequest
			originalLookup := cmdresp.GetCommandResponse
			saveEtcdRequest = func(request *proto.EtcdRequest) error {
				saved <- request
				return nil
			}
			cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
				return &proto.CommandResponse{Response: "OVERRIDE", Matched: matched}, nil
			}
			t.Cleanup(func() {
				saveEtcdRequest = originalSave
				cmdresp.GetCommandResponse = originalLookup
			})

			nextCalls := 0
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalls++
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"key":"secret"}` {
					t.Errorf("downstream body = %q", body)
				}
				w.WriteHeader(http.StatusAccepted)
			})
			handler := captureRequests(cmdresp.MuxMiddleware("etcd")(next))
			request := httptest.NewRequest(http.MethodPost, "/v3/kv/range", strings.NewReader(`{"key":"secret"}`))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)

			select {
			case captured := <-saved:
				if !strings.Contains(captured.Data, `"path":"/v3/kv/range"`) || !strings.Contains(captured.Data, `"body":"{\"key\":\"secret\"}"`) {
					t.Fatalf("captured request = %s", captured.Data)
				}
			case <-time.After(time.Second):
				t.Fatal("request was not captured")
			}
			select {
			case duplicate := <-saved:
				t.Fatalf("request captured twice: %+v", duplicate)
			case <-time.After(25 * time.Millisecond):
			}
			if matched && nextCalls != 0 {
				t.Fatalf("matched override called downstream %d times", nextCalls)
			}
			if !matched && nextCalls != 1 {
				t.Fatalf("unmatched override called downstream %d times", nextCalls)
			}
		})
	}
}

func newEtcdTestRouter() http.Handler {
	router := newRouterWithoutOverrides()
	return router
}

func newRouterWithoutOverrides() http.Handler {
	router := mux.NewRouter()
	registerRoutes(router)
	return router
}
