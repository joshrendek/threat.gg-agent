package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestMain(m *testing.M) {
	saveMcpRequest = func(*proto.McpRequest) error { return nil }
	os.Exit(m.Run())
}

func post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func result(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json (%s): %v", rec.Body.String(), err)
	}
	return out
}

func TestInitialize(t *testing.T) {
	out := result(t, post(t, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"scanner","version":"1.0"}}}`))
	res, _ := out["result"].(map[string]any)
	if res == nil {
		t.Fatalf("no result: %v", out)
	}
	if si, _ := res["serverInfo"].(map[string]any); si == nil || si["name"] == "" {
		t.Fatalf("no serverInfo: %v", res)
	}
	if _, ok := res["capabilities"]; !ok {
		t.Fatalf("no capabilities: %v", res)
	}
	if out["id"].(float64) != 1 {
		t.Fatalf("id not echoed: %v", out["id"])
	}
}

func TestToolsListHasBait(t *testing.T) {
	res := result(t, post(t, "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))["result"].(map[string]any)
	names := map[string]bool{}
	for _, tv := range res["tools"].([]any) {
		names[tv.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"execute_command", "read_file", "query_database", "fetch_url", "get_secret"} {
		if !names[want] {
			t.Errorf("tools/list missing bait tool %q", want)
		}
	}
}

func TestToolsCallCapturesAndReturnsCannedResult(t *testing.T) {
	got := make(chan *proto.McpRequest, 1)
	orig := saveMcpRequest
	saveMcpRequest = func(in *proto.McpRequest) error { got <- in; return nil }
	defer func() { saveMcpRequest = orig }()

	rec := post(t, "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"whoami"}}}`)

	select {
	case in := <-got:
		if in.RpcMethod != "tools/call" || in.Tool != "execute_command" || in.Transport != "streamable" {
			t.Fatalf("bad capture: method=%q tool=%q transport=%q", in.RpcMethod, in.Tool, in.Transport)
		}
		if !strings.Contains(in.Body, "whoami") {
			t.Fatalf("body not captured: %s", in.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("tools/call was not captured")
	}

	res := result(t, rec)["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "root") {
		t.Fatalf("execute_command whoami should return root, got %q", text)
	}
}

func TestUnknownMethodReturns32601(t *testing.T) {
	out := result(t, post(t, "/mcp", `{"jsonrpc":"2.0","id":4,"method":"does/notexist"}`))
	e, _ := out["error"].(map[string]any)
	if e == nil || e["code"].(float64) != -32601 {
		t.Fatalf("want -32601 method not found, got %v", out)
	}
}

func TestMessagesTransportTaggedSse(t *testing.T) {
	got := make(chan *proto.McpRequest, 1)
	orig := saveMcpRequest
	saveMcpRequest = func(in *proto.McpRequest) error { got <- in; return nil }
	defer func() { saveMcpRequest = orig }()
	post(t, "/messages", `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	select {
	case in := <-got:
		if in.Transport != "sse" || in.RpcMethod != "tools/list" {
			t.Fatalf("messages transport/method = %q/%q", in.Transport, in.RpcMethod)
		}
	case <-time.After(time.Second):
		t.Fatal("/messages not captured")
	}
}

func TestSSEEmitsEndpointEvent(t *testing.T) {
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sse", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("sse content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "event: endpoint") {
		t.Fatalf("sse missing endpoint event: %s", rec.Body.String())
	}
}

func TestCatchAllNotCaptured(t *testing.T) {
	got := make(chan *proto.McpRequest, 1)
	orig := saveMcpRequest
	saveMcpRequest = func(in *proto.McpRequest) error { got <- in; return nil }
	defer func() { saveMcpRequest = orig }()
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("catch-all status = %d, want 404", rec.Code)
	}
	select {
	case in := <-got:
		t.Fatalf("catch-all noise was captured: %+v", in)
	case <-time.After(120 * time.Millisecond):
	}
}

func TestDeleteMcpCaptured(t *testing.T) {
	got := make(chan *proto.McpRequest, 1)
	orig := saveMcpRequest
	saveMcpRequest = func(in *proto.McpRequest) error { got <- in; return nil }
	defer func() { saveMcpRequest = orig }()
	rec := httptest.NewRecorder()
	newRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/mcp", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /mcp status = %d, want 200", rec.Code)
	}
	select {
	case in := <-got:
		if in.RpcMethod != "disconnect" || in.Transport != "streamable" {
			t.Fatalf("DELETE capture method/transport = %q/%q", in.RpcMethod, in.Transport)
		}
	case <-time.After(time.Second):
		t.Fatal("DELETE /mcp was not captured")
	}
}

func TestEmptyMethodInvalidRequest(t *testing.T) {
	out := result(t, post(t, "/mcp", `{"jsonrpc":"2.0","id":9}`))
	e, _ := out["error"].(map[string]any)
	if e == nil || e["code"].(float64) != -32600 {
		t.Fatalf("empty method should be -32600 Invalid Request, got %v", out)
	}
	if out["id"].(float64) != 9 {
		t.Fatalf("id should be echoed on invalid request, got %v", out["id"])
	}
}
