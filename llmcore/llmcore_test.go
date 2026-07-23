package llmcore

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestCaptureRecordsRequestOnceWithModelAndRestoresBody(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 2)
	save := func(in *proto.LlmRequest) error { saved <- in; return nil }

	downstreamBody := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		downstreamBody = string(b)
		w.WriteHeader(http.StatusOK)
	})

	h := Capture(save)(next)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"llama3.2","messages":[]}`))
	req.RemoteAddr = "203.0.113.7:52344"
	req.Header.Set("User-Agent", "python-requests/2.31")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	select {
	case got := <-saved:
		if got.Model != "llama3.2" {
			t.Fatalf("model = %q, want llama3.2", got.Model)
		}
		if got.RemoteAddr != "203.0.113.7" {
			t.Fatalf("remote_addr = %q, want 203.0.113.7 (port stripped)", got.RemoteAddr)
		}
		if got.Path != "/v1/chat/completions" || got.Method != "POST" {
			t.Fatalf("path/method = %q/%q", got.Path, got.Method)
		}
		if !strings.Contains(got.Body, `"model":"llama3.2"`) {
			t.Fatalf("body not captured: %q", got.Body)
		}
		if got.UserAgent != "python-requests/2.31" {
			t.Fatalf("user_agent = %q", got.UserAgent)
		}
	case <-time.After(time.Second):
		t.Fatal("request was not captured")
	}
	// Exactly once.
	select {
	case dup := <-saved:
		t.Fatalf("captured twice: %+v", dup)
	case <-time.After(25 * time.Millisecond):
	}
	if downstreamBody != `{"model":"llama3.2","messages":[]}` {
		t.Fatalf("downstream body not restored: %q", downstreamBody)
	}
}

func TestCaptureTruncatesOversizeBody(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 1)
	save := func(in *proto.LlmRequest) error { saved <- in; return nil }
	h := Capture(save)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	big := strings.Repeat("x", MaxBodySize+500)
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", strings.NewReader(big))
	h.ServeHTTP(httptest.NewRecorder(), req)
	got := <-saved
	if len(got.Body) != MaxBodySize {
		t.Fatalf("captured body len = %d, want %d", len(got.Body), MaxBodySize)
	}
}

func TestParseModel(t *testing.T) {
	if m := ParseModel([]byte(`{"model":"gpt-4o","x":1}`)); m != "gpt-4o" {
		t.Fatalf("ParseModel = %q, want gpt-4o", m)
	}
	if m := ParseModel([]byte(`not json`)); m != "" {
		t.Fatalf("ParseModel(bad) = %q, want empty", m)
	}
}

type errAfterDataReader struct {
	data []byte
	done bool
}

func (e *errAfterDataReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, errors.New("boom")
	}
	e.done = true
	n := copy(p, e.data)
	return n, errors.New("boom") // returns data + error together
}

func TestCaptureRestoresBodyEvenOnReadError(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 1)
	save := func(in *proto.LlmRequest) error { saved <- in; return nil }
	got := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/completions", &errAfterDataReader{data: []byte(`{"model":"m"}`)})
	Capture(save)(next).ServeHTTP(httptest.NewRecorder(), req)
	rec := <-saved
	if rec.Body != `{"model":"m"}` {
		t.Fatalf("captured body = %q, want restored partial", rec.Body)
	}
	if got != `{"model":"m"}` {
		t.Fatalf("downstream body = %q, want restored partial", got)
	}
}
