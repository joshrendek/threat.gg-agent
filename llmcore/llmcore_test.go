package llmcore

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
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
		if got.ResponseStatus != http.StatusOK {
			t.Fatalf("response status = %d, want 200", got.ResponseStatus)
		}
		if got.ResponseSource != proto.LlmResponseSource_LLM_RESPONSE_SOURCE_BUILTIN {
			t.Fatalf("response source = %v, want builtin", got.ResponseSource)
		}
		if got.ReplyKind != proto.LlmReplyKind_LLM_REPLY_KIND_STATIC_ENDPOINT {
			t.Fatalf("reply kind = %v, want static endpoint", got.ReplyKind)
		}
		if got.StreamOutcome != proto.LlmStreamOutcome_LLM_STREAM_OUTCOME_NOT_STREAMED {
			t.Fatalf("stream outcome = %v, want not streamed", got.StreamOutcome)
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

func TestCaptureRecordsResponseStatusContentTypeLatencyAndReplyKind(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 1)
	handler := Capture(func(in *proto.LlmRequest) error {
		saved <- in
		return nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MarkReplyKind(r, proto.LlmReplyKind_LLM_REPLY_KIND_ARITHMETIC)
		// Invalid values stay bounded and cannot overwrite a valid classification.
		MarkReplyKind(r, proto.LlmReplyKind(999))
		time.Sleep(5 * time.Millisecond)
		WriteJSON(w, http.StatusCreated, map[string]bool{"ok": true})
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(
		http.MethodPost, "/api/generate", strings.NewReader(`{"model":"m"}`),
	))
	got := <-saved
	if got.ResponseStatus != http.StatusCreated {
		t.Fatalf("response status = %d, want 201", got.ResponseStatus)
	}
	if got.ResponseContentType != CTJSON {
		t.Fatalf("response content type = %q, want %q", got.ResponseContentType, CTJSON)
	}
	if got.ElapsedMs < 4 {
		t.Fatalf("elapsed_ms = %d, want measured handler latency", got.ElapsedMs)
	}
	if got.ReplyKind != proto.LlmReplyKind_LLM_REPLY_KIND_ARITHMETIC {
		t.Fatalf("reply kind = %v, want arithmetic", got.ReplyKind)
	}
}

func TestCaptureRecordsSemanticReplyKindFromGeneration(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 1)
	handler := Capture(func(in *proto.LlmRequest) error {
		saved <- in
		return nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		OllamaGenerate(w, r, Profile{DefaultModel: "llama3.2:latest"})
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(
		http.MethodPost,
		"/api/generate",
		strings.NewReader(`{"model":"llama3.2:latest","prompt":"Reply with a concise description of what an Ollama server does.","stream":false}`),
	))

	got := <-saved
	if got.ReplyKind != proto.LlmReplyKind_LLM_REPLY_KIND_OLLAMA_DESCRIPTION {
		t.Fatalf("reply kind = %v, want Ollama description", got.ReplyKind)
	}
	if !strings.Contains(recorder.Body.String(), "hosts and runs language models") {
		t.Fatalf("response was not semantic: %s", recorder.Body.String())
	}
}

func TestCaptureClassifiesHTTPError(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 1)
	handler := Capture(func(in *proto.LlmRequest) error {
		saved <- in
		return nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		MarkReplyKind(r, proto.LlmReplyKind_LLM_REPLY_KIND_MODEL_INTRO_EN)
		WriteError(w, http.StatusBadRequest, "bad request", "invalid_request_error", "")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/completions", nil))
	got := <-saved
	if got.ResponseStatus != http.StatusBadRequest {
		t.Fatalf("response status = %d, want 400", got.ResponseStatus)
	}
	if got.ReplyKind != proto.LlmReplyKind_LLM_REPLY_KIND_ERROR {
		t.Fatalf("reply kind = %v, want error", got.ReplyKind)
	}
}

func TestCaptureDoesNotRetainResponseBodyAndBoundsContentType(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 1)
	handler := Capture(func(in *proto.LlmRequest) error {
		saved <- in
		return nil
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "Application/JSON; charset=utf-8; boundary=ignored")
		_, _ = io.WriteString(w, "generated secret response")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/generate", nil))
	got := <-saved
	if got.ResponseContentType != "application/json" {
		t.Fatalf("response content type = %q, want bounded media type", got.ResponseContentType)
	}
	if strings.Contains(got.String(), "generated secret response") {
		t.Fatal("captured request retained response body")
	}
}

func TestCaptureClassifiesCompletedAndAbortedStreams(t *testing.T) {
	tests := []struct {
		name   string
		writer http.ResponseWriter
		want   proto.LlmStreamOutcome
	}{
		{
			name:   "completed",
			writer: httptest.NewRecorder(),
			want:   proto.LlmStreamOutcome_LLM_STREAM_OUTCOME_COMPLETED,
		},
		{
			name:   "write error",
			writer: &errorResponseWriter{header: make(http.Header)},
			want:   proto.LlmStreamOutcome_LLM_STREAM_OUTCOME_ABORTED,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			saved := make(chan *proto.LlmRequest, 1)
			handler := Capture(func(in *proto.LlmRequest) error {
				saved <- in
				return nil
			})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", CTNDJSON)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("{\"done\":true}\n"))
				w.(http.Flusher).Flush()
			}))

			handler.ServeHTTP(test.writer, httptest.NewRequest(http.MethodPost, "/api/chat", nil))
			got := <-saved
			if got.StreamOutcome != test.want {
				t.Fatalf("stream outcome = %v, want %v", got.StreamOutcome, test.want)
			}
		})
	}
}

func TestCaptureClassifiesCanceledStreamAsAborted(t *testing.T) {
	saved := make(chan *proto.LlmRequest, 1)
	handler := Capture(func(in *proto.LlmRequest) error {
		saved <- in
		return nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		cancelRequestContext(r)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(ctx)
	request = request.WithContext(context.WithValue(request.Context(), cancelContextKey{}, cancel))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if got := (<-saved).StreamOutcome; got != proto.LlmStreamOutcome_LLM_STREAM_OUTCOME_ABORTED {
		t.Fatalf("stream outcome = %v, want aborted", got)
	}
}

type cancelContextKey struct{}

func cancelRequestContext(r *http.Request) {
	r.Context().Value(cancelContextKey{}).(context.CancelFunc)()
}

type errorResponseWriter struct {
	header http.Header
}

func (w *errorResponseWriter) Header() http.Header { return w.header }
func (w *errorResponseWriter) WriteHeader(_ int)   {}
func (w *errorResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("client disconnected")
}

type optionalResponseWriter struct {
	header       http.Header
	flushed      bool
	pushed       bool
	readFromData string
	closeNotify  chan bool
}

func (w *optionalResponseWriter) Header() http.Header         { return w.header }
func (w *optionalResponseWriter) WriteHeader(_ int)           {}
func (w *optionalResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *optionalResponseWriter) Flush()                      { w.flushed = true }
func (w *optionalResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	left, right := net.Pipe()
	_ = right.Close()
	return left, bufio.NewReadWriter(bufio.NewReader(left), bufio.NewWriter(left)), nil
}
func (w *optionalResponseWriter) Push(_ string, _ *http.PushOptions) error {
	w.pushed = true
	return nil
}
func (w *optionalResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	data, err := io.ReadAll(r)
	w.readFromData = string(data)
	return int64(len(data)), err
}
func (w *optionalResponseWriter) CloseNotify() <-chan bool { return w.closeNotify }

func TestCaptureResponseWriterPreservesStreamingInterfaces(t *testing.T) {
	base := &optionalResponseWriter{header: make(http.Header), closeNotify: make(chan bool)}
	writer := newCaptureResponseWriter(base)

	controller := http.NewResponseController(writer)
	if err := controller.Flush(); err != nil || !base.flushed {
		t.Fatalf("ResponseController.Flush not forwarded: err=%v flushed=%v", err, base.flushed)
	}
	conn, _, err := controller.Hijack()
	if err != nil {
		t.Fatalf("ResponseController.Hijack: %v", err)
	}
	_ = conn.Close()

	flusher, ok := any(writer).(http.Flusher)
	if !ok {
		t.Fatal("wrapped writer lost http.Flusher")
	}
	flusher.Flush()
	if !base.flushed {
		t.Fatal("Flush was not forwarded")
	}

	hijacker, ok := any(writer).(http.Hijacker)
	if !ok {
		t.Fatal("wrapped writer lost http.Hijacker")
	}
	conn, _, err = hijacker.Hijack()
	if err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	_ = conn.Close()

	pusher, ok := any(writer).(http.Pusher)
	if !ok {
		t.Fatal("wrapped writer lost http.Pusher")
	}
	if err := pusher.Push("/asset", nil); err != nil || !base.pushed {
		t.Fatalf("Push not forwarded: err=%v pushed=%v", err, base.pushed)
	}

	readerFrom, ok := any(writer).(io.ReaderFrom)
	if !ok {
		t.Fatal("wrapped writer lost io.ReaderFrom")
	}
	if _, err := readerFrom.ReadFrom(strings.NewReader("chunk")); err != nil || base.readFromData != "chunk" {
		t.Fatalf("ReadFrom not forwarded: err=%v data=%q", err, base.readFromData)
	}

	notifier, ok := any(writer).(http.CloseNotifier) //nolint:staticcheck
	if !ok || notifier.CloseNotify() != base.closeNotify {
		t.Fatal("wrapped writer lost http.CloseNotifier")
	}
}

func TestCaptureResponseWriterReportsUnsupportedControllerOperations(t *testing.T) {
	base := &errorResponseWriter{header: make(http.Header)}
	writer := newCaptureResponseWriter(base)
	controller := http.NewResponseController(writer)
	if err := controller.Flush(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Flush error = %v, want ErrNotSupported", err)
	}
	if _, _, err := controller.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack error = %v, want ErrNotSupported", err)
	}
}
