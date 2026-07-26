// Package llmcore holds the shared HTTP machinery for the LLM-serving honeypots
// (vLLM, Ollama, Ray, LocalAI, llama.cpp, ComfyUI): request capture with a body cap,
// JSON/error helpers, and the dynamic completion generators. Each product package is a
// thin wrapper that configures identity + routes and reuses this core.
package llmcore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

// MaxBodySize caps how much of a request body is captured (defense in depth,
// independent of any global middleware).
const MaxBodySize = 1 << 20 // 1MB

var logger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "llmcore").Logger()

// ParseModel returns the JSON "model" field from body, or "" if absent/unparseable.
func ParseModel(body []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	return m.Model
}

// Capture returns middleware that records each signal request and the bounded outcome of
// its response. It deliberately does not retain response bodies. The request body is read
// with a 1MB LimitReader and restored so downstream handlers can read it again.
func Capture(save func(*proto.LlmRequest) error) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			in, ok := captureRequest(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			started := time.Now()
			metadata := &responseMetadata{
				source:    proto.LlmResponseSource_LLM_RESPONSE_SOURCE_BUILTIN,
				replyKind: proto.LlmReplyKind_LLM_REPLY_KIND_STATIC_ENDPOINT,
			}
			r = r.WithContext(context.WithValue(r.Context(), responseMetadataKey{}, metadata))
			writer := newCaptureResponseWriter(w)

			defer func() {
				source, replyKind := metadata.snapshot()
				if writer.status >= http.StatusBadRequest {
					replyKind = proto.LlmReplyKind_LLM_REPLY_KIND_ERROR
				}
				in.ResponseStatus = int32(writer.status)
				in.ResponseContentType = writer.responseContentType()
				in.ElapsedMs = time.Since(started).Milliseconds()
				in.ResponseSource = source
				in.ReplyKind = replyKind
				in.StreamOutcome = writer.streamOutcome(r.Context())
				saveCapturedRequest(in, save)
			}()

			next.ServeHTTP(writer, r)
		})
	}
}

func captureRequest(r *http.Request) (*proto.LlmRequest, bool) {
	// Only persist requests that touch a real LLM API surface. Generic internet scanning
	// (favicon, nmap, proxy CONNECT, Next.js exploits, LFI probes) still gets a response from
	// the honeypot's handlers, but is not stored — it otherwise drowns the real LLM signal.
	if !isSignalPath(r.URL.Path) {
		return nil, false
	}

	guid := uuid.NewV4()

	var body string
	if r.Body != nil {
		data, _ := io.ReadAll(io.LimitReader(r.Body, MaxBodySize+1))
		_ = r.Body.Close()
		captured := data
		if len(captured) > MaxBodySize {
			captured = captured[:MaxBodySize]
		}
		body = string(captured)
		// Restore the body (even after a partial/errored read) so downstream can re-read it.
		r.Body = io.NopCloser(bytes.NewReader(data))
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	in := &proto.LlmRequest{
		RemoteAddr: ip,
		Guid:       guid.String(),
		Headers:    persistence.HttpToMap(map[string][]string(r.Header)),
		Path:       r.URL.Path,
		Method:     r.Method,
		Body:       body,
		Model:      ParseModel([]byte(body)),
		UserAgent:  r.UserAgent(),
	}
	logger.Info().Str("method", in.Method).Str("path", in.Path).Str("remote_addr", in.RemoteAddr).Msg("llm request")
	return in, true
}

func saveCapturedRequest(in *proto.LlmRequest, save func(*proto.LlmRequest) error) {
	go func(req *proto.LlmRequest) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error().Interface("panic", rec).Msg("panic saving llm request")
			}
		}()
		if err := save(req); err != nil {
			logger.Error().Err(err).Msg("error saving llm request")
		}
	}(in)
}

type responseMetadataKey struct{}

type responseMetadata struct {
	mu        sync.Mutex
	source    proto.LlmResponseSource
	replyKind proto.LlmReplyKind
}

func (m *responseMetadata) snapshot() (proto.LlmResponseSource, proto.LlmReplyKind) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.source, m.replyKind
}

// MarkResponseSource annotates a captured request with a bounded response source.
// Calls outside Capture, or with an unknown enum value, are harmless no-ops.
func MarkResponseSource(r *http.Request, source proto.LlmResponseSource) {
	if r == nil || (source != proto.LlmResponseSource_LLM_RESPONSE_SOURCE_BUILTIN &&
		source != proto.LlmResponseSource_LLM_RESPONSE_SOURCE_COMMAND_RESPONSE) {
		return
	}
	metadata, _ := r.Context().Value(responseMetadataKey{}).(*responseMetadata)
	if metadata == nil {
		return
	}
	metadata.mu.Lock()
	metadata.source = source
	metadata.mu.Unlock()
}

// MarkReplyKind annotates a captured request with a bounded reply classification.
// It is metadata-only: callers must never pass or retain generated response text.
func MarkReplyKind(r *http.Request, kind proto.LlmReplyKind) {
	if r == nil || kind <= proto.LlmReplyKind_LLM_REPLY_KIND_UNSPECIFIED ||
		kind > proto.LlmReplyKind_LLM_REPLY_KIND_ERROR {
		return
	}
	metadata, _ := r.Context().Value(responseMetadataKey{}).(*responseMetadata)
	if metadata == nil {
		return
	}
	metadata.mu.Lock()
	metadata.replyKind = kind
	metadata.mu.Unlock()
}

type captureResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	contentType string
	flushed     bool
	writeErr    error
}

// captureResponseWriter intentionally exposes the optional net/http writer interfaces
// used by streaming handlers. Operations are forwarded through ResponseController and
// report http.ErrNotSupported when the wrapped writer lacks the capability.
func newCaptureResponseWriter(w http.ResponseWriter) *captureResponseWriter {
	return &captureResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
	}
}

func (w *captureResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *captureResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	if contentType := w.Header().Get("Content-Type"); contentType != "" {
		w.contentType = contentType
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *captureResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		if w.Header().Get("Content-Type") == "" && len(p) > 0 {
			w.contentType = http.DetectContentType(p)
		}
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	if err != nil && w.writeErr == nil {
		w.writeErr = err
	}
	return n, err
}

func (w *captureResponseWriter) Flush() {
	_ = w.FlushError()
}

// FlushError lets http.ResponseController preserve ErrNotSupported while Flush keeps
// compatibility with handlers that type-assert the legacy http.Flusher interface.
func (w *captureResponseWriter) FlushError() error {
	w.flushed = true
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if err != nil &&
		!errors.Is(err, http.ErrNotSupported) && w.writeErr == nil {
		w.writeErr = err
	}
	return err
}

func (w *captureResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil && !errors.Is(err, http.ErrNotSupported) && w.writeErr == nil {
		w.writeErr = err
	}
	return conn, rw, err
}

func (w *captureResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	err := pusher.Push(target, opts)
	if err != nil && !errors.Is(err, http.ErrNotSupported) && w.writeErr == nil {
		w.writeErr = err
	}
	return err
}

func (w *captureResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	var (
		n   int64
		err error
	)
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = readerFrom.ReadFrom(r)
	} else {
		// Hide ReadFrom from io.Copy so it uses Write and retains error tracking.
		n, err = io.Copy(struct{ io.Writer }{w}, r)
	}
	if err != nil && w.writeErr == nil {
		w.writeErr = err
	}
	return n, err
}

// CloseNotify preserves the legacy interface still used by some streaming libraries.
// Real net/http writers provide it. For test/custom writers that do not, an inert channel
// avoids a goroutine that could outlive the request; new code should use Request.Context.
func (w *captureResponseWriter) CloseNotify() <-chan bool {
	if notifier, ok := w.ResponseWriter.(http.CloseNotifier); ok { //nolint:staticcheck
		return notifier.CloseNotify()
	}
	return neverCloseNotify
}

var neverCloseNotify = make(chan bool)

func (w *captureResponseWriter) responseContentType() string {
	value := w.contentType
	if headerValue := w.Header().Get("Content-Type"); headerValue != "" {
		value = headerValue
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if mediaType, _, err := mime.ParseMediaType(value); err == nil {
		// Store the bounded media type, not arbitrary authored header parameters.
		return strings.ToLower(mediaType)
	}
	const maxContentTypeLen = 255
	if len(value) > maxContentTypeLen {
		value = value[:maxContentTypeLen]
	}
	return value
}

func (w *captureResponseWriter) streamOutcome(ctx context.Context) proto.LlmStreamOutcome {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(w.responseContentType(), ";")[0]))
	streamed := w.flushed || contentType == "text/event-stream" ||
		contentType == "application/x-ndjson" || contentType == "application/stream+json"
	if !streamed {
		return proto.LlmStreamOutcome_LLM_STREAM_OUTCOME_NOT_STREAMED
	}
	if w.writeErr != nil || ctx.Err() != nil {
		return proto.LlmStreamOutcome_LLM_STREAM_OUTCOME_ABORTED
	}
	return proto.LlmStreamOutcome_LLM_STREAM_OUTCOME_COMPLETED
}

// writeCompactJSON marshals v with no trailing newline. json.Encoder.Encode appends one,
// which inflates Content-Length by a byte relative to every real server we emulate (Gin,
// FastAPI and Fiber all write the marshalled bytes directly) — a free fingerprint.
//
// Callers should pass structs with the field order of the product being emulated rather than
// map[string]any: encoding/json sorts map keys alphabetically, so a map-built body has a key
// order no real implementation produces.
func writeCompactJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = w.Write(b)
}

// WriteJSON marshals v and writes it with the given status and application/json.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	WriteJSONCT(w, status, CTJSON, v)
}

// WriteJSONCT is WriteJSON with an explicit content type, so callers can pick the charset
// suffix their framework would emit (see the CT* constants).
func WriteJSONCT(w http.ResponseWriter, status int, contentType string, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	writeCompactJSON(w, v)
}

// WriteError writes an OpenAI-style error envelope: {"error":{"message","type","code"}}.
func WriteError(w http.ResponseWriter, status int, message, errType, code string) {
	WriteJSON(w, status, map[string]any{
		"error": map[string]any{"message": message, "type": errType, "code": code},
	})
}
