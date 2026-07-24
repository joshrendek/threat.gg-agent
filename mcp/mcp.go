// Package mcp is a honeypot that emulates an exposed, unauthenticated Model Context Protocol
// (MCP) server. It speaks JSON-RPC 2.0 over both transports (streamable HTTP /mcp and legacy
// SSE /sse + /messages), advertises a catalog of tempting-but-fake dangerous tools, and returns
// convincing canned results — NOTHING is ever executed. The value is capturing tools/call
// arguments: the commands, paths, SQL, and payloads attackers run against agent infrastructure.
package mcp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort = "3000"
	maxBodySize = 1 << 20 // 1MB
)

var _ honeypots.Honeypot = &honeypot{}
var saveMcpRequest = persistence.SaveMcpRequest

type honeypot struct {
	logger zerolog.Logger
}

func New() honeypots.Honeypot {
	return &honeypot{logger: zerolog.New(os.Stdout).With().Caller().Str("honeypot", "mcp").Logger()}
}

func (h *honeypot) Name() string { return "mcp" }

func (h *honeypot) Start() {
	port := os.Getenv("MCP_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	h.logger.Info().Str("port", port).Msg("starting mcp honeypot")
	h.logger.Fatal().Err(http.ListenAndServe(fmt.Sprintf(":%s", port), newRouter())).Msg("failed to start")
}

func newRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/mcp", handleRPC("streamable")).Methods(http.MethodPost)
	r.HandleFunc("/mcp", handleSSE("streamable")).Methods(http.MethodGet)
	r.HandleFunc("/mcp", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }).Methods(http.MethodDelete)
	r.HandleFunc("/messages", handleRPC("sse")).Methods(http.MethodPost)
	r.HandleFunc("/sse", handleSSE("sse")).Methods(http.MethodGet)
	r.PathPrefix("/").HandlerFunc(handleCatchAll)
	return r
}

func handleRPC(transport string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		method, tool := rpcMethodAndTool(body)
		capture(r, transport, method, tool, body)
		dispatch(w, body)
	}
}

func handleSSE(transport string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		capture(r, transport, "connect", "", nil)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		// Advertise the message-post endpoint (legacy SSE handshake), then close. A honeypot need
		// not hold the stream open; scanners read the endpoint event and proceed to POST.
		fmt.Fprintf(w, "event: endpoint\ndata: /messages?sessionId=%s\n\n", uuid.NewV4().String())
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// handleCatchAll answers generic scan noise plausibly but does NOT persist it.
func handleCatchAll(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"Not found"}}`) //nolint:errcheck
}

func readBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	data, _ := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	_ = r.Body.Close()
	if len(data) > maxBodySize {
		data = data[:maxBodySize]
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	return data
}

func capture(r *http.Request, transport, method, tool string, body []byte) {
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i != -1 {
		ip = ip[:i]
	}
	in := &proto.McpRequest{
		RemoteAddr: ip,
		Guid:       uuid.NewV4().String(),
		Headers:    persistence.HttpToMap(map[string][]string(r.Header)),
		Transport:  transport,
		RpcMethod:  method,
		Tool:       tool,
		Body:       string(body),
		UserAgent:  r.UserAgent(),
	}
	// Snapshot the save seam at request time so a slow save goroutine always uses the value in
	// effect when the request was handled (deterministic under the injectable test seam).
	save := saveMcpRequest
	go func(req *proto.McpRequest) {
		defer func() { _ = recover() }()
		_ = save(req)
	}(in)
}
