// Package cmdresp is the shared client side of the admin-editable command_responses
// override. Every honeypot consults it (scoped by command_type) before its hardcoded
// handler and branches on Matched, so behavior never regresses when the server is
// unreachable or has no authored row. It centralizes the gRPC seam, the input cap, the
// HTTP body/middleware framing, and the SQL result framing so each honeypot is a thin
// call site. (ssh/telnet/redis/postgres predate this package and keep their own seams.)
package cmdresp

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// MaxServerLookupLen bounds the attacker-controlled command forwarded to the server's
// response lookup; anything longer skips the lookup and falls back to local handlers.
const MaxServerLookupLen = 4096

// HTTPResponsePrefix marks an opt-in structured HTTP response stored in the existing
// response text column. Plain rows remain body-only for backward compatibility.
const HTTPResponsePrefix = "@http\n"

type authoredHTTPResponse struct {
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

// GetCommandResponse is an injectable seam over the gRPC call so the matched/miss/error
// paths are unit-testable without a live server.
var GetCommandResponse = persistence.GetCommandResponse
var SaveResponseLookup = persistence.SaveResponseLookup

// Lookup returns the admin-authored response for (commandType, command) when a Matched row
// exists, and ("", false) on a miss, an error, or an oversized command — so the caller
// falls back to its hardcoded handler. Matched (not a non-empty Response) is the gate, so
// an intentionally-silent authored row is honored rather than treated as a miss.
func Lookup(commandType, command string) (string, bool) {
	if len(command) > MaxServerLookupLen {
		return "", false
	}
	resp, err := GetCommandResponse(&proto.CommandRequest{Command: command, CommandType: commandType})
	if err != nil || resp == nil || !resp.Matched {
		return "", false
	}
	return resp.Response, true
}

// LookupAndRecord persists the exact bounded key used for response matching, then performs
// the normal lookup. A missing session GUID preserves lookup behavior but skips telemetry.
func LookupAndRecord(commandType, command, guid string) (string, bool) {
	if len(command) > MaxServerLookupLen {
		return "", false
	}
	if guid != "" {
		request := &proto.ResponseLookupRequest{Guid: guid, CommandType: commandType, LookupKey: command}
		go func() { _ = SaveResponseLookup(request) }()
	}
	return Lookup(commandType, command)
}

// HTTPOverride writes an admin-authored response as the HTTP body when a row is authored
// for (commandType, "METHOD /path"), returning true when it handled the request. The
// caller's already-set Content-Type/headers are preserved; on a miss it writes nothing and
// returns false so the caller renders its default response.
func HTTPOverride(w http.ResponseWriter, r *http.Request, commandType string) bool {
	body, ok := Lookup(commandType, r.Method+" "+r.URL.Path)
	if !ok {
		return false
	}
	if response, structured := parseHTTPResponse(body); structured {
		for name, value := range response.Headers {
			if validHTTPHeader(name, value) {
				w.Header().Set(name, value)
			}
		}
		defaultJSONContentType(w, response.Body)
		status := response.Status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		io.WriteString(w, response.Body) //nolint:errcheck
		return true
	}
	defaultJSONContentType(w, body)
	io.WriteString(w, body) //nolint:errcheck
	return true
}

// defaultJSONContentType sets Content-Type to application/json for a JSON-looking authored
// body when neither the caller nor the authored row already set one. Without it, a JSON body
// is written with no Content-Type and Go's sniffer labels it text/plain — a fidelity tell for
// API honeypots (vLLM/Ollama/Elasticsearch/etc.) whose real servers always send
// application/json. Non-JSON or empty bodies are left for the caller / Go's default handling.
func defaultJSONContentType(w http.ResponseWriter, body string) {
	if w.Header().Get("Content-Type") != "" {
		return
	}
	if t := strings.TrimLeft(body, " \t\r\n"); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		w.Header().Set("Content-Type", "application/json")
	}
}

func parseHTTPResponse(value string) (authoredHTTPResponse, bool) {
	if !strings.HasPrefix(value, HTTPResponsePrefix) {
		return authoredHTTPResponse{}, false
	}
	var response authoredHTTPResponse
	if err := json.Unmarshal([]byte(strings.TrimPrefix(value, HTTPResponsePrefix)), &response); err != nil {
		return authoredHTTPResponse{}, false
	}
	if response.Status != 0 && (response.Status < 100 || response.Status > 599) {
		return authoredHTTPResponse{}, false
	}
	return response, true
}

func validHTTPHeader(name, value string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isHTTPTokenByte(name[i]) {
			return false
		}
	}
	for i := 0; i < len(value); i++ {
		if value[i] == '\t' {
			continue
		}
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func isHTTPTokenByte(b byte) bool {
	if b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' {
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}

// MuxMiddleware returns net/http middleware (compatible with gorilla/mux Router.Use) that
// applies HTTPOverride before the wrapped handler, intercepting a Matched request and
// otherwise falling through unchanged.
func MuxMiddleware(commandType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if HTTPOverride(w, r, commandType) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rowReturningVerbs are the leading SQL keywords whose statements return a result set;
// everything else (set/use/insert/...) reports only an OK/completion packet. Shared by the
// binary tabular honeypots (mysql) to decide how to frame stored plain text into a wire
// result.
var rowReturningVerbs = []string{"select", "show", "with", "values", "table"}

// IsRowReturning reports whether a query should be framed as a data row (true) or as a bare
// OK/completion packet (false), based on its leading verb (case-insensitive).
func IsRowReturning(query string) bool {
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return false
	}
	verb := strings.ToLower(fields[0])
	for _, v := range rowReturningVerbs {
		if verb == v {
			return true
		}
	}
	return false
}
