// Package cmdresp is the shared client side of the admin-editable command_responses
// override. Every honeypot consults it (scoped by command_type) before its hardcoded
// handler and branches on Matched, so behavior never regresses when the server is
// unreachable or has no authored row. It centralizes the gRPC seam, the input cap, the
// HTTP body/middleware framing, and the SQL result framing so each honeypot is a thin
// call site. (ssh/telnet/redis/postgres predate this package and keep their own seams.)
package cmdresp

import (
	"io"
	"net/http"
	"strings"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// MaxServerLookupLen bounds the attacker-controlled command forwarded to the server's
// response lookup; anything longer skips the lookup and falls back to local handlers.
const MaxServerLookupLen = 4096

// GetCommandResponse is an injectable seam over the gRPC call so the matched/miss/error
// paths are unit-testable without a live server.
var GetCommandResponse = persistence.GetCommandResponse

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

// HTTPOverride writes an admin-authored response as the HTTP body when a row is authored
// for (commandType, "METHOD /path"), returning true when it handled the request. The
// caller's already-set Content-Type/headers are preserved; on a miss it writes nothing and
// returns false so the caller renders its default response.
func HTTPOverride(w http.ResponseWriter, r *http.Request, commandType string) bool {
	body, ok := Lookup(commandType, r.Method+" "+r.URL.Path)
	if !ok {
		return false
	}
	io.WriteString(w, body) //nolint:errcheck
	return true
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
