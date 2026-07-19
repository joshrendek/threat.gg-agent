package postgres

import (
	"context"
	"strings"

	wire "github.com/jeroenrinzema/psql-wire"
	"github.com/lib/pq/oid"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// maxServerLookupLen bounds the attacker-controlled query we forward to the server's
// response lookup; anything longer skips the lookup and falls back to local handlers.
const maxServerLookupLen = 4096

// serverVersion is advertised in the pg startup handshake (server_version parameter). It is
// the short form of the `select version()` command_responses seed and must stay coherent
// with it — a mismatch between the handshake version and version() is a honeypot tell.
const serverVersion = "14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)"

// getCommandResponse is an injectable seam over the gRPC call so the server-matched and
// miss/error paths are unit-testable without a live server.
var getCommandResponse = persistence.GetCommandResponse

// resultTextColumn is the single ("result" text) column used to frame an admin-authored
// row-returning postgres response.
var resultTextColumn = wire.Columns{
	// Width -1 is postgres' "variable length" type size for text, so the row value is not
	// truncated regardless of the authored response length.
	{Table: 0, Name: "result", Oid: oid.T_text, Width: -1},
}

// rowReturningVerbs are the leading SQL keywords whose statements return a result set in
// postgres; everything else (set/begin/commit/insert/...) reports only a CommandComplete
// tag. The query is already lowercased by the caller.
var rowReturningVerbs = []string{"select", "show", "with", "values", "table"}

// isRowReturning reports whether the query should be framed as a data row (true) or as a
// bare CommandComplete tag (false), based on its leading verb.
func isRowReturning(query string) bool {
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

// commandTag returns the CommandComplete tag for a non-row statement. The stored response
// is what psql displays for such a statement, so a non-empty authored response is used
// verbatim; an empty response derives the tag from the statement's verb (e.g. "SET").
func commandTag(query, response string) string {
	if t := strings.TrimSpace(response); t != "" {
		return t
	}
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return "OK"
	}
	return strings.ToUpper(fields[0])
}

// writeFramedResponse renders an admin-authored postgres response onto the wire writer.
// The postgres wire protocol is binary/message-framed, so admins author plain text and the
// honeypot handles the framing: a row-returning query emits the stored text as a single
// ("result" text) row and completes as SELECT 1; a tag statement emits only a
// CommandComplete carrying the derived/authored tag.
func writeFramedResponse(rowReturning bool, response, query string, writer wire.DataWriter) error {
	if rowReturning {
		if err := writer.Row([]any{response}); err != nil {
			return err
		}
		return writer.Complete("SELECT 1")
	}
	return writer.Complete(commandTag(query, response))
}

// serverStatement builds the prepared statement that renders an admin-authored response,
// selecting the ("result" text) column set only for row-returning queries.
func serverStatement(query, response string) wire.PreparedStatements {
	rowReturning := isRowReturning(query)
	handle := func(ctx context.Context, writer wire.DataWriter, _ []wire.Parameter) error {
		return writeFramedResponse(rowReturning, response, query, writer)
	}
	if rowReturning {
		return wire.Prepared(wire.NewStatement(handle, wire.WithColumns(resultTextColumn)))
	}
	return wire.Prepared(wire.NewStatement(handle))
}

// lookupServerStatement consults the admin-editable command_responses (scoped to
// command_type="postgres") for the given (already-lowercased) query. It returns
// (statement, true) on a Matched row and (nil, false) on a miss, an error, or an oversized
// query, so the caller falls back to the hardcoded responses map and behavior never
// regresses when the server is unreachable.
func lookupServerStatement(query string) (wire.PreparedStatements, bool) {
	if len(query) > maxServerLookupLen {
		return nil, false
	}
	resp, err := getCommandResponse(&proto.CommandRequest{Command: query, CommandType: "postgres"})
	if err != nil || resp == nil || !resp.Matched {
		return nil, false
	}
	return serverStatement(query, resp.Response), true
}
