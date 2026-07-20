package postgres

import (
	"context"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	wire "github.com/jeroenrinzema/psql-wire"
	"github.com/lib/pq/oid"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// maxServerLookupLen bounds the attacker-controlled query we forward to the server's
// response lookup; anything longer skips the lookup and falls back to local handlers.
const maxServerLookupLen = 4096
const postgresResponsePrefix = "@pg\n"
const maxStructuredResponseLen = 1 << 20

type postgresResponseColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type structuredPostgresResponse struct {
	Columns []postgresResponseColumn `json:"columns,omitempty"`
	Rows    [][]any                  `json:"rows,omitempty"`
	Tag     string                   `json:"tag"`
}

var postgresColumnTypes = map[string]struct {
	oid   oid.Oid
	width int16
}{
	"bool":        {oid.T_bool, 1},
	"date":        {oid.T_date, 4},
	"float4":      {oid.T_float4, 4},
	"float8":      {oid.T_float8, 8},
	"int2":        {oid.T_int2, 2},
	"int4":        {oid.T_int4, 4},
	"int8":        {oid.T_int8, 8},
	"json":        {oid.T_json, -1},
	"jsonb":       {oid.T_jsonb, -1},
	"name":        {oid.T_name, 64},
	"numeric":     {oid.T_numeric, -1},
	"oid":         {oid.T_oid, 4},
	"text":        {oid.T_text, -1},
	"timestamp":   {oid.T_timestamp, 8},
	"timestamptz": {oid.T_timestamptz, 8},
	"varchar":     {oid.T_varchar, -1},
}

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

func parseStructuredResponse(value string) (structuredPostgresResponse, bool) {
	if !strings.HasPrefix(value, postgresResponsePrefix) || len(value) > maxStructuredResponseLen {
		return structuredPostgresResponse{}, false
	}
	decoder := json.NewDecoder(strings.NewReader(strings.TrimPrefix(value, postgresResponsePrefix)))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var response structuredPostgresResponse
	if err := decoder.Decode(&response); err != nil {
		return structuredPostgresResponse{}, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return structuredPostgresResponse{}, false
	}
	if !normalizeStructuredResponse(&response) {
		return structuredPostgresResponse{}, false
	}
	return response, true
}

func normalizeStructuredResponse(response *structuredPostgresResponse) bool {
	if len(response.Columns) > 64 || len(response.Rows) > 1000 || !validPostgresTag(response.Tag) {
		return false
	}
	seen := make(map[string]struct{}, len(response.Columns))
	for _, column := range response.Columns {
		if column.Name == "" || len(column.Name) > 63 || strings.ContainsAny(column.Name, "\x00\r\n") {
			return false
		}
		if _, ok := postgresColumnTypes[column.Type]; !ok {
			return false
		}
		if _, exists := seen[column.Name]; exists {
			return false
		}
		seen[column.Name] = struct{}{}
	}
	for rowIndex, row := range response.Rows {
		if len(row) != len(response.Columns) {
			return false
		}
		for columnIndex, value := range row {
			normalized, ok := normalizePostgresValue(response.Columns[columnIndex].Type, value)
			if !ok {
				return false
			}
			response.Rows[rowIndex][columnIndex] = normalized
		}
	}
	return len(response.Columns) > 0 || len(response.Rows) == 0
}

func normalizePostgresValue(columnType string, value any) (any, bool) {
	if value == nil {
		return nil, true
	}
	switch columnType {
	case "text", "name", "varchar", "json", "jsonb":
		text, ok := value.(string)
		return text, ok && len(text) <= maxStructuredResponseLen
	case "bool":
		boolean, ok := value.(bool)
		return boolean, ok
	case "int2":
		number, ok := value.(json.Number)
		parsed, err := strconv.ParseInt(string(number), 10, 16)
		return int16(parsed), ok && err == nil
	case "int4":
		number, ok := value.(json.Number)
		parsed, err := strconv.ParseInt(string(number), 10, 32)
		return int32(parsed), ok && err == nil
	case "int8":
		number, ok := value.(json.Number)
		parsed, err := strconv.ParseInt(string(number), 10, 64)
		return parsed, ok && err == nil
	case "oid":
		number, ok := value.(json.Number)
		parsed, err := strconv.ParseUint(string(number), 10, 32)
		return uint32(parsed), ok && err == nil
	case "float4":
		number, ok := value.(json.Number)
		parsed, err := strconv.ParseFloat(string(number), 32)
		return float32(parsed), ok && err == nil
	case "float8":
		number, ok := value.(json.Number)
		parsed, err := strconv.ParseFloat(string(number), 64)
		return parsed, ok && err == nil
	case "numeric":
		number, ok := value.(json.Number)
		if !ok {
			return nil, false
		}
		var numeric pgtype.Numeric
		if err := numeric.Scan(string(number)); err != nil {
			return nil, false
		}
		return numeric, true
	case "date":
		return parsePostgresTime(value, time.DateOnly)
	case "timestamp":
		return parsePostgresTime(value, "2006-01-02 15:04:05")
	case "timestamptz":
		return parsePostgresTime(value, time.RFC3339)
	default:
		return nil, false
	}
}

func parsePostgresTime(value any, layout string) (time.Time, bool) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(layout, text)
	return parsed, err == nil
}

func validPostgresTag(tag string) bool {
	return tag != "" && len(tag) <= 128 && !strings.ContainsAny(tag, "\x00\r\n")
}

func structuredStatement(response structuredPostgresResponse) wire.PreparedStatements {
	columns := make(wire.Columns, 0, len(response.Columns))
	for _, column := range response.Columns {
		columnType := postgresColumnTypes[column.Type]
		columns = append(columns, wire.Column{Table: 0, Name: column.Name, Oid: columnType.oid, Width: columnType.width})
	}
	handle := func(ctx context.Context, writer wire.DataWriter, _ []wire.Parameter) error {
		return writeStructuredResponse(response, writer)
	}
	if len(columns) > 0 {
		return wire.Prepared(wire.NewStatement(handle, wire.WithColumns(columns)))
	}
	return wire.Prepared(wire.NewStatement(handle))
}

func writeStructuredResponse(response structuredPostgresResponse, writer wire.DataWriter) error {
	for _, row := range response.Rows {
		if err := writer.Row(row); err != nil {
			return err
		}
	}
	return writer.Complete(response.Tag)
}

// serverStatement builds the prepared statement that renders an admin-authored response,
// selecting the ("result" text) column set only for row-returning queries.
func serverStatement(query, response string) wire.PreparedStatements {
	if structured, ok := parseStructuredResponse(response); ok {
		return structuredStatement(structured)
	}
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
