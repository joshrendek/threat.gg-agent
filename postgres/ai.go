package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	wire "github.com/jeroenrinzema/psql-wire"
	pgcodes "github.com/jeroenrinzema/psql-wire/codes"
	psqlerr "github.com/jeroenrinzema/psql-wire/errors"
	"github.com/rs/zerolog"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/sqlai"
)

// generateResponse is the AI-first path (spec §8 item 7, §15). Swappable for tests.
var generateResponse sqlai.Generate = persistence.GenerateResponse

// getCommandResponseWithin is the legacy lookup with a caller-chosen deadline,
// used after a slow generate call so the attacker waits at most
// sqlai.DegradedLookup more.
var getCommandResponseWithin = persistence.GetCommandResponseWithin

// aiSessions remembers per attacker session whether the server answers with AI.
var aiSessions = sqlai.NewSessions(maxPostgresSessions, postgresSessionTTL)

// aiLogger reports AI replies the agent discarded. It never logs query or
// cell text. Swappable for tests.
var aiLogger = zerolog.New(os.Stdout).With().Caller().Str("honeypot", "postgres").Logger()

type aiAnswer struct {
	stmt     wire.PreparedStatements
	degraded bool
}

// aiStatement asks the server for a generated answer to raw (the query as the
// client sent it). ok=false means use the legacy path; a.degraded then asks
// for the short lookup deadline. That happens when this ask already took
// longer than a first ask may (a late NONE, or a slow error), or when a Live
// session's ask produced nothing usable, so one query never waits the
// generate budget plus the full legacy lookup.
func aiStatement(guid, raw string) (aiAnswer, bool) {
	before := aiSessions.Get(guid)
	start := time.Now()
	out := sqlai.Ask(generateResponse, "postgres", guid, raw, before)
	elapsed := time.Since(start)
	aiSessions.Set(guid, out.Session)
	fallback := aiAnswer{degraded: out.Degraded || elapsed > sqlai.FirstBudget || before.State == sqlai.Live}
	if out.ResultSet == nil {
		return fallback, false
	}
	if e := out.ResultSet.GetError(); e != nil {
		pgErr := postgresAIError(e)
		if pgErr == nil {
			logDiscardedAIReply(out.GenerationID, "error_not_mapped")
			return fallback, false
		}
		// The error comes from the statement, never the handler: psql-wire
		// then reports it at Execute, after Parse/Describe/Bind succeeded,
		// so extended-protocol clients stay in sync through Sync.
		return aiAnswer{stmt: wire.Prepared(wire.NewStatement(func(context.Context, wire.DataWriter, []wire.Parameter) error {
			return pgErr
		}))}, true
	}
	resp, ok := postgresAIResponse(out.ResultSet)
	if !ok {
		logDiscardedAIReply(out.GenerationID, "result_not_encodable")
		return fallback, false
	}
	return aiAnswer{stmt: structuredStatement(resp)}, true
}

// logDiscardedAIReply records an answered reply the agent could not put on
// the wire: the server billed it but the attacker got the legacy answer.
func logDiscardedAIReply(generationID, reason string) {
	aiLogger.Warn().Str("generation_id", generationID).Str("protocol", "postgres").Str("reason", reason).Msg("discarded AI reply")
}

// postgresAIError is the ErrorResponse for a mapped condition, or nil when the
// condition is unknown or the message is empty after cleaning.
func postgresAIError(e *proto.SqlError) error {
	m, ok := sqlai.Errors[e.GetCode()]
	msg := sqlai.Clean(e.GetMessage(), false)
	if !ok || msg == "" {
		return nil
	}
	return psqlerr.WithCode(errors.New(msg), pgcodes.Code(m.SQLState))
}

// postgresAIResponse converts a generated result set for the structured
// renderer. Unlike authored rows (normalizeStructuredResponse) it allows
// duplicate column names, which Postgres itself produces ("SELECT 1, 2").
func postgresAIResponse(rs *proto.ResultSet) (structuredPostgresResponse, bool) {
	cols, rows := rs.GetColumns(), rs.GetRows()
	if len(cols) > 64 || len(rows) > 1000 || (len(rows) > 0 && len(cols) == 0) {
		return structuredPostgresResponse{}, false
	}
	resp := structuredPostgresResponse{Columns: make([]postgresResponseColumn, 0, len(cols))}
	for _, c := range cols {
		name := sqlai.Clean(c.GetName(), false)
		if name == "" {
			name = "?column?" // Postgres's own name for an unnamed expression
		}
		if _, ok := postgresColumnTypes[c.GetType()]; !ok || len(name) > 63 {
			return structuredPostgresResponse{}, false
		}
		resp.Columns = append(resp.Columns, postgresResponseColumn{Name: name, Type: c.GetType()})
	}
	for _, row := range rows {
		values, nulls := row.GetValues(), row.GetNulls()
		if len(values) != len(cols) || (len(nulls) != 0 && len(nulls) != len(values)) {
			return structuredPostgresResponse{}, false
		}
		out := make([]any, len(values))
		for i, v := range values {
			if len(nulls) > 0 && nulls[i] {
				continue // nil is NULL
			}
			typed, ok := normalizePostgresValue(resp.Columns[i].Type, aiValue(resp.Columns[i].Type, sqlai.Clean(v, true)))
			if !ok {
				return structuredPostgresResponse{}, false
			}
			out[i] = typed
		}
		resp.Rows = append(resp.Rows, out)
	}
	tag := sqlai.Clean(rs.GetCommandTag(), false)
	if tag == "" && len(cols) > 0 {
		tag = fmt.Sprintf("SELECT %d", len(rows))
	}
	if !validPostgresTag(tag) {
		return structuredPostgresResponse{}, false
	}
	resp.Tag = tag
	return resp, true
}

// aiValue turns the server's text cell into the JSON-decoded shape
// normalizePostgresValue expects: json.Number for numbers, bool for bool.
func aiValue(columnType, v string) any {
	switch columnType {
	case "int2", "int4", "int8", "oid", "float4", "float8", "numeric":
		return json.Number(v)
	case "bool":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return v // a string: normalizePostgresValue rejects it
		}
		return b
	}
	return v
}

// lookupServerStatementWithin is lookupServerStatement with a caller-chosen
// deadline, used on the degraded path.
func lookupServerStatementWithin(query string, within time.Duration) (wire.PreparedStatements, bool) {
	if len(query) > maxServerLookupLen {
		return nil, false
	}
	resp, err := getCommandResponseWithin(&proto.CommandRequest{Command: query, CommandType: "postgres"}, within)
	if err != nil || resp == nil || !resp.Matched {
		return nil, false
	}
	return serverStatement(query, resp.Response), true
}
