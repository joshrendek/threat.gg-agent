package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	wire "github.com/jeroenrinzema/psql-wire"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// fakeWriter is a test double for wire.DataWriter that records the framing calls the
// honeypot makes, so we can assert postgres wire framing without a live pg connection.
type fakeWriter struct {
	rows      [][]any
	completed string
	emptied   bool
}

func (f *fakeWriter) Row(v []any) error          { f.rows = append(f.rows, v); return nil }
func (f *fakeWriter) Written() uint64            { return uint64(len(f.rows)) }
func (f *fakeWriter) Empty() error               { f.emptied = true; return nil }
func (f *fakeWriter) Complete(desc string) error { f.completed = desc; return nil }

// TestIsRowReturning: row-returning verbs (select/show/with/values/table) frame as a data
// row; everything else (set/begin/commit/insert/...) frames as a CommandComplete tag.
func TestIsRowReturning(t *testing.T) {
	rowReturning := []string{
		"select version()",
		"  select datname from pg_database;",
		"SHOW server_version",
		"with x as (select 1) select * from x",
		"values (1)",
		"table pg_database",
	}
	for _, q := range rowReturning {
		if !isRowReturning(q) {
			t.Errorf("isRowReturning(%q) = false, want true", q)
		}
	}
	commandTagOnly := []string{
		"set datestyle to 'iso'",
		"begin",
		"commit",
		"rollback",
		"insert into t values (1)",
		"reset all",
	}
	for _, q := range commandTagOnly {
		if isRowReturning(q) {
			t.Errorf("isRowReturning(%q) = true, want false", q)
		}
	}
}

// TestCommandTag: the stored response is what psql displays for a tag statement, so a
// non-empty response is used verbatim; an empty response derives the tag from the verb.
func TestCommandTag(t *testing.T) {
	if got := commandTag("begin", "BEGIN"); got != "BEGIN" {
		t.Errorf("commandTag with authored response = %q, want BEGIN", got)
	}
	if got := commandTag("set datestyle to 'iso'", ""); got != "SET" {
		t.Errorf("commandTag empty response = %q, want SET (derived from verb)", got)
	}
}

// TestWriteFramedResponse: row-returning queries emit one ("result" text) row then
// SELECT 1; tag statements emit only a CommandComplete with no rows.
func TestWriteFramedResponse(t *testing.T) {
	// Row-returning: single row carrying the stored text, completed as SELECT 1.
	fw := &fakeWriter{}
	if err := writeFramedResponse(true, "PostgreSQL 14.11", "select version()", fw); err != nil {
		t.Fatalf("writeFramedResponse row: %v", err)
	}
	if len(fw.rows) != 1 || len(fw.rows[0]) != 1 || fw.rows[0][0] != "PostgreSQL 14.11" {
		t.Fatalf("row framing wrote %v, want one single-column row with the stored text", fw.rows)
	}
	if fw.completed != "SELECT 1" {
		t.Fatalf("row framing completed %q, want SELECT 1", fw.completed)
	}

	// Tag statement: no rows, CommandComplete carries the tag.
	fw = &fakeWriter{}
	if err := writeFramedResponse(false, "", "begin", fw); err != nil {
		t.Fatalf("writeFramedResponse tag: %v", err)
	}
	if len(fw.rows) != 0 {
		t.Fatalf("tag framing wrote rows %v, want none", fw.rows)
	}
	if fw.completed != "BEGIN" {
		t.Fatalf("tag framing completed %q, want BEGIN", fw.completed)
	}
}

// TestLookupServerStatement exercises the seam: a Matched row yields a statement (ok=true);
// a miss, an error, and an oversized query all yield ok=false so the caller falls back to
// the hardcoded responses map. The lookup is scoped to command_type="postgres".
func TestLookupServerStatement(t *testing.T) {
	orig := getCommandResponse
	defer func() { getCommandResponse = orig }()

	// Matched → handled.
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "postgres" {
			t.Fatalf("command_type = %q, want postgres", in.CommandType)
		}
		if in.Command != "select version()" {
			t.Fatalf("command = %q, want the query", in.Command)
		}
		return &proto.CommandResponse{Response: "PostgreSQL 14.11", Matched: true}, nil
	}
	if stmt, ok := lookupServerStatement("select version()"); !ok || stmt == nil {
		t.Fatalf("matched: ok=%v stmt=%v; want true, non-nil", ok, stmt)
	}

	// Not matched → fall back.
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "x", Matched: false}, nil
	}
	if _, ok := lookupServerStatement("select 1"); ok {
		t.Fatal("unmatched: ok=true, want false")
	}

	// Error → fall back.
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		return nil, errors.New("boom")
	}
	if _, ok := lookupServerStatement("select 1"); ok {
		t.Fatal("error: ok=true, want false")
	}

	// Oversized → not forwarded.
	called := false
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		called = true
		return &proto.CommandResponse{Response: "x", Matched: true}, nil
	}
	if _, ok := lookupServerStatement(strings.Repeat("a", maxServerLookupLen+1)); ok {
		t.Fatal("oversized: ok=true, want false")
	}
	if called {
		t.Fatal("oversized query must not be forwarded to the server lookup")
	}
}

// compile-time assurance the fake satisfies the wire interface used by the framing code.
var _ wire.DataWriter = (*fakeWriter)(nil)

// silence unused import in case context is only referenced transitively.
var _ = context.Background
