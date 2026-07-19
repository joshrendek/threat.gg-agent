package mysql

import (
	"bytes"
	"testing"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// TestHandleComQuery_ServerOverride: mysql is binary/packet-framed like postgres, so a
// Matched mysql row is FRAMED — a row-returning query renders the stored text as a single
// ("result") column/row result set; a non-row statement renders an OK packet. A miss falls
// back to the hardcoded queryResponses/prefix handling. Scoped to command_type="mysql",
// keyed by the normalized (lowercased, trimmed) query.
func TestHandleComQuery_ServerOverride(t *testing.T) {
	orig := cmdresp.GetCommandResponse
	defer func() { cmdresp.GetCommandResponse = orig }()

	// (a) Matched row-returning → the stored text is packed into the result-set row bytes.
	cmdresp.GetCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "mysql" || in.Command != "select @@version" {
			t.Fatalf("forwarded (%q,%q), want (mysql,select @@version)", in.CommandType, in.Command)
		}
		return &proto.CommandResponse{Response: "8.0.35-CUSTOM", Matched: true}, nil
	}
	var buf bytes.Buffer
	if _, err := handleComQuery(&buf, 1, "SELECT @@version"); err != nil {
		t.Fatalf("matched row-returning: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("8.0.35-CUSTOM")) {
		t.Fatalf("matched row-returning: result set missing the stored text; got % x", buf.Bytes())
	}

	// (b) Matched non-row → OK packet (0x00 marker), stored text NOT rendered as a row.
	cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "IGNORED-FOR-OK", Matched: true}, nil
	}
	buf.Reset()
	if _, err := handleComQuery(&buf, 1, "SET names utf8"); err != nil {
		t.Fatalf("matched non-row: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("IGNORED-FOR-OK")) {
		t.Fatalf("matched non-row: OK packet must not carry the stored text; got % x", buf.Bytes())
	}
	if len(buf.Bytes()) < 5 || buf.Bytes()[4] != 0x00 {
		t.Fatalf("matched non-row: expected an OK packet (0x00 marker); got % x", buf.Bytes())
	}

	// (c) Miss → hardcoded path (unknown SELECT returns an empty result set, no panic).
	cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Matched: false}, nil
	}
	buf.Reset()
	if _, err := handleComQuery(&buf, 1, "SELECT something_unknown"); err != nil {
		t.Fatalf("miss: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("miss: expected the hardcoded handler to write a response")
	}
}
