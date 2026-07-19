package redis

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// TestServerResponse_OverrideAndFallback exercises the redis server-authored override via
// the injectable getCommandResponse seam. RESP is line-oriented text, so a Matched row is
// written to the connection VERBATIM (the admin authors exact RESP frames). A miss, an
// error, and an oversized command all return handled=false so the caller falls back to the
// hardcoded switch (the no-regression guarantee).
func TestServerResponse_OverrideAndFallback(t *testing.T) {
	orig := getCommandResponse
	defer func() { getCommandResponse = orig }()

	// (a) Matched=true → verbatim RESP bytes written, handled=true, scoped to command_type=redis.
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "redis" {
			t.Fatalf("command_type = %q, want redis", in.CommandType)
		}
		if in.Command != "MODULE LOAD /tmp/exp.so" {
			t.Fatalf("command = %q, want the full joined command", in.Command)
		}
		return &proto.CommandResponse{Response: "+OK\r\n", Matched: true}, nil
	}
	var buf bytes.Buffer
	handled, err := serverResponse("MODULE LOAD /tmp/exp.so", &buf)
	if !handled || err != nil {
		t.Fatalf("matched: handled=%v err=%v; want true, nil", handled, err)
	}
	if buf.String() != "+OK\r\n" {
		t.Fatalf("matched: wrote %q, want %q (verbatim)", buf.String(), "+OK\r\n")
	}

	// (b) Matched=false → handled=false, nothing written (caller falls back to switch).
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "IGNORED", Matched: false}, nil
	}
	buf.Reset()
	if handled, _ := serverResponse("PING", &buf); handled || buf.Len() != 0 {
		t.Fatalf("unmatched: handled=%v wrote %q; want false, empty", handled, buf.String())
	}

	// (c) server error → handled=false (fall back).
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		return nil, errors.New("boom")
	}
	buf.Reset()
	if handled, _ := serverResponse("PING", &buf); handled || buf.Len() != 0 {
		t.Fatalf("error: handled=%v wrote %q; want false, empty", handled, buf.String())
	}

	// (d) oversized input must NOT be forwarded to the server lookup.
	called := false
	getCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		called = true
		return &proto.CommandResponse{Response: "X", Matched: true}, nil
	}
	buf.Reset()
	if handled, _ := serverResponse(strings.Repeat("a", maxServerLookupLen+1), &buf); handled {
		t.Fatal("oversized: handled must be false")
	}
	if called {
		t.Fatal("oversized input must not be forwarded to the server lookup")
	}
}
