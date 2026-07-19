package telnet

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/joshrendek/threat.gg-agent/proto"
)

// TestExecuteCommand_ServerOverrideAndFallback exercises the core new logic via the
// injectable getCommandResponse seam: a Matched server response is returned verbatim;
// an unmatched response, an error, an oversized command, and exit commands all fall
// back to the local hardcoded handlers (the no-regression guarantee).
func TestExecuteCommand_ServerOverrideAndFallback(t *testing.T) {
	orig := getCommandResponse
	defer func() { getCommandResponse = orig }()

	// (a) Matched=true → server response wins, and it's scoped to command_type=telnet.
	getCommandResponse = func(in *pb.CommandRequest) (*pb.CommandResponse, error) {
		if in.CommandType != "telnet" {
			t.Fatalf("command_type = %q, want telnet", in.CommandType)
		}
		return &pb.CommandResponse{Response: "SERVER-OK\r\n", Matched: true}, nil
	}
	if out, exit := executeCommand("whoami"); out != "SERVER-OK\r\n" || exit {
		t.Fatalf(`matched: got %q, %v; want "SERVER-OK\r\n", false`, out, exit)
	}

	// (b) Matched=false → fall back to the local handler (root\r\n), NOT the server text.
	getCommandResponse = func(in *pb.CommandRequest) (*pb.CommandResponse, error) {
		return &pb.CommandResponse{Response: "IGNORED", Matched: false}, nil
	}
	if out, exit := executeCommand("whoami"); out != "root\r\n" || exit {
		t.Fatalf(`unmatched: got %q, %v; want "root\r\n", false`, out, exit)
	}

	// (c) server error → fall back.
	getCommandResponse = func(in *pb.CommandRequest) (*pb.CommandResponse, error) {
		return nil, errors.New("boom")
	}
	if out, _ := executeCommand("whoami"); out != "root\r\n" {
		t.Fatalf(`error: got %q; want "root\r\n"`, out)
	}

	// (d) oversized input must NOT be forwarded to the server lookup.
	called := false
	getCommandResponse = func(in *pb.CommandRequest) (*pb.CommandResponse, error) {
		called = true
		return &pb.CommandResponse{Response: "X", Matched: true}, nil
	}
	executeCommand(strings.Repeat("a", maxServerLookupLen+1))
	if called {
		t.Fatal("oversized input must not be forwarded to the server lookup")
	}

	// exit always closes, regardless of the server.
	if out, exit := executeCommand("exit"); out != "" || !exit {
		t.Fatalf(`exit: got %q, %v; want "", true`, out, exit)
	}
}
