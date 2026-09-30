package sshd

import (
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"golang.org/x/crypto/ssh"
)

// Use the real SSH client/server handshake and session exec path: a correct
// response string alone doesn't prove that a client accepts the exit status.
func TestExecValidatorRepliesAndCapturesOriginal(t *testing.T) {
	oldGen, oldLookup, oldSave := generateResponse, lookupCommandResponse, saveShellCommand
	t.Cleanup(func() { generateResponse, lookupCommandResponse, saveShellCommand = oldGen, oldLookup, oldSave })
	// Pin the legacy path: a server that predates GenerateResponse.
	generateResponse = func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		return nil, persistence.ErrUnimplemented
	}
	lookupCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.Command == "uname -a" {
			return &proto.CommandResponse{Response: "Linux configured-host test-kernel\r\n", Matched: true}, nil
		}
		return &proto.CommandResponse{Response: "command not found\r\n"}, nil
	}
	saved := make(chan *proto.ShellCommandRequest, 4)
	saveShellCommand = func(in *proto.ShellCommandRequest) error { saved <- in; return nil }
	client, stop := startTestSSH(t, "validator-test")
	defer stop()
	for _, tc := range []struct {
		command, want string
		status        int
	}{
		{"uname -a 2>/dev/null || echo 'Unknown'", "Linux configured-host test-kernel", 0},
		{"echo xsec", "xsec", 0},
		{"missing-command", "command not found", 127},
	} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, runErr := session.Output(tc.command)
		session.Close()
		if strings.TrimSpace(string(out)) != tc.want {
			t.Fatalf("%q: output=%q error=%v", tc.command, out, runErr)
		}
		if tc.status == 0 && runErr != nil {
			t.Fatal("successful exec reported failure", runErr)
		}
		if tc.status != 0 {
			if exit, ok := runErr.(*ssh.ExitError); !ok || exit.ExitStatus() != tc.status {
				t.Fatal("wrong failure status", runErr)
			}
		}
		select {
		case in := <-saved:
			if in.Cmd != tc.command || in.Guid != "validator-test" {
				t.Fatal("raw capture lost", in)
			}
		case <-time.After(time.Second):
			t.Fatal("capture missing")
		}
	}
}
