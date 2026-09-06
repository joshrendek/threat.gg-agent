package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
)

// Use the real SSH client/server handshake and session exec path: a correct
// response string alone doesn't prove that a client accepts the exit status.
func TestExecValidatorRepliesAndCapturesOriginal(t *testing.T) {
	oldLookup, oldSave := lookupCommandResponse, saveShellCommand
	t.Cleanup(func() { lookupCommandResponse, saveShellCommand = oldLookup, oldSave })
	lookupCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.Command == "uname -a" {
			return &proto.CommandResponse{Response: "Linux configured-host test-kernel\r\n", Matched: true}, nil
		}
		return &proto.CommandResponse{Response: "command not found\r\n"}, nil
	}
	saved := make(chan *proto.ShellCommandRequest, 4)
	saveShellCommand = func(in *proto.ShellCommandRequest) error { saved <- in; return nil }
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		server, chans, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		h := &honeypot{logger: zerolog.New(io.Discard)}
		h.handleChannels(chans, &ssh.Permissions{Extensions: map[string]string{"guid": "validator-test"}})
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	clientConn, chans, requests, err := ssh.NewClientConn(conn, listener.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(clientConn, chans, requests)
	defer client.Close()
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
	client.Close()
	<-serverDone
}
