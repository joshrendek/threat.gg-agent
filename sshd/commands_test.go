package sshd

import (
	"errors"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestSSHCommandValidators(t *testing.T) {
	old := lookupCommandResponse
	t.Cleanup(func() { lookupCommandResponse = old })
	lookupCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "ssh" {
			t.Fatalf("wrong protocol: %q", in.CommandType)
		}
		if in.Command == "uname -a" {
			return &proto.CommandResponse{Response: "Linux configured-host configured-kernel\r\n", Matched: true}, nil
		}
		return &proto.CommandResponse{Response: "MISS"}, nil
	}
	for _, tc := range []struct{ command, want string }{
		{"uname -a 2>/dev/null || echo 'Unknown'", "Linux configured-host configured-kernel\r\n"},
		{"uname -a 2>/dev/null", "Linux configured-host configured-kernel\r\n"},
		{"uname -a 2> /dev/null || echo \"Unknown\"", "Linux configured-host configured-kernel\r\n"},
		{"echo xsec", "xsec\r\n"}, {"echo SSH_TEST_OK", "SSH_TEST_OK\r\n"},
		{"echo 'hello world' \"second token\"", "hello world second token\r\n"},
		{"echo", "\r\n"},
	} {
		got, err := commandResponse(tc.command)
		if err != nil || got == nil || !got.Matched || got.Response != tc.want {
			t.Errorf("%q: %+v, %v", tc.command, got, err)
		}
	}
	for _, command := range []string{"echo $(id)", "echo `id`", "echo $HOME", "echo x; id", "echo x\x00", "echo -e hi", "echo -n hi", "uname -a 2>/tmp/file", "uname -a 2>/dev/null; id", "echo " + strings.Repeat("x", 4096)} {
		got, err := commandResponse(command)
		if err != nil || got.Matched || got.Response != "MISS" {
			t.Errorf("unsupported %q was answered: %+v, %v", command, got, err)
		}
	}
	lookupCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "", Matched: true}, nil
	}
	if got, _ := commandResponse("echo xsec"); got.Response != "" {
		t.Fatal("server override lost")
	}
	lookupCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) { return nil, errors.New("offline") }
	if got, err := commandResponse("echo xsec"); err != nil || got.Response != "xsec\r\n" {
		t.Fatal("echo unavailable during control-plane outage")
	}
	if got, err := commandResponse("uname -a 2>/dev/null"); err == nil || got != nil {
		t.Fatal("invented uname persona during outage")
	}
}
