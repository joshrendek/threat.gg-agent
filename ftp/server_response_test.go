package ftp

import (
	"net"
	"testing"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

// fakeConn is a minimal net.Conn whose only usable method is RemoteAddr (all handleCommand
// needs on the override path). Any other call panics, which is fine — the override returns
// before touching the connection.
type fakeConn struct{ net.Conn }

func (fakeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 21} }

// TestHandleCommand_ServerOverride: a Matched ftp row is returned verbatim (admins author
// the full "NNN ...\r\n" reply, since sendMsg adds no framing); a miss falls back to the
// hardcoded reply. The lookup is scoped to command_type="ftp" and keyed by the raw line.
func TestHandleCommand_ServerOverride(t *testing.T) {
	orig := cmdresp.GetCommandResponse
	defer func() { cmdresp.GetCommandResponse = orig }()

	// (a) Matched → verbatim override wins over the hardcoded SysType.
	cmdresp.GetCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "ftp" || in.Command != "SYST" {
			t.Fatalf("forwarded (%q,%q), want (ftp,SYST)", in.CommandType, in.Command)
		}
		return &proto.CommandResponse{Response: "215 UNIX Type: L8 (custom)\r\n", Matched: true}, nil
	}
	out, err := handleCommand("SYST", &ConnectionConfig{}, &AuthUser{}, fakeConn{}, zerolog.Nop())
	if err != nil || out != "215 UNIX Type: L8 (custom)\r\n" {
		t.Fatalf("matched: (%q,%v), want the override,nil", out, err)
	}

	// (b) Miss → hardcoded SysType.
	cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Matched: false}, nil
	}
	out, err = handleCommand("SYST", &ConnectionConfig{}, &AuthUser{}, fakeConn{}, zerolog.Nop())
	if err != nil || out != SysType {
		t.Fatalf("miss: (%q,%v), want SysType,nil", out, err)
	}
}
