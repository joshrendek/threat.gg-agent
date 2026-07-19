package smtp

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	pb "github.com/joshrendek/threat.gg-agent/proto"
)

// TestHandleConnection_ServerOverride drives the real command loop over a net.Pipe: a
// Matched smtp row (keyed by the CRLF-trimmed command line) is written verbatim to the
// client; an unmatched command falls back to the hardcoded reply. This exercises the hook
// placement + verbatim framing end-to-end.
func TestHandleConnection_ServerOverride(t *testing.T) {
	orig := cmdresp.GetCommandResponse
	defer func() { cmdresp.GetCommandResponse = orig }()
	cmdresp.GetCommandResponse = func(in *pb.CommandRequest) (*pb.CommandResponse, error) {
		if in.CommandType == "smtp" && in.Command == "VRFY root" {
			return &pb.CommandResponse{Response: "250 root <root@corp.com>\r\n", Matched: true}, nil
		}
		return &pb.CommandResponse{Matched: false}, nil
	}

	client, server := net.Pipe()
	defer client.Close()
	go handleConnection(server)

	br := bufio.NewReader(client)
	if _, err := br.ReadString('\n'); err != nil { // consume the 220 banner
		t.Fatalf("reading banner: %v", err)
	}

	// (a) Matched → verbatim override.
	client.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(client, "VRFY root\r\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "250 root <root@corp.com>\r\n" {
		t.Fatalf("matched: (%q,%v), want the override reply", line, err)
	}

	// (b) Miss → hardcoded VRFY reply.
	fmt.Fprint(client, "VRFY nobody\r\n")
	line, err = br.ReadString('\n')
	if err != nil || line != "252 Cannot VRFY user\r\n" {
		t.Fatalf("miss: (%q,%v), want the hardcoded 252 reply", line, err)
	}
}
