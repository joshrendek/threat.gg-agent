package telnet

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/joshrendek/threat.gg-agent/proto"
)

// pipeClient is the attacker's side of a net.Pipe connection to handleConnection.
type pipeClient struct {
	t      *testing.T
	conn   net.Conn
	bytes  chan byte
	logins chan *pb.TelnetLoginRequest
	saves  chan *pb.TelnetCommandRequest
	done   chan struct{}
}

// startPipeSession runs handleConnection over net.Pipe with the capture seams
// swapped, so no gRPC client is needed. The caller swaps the server seams.
func startPipeSession(t *testing.T) *pipeClient {
	t.Helper()
	oldLogin, oldSave := saveTelnetLogin, saveTelnetCommand
	c := &pipeClient{t: t, bytes: make(chan byte, 1<<16), done: make(chan struct{}),
		logins: make(chan *pb.TelnetLoginRequest, 4), saves: make(chan *pb.TelnetCommandRequest, 16)}
	saveTelnetLogin = func(in *pb.TelnetLoginRequest) error { c.logins <- in; return nil }
	saveTelnetCommand = func(in *pb.TelnetCommandRequest) error { c.saves <- in; return nil }
	server, client := net.Pipe()
	c.conn = client
	go func() {
		defer close(c.done)
		handleConnection(server)
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			n, err := client.Read(buf)
			for _, b := range buf[:n] {
				c.bytes <- b
			}
			if err != nil {
				close(c.bytes)
				return
			}
		}
	}()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			t.Error("handleConnection did not return")
		}
		saveTelnetLogin, saveTelnetCommand = oldLogin, oldSave
	})
	return c
}

// readUntil returns everything received up to and including marker.
func (c *pipeClient) readUntil(marker string) string {
	c.t.Helper()
	var b bytes.Buffer
	deadline := time.After(5 * time.Second)
	for !strings.HasSuffix(b.String(), marker) {
		select {
		case x, ok := <-c.bytes:
			if !ok {
				c.t.Fatalf("connection closed waiting for %q, got %q", marker, b.String())
			}
			b.WriteByte(x)
		case <-deadline:
			c.t.Fatalf("timed out waiting for %q, got %q", marker, b.String())
		}
	}
	return b.String()
}

func (c *pipeClient) send(line string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, line+"\r\n"); err != nil {
		c.t.Fatal(err)
	}
}

// step sends a command and returns the bytes received up to the next prompt,
// which must be exactly want followed by the literal prompt.
func (c *pipeClient) step(line, want string) {
	c.t.Helper()
	c.send(line)
	if got := c.readUntil("~ # "); got != want+"~ # " {
		c.t.Fatalf("after %q: got %q, want %q", line, got, want+"~ # ")
	}
}

func (c *pipeClient) login() *pb.TelnetLoginRequest {
	c.t.Helper()
	c.readUntil("device login: ")
	c.send("admin")
	c.readUntil("Password: ")
	c.send("xc3511")
	if got := c.readUntil("~ # "); !strings.HasSuffix(got, banner+"~ # ") {
		c.t.Fatalf("banner and prompt missing: %q", got)
	}
	select {
	case in := <-c.logins:
		if in.Username != "admin" || in.Password != "xc3511" || in.Guid == "" {
			c.t.Fatalf("login capture %+v", in)
		}
		return in
	case <-time.After(2 * time.Second):
		c.t.Fatal("login capture missing")
		return nil
	}
}

// captures collects n command captures keyed by command. Each save runs in its
// own goroutine, so arrival order is not asserted.
func (c *pipeClient) captures(n int) map[string]*pb.TelnetCommandRequest {
	c.t.Helper()
	got := map[string]*pb.TelnetCommandRequest{}
	for i := 0; i < n; i++ {
		select {
		case in := <-c.saves:
			got[in.Command] = in
		case <-time.After(2 * time.Second):
			c.t.Fatalf("command capture missing after %d of %d", i, n)
		}
	}
	return got
}

// Login, one AI-answered command with hostile output, a NONE fallback and a
// deterministic probe, then exit. Every capture is saved after the reply and
// the AI-answered one carries the ledger marker.
func TestConnectionAIAnsweredCommandIsCapturedWithMarker(t *testing.T) {
	f := swapServer(t, func(in *pb.GenerateRequest) (*pb.GenerateReply, error) {
		if in.Input == "cat /proc/version" {
			return aiReply("\x1b]0;owned\x07\x1b[31mLinux version 3.10.0\x1b[0m\n"), nil
		}
		return noneReply(in)
	}, lookupMiss)
	c := startPipeSession(t)
	login := c.login()

	// AI stdout is sanitized on the wire: no ESC, \n becomes \r\n.
	c.step("cat /proc/version", "Linux version 3.10.0\r\n")
	c.step("whoami", "root\r\n")
	c.step("/bin/busybox ECCHI", "ECCHI: applet not found\r\n")
	c.send("exit")
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("exit did not close the connection")
	}

	got := c.captures(4)
	for _, want := range []struct{ cmd, source, gen string }{
		{"cat /proc/version", "ai", "gen-1"},
		{"whoami", "", ""},
		{"/bin/busybox ECCHI", "", ""},
		{"exit", "", ""},
	} {
		in := got[want.cmd]
		if in == nil || in.ResponseSource != want.source || in.GenerationId != want.gen || in.Guid != login.Guid {
			t.Fatalf("capture %+v, want %+v (guid %s)", in, want, login.Guid)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.generates) != 2 {
		t.Fatalf("generate calls %d, want 2 (the probe and exit never reach AI)", len(f.generates))
	}
	for _, in := range f.generates {
		if in.Guid != login.Guid || in.Protocol != "telnet" {
			t.Fatalf("generate request %+v", in)
		}
	}
}

// A server without GenerateResponse keeps today's session byte-for-byte.
func TestConnectionUnimplementedServerKeepsLegacySession(t *testing.T) {
	swapServer(t, unimplemented, lookupMiss)
	c := startPipeSession(t)
	c.login()
	c.step("uname -a", "Linux device 4.14.151 #1 SMP Tue Nov 5 12:38:07 UTC 2024 armv7l GNU/Linux\r\n")
	c.step("enable\x00", "")
	c.step("ps", "-sh: ps: not found\r\n")
	got := c.captures(3)
	for _, cmd := range []string{"uname -a", "enable\x00", "ps"} {
		if in := got[cmd]; in == nil || in.ResponseSource != "" || in.GenerationId != "" {
			t.Fatalf("capture %+v, want legacy %q", in, cmd)
		}
	}
}
