package sshd

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"golang.org/x/crypto/ssh"
)

func terminalReply(source proto.GenerateSource, stdout string, code int32, cwd, hostname string) *proto.GenerateReply {
	return &proto.GenerateReply{Source: source, GenerationId: "gen-1",
		Body: &proto.GenerateReply_Terminal{Terminal: &proto.Terminal{Stdout: stdout, ExitCode: code, Cwd: cwd, Hostname: hostname}}}
}

func aiReply(stdout string, code int32, cwd string) *proto.GenerateReply {
	return terminalReply(proto.GenerateSource_GENERATE_SOURCE_AI, stdout, code, cwd, "srv-01")
}

type seams struct {
	saved   chan *proto.ShellCommandRequest
	lookups atomic.Int32
}

// swapSeams replaces the generate, legacy lookup and capture seams for one
// test. The legacy lookup answers "command not found" so a fallback is visible.
func swapSeams(t *testing.T, gen func(*proto.GenerateRequest) (*proto.GenerateReply, error)) *seams {
	t.Helper()
	oldGen, oldLookup, oldSave := generateResponse, lookupCommandResponse, saveShellCommand
	t.Cleanup(func() { generateResponse, lookupCommandResponse, saveShellCommand = oldGen, oldLookup, oldSave })
	s := &seams{saved: make(chan *proto.ShellCommandRequest, 16)}
	saveShellCommand = func(in *proto.ShellCommandRequest) error { s.saved <- in; return nil }
	lookupCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		s.lookups.Add(1)
		return &proto.CommandResponse{Response: "bash: " + in.Command + ": command not found\r\n"}, nil
	}
	generateResponse = func(in *proto.GenerateRequest, within time.Duration) (*proto.GenerateReply, error) {
		if within != generateBudget {
			t.Errorf("budget %v, want %v", within, generateBudget)
		}
		return gen(in)
	}
	return s
}

func (s *seams) capture(t *testing.T) *proto.ShellCommandRequest {
	t.Helper()
	select {
	case in := <-s.saved:
		return in
	case <-time.After(2 * time.Second):
		t.Fatal("capture missing")
		return nil
	}
}

func execOutput(t *testing.T, guid, command string) (string, error) {
	t.Helper()
	client, stop := startTestSSH(t, guid)
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, runErr := session.Output(command)
	session.Close()
	return string(out), runErr
}

func exitStatus(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exit *ssh.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("not an exit status: %v", err)
	}
	return exit.ExitStatus()
}

func TestExecUsesAIReplyExitCodeAndCRLF(t *testing.T) {
	var got *proto.GenerateRequest
	s := swapSeams(t, func(in *proto.GenerateRequest) (*proto.GenerateReply, error) {
		got = in
		return aiReply("total 0\ndrwx------ 2 root root 4096 Sep 30 12:00 .\n", 2, "/root"), nil
	})
	out, runErr := execOutput(t, "ai-guid", "ls -la /root")
	if out != "total 0\r\ndrwx------ 2 root root 4096 Sep 30 12:00 .\r\n" {
		t.Fatalf("output %q", out)
	}
	if code := exitStatus(t, runErr); code != 2 {
		t.Fatalf("want exit 2, got %d", code)
	}
	if got == nil || got.Guid != "ai-guid" || got.Protocol != "ssh" || got.Input != "ls -la /root" || got.DeadlineMs != 3000 {
		t.Fatalf("request %+v", got)
	}
	in := s.capture(t)
	if in.ResponseSource != "ai" || in.GenerationId != "gen-1" || in.Cmd != "ls -la /root" || in.Guid != "ai-guid" {
		t.Fatalf("capture %+v", in)
	}
	if n := s.lookups.Load(); n != 0 {
		t.Fatalf("legacy lookup consulted %d times on an AI reply", n)
	}
}

func TestExecSourceLabelsAndExitClamp(t *testing.T) {
	for _, tc := range []struct {
		source proto.GenerateSource
		code   int32
		label  string
		status int
	}{
		{proto.GenerateSource_GENERATE_SOURCE_AI_CACHED, 0, "ai_cached", 0},
		{proto.GenerateSource_GENERATE_SOURCE_LOCAL, 1, "local", 1},
		{proto.GenerateSource_GENERATE_SOURCE_AI, 300, "ai", 255},
		{proto.GenerateSource_GENERATE_SOURCE_AI, -1, "ai", 255},
	} {
		s := swapSeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
			return terminalReply(tc.source, "ok\n", tc.code, "/", "h"), nil
		})
		out, runErr := execOutput(t, "g", "id")
		if out != "ok\r\n" {
			t.Fatalf("%v: output %q", tc.source, out)
		}
		if code := exitStatus(t, runErr); code != tc.status {
			t.Fatalf("%v code %d: exit %d, want %d", tc.source, tc.code, code, tc.status)
		}
		if in := s.capture(t); in.ResponseSource != tc.label || in.GenerationId != "gen-1" {
			t.Fatalf("%v: capture %+v", tc.source, in)
		}
	}
}

func TestExecFallsBackWhenUnimplemented(t *testing.T) {
	s := swapSeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return nil, persistence.ErrUnimplemented
	})
	out, runErr := execOutput(t, "g", "missing-command")
	if out != "bash: missing-command: command not found\r\n" {
		t.Fatalf("legacy path must answer: %q", out)
	}
	if code := exitStatus(t, runErr); code != 127 {
		t.Fatalf("want 127, got %d", code)
	}
	if s.lookups.Load() == 0 {
		t.Fatal("legacy lookupCommandResponse was not consulted")
	}
	if in := s.capture(t); in.ResponseSource != "" || in.GenerationId != "" || in.Cmd != "missing-command" {
		t.Fatalf("legacy capture must carry no AI link: %+v", in)
	}
}

func TestExecFallsBackOnErrorAndNoneAndMissingBody(t *testing.T) {
	for name, gen := range map[string]func(*proto.GenerateRequest) (*proto.GenerateReply, error){
		"error": func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
			return nil, errors.New("deadline exceeded")
		},
		"none": func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
			return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "x"}, nil
		},
		"unspecified": func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
			return terminalReply(0, "leak\n", 0, "/", "h"), nil
		},
		"nil reply": func(*proto.GenerateRequest) (*proto.GenerateReply, error) { return nil, nil },
		"missing body": func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
			return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI}, nil
		},
	} {
		s := swapSeams(t, gen)
		// The echo validator lives on the legacy path; it must still be reachable.
		out, runErr := execOutput(t, "g", "echo xsec")
		if out != "xsec\r\n" || runErr != nil {
			t.Fatalf("%s: legacy echo must still work: %q %v", name, out, runErr)
		}
		if in := s.capture(t); in.ResponseSource != "" || in.GenerationId != "" {
			t.Fatalf("%s: capture %+v", name, in)
		}
	}
}

func TestExecSanitisesAIOutput(t *testing.T) {
	s := swapSeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		return aiReply("\x1b]0;owned\x07\x1b[31mred\x1b[0m\n", 0, "/root"), nil
	})
	out, _ := execOutput(t, "g", "cat x")
	if strings.Contains(out, "\x1b") || out != "red\r\n" {
		t.Fatalf("got %q", out)
	}
	// Drain the async capture so it finishes before the seams are restored.
	if in := s.capture(t); in.ResponseSource != "ai" {
		t.Fatalf("capture %+v", in)
	}
}

func TestExecSanitisesLegacyOutput(t *testing.T) {
	s := swapSeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) { return nil, persistence.ErrUnimplemented })
	lookupCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Response: "\x1b]52;c;cm0gLXJmIC8=\x07plain\r\n", Matched: true}, nil
	}
	out, runErr := execOutput(t, "g", "whoami")
	if out != "plain\r\n" || runErr != nil {
		t.Fatalf("got %q %v", out, runErr)
	}
	if in := s.capture(t); in.ResponseSource != "" {
		t.Fatalf("capture %+v", in)
	}
}

// Server-supplied cwd and hostname end up in the prompt, so they are held to a
// single printable line; anything else leaves the prompt field unchanged.
func TestCommandReplyRejectsHostilePromptFields(t *testing.T) {
	for _, tc := range []struct{ cwd, hostname, wantCwd, wantHost string }{
		{"/tmp", "srv-01", "/tmp", "srv-01"},
		{"/tmp\x1b]0;owned\x07", "srv\x1b[2J-01", "/tmp", "srv-01"},
		{"/tmp\nroot@evil:/# ", "srv\r\nx", "", ""},
		{"", "", "", ""},
		{strings.Repeat("a", maxPromptField+1), "ok", "", "ok"},
	} {
		swapSeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
			return terminalReply(proto.GenerateSource_GENERATE_SOURCE_AI, "", 0, tc.cwd, tc.hostname), nil
		})
		got := commandReply("g", "cd x", "/")
		if got.Cwd != tc.wantCwd || got.Hostname != tc.wantHost {
			t.Errorf("cwd %q host %q: got cwd %q host %q", tc.cwd, tc.hostname, got.Cwd, got.Hostname)
		}
	}
}

func TestCommandReplySkipsGenerateForBlankInput(t *testing.T) {
	var calls atomic.Int32
	swapSeams(t, func(*proto.GenerateRequest) (*proto.GenerateReply, error) {
		calls.Add(1)
		return aiReply("x\n", 0, "/"), nil
	})
	if got := commandReply("g", "  \t", "/"); got.Source != "" {
		t.Fatalf("blank input answered by AI: %+v", got)
	}
	if calls.Load() != 0 {
		t.Fatal("blank input must not spend a generation")
	}
}

// The first PTY-path test in this repo. Legacy users keep today's prompt
// byte-for-byte; an AI reply with empty stdout (cd) prints nothing and moves
// the prompt to the persona hostname and new cwd.
func TestShellPromptTracksHostnameAndCwd(t *testing.T) {
	s := swapSeams(t, func(in *proto.GenerateRequest) (*proto.GenerateReply, error) {
		switch in.Input {
		case "cd /tmp":
			return aiReply("", 0, "/tmp"), nil
		case "pwd":
			return aiReply("/tmp\n", 0, "/tmp"), nil
		}
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil
	})
	client, stop := startTestSSH(t, "pty-guid")
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		t.Fatal(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	bytesCh := make(chan byte, 4096)
	go func() {
		r := bufio.NewReader(stdout)
		for {
			c, err := r.ReadByte()
			if err != nil {
				close(bytesCh)
				return
			}
			bytesCh <- c
		}
	}()
	readUntil := func(marker string) string {
		t.Helper()
		var b strings.Builder
		deadline := time.After(5 * time.Second)
		for !strings.HasSuffix(b.String(), marker) {
			select {
			case c, ok := <-bytesCh:
				if !ok {
					t.Fatalf("stream closed waiting for %q, got %q", marker, b.String())
				}
				b.WriteByte(c)
			case <-deadline:
				t.Fatalf("timed out waiting for %q, got %q", marker, b.String())
			}
		}
		return b.String()
	}
	// The server-side line editor echoes typed input, then CRLF, then output.
	step := func(line, wantOutput, wantPrompt string) {
		t.Helper()
		io.WriteString(stdin, line+"\r")
		got := readUntil(wantPrompt)
		if want := line + "\r\n" + wantOutput + wantPrompt; got != want {
			t.Fatalf("after %q: got %q, want %q", line, got, want)
		}
	}
	if got := readUntil("# "); got != "root@localhost:/# " {
		t.Fatalf("initial prompt %q", got)
	}
	// NONE falls back to the legacy answer and leaves the prompt untouched.
	step("whoami", "bash: whoami: command not found\r\n", "root@localhost:/# ")
	// Empty stdout prints nothing, not "command not found", and moves cwd.
	step("cd /tmp", "", "root@srv-01:/tmp# ")
	step("pwd", "/tmp\r\n", "root@srv-01:/tmp# ")
	for _, want := range []struct{ cmd, source string }{{"whoami", ""}, {"cd /tmp", "ai"}, {"pwd", "ai"}} {
		in := s.capture(t)
		if in.Cmd != want.cmd || in.ResponseSource != want.source || in.Guid != "pty-guid" {
			t.Fatalf("capture %+v, want %+v", in, want)
		}
	}
	stdin.Close()
}
