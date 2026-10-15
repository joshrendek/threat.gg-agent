package telnet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/shellai"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func terminalReply(source pb.GenerateSource, stdout string, code int32) *pb.GenerateReply {
	return &pb.GenerateReply{Source: source, GenerationId: "gen-1",
		Body: &pb.GenerateReply_Terminal{Terminal: &pb.Terminal{Stdout: stdout, ExitCode: code, Cwd: "/root", Hostname: "dvr"}}}
}

func aiReply(stdout string) *pb.GenerateReply {
	return terminalReply(pb.GenerateSource_GENERATE_SOURCE_AI, stdout, 0)
}

func noneReply(*pb.GenerateRequest) (*pb.GenerateReply, error) {
	return &pb.GenerateReply{Source: pb.GenerateSource_GENERATE_SOURCE_NONE}, nil
}

func unimplemented(*pb.GenerateRequest) (*pb.GenerateReply, error) {
	return nil, persistence.ErrUnimplemented
}

func lookupMiss(*pb.CommandRequest) (*pb.CommandResponse, error) {
	return &pb.CommandResponse{Response: "IGNORED", Matched: false}, nil
}

// fakeServer records every generate and authored-lookup call made through the
// telnet seams. It is safe for use from the connection goroutine.
type fakeServer struct {
	mu        sync.Mutex
	generates []*pb.GenerateRequest
	lookups   []*pb.CommandRequest
	withins   []time.Duration
}

func (f *fakeServer) counts() (generates, lookups int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.generates), len(f.lookups)
}

// swapServer replaces the generate and authored-lookup seams for one test.
func swapServer(t *testing.T, gen func(*pb.GenerateRequest) (*pb.GenerateReply, error), lookup func(*pb.CommandRequest) (*pb.CommandResponse, error)) *fakeServer {
	t.Helper()
	oldGen, oldLookup := generateResponse, lookupCommandResponse
	t.Cleanup(func() { generateResponse, lookupCommandResponse = oldGen, oldLookup })
	f := &fakeServer{}
	generateResponse = func(in *pb.GenerateRequest, within time.Duration) (*pb.GenerateReply, error) {
		if within != shellai.GenerateBudget {
			t.Errorf("generate budget %v, want %v", within, shellai.GenerateBudget)
		}
		f.mu.Lock()
		f.generates = append(f.generates, in)
		f.mu.Unlock()
		return gen(in)
	}
	lookupCommandResponse = func(in *pb.CommandRequest, within time.Duration) (*pb.CommandResponse, error) {
		if in.CommandType != "telnet" {
			t.Errorf("command_type = %q, want telnet", in.CommandType)
		}
		f.mu.Lock()
		f.lookups = append(f.lookups, in)
		f.withins = append(f.withins, within)
		f.mu.Unlock()
		return lookup(in)
	}
	return f
}

func TestCommandReplySendsNormalizedTelnetRequest(t *testing.T) {
	f := swapServer(t, func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return aiReply("x\n"), nil }, lookupMiss)
	commandReply("guid-1", "cat /proc/version\x00\x04 \r\n")
	if len(f.generates) != 1 {
		t.Fatalf("generate calls %d, want 1", len(f.generates))
	}
	in := f.generates[0]
	if in.Protocol != "telnet" || in.Guid != "guid-1" || in.Input != "cat /proc/version" || in.DeadlineMs != 3000 {
		t.Fatalf("request %+v", in)
	}
}

// Bot shell probes with NUL or EOT padding stay deterministic: the bare shell
// verbs print nothing and reach neither the AI nor the authored lookup.
func TestNULTerminatedShellProbes(t *testing.T) {
	f := swapServer(t, func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return aiReply("LEAK\n"), nil },
		func(*pb.CommandRequest) (*pb.CommandResponse, error) {
			return &pb.CommandResponse{Response: "LEAK\r\n", Matched: true}, nil
		})
	for _, command := range []string{"enable", "system", "shell", "sh", "linuxshell"} {
		for _, end := range []string{"", "\x00", "\x00\r\n", "\x04", "\x00 \t\x00"} {
			if r := commandReply("g", command+end); r.Output != "" || r.Exit || r.Source != "" {
				t.Errorf("%q: %+v", command+end, r)
			}
		}
	}
	if r := commandReply("g", "/bin/busybox UNSTABLE\x00"); r.Output != "UNSTABLE: applet not found\r\n" {
		t.Fatal(r.Output)
	}
	if r := commandReply("g", "\x00\x04\r\n"); r.Output != "" || r.Exit {
		t.Fatal("empty padding became a command")
	}
	if r := commandReply("g", "exit\x00"); !r.Exit {
		t.Fatal("terminated exit did not close")
	}
	if g, l := f.counts(); g != 0 || l != 0 {
		t.Fatalf("probes reached the server: generate=%d lookup=%d", g, l)
	}
}

// Embedded controls survive normalization and are forwarded as one command.
func TestEmbeddedControlsAreForwardedIntact(t *testing.T) {
	f := swapServer(t, noneReply, lookupMiss)
	if r := commandReply("g", "echo a\x00b\x00"); r.Output != "a\x00b\r\n" {
		t.Fatalf("embedded bytes changed: %q", r.Output)
	}
	if f.generates[0].Input != "echo a\x00b" || f.lookups[0].Command != "echo a\x00b" {
		t.Fatalf("generate %q lookup %q", f.generates[0].Input, f.lookups[0].Command)
	}
}

func TestDeterministicProbesNeverReachServer(t *testing.T) {
	f := swapServer(t, func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return aiReply("LEAK\n"), nil },
		func(*pb.CommandRequest) (*pb.CommandResponse, error) {
			return &pb.CommandResponse{Response: "LEAK\r\n", Matched: true}, nil
		})
	for input, want := range map[string]string{
		"/bin/busybox HISILICON":         "HISILICON: applet not found\r\n",
		"/bin/busybox rotating-probe-42": "rotating-probe-42: applet not found\r\n",
		"/bin/busybox ECCHI\x00":         "ECCHI: applet not found\r\n",
		"/bin/busybox uname -a":          "Linux device 4.14.151 #1 SMP Tue Nov 5 12:38:07 UTC 2024 armv7l GNU/Linux\r\n",
		"/bin/busybox cat /etc/passwd":   handleCat([]string{"/etc/passwd"}),
		"/bin/busybox echo hi\x04":       "hi\r\n",
		"enable\x00":                     "",
		"sh":                             "",
		"linuxshell\x04":                 "",
	} {
		if r := commandReply("g", input); r.Output != want || r.Source != "" || r.Exit {
			t.Errorf("%q: got %+v, want %q", input, r, want)
		}
	}
	for _, input := range []string{"exit", "quit", "logout"} {
		if r := commandReply("g", input); !r.Exit {
			t.Errorf("%q did not exit", input)
		}
	}
	if g, l := f.counts(); g != 0 || l != 0 {
		t.Fatalf("deterministic probes reached the server: generate=%d lookup=%d", g, l)
	}
	// A shell verb with arguments is real attacker input, not the bare probe.
	if r := commandReply("g", "sh -c id"); r.Source != "ai" {
		t.Fatalf("sh with arguments must reach the AI: %+v", r)
	}
}

// AI first, then the authored lookup, then the local handlers.
func TestCommandReplyOrdering(t *testing.T) {
	f := swapServer(t, func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return aiReply("ai-root\n"), nil },
		func(*pb.CommandRequest) (*pb.CommandResponse, error) {
			return &pb.CommandResponse{Response: "AUTHORED\r\n", Matched: true}, nil
		})
	if r := commandReply("g", "whoami"); r.Output != "ai-root\n" || r.Source != "ai" || r.GenerationID != "gen-1" {
		t.Fatalf("AI must win: %+v", r)
	}
	if _, l := f.counts(); l != 0 {
		t.Fatalf("authored lookup consulted %d times on an AI answer", l)
	}

	f = swapServer(t, noneReply, func(*pb.CommandRequest) (*pb.CommandResponse, error) {
		return &pb.CommandResponse{Response: "AUTHORED\r\n", Matched: true}, nil
	})
	if r := commandReply("g", "whoami"); r.Output != "AUTHORED\r\n" || r.Source != "" || r.GenerationID != "" {
		t.Fatalf("authored must answer after NONE: %+v", r)
	}
	if g, l := f.counts(); g != 1 || l != 1 {
		t.Fatalf("generate=%d lookup=%d, want 1/1", g, l)
	}

	// Matched with an empty body is an intentional empty answer, not a miss.
	swapServer(t, noneReply, func(*pb.CommandRequest) (*pb.CommandResponse, error) {
		return &pb.CommandResponse{Matched: true}, nil
	})
	if r := commandReply("g", "whoami"); r.Output != "" {
		t.Fatalf("matched empty: %+v", r)
	}

	for name, lookup := range map[string]func(*pb.CommandRequest) (*pb.CommandResponse, error){
		"miss":  lookupMiss,
		"error": func(*pb.CommandRequest) (*pb.CommandResponse, error) { return nil, errors.New("boom") },
		"nil":   func(*pb.CommandRequest) (*pb.CommandResponse, error) { return nil, nil },
	} {
		swapServer(t, noneReply, lookup)
		if r := commandReply("g", "whoami"); r.Output != "root\r\n" || r.Source != "" {
			t.Fatalf("%s: local handler must answer: %+v", name, r)
		}
	}
}

func TestCommandReplyAcceptMatrix(t *testing.T) {
	for _, tc := range []struct {
		source pb.GenerateSource
		code   int32
		label  string
	}{
		{pb.GenerateSource_GENERATE_SOURCE_AI, 0, "ai"},
		{pb.GenerateSource_GENERATE_SOURCE_AI_CACHED, 1, "ai_cached"},
		{pb.GenerateSource_GENERATE_SOURCE_LOCAL, 127, "local"},
		{pb.GenerateSource_GENERATE_SOURCE_AI, 300, "ai"},
		{pb.GenerateSource_GENERATE_SOURCE_AI, -1, "ai"},
	} {
		f := swapServer(t, func(*pb.GenerateRequest) (*pb.GenerateReply, error) {
			return terminalReply(tc.source, "-sh: foo: not found\n", tc.code), nil
		}, lookupMiss)
		r := commandReply("g", "foo")
		if r.Output != "-sh: foo: not found\n" || r.Source != tc.label || r.GenerationID != "gen-1" || r.Exit {
			t.Errorf("%v code %d: %+v", tc.source, tc.code, r)
		}
		if _, l := f.counts(); l != 0 {
			t.Errorf("%v: authored lookup consulted on an answer", tc.source)
		}
	}
}

func TestCommandReplyFallbackMatrix(t *testing.T) {
	for name, gen := range map[string]func(*pb.GenerateRequest) (*pb.GenerateReply, error){
		"unimplemented": unimplemented,
		"none":          noneReply,
		"error":         func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return nil, errors.New("boom") },
		"grpc internal": func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return nil, status.Error(codes.Internal, "x") },
		"none with body": func(*pb.GenerateRequest) (*pb.GenerateReply, error) {
			return terminalReply(pb.GenerateSource_GENERATE_SOURCE_NONE, "leak\n", 0), nil
		},
		"unspecified": func(*pb.GenerateRequest) (*pb.GenerateReply, error) {
			return terminalReply(0, "leak\n", 0), nil
		},
		"missing body": func(*pb.GenerateRequest) (*pb.GenerateReply, error) {
			return &pb.GenerateReply{Source: pb.GenerateSource_GENERATE_SOURCE_AI, GenerationId: "gen-1"}, nil
		},
		"nil reply": func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return nil, nil },
		"reply with error": func(*pb.GenerateRequest) (*pb.GenerateReply, error) {
			return aiReply("leak\n"), errors.New("boom")
		},
	} {
		f := swapServer(t, gen, lookupMiss)
		r := commandReply("g", "whoami")
		if r.Output != "root\r\n" || r.Source != "" || r.GenerationID != "" {
			t.Errorf("%s: got %+v", name, r)
		}
		if _, l := f.counts(); l != 1 {
			t.Errorf("%s: authored lookup calls %d, want 1", name, l)
		}
	}
}

// After a slow generate call the authored lookup uses the short deadline so a
// degraded server costs one generate budget plus a short lookup.
func TestCommandReplyDegradedLookupDeadline(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want time.Duration
	}{
		"deadline":      {context.DeadlineExceeded, shellai.DegradedLookupTimeout},
		"unavailable":   {status.Error(codes.Unavailable, "down"), shellai.DegradedLookupTimeout},
		"unimplemented": {persistence.ErrUnimplemented, shellai.LookupTimeout},
		"other":         {errors.New("boom"), shellai.LookupTimeout},
	} {
		f := swapServer(t, func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return nil, tc.err }, lookupMiss)
		commandReply("g", "whoami")
		if len(f.withins) != 1 || f.withins[0] != tc.want {
			t.Errorf("%s: lookup deadlines %v, want [%v]", name, f.withins, tc.want)
		}
	}
	f := swapServer(t, noneReply, lookupMiss)
	commandReply("g", "whoami")
	if f.withins[0] != shellai.LookupTimeout {
		t.Fatalf("NONE: lookup deadline %v, want %v", f.withins[0], shellai.LookupTimeout)
	}
}

func TestCommandReplyOversizedInputNeverForwarded(t *testing.T) {
	f := swapServer(t, func(*pb.GenerateRequest) (*pb.GenerateReply, error) { return aiReply("X"), nil },
		func(*pb.CommandRequest) (*pb.CommandResponse, error) {
			return &pb.CommandResponse{Response: "X", Matched: true}, nil
		})
	long := strings.Repeat("a", maxServerLookupLen+1)
	if r := commandReply("g", long); r.Output != "-sh: "+long+": not found\r\n" {
		t.Fatalf("oversized input: %.40q", r.Output)
	}
	if g, l := f.counts(); g != 0 || l != 0 {
		t.Fatalf("oversized input forwarded: generate=%d lookup=%d", g, l)
	}
}

// With a server that predates GenerateResponse and no authored rows, every
// static command answers exactly as before AI existed.
func TestLegacyBehaviourUnchangedWhenUnimplemented(t *testing.T) {
	swapServer(t, unimplemented, lookupMiss)
	for input, want := range map[string]string{
		"uname":             "Linux\r\n",
		"uname -a":          "Linux device 4.14.151 #1 SMP Tue Nov 5 12:38:07 UTC 2024 armv7l GNU/Linux\r\n",
		"ls":                "bin      etc      lib      proc     sys      usr\r\ndev      home     mnt      root     tmp      var\r\n",
		"cat /etc/passwd":   "root:x:0:0:root:/root:/bin/sh\r\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\r\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\r\n",
		"cat /proc/mounts":  "rootfs / rootfs rw 0 0\r\nproc /proc proc rw,nosuid,nodev,noexec 0 0\r\nsysfs /sys sysfs rw,nosuid,nodev,noexec 0 0\r\ntmpfs /tmp tmpfs rw,nosuid,nodev 0 0\r\n",
		"cat /proc/cpuinfo": "processor\t: 0\r\nmodel name\t: ARMv7 Processor rev 4 (v7l)\r\nBogoMIPS\t: 38.40\r\nHardware\t: Generic DT based system\r\n",
		"cat /nope":         "cat: /nope: No such file or directory\r\n",
		"cat":               "",
		"id":                "uid=0(root) gid=0(root) groups=0(root)\r\n",
		"whoami":            "root\r\n",
		"pwd":               "/root\r\n",
		"cd /tmp":           "",
		"echo hello world":  "hello world\r\n",
		"wget":              "wget: missing URL\r\n",
		"wget http://x/a":   "Connecting to http://x/a... connection timed out.\r\n",
		"curl":              "curl: no URL specified\r\n",
		"curl http://x/a":   "curl: (28) Connection timed out after 10000 milliseconds\r\n",
		"tftp -g x":         "tftp: timeout\r\n",
		"busybox":           "BusyBox v1.30.1 () multi-call binary.\r\nCurrently defined functions:\r\n\tcat, cp, echo, grep, id, ifconfig, kill, ls, mkdir, mount,\r\n\tmv, ps, pwd, rm, sh, telnet, tftp, top, uname, wget\r\n",
		"sh -c id":          "",
		"enable":            "",
		"ps aux":            "-sh: ps: not found\r\n",
		"/bin/busybox":      "-sh: /bin/busybox: not found\r\n",
		"/bin/busybox ABC":  "ABC: applet not found\r\n",
	} {
		r := commandReply("g", input)
		if r.Output != want || r.Exit || r.Source != "" || r.GenerationID != "" {
			t.Errorf("%q: got %+v, want %q", input, r, want)
		}
	}
}

func TestExecuteBusyBoxAppletProbe(t *testing.T) {
	swapServer(t, unimplemented, lookupMiss)
	for _, marker := range []string{"HISILICON", "STC", "BOTNET", "rotating-probe-42"} {
		input := "/bin/busybox " + marker
		want := marker + ": applet not found\r\n"
		if r := commandReply("g", input); r.Output != want || r.Exit {
			t.Errorf("commandReply(%q) = %+v; want %q", input, r, want)
		}
	}
}

func TestPrintableAppletNameBoundsUntrustedOutput(t *testing.T) {
	name := strings.Repeat("a", 200) + "\x00\n"
	got := printableAppletName(name)
	if len(got) != 128 {
		t.Fatalf("printableAppletName length = %d, want 128", len(got))
	}
	if strings.ContainsAny(got, "\x00\r\n") {
		t.Fatalf("printableAppletName contains control characters: %q", got)
	}
}
