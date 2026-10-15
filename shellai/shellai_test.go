package shellai

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func terminal(source proto.GenerateSource, stdout string, code int32) *proto.GenerateReply {
	return &proto.GenerateReply{Source: source, GenerationId: "gen-1",
		Body: &proto.GenerateReply_Terminal{Terminal: &proto.Terminal{Stdout: stdout, ExitCode: code, Cwd: "/root", Hostname: "dvr"}}}
}

func fixed(reply *proto.GenerateReply, err error) Generate {
	return func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) { return reply, err }
}

func TestAskSendsRequestWithBudget(t *testing.T) {
	var got *proto.GenerateRequest
	var within time.Duration
	out, err := Ask(func(in *proto.GenerateRequest, w time.Duration) (*proto.GenerateReply, error) {
		got, within = in, w
		return terminal(proto.GenerateSource_GENERATE_SOURCE_AI, "x\n", 0), nil
	}, "telnet", "g", "ps")
	if err != nil || !out.Answered {
		t.Fatalf("want answered, got %+v %v", out, err)
	}
	if got.Protocol != "telnet" || got.Guid != "g" || got.Input != "ps" || got.DeadlineMs != 3000 || within != GenerateBudget {
		t.Fatalf("request %+v within %v", got, within)
	}
	if out.Stdout != "x\n" || out.Cwd != "/root" || out.Hostname != "dvr" || out.Source != "ai" || out.GenerationID != "gen-1" {
		t.Fatalf("outcome %+v", out)
	}
}

func TestAskAcceptMatrix(t *testing.T) {
	for name, tc := range map[string]struct {
		gen      Generate
		answered bool
		degraded bool
		source   string
		code     uint32
	}{
		"ai":            {fixed(terminal(proto.GenerateSource_GENERATE_SOURCE_AI, "x", 2), nil), true, false, "ai", 2},
		"ai_cached":     {fixed(terminal(proto.GenerateSource_GENERATE_SOURCE_AI_CACHED, "x", 0), nil), true, false, "ai_cached", 0},
		"local":         {fixed(terminal(proto.GenerateSource_GENERATE_SOURCE_LOCAL, "x", 1), nil), true, false, "local", 1},
		"exit too high": {fixed(terminal(proto.GenerateSource_GENERATE_SOURCE_AI, "x", 300), nil), true, false, "ai", 255},
		"exit negative": {fixed(terminal(proto.GenerateSource_GENERATE_SOURCE_AI, "x", -1), nil), true, false, "ai", 255},
		"none":          {fixed(&proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "x"}, nil), false, false, "", 0},
		"none+body":     {fixed(terminal(proto.GenerateSource_GENERATE_SOURCE_NONE, "leak", 0), nil), false, false, "", 0},
		"unspecified":   {fixed(terminal(0, "leak", 0), nil), false, false, "", 0},
		"missing body":  {fixed(&proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI}, nil), false, false, "", 0},
		"nil reply":     {fixed(nil, nil), false, false, "", 0},
		"unimplemented": {fixed(nil, persistence.ErrUnimplemented), false, false, "", 0},
		"error":         {fixed(nil, errors.New("boom")), false, false, "", 0},
		"slow":          {fixed(nil, context.DeadlineExceeded), false, true, "", 0},
		"unavailable":   {fixed(nil, status.Error(codes.Unavailable, "down")), false, true, "", 0},
		"reply+error":   {fixed(terminal(proto.GenerateSource_GENERATE_SOURCE_AI, "x", 0), errors.New("boom")), false, false, "", 0},
	} {
		out, _ := Ask(tc.gen, "telnet", "g", "ps")
		if out.Answered != tc.answered || out.Degraded != tc.degraded || out.Source != tc.source || out.ExitCode != tc.code {
			t.Errorf("%s: got %+v", name, out)
		}
		if !tc.answered && (out.Stdout != "" || out.GenerationID != "") {
			t.Errorf("%s: unanswered outcome leaked fields %+v", name, out)
		}
	}
}

func TestAskSkipsBlankInputAndNilGenerate(t *testing.T) {
	calls := 0
	gen := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		calls++
		return terminal(proto.GenerateSource_GENERATE_SOURCE_AI, "x", 0), nil
	}
	if out, _ := Ask(gen, "telnet", "g", " \t"); out.Answered || calls != 0 {
		t.Fatalf("blank input must not spend a generation: %+v calls=%d", out, calls)
	}
	if out, err := Ask(nil, "telnet", "g", "ps"); out.Answered || err != nil {
		t.Fatalf("nil generate: %+v %v", out, err)
	}
}

func TestIsServerSlow(t *testing.T) {
	for err, want := range map[error]bool{
		nil:                      false,
		context.DeadlineExceeded: true,
		fmt.Errorf("w: %w", context.DeadlineExceeded): true,
		status.Error(codes.DeadlineExceeded, "x"):     true,
		status.Error(codes.Unavailable, "x"):          true,
		status.Error(codes.Internal, "x"):             false,
		persistence.ErrUnimplemented:                  false,
		errors.New("other"):                           false,
	} {
		if got := IsServerSlow(err); got != want {
			t.Errorf("%v: got %v want %v", err, got, want)
		}
	}
}
