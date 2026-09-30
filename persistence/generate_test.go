package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// unimplementedClient embeds the generated client interface so only the method
// under test needs a body; any other call panics on the nil embedded interface.
type unimplementedClient struct {
	proto.HoneypotClient
	calls int
}

func (c *unimplementedClient) GenerateResponse(context.Context, *proto.GenerateRequest, ...grpc.CallOption) (*proto.GenerateReply, error) {
	c.calls++
	return nil, status.Error(codes.Unimplemented, "unknown method GenerateResponse")
}

type okGenerateClient struct {
	proto.HoneypotClient
	deadline time.Time
	hasDl    bool
}

func (c *okGenerateClient) GenerateResponse(ctx context.Context, _ *proto.GenerateRequest, _ ...grpc.CallOption) (*proto.GenerateReply, error) {
	c.deadline, c.hasDl = ctx.Deadline()
	return &proto.GenerateReply{
		Source: proto.GenerateSource_GENERATE_SOURCE_AI,
		Body:   &proto.GenerateReply_Terminal{Terminal: &proto.Terminal{Stdout: "x\n", Hostname: "h", Cwd: "/"}},
	}, nil
}

type failingGenerateClient struct {
	proto.HoneypotClient
	calls int
	err   error
}

func (c *failingGenerateClient) GenerateResponse(context.Context, *proto.GenerateRequest, ...grpc.CallOption) (*proto.GenerateReply, error) {
	c.calls++
	return nil, c.err
}

func restoreGenerateState(t *testing.T) {
	t.Helper()
	oldClient, oldNow := honeypotClient, generateNow
	resetUnimplemented()
	t.Cleanup(func() {
		honeypotClient, generateNow = oldClient, oldNow
		resetUnimplemented()
	})
}

func TestGenerateResponseMemoizesUnimplemented(t *testing.T) {
	restoreGenerateState(t)
	c := &unimplementedClient{}
	honeypotClient = c
	now := time.Now()
	generateNow = func() time.Time { return now }
	req := &proto.GenerateRequest{Guid: "g", Protocol: "ssh", Input: "id"}

	if _, err := GenerateResponse(req, time.Second); err != ErrUnimplemented || c.calls != 1 {
		t.Fatalf("first call: want ErrUnimplemented with 1 call, got err=%v calls=%d", err, c.calls)
	}
	if _, err := GenerateResponse(req, time.Second); err != ErrUnimplemented || c.calls != 1 {
		t.Fatalf("second call must be served from the memo: calls=%d err=%v", c.calls, err)
	}
	now = now.Add(6 * time.Minute)
	if _, err := GenerateResponse(req, time.Second); err != ErrUnimplemented || c.calls != 2 {
		t.Fatalf("memo must expire after 5 minutes: calls=%d err=%v", c.calls, err)
	}
}

func TestGenerateResponseOtherErrorsBypassMemo(t *testing.T) {
	restoreGenerateState(t)
	c := &failingGenerateClient{err: status.Error(codes.Unavailable, "down")}
	honeypotClient = c
	req := &proto.GenerateRequest{}
	for i := 1; i <= 2; i++ {
		_, err := GenerateResponse(req, time.Second)
		if err == nil || err == ErrUnimplemented || status.Code(err) != codes.Unavailable {
			t.Fatalf("want unchanged Unavailable error, got %v", err)
		}
		if c.calls != i {
			t.Fatalf("non-Unimplemented errors must not memoize: calls=%d want %d", c.calls, i)
		}
	}
}

func TestGenerateResponseSetsDeadlineAndReturnsReply(t *testing.T) {
	restoreGenerateState(t)
	c := &okGenerateClient{}
	honeypotClient = c
	within := 3 * time.Second
	start := time.Now()
	r, err := GenerateResponse(&proto.GenerateRequest{Guid: "g", Protocol: "ssh", Input: "id"}, within)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.GetSource() != proto.GenerateSource_GENERATE_SOURCE_AI || r.GetTerminal().GetStdout() != "x\n" {
		t.Fatalf("reply not returned intact: %v", r)
	}
	if !c.hasDl {
		t.Fatal("call must carry a deadline")
	}
	if got := c.deadline.Sub(start); got > within+time.Second {
		t.Fatalf("deadline %v exceeds within=%v", got, within)
	}
}

func TestGenerateResponseNilClient(t *testing.T) {
	restoreGenerateState(t)
	honeypotClient = nil
	if _, err := GenerateResponse(&proto.GenerateRequest{}, time.Second); err == nil {
		t.Fatal("nil client must error, not panic")
	}
}

func TestGenerateResponseNonPositiveWithin(t *testing.T) {
	restoreGenerateState(t)
	c := &okGenerateClient{}
	honeypotClient = c
	if _, err := GenerateResponse(&proto.GenerateRequest{}, 0); err == nil || c.hasDl {
		t.Fatalf("within<=0 must error without calling the client: err=%v", err)
	}
}
