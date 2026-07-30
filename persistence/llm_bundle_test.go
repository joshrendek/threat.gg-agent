package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type llmBundleClient struct {
	proto.HoneypotClient
	deadline chan time.Duration
	auth     chan string
	reply    *proto.LlmBundleReply
	err      error
	known    chan string
}

func (c llmBundleClient) GetLlmBundle(ctx context.Context, in *proto.LlmBundleRequest, opts ...grpc.CallOption) (*proto.LlmBundleReply, error) {
	if c.deadline != nil {
		if deadline, ok := ctx.Deadline(); ok {
			c.deadline <- time.Until(deadline)
		} else {
			c.deadline <- time.Duration(1<<63 - 1)
		}
	}
	if c.auth != nil {
		md, _ := metadata.FromOutgoingContext(ctx)
		values := md.Get("authorization")
		if len(values) == 0 {
			c.auth <- ""
		} else {
			c.auth <- values[0]
		}
	}
	if c.known != nil {
		c.known <- in.GetKnownVersion()
	}
	return c.reply, c.err
}

func withClient(t *testing.T, client proto.HoneypotClient) {
	t.Helper()
	original := honeypotClient
	honeypotClient = client
	t.Cleanup(func() { honeypotClient = original })
}

// TestGetLlmBundleWithoutAClientIsACleanError, not a panic. The poller starts from
// main.go after persistence.Setup, but a unit test or a startup-order change must get
// an error it can fail open on rather than take the process down.
func TestGetLlmBundleWithoutAClientIsACleanError(t *testing.T) {
	withClient(t, nil)
	reply, err := GetLlmBundle(&proto.LlmBundleRequest{})
	if err == nil {
		t.Fatal("want an error when the client is not connected")
	}
	if reply != nil {
		t.Fatalf("want a nil reply, got %#v", reply)
	}
}

// TestGetLlmBundleIsBounded: this call runs on a background goroutine, but an
// unbounded one against a hung server would pin that goroutine until the process
// restarts and the node would silently stop refreshing its corpus -- the exact
// invisible-staleness failure the PRD's bundle-version visibility exists to catch.
func TestGetLlmBundleIsBounded(t *testing.T) {
	deadlines := make(chan time.Duration, 1)
	withClient(t, llmBundleClient{deadline: deadlines, err: context.DeadlineExceeded})

	original := llmBundleTimeout
	llmBundleTimeout = 250 * time.Millisecond
	t.Cleanup(func() { llmBundleTimeout = original })

	if _, err := GetLlmBundle(&proto.LlmBundleRequest{}); err == nil {
		t.Fatal("want the transport error to propagate")
	}
	remaining := <-deadlines
	if remaining <= 0 || remaining > llmBundleTimeout {
		t.Fatalf("deadline remaining = %v, want (0, %v]", remaining, llmBundleTimeout)
	}
	if original != 10*time.Second {
		t.Fatalf("default llmBundleTimeout = %v, want 10s", original)
	}
}

// TestGetLlmBundleSendsTheAPIKey: the corpus is operational configuration, not public
// data, and the server puts GetLlmBundle behind the same authUnaryInterceptor as every
// other RPC. Riding the existing authenticated channel is why the PRD chose gRPC over
// a second HTTP surface, so the metadata actually being attached is load-bearing.
func TestGetLlmBundleSendsTheAPIKey(t *testing.T) {
	auth := make(chan string, 1)
	withClient(t, llmBundleClient{auth: auth, reply: &proto.LlmBundleReply{Unchanged: true}})

	if _, err := GetLlmBundle(&proto.LlmBundleRequest{}); err != nil {
		t.Fatal(err)
	}
	// connMetadata is built from API_KEY at package init; the assertion is that the
	// same metadata every other call carries is attached here too.
	want := connMetadata.Get("authorization")
	got := <-auth
	if len(want) == 0 {
		if got != "" {
			t.Fatalf("authorization = %q with no API_KEY set", got)
		}
		return
	}
	if got != want[0] {
		t.Fatalf("authorization = %q, want %q", got, want[0])
	}
}

// TestGetLlmBundleReturnsNoUpdateNotAnEmptyBundle. A transport failure must be
// distinguishable from "the corpus is now empty": the first keeps the last-good
// ruleset, the second would drop it fleet-wide. This layer therefore never
// manufactures a reply.
func TestGetLlmBundleReturnsNoUpdateNotAnEmptyBundle(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"internal", status.Error(codes.Internal, "llm bundle lookup failed")},
		{"unimplemented", status.Error(codes.Unimplemented, "unknown method")},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad key")},
		{"deadline", context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withClient(t, llmBundleClient{err: tc.err})
			reply, err := GetLlmBundle(&proto.LlmBundleRequest{KnownVersion: "v1"})
			if err == nil {
				t.Fatal("want the error to propagate so the caller keeps its bundle")
			}
			if reply != nil {
				t.Fatalf("want a nil reply, got %#v", reply)
			}
			// The gRPC status code must survive, or the poller cannot tell an old server
			// (Unimplemented, expected) from a real failure (an error loop).
			if status.Code(err) != status.Code(tc.err) {
				t.Fatalf("status code = %v, want %v", status.Code(err), status.Code(tc.err))
			}
		})
	}
}

func TestGetLlmBundleForwardsTheKnownVersionAndReply(t *testing.T) {
	known := make(chan string, 1)
	want := &proto.LlmBundleReply{Version: "v2", Rules: []*proto.LlmPromptRule{{Id: "x"}}}
	withClient(t, llmBundleClient{known: known, reply: want})

	got, err := GetLlmBundle(&proto.LlmBundleRequest{KnownVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if sent := <-known; sent != "v1" {
		t.Fatalf("known_version = %q, want v1", sent)
	}
	if got != want {
		t.Fatalf("reply = %#v, want it passed through untouched", got)
	}
}
