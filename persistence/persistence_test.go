package persistence

import (
	"context"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc"
)

// blockingClient stands in for a stalled gRPC server: the calls the honeypots make block
// until their context is cancelled. Every other method is inherited (and unused) from the
// embedded nil interface.
type blockingClient struct {
	proto.HoneypotClient
}

func (blockingClient) SaveMemcachedConnect(ctx context.Context, in *proto.MemcachedConnectRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveMemcachedCommand(ctx context.Context, in *proto.MemcachedCommandRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestSaveMemcachedIsTimeBounded is the regression for finding 5: a fire-and-forget
// persistence call against a stalled server must return within the bounded timeout
// instead of blocking forever and letting goroutines/calls accumulate.
func TestSaveMemcachedIsTimeBounded(t *testing.T) {
	origClient, origTimeout := honeypotClient, saveTimeout
	t.Cleanup(func() { honeypotClient, saveTimeout = origClient, origTimeout })
	honeypotClient = blockingClient{}
	saveTimeout = 100 * time.Millisecond

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"connect", func() error { return SaveMemcachedConnect(&proto.MemcachedConnectRequest{}) }},
		{"command", func() error { return SaveMemcachedCommand(&proto.MemcachedCommandRequest{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan error, 1)
			start := time.Now()
			go func() { done <- tc.call() }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expected a deadline error from the stalled server, got nil")
				}
				if elapsed := time.Since(start); elapsed > 2*time.Second {
					t.Fatalf("call took %v, want bounded near saveTimeout", elapsed)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("call did not return; persistence is not time-bounded")
			}
		})
	}
}
