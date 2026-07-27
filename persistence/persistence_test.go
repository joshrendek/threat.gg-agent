package persistence

import (
	"context"
	"errors"
	"sync"
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

func (blockingClient) SaveVllm(ctx context.Context, in *proto.LlmRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveOllama(ctx context.Context, in *proto.LlmRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveRay(ctx context.Context, in *proto.LlmRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveLocalai(ctx context.Context, in *proto.LlmRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveLlamacpp(ctx context.Context, in *proto.LlmRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveComfyui(ctx context.Context, in *proto.LlmRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) GetCommandResponse(ctx context.Context, in *proto.CommandRequest, opts ...grpc.CallOption) (*proto.CommandResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestAsynchronousSaveCallsAreTimeBounded ensures a stalled gRPC server cannot
// retain fire-and-forget capture goroutines or their request buffers indefinitely.
func TestAsynchronousSaveCallsAreTimeBounded(t *testing.T) {
	origClient, origTimeout := honeypotClient, saveTimeout
	t.Cleanup(func() { honeypotClient, saveTimeout = origClient, origTimeout })
	honeypotClient = blockingClient{}
	saveTimeout = 100 * time.Millisecond

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"vllm", func() error { return SaveVllmRequest(&proto.LlmRequest{}) }},
		{"ollama", func() error { return SaveOllamaRequest(&proto.LlmRequest{}) }},
		{"ray", func() error { return SaveRayRequest(&proto.LlmRequest{}) }},
		{"localai", func() error { return SaveLocalaiRequest(&proto.LlmRequest{}) }},
		{"llamacpp", func() error { return SaveLlamacppRequest(&proto.LlmRequest{}) }},
		{"comfyui", func() error { return SaveComfyuiRequest(&proto.LlmRequest{}) }},
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

func TestGetCommandResponseWithinHonorsConcurrentShortDeadlines(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = blockingClient{}

	const callers = 16
	var wg sync.WaitGroup
	errorsSeen := make(chan error, callers)
	started := time.Now()
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := GetCommandResponseWithin(&proto.CommandRequest{
				CommandType: "ollama",
				Command:     "GET /api/tags",
			}, 25*time.Millisecond)
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(errorsSeen)

	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("%d concurrent lookups took %v, want fail-open near the shared short deadline", callers, elapsed)
	}
	for err := range errorsSeen {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lookup error = %v, want context deadline exceeded", err)
		}
	}
}

func TestGetCommandResponseWithinRejectsNonPositiveDeadline(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = blockingClient{}

	for _, timeout := range []time.Duration{0, -time.Millisecond} {
		started := time.Now()
		if _, err := GetCommandResponseWithin(&proto.CommandRequest{}, timeout); err == nil {
			t.Fatalf("timeout %v: expected validation error", timeout)
		}
		if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
			t.Fatalf("timeout %v: validation took %v, want immediate failure", timeout, elapsed)
		}
	}
}
