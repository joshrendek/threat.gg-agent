package persistence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// blockingClient stands in for a stalled gRPC server: the calls the honeypots make block
// until their context is cancelled. Every other method is inherited (and unused) from the
// embedded nil interface.
type blockingClient struct {
	proto.HoneypotClient
}

type deadlineInspectingClient struct {
	proto.HoneypotClient
	remaining chan time.Duration
}

func (c deadlineInspectingClient) GetCommandResponse(ctx context.Context, in *proto.CommandRequest, opts ...grpc.CallOption) (*proto.CommandResponse, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		c.remaining <- time.Duration(1<<63 - 1)
	} else {
		c.remaining <- time.Until(deadline)
	}
	return nil, context.DeadlineExceeded
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

func (blockingClient) SaveS3Request(ctx context.Context, in *proto.S3Request, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveLmstudio(ctx context.Context, in *proto.LlmRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveMssqlLogin(ctx context.Context, in *proto.MssqlRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveKubeletRequest(ctx context.Context, in *proto.KubeletRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveConsulRequest(ctx context.Context, in *proto.ConsulRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingClient) SaveQuery(ctx context.Context, in *proto.QueryRequest, opts ...grpc.CallOption) (*proto.SaveReply, error) {
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
		{"s3", func() error { return SaveS3Request(&proto.S3Request{}) }},
		{"lmstudio", func() error { return SaveLmstudioRequest(&proto.LlmRequest{}) }},
		{"mssql-login", func() error { return SaveMssqlLogin(&proto.MssqlRequest{}) }},
		{"kubelet", func() error { return SaveKubeletRequest(&proto.KubeletRequest{}) }},
		{"consul", func() error { return SaveConsulRequest(&proto.ConsulRequest{}) }},
		{"sql-query", func() error { return SaveQuery(&proto.QueryRequest{}) }},
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

func TestSaveS3RequestIsNoOpWithoutClient(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = nil
	require.NoError(t, SaveS3Request(&proto.S3Request{}))
}

func TestSaveLmstudioRequestIsNoOpWithoutClient(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = nil
	require.NoError(t, SaveLmstudioRequest(&proto.LlmRequest{}))
}

func TestSaveMssqlCallsAreNoOpWithoutClient(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = nil
	require.NoError(t, SaveMssqlLogin(&proto.MssqlRequest{}))
	require.NoError(t, SaveQuery(&proto.QueryRequest{}))
}

func TestSaveKubeletRequestIsNoOpWithoutClient(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = nil
	require.NoError(t, SaveKubeletRequest(&proto.KubeletRequest{}))
}

func TestSaveConsulRequestIsNoOpWithoutClient(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = nil
	require.NoError(t, SaveConsulRequest(&proto.ConsulRequest{}))
}

func TestGetCommandResponseWithinHonorsConcurrentShortDeadlines(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })

	const callers = 16
	remaining := make(chan time.Duration, callers)
	honeypotClient = deadlineInspectingClient{remaining: remaining}
	var wg sync.WaitGroup
	errorsSeen := make(chan error, callers)
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

	for err := range errorsSeen {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lookup error = %v, want context deadline exceeded", err)
		}
	}
	close(remaining)
	for duration := range remaining {
		if duration > 100*time.Millisecond {
			t.Fatalf("context deadline remaining = %v, want the requested 25ms bound", duration)
		}
	}
}

func TestGetCommandResponseWithinCancelsStalledRPC(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = blockingClient{}

	done := make(chan error, 1)
	go func() {
		_, err := GetCommandResponseWithin(&proto.CommandRequest{}, 25*time.Millisecond)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lookup error = %v, want context deadline exceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled lookup ignored its short context deadline")
	}
}

func TestGetCommandResponseWithinRejectsNonPositiveDeadline(t *testing.T) {
	originalClient := honeypotClient
	t.Cleanup(func() { honeypotClient = originalClient })
	honeypotClient = blockingClient{}

	for _, timeout := range []time.Duration{0, -time.Millisecond} {
		if _, err := GetCommandResponseWithin(&proto.CommandRequest{}, timeout); err == nil {
			t.Fatalf("timeout %v: expected validation error", timeout)
		}
	}
}
