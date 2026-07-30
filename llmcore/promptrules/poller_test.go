package promptrules

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testPoller wires a Poller to in-memory fakes so nothing touches gRPC and nothing
// touches the package-level bundle pointer.
type testPoller struct {
	*Poller
	mu       sync.Mutex
	stored   []*Bundle
	requests []string
	held     *Bundle
}

func newTestPoller(get func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error)) *testPoller {
	tp := &testPoller{}
	tp.Poller = &Poller{
		Get: func(in *proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
			tp.mu.Lock()
			tp.requests = append(tp.requests, in.GetKnownVersion())
			tp.mu.Unlock()
			return get(in)
		},
		Store: func(b *Bundle) {
			tp.mu.Lock()
			tp.stored = append(tp.stored, b)
			tp.held = b
			tp.mu.Unlock()
		},
		Held: func() *Bundle {
			tp.mu.Lock()
			defer tp.mu.Unlock()
			return tp.held
		},
	}
	return tp
}

func (tp *testPoller) snapshot() (stored []*Bundle, requests []string, held *Bundle) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return append([]*Bundle(nil), tp.stored...), append([]string(nil), tp.requests...), tp.held
}

func replyWith(version string, rules ...*proto.LlmPromptRule) *proto.LlmBundleReply {
	return &proto.LlmBundleReply{Version: version, Rules: rules}
}

func TestPollLoadsAndThenSendsTheHeldVersionAsTheETag(t *testing.T) {
	tp := newTestPoller(func(in *proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		if in.GetKnownVersion() == "v1" {
			return &proto.LlmBundleReply{Version: "v1", Unchanged: true}, nil
		}
		return replyWith("v1", rule(id(1), MatchContains, "probe")), nil
	})

	if got := tp.pollOnce(); got != outcomeUpdated {
		t.Fatalf("first poll = %v, want updated", got)
	}
	if got := tp.pollOnce(); got != outcomeUnchanged {
		t.Fatalf("second poll = %v, want unchanged", got)
	}
	stored, requests, held := tp.snapshot()
	if len(stored) != 1 {
		t.Fatalf("stored %d bundles, want 1: an unchanged poll must not rebuild", len(stored))
	}
	if held.Version() != "v1" || held.Len() != 1 {
		t.Fatalf("held bundle = version %q, %d rules", held.Version(), held.Len())
	}
	if len(requests) != 2 || requests[0] != "" || requests[1] != "v1" {
		t.Fatalf("known_version sequence = %v, want [\"\", \"v1\"]", requests)
	}
}

// TestFailedPullKeepsTheLastGoodBundle. Every failure mode means "I learned
// nothing", never "the corpus is now empty" -- an empty bundle on a transport error
// would turn a control-plane blip into a fleet-wide behaviour change.
func TestFailedPullKeepsTheLastGoodBundle(t *testing.T) {
	failures := []struct {
		name  string
		reply *proto.LlmBundleReply
		err   error
		want  outcome
	}{
		{name: "transport error", err: errors.New("connection refused"), want: outcomeFailed},
		{name: "deadline exceeded", err: status.Error(codes.DeadlineExceeded, "timeout"), want: outcomeFailed},
		{name: "server internal error", err: status.Error(codes.Internal, "llm bundle lookup failed"), want: outcomeFailed},
		{name: "unauthenticated", err: status.Error(codes.Unauthenticated, "nope"), want: outcomeFailed},
		{name: "nil reply with no error", want: outcomeFailed},
		{name: "unimplemented (old server)", err: status.Error(codes.Unimplemented, "unknown method"), want: outcomeUnsupported},
	}
	for _, tc := range failures {
		t.Run(tc.name, func(t *testing.T) {
			first := true
			tp := newTestPoller(func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
				if first {
					first = false
					return replyWith("good", rule(id(1), MatchContains, "probe", replyText("last good"))), nil
				}
				return tc.reply, tc.err
			})
			if got := tp.pollOnce(); got != outcomeUpdated {
				t.Fatalf("seed poll = %v", got)
			}
			if got := tp.pollOnce(); got != tc.want {
				t.Fatalf("failing poll = %v, want %v", got, tc.want)
			}
			stored, _, held := tp.snapshot()
			if len(stored) != 1 {
				t.Fatalf("a failed pull stored %d bundles; it must store none", len(stored)-1)
			}
			if held.Version() != "good" || held.Len() != 1 {
				t.Fatal("the last-good bundle was disturbed by a failed pull")
			}
			if got := held.Matcher().Match(StagePreBuiltin, "probe"); got == nil || got.ReplyText != "last good" {
				t.Fatal("the last-good bundle stopped answering after a failed pull")
			}
		})
	}
}

// TestNeverSuccessfulPollYieldsTheCompiledFloor: a node that can never reach the
// control plane holds no bundle, and no bundle is the compiled floor.
func TestNeverSuccessfulPollYieldsTheCompiledFloor(t *testing.T) {
	tp := newTestPoller(func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		return nil, errors.New("connection refused")
	})
	for i := 0; i < 5; i++ {
		if got := tp.pollOnce(); got != outcomeFailed {
			t.Fatalf("poll %d = %v", i, got)
		}
	}
	stored, requests, held := tp.snapshot()
	if len(stored) != 0 || held != nil {
		t.Fatal("a never-successful poller must never store a bundle")
	}
	for i, known := range requests {
		if known != "" {
			t.Fatalf("request %d carried known_version %q with no bundle held", i, known)
		}
	}
	// And a nil bundle is inert rather than fatal.
	if held.Matcher().Match(StagePreBuiltin, "anything") != nil || held.BuiltinDisabled(BuiltinEchoLiteral) {
		t.Fatal("the compiled floor is not inert")
	}
}

// TestUnimplementedIsNotAnErrorLoop: a new agent against an old server is a normal,
// expected deployment state, so it must be logged once and then be quiet.
func TestUnimplementedIsNotAnErrorLoop(t *testing.T) {
	tp := newTestPoller(func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		return nil, status.Error(codes.Unimplemented, "unknown method GetLlmBundle")
	})
	for i := 0; i < 3; i++ {
		if got := tp.pollOnce(); got != outcomeUnsupported {
			t.Fatalf("poll %d = %v, want unsupported", i, got)
		}
	}
	if !tp.loggedUnsupported {
		t.Fatal("the unsupported notice was never emitted")
	}
	stored, _, _ := tp.snapshot()
	if len(stored) != 0 {
		t.Fatal("an old server must not produce a bundle")
	}
}

// TestAPanickingTransportIsRecoveredAndRetried. The poll goroutine shares a process
// with 28 honeypots; an unexpected panic in an optional control-plane refresh must
// cost the corpus update and nothing else.
func TestAPanickingTransportIsRecoveredAndRetried(t *testing.T) {
	calls := 0
	tp := newTestPoller(func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		calls++
		if calls == 1 {
			panic("client exploded")
		}
		return replyWith("v1", rule(id(1), MatchContains, "probe")), nil
	})

	if got := tp.safePollOnce(); got != outcomeFailed {
		t.Fatalf("panicking poll = %v, want failed", got)
	}
	if got := tp.safePollOnce(); got != outcomeUpdated {
		t.Fatalf("retry after a panic = %v, want updated", got)
	}
	if _, _, held := tp.snapshot(); held.Version() != "v1" {
		t.Fatal("the retry did not load the bundle")
	}
}

func TestAnOversizedBundleIsRefusedNotTruncated(t *testing.T) {
	rules := make([]*proto.LlmPromptRule, 0, MaxBundleRules+1)
	for i := 0; i <= MaxBundleRules; i++ {
		rules = append(rules, rule(id(i), MatchExact, "probe "+id(i)))
	}
	tp := newTestPoller(func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		return replyWith("huge", rules...), nil
	})
	if got := tp.pollOnce(); got != outcomeFailed {
		t.Fatalf("oversized bundle poll = %v, want failed", got)
	}
	if stored, _, _ := tp.snapshot(); len(stored) != 0 {
		t.Fatal("an oversized bundle must not be stored, not even partially")
	}
}

func TestPollIntervalAndJitterBounds(t *testing.T) {
	// The production zero value: 5 minutes +-60 s, never outside that window.
	p := &Poller{}
	for i := 0; i < 2000; i++ {
		got := p.nextInterval()
		if got < DefaultPollInterval-DefaultPollJitter || got > DefaultPollInterval+DefaultPollJitter {
			t.Fatalf("interval %v outside [%v, %v]", got,
				DefaultPollInterval-DefaultPollJitter, DefaultPollInterval+DefaultPollJitter)
		}
	}

	// The jitter genuinely spreads: a fleet-wide change must not stampede. Both
	// extremes are reachable, which is what says the span is [-jitter, +jitter].
	lowest := &Poller{Rand: func(int64) int64 { return 0 }}
	if got := lowest.nextInterval(); got != DefaultPollInterval-DefaultPollJitter {
		t.Fatalf("lowest interval = %v", got)
	}
	highest := &Poller{Rand: func(n int64) int64 { return n - 1 }}
	if got := highest.nextInterval(); got != DefaultPollInterval+DefaultPollJitter {
		t.Fatalf("highest interval = %v", got)
	}

	// An explicit interval with no jitter is exact, so timing tests are deterministic.
	if got := (&Poller{Interval: 10 * time.Millisecond}).nextInterval(); got != 10*time.Millisecond {
		t.Fatalf("explicit interval = %v", got)
	}
	// Jitter wider than the interval is clamped so the result stays positive.
	clamped := &Poller{Interval: time.Second, Jitter: time.Hour, Rand: func(int64) int64 { return 0 }}
	if got := clamped.nextInterval(); got <= 0 {
		t.Fatalf("clamped interval = %v, want positive", got)
	}
}

func TestRunPollsImmediatelyAndStopsOnContextCancel(t *testing.T) {
	polls := make(chan struct{}, 8)
	tp := newTestPoller(func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		select {
		case polls <- struct{}{}:
		default:
		}
		return replyWith("v1", rule(id(1), MatchContains, "probe")), nil
	})
	tp.Interval = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tp.Run(ctx)
		close(done)
	}()

	// A restarting honeypot must not serve the compiled floor for a full interval when
	// a corpus is sitting there waiting for it, so the first poll is immediate.
	select {
	case <-polls:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("Run did not poll immediately")
	}
	// And it keeps polling.
	select {
	case <-polls:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("Run did not poll again")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// TestGetLlmBundleSeamIsInjectable mirrors cmdresp.GetCommandResponse: the gRPC call
// must be replaceable so the failure paths are testable without a live server.
func TestGetLlmBundleSeamIsInjectable(t *testing.T) {
	original := GetLlmBundle
	t.Cleanup(func() { GetLlmBundle = original })

	called := false
	GetLlmBundle = func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		called = true
		return &proto.LlmBundleReply{Version: "seam", Unchanged: true}, nil
	}
	// A Poller with no Get set falls back to the package seam.
	p := &Poller{Store: func(*Bundle) { t.Error("unchanged must not store") }, Held: func() *Bundle { return nil }}
	if got := p.pollOnce(); got != outcomeUnchanged {
		t.Fatalf("poll = %v", got)
	}
	if !called {
		t.Fatal("the package-level GetLlmBundle seam was not used")
	}
}

// TestDefaultStoreAndHeldUseThePackagePointer covers the production wiring: an
// unconfigured Poller reads and writes the atomic pointer llmcore serves from.
func TestDefaultStoreAndHeldUseThePackagePointer(t *testing.T) {
	t.Cleanup(func() { Store(nil) })
	Store(nil)

	original := GetLlmBundle
	t.Cleanup(func() { GetLlmBundle = original })
	GetLlmBundle = func(in *proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
		if in.GetKnownVersion() == "prod" {
			return &proto.LlmBundleReply{Version: "prod", Unchanged: true}, nil
		}
		return replyWith("prod", rule(id(1), MatchContains, "probe")), nil
	}

	p := &Poller{}
	if got := p.pollOnce(); got != outcomeUpdated {
		t.Fatalf("poll = %v", got)
	}
	if Current().Version() != "prod" {
		t.Fatalf("Current().Version() = %q", Current().Version())
	}
	if got := p.pollOnce(); got != outcomeUnchanged {
		t.Fatalf("second poll = %v; Held must report the stored version as the ETag", got)
	}
}
