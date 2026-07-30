package promptrules

import (
	"context"
	"math/rand"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Poll cadence. PRD 034 specifies five minutes with +-60 s of jitter.
//
// The jitter is not politeness, it is the thing that keeps a hot corpus change from
// arriving as a synchronised fleet-wide thundering herd against one Postgres. The
// interval is not longer than five minutes because the interval IS the rollback
// window: "disable the rule in the admin UI and it is gone within one poll" is the
// property the whole PRD exists to buy, and every minute added here is a minute a
// bad rule keeps answering.
const (
	DefaultPollInterval = 5 * time.Minute
	DefaultPollJitter   = 60 * time.Second
)

// GetLlmBundle is the injectable seam over the gRPC call, mirroring
// cmdresp.GetCommandResponse. It exists so the matched / unchanged / error /
// Unimplemented paths are unit-testable without a live server -- and those paths,
// not the happy one, are where a control-plane outage either does or does not take
// 28 honeypots' worth of answers with it.
var GetLlmBundle = persistence.GetLlmBundle

// outcome describes what one poll did, for tests and for the log line.
type outcome int

const (
	outcomeUpdated outcome = iota
	outcomeUnchanged
	outcomeFailed
	// outcomeUnsupported is an old server that has no GetLlmBundle. It is a normal,
	// expected deployment state (PRD 034: "no ordered deploy required in either
	// direction"), not an error, and must not produce an error loop in the log.
	outcomeUnsupported
)

func (o outcome) String() string {
	switch o {
	case outcomeUpdated:
		return "updated"
	case outcomeUnchanged:
		return "unchanged"
	case outcomeUnsupported:
		return "unsupported"
	default:
		return "failed"
	}
}

// Poller refreshes the corpus in the background. Nothing it does is on the inference
// request path: ReplyFor reads an atomic pointer, and this goroutine is the only
// writer.
type Poller struct {
	// Interval and Jitter default to DefaultPollInterval / DefaultPollJitter.
	Interval time.Duration
	Jitter   time.Duration

	// Get defaults to the package-level GetLlmBundle seam.
	Get func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error)
	// Store defaults to the package-level Store, so a test can observe the swap
	// without touching the global bundle pointer.
	Store func(*Bundle)
	// Held returns the currently held bundle. Defaults to Current.
	Held func() *Bundle

	// Sleep defaults to a real timer honouring ctx. Injectable so the loop test does
	// not take five minutes.
	Sleep func(ctx context.Context, d time.Duration) bool
	// Rand returns a value in [0,n); defaults to math/rand.
	Rand func(n int64) int64

	// loggedUnsupported keeps the "this server has no GetLlmBundle" notice to one line
	// for the life of the process instead of one every five minutes forever.
	loggedUnsupported bool
}

// Start launches the corpus poller. Called once from main.go alongside the 15-minute
// updater loop and the 30-second checkin loop.
func Start() {
	go (&Poller{}).Run(context.Background())
}

// Run polls until ctx is cancelled. The first poll happens immediately -- a honeypot
// that has just restarted should not serve the compiled floor for five minutes when
// a corpus is sitting there waiting for it -- and subsequent polls are jittered.
func (p *Poller) Run(ctx context.Context) {
	for {
		p.safePollOnce()
		if !p.sleep(ctx, p.nextInterval()) {
			return
		}
	}
}

// safePollOnce is the recover() discipline PRD 034 requires, modelled on
// cmdresp.safeLLMOverrideLookup. This goroutine shares a process with 28 honeypots;
// an unexpected panic in an optional control-plane refresh must cost the corpus
// update and nothing else. The next tick retries.
func (p *Poller) safePollOnce() (result outcome) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Error().Interface("panic", rec).Msg("recovered panic polling the llm prompt-rule bundle")
			result = outcomeFailed
		}
	}()
	return p.pollOnce()
}

// pollOnce performs one version-gated refresh.
//
// Note what is NOT here: there is no path that reaches Store with an empty or
// partial bundle. A transport error, a nil reply, an Unimplemented server and an
// oversized corpus all return without storing, which leaves the last-good bundle (or
// the compiled floor) in place. That is the only correct reading of a failed pull:
// "I learned nothing", never "the corpus is now empty".
func (p *Poller) pollOnce() outcome {
	known := p.held().Version()
	reply, err := p.get()(&proto.LlmBundleRequest{KnownVersion: known})
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			if !p.loggedUnsupported {
				p.loggedUnsupported = true
				logger.Info().Msg("server does not serve llm prompt-rule bundles; using the compiled groups")
			}
			return outcomeUnsupported
		}
		logger.Warn().Err(err).Str("known_version", known).Msg("llm prompt-rule bundle poll failed; keeping the last-good bundle")
		return outcomeFailed
	}
	if reply == nil {
		logger.Warn().Msg("llm prompt-rule bundle poll returned no reply; keeping the last-good bundle")
		return outcomeFailed
	}
	if reply.GetUnchanged() {
		// Short-circuit without rebuilding. An unchanged poll is the overwhelmingly
		// common case, and recompiling every regex to arrive at the bundle we already
		// hold would be pure waste.
		return outcomeUnchanged
	}

	bundle, err := Load(reply)
	if err != nil {
		logger.Error().Err(err).Str("version", reply.GetVersion()).Msg("refusing llm prompt-rule bundle; keeping the last-good bundle")
		return outcomeFailed
	}
	p.store()(bundle)
	logger.Info().
		Str("version", bundle.Version()).
		Int("rules", bundle.Len()).
		Int("dropped", bundle.Dropped()).
		Strs("disabled_builtins", bundle.DisabledBuiltins()).
		Msg("loaded llm prompt-rule bundle")
	return outcomeUpdated
}

// nextInterval returns the poll interval with +-Jitter of spread. A zero-valued
// Poller -- the production one -- gets the PRD's 5 minutes +-60 s. A test that sets
// only Interval gets no jitter, so its timing assertions are exact.
func (p *Poller) nextInterval() time.Duration {
	interval, jitter := p.Interval, p.Jitter
	if interval <= 0 {
		interval = DefaultPollInterval
		if jitter <= 0 {
			jitter = DefaultPollJitter
		}
	}
	if jitter <= 0 {
		return interval
	}
	if jitter >= interval {
		// Keep the resulting interval strictly positive no matter how a caller
		// configures it: jitter == interval would allow a zero-length sleep and turn the
		// poll loop into a spin.
		jitter = interval / 2
		if jitter == 0 {
			return interval
		}
	}
	span := int64(2*jitter) + 1
	return interval + time.Duration(p.random(span)) - jitter
}

func (p *Poller) random(n int64) int64 {
	if n <= 0 {
		return 0
	}
	if p.Rand != nil {
		return p.Rand(n)
	}
	return rand.Int63n(n)
}

func (p *Poller) get() func(*proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
	if p.Get != nil {
		return p.Get
	}
	return GetLlmBundle
}

func (p *Poller) store() func(*Bundle) {
	if p.Store != nil {
		return p.Store
	}
	return Store
}

func (p *Poller) held() *Bundle {
	if p.Held != nil {
		return p.Held()
	}
	return Current()
}

// sleep waits for d, reporting false when ctx was cancelled first.
func (p *Poller) sleep(ctx context.Context, d time.Duration) bool {
	if p.Sleep != nil {
		return p.Sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
