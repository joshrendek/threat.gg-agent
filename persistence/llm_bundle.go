package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/metadata"
)

// llmBundleTimeout bounds the PRD 034 corpus poll. It is generous compared with
// cmdresp's 250 ms LLM override deadline, and deliberately so: that deadline is
// short because it sits on the inference request path, where a slow control plane
// would become an elapsed_ms fingerprint. This call sits on a background goroutine
// that runs every five minutes and blocks nothing. The only thing the bound has to
// prevent is a hung stream pinning the poll goroutine until the process restarts.
//
// A package var so tests can shrink it, matching saveTimeout.
var llmBundleTimeout = 10 * time.Second

// GetLlmBundle fetches the LLM prompt-rule corpus (PRD 034). known_version is the
// ETag: when it matches, the server answers unchanged=true with no rules.
//
// Every failure mode here means "no update", never "the corpus is now empty" -- the
// caller keeps its last-good bundle. That distinction is the whole fail-open story:
// returning an empty bundle on a transport error would turn a control-plane blip
// into a fleet-wide behaviour change.
func GetLlmBundle(in *proto.LlmBundleRequest) (*proto.LlmBundleReply, error) {
	// Guard against an uninitialized client (before Setup, or in unit tests) so the
	// caller gets a clean error and keeps its compiled behaviour instead of panicking.
	if honeypotClient == nil {
		return nil, errors.New("honeypot client not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), llmBundleTimeout)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	return honeypotClient.GetLlmBundle(ctx, in)
}
