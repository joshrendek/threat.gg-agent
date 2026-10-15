// Package shellai is the agent half of AI answers for the interactive shell
// honeypots (ssh and telnet): how long to wait for a generated reply, which
// replies count as an answer, and when the server is slow enough that the
// legacy lookup should use its short deadline.
package shellai

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Generate has persistence.GenerateResponse's signature.
type Generate func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error)

const (
	// GenerateBudget bounds how long an attacker waits for an AI reply before
	// the legacy path answers instead.
	GenerateBudget = 3 * time.Second
	// LookupTimeout is the normal legacy lookup deadline.
	LookupTimeout = 3 * time.Second
	// DegradedLookupTimeout replaces LookupTimeout after the generate call was
	// slow or unreachable, so a degraded server costs an attacker
	// GenerateBudget plus a short lookup, not two full waits.
	DegradedLookupTimeout = 600 * time.Millisecond
)

// answeredSources maps the GenerateResponse sources that carry an answer to
// their capture label. NONE and UNSPECIFIED are absent: they mean fall back.
var answeredSources = map[proto.GenerateSource]string{
	proto.GenerateSource_GENERATE_SOURCE_AI:        "ai",
	proto.GenerateSource_GENERATE_SOURCE_AI_CACHED: "ai_cached",
	proto.GenerateSource_GENERATE_SOURCE_LOCAL:     "local",
}

// Outcome is one ask. The answer fields are set only when Answered.
type Outcome struct {
	Answered bool
	// Degraded reports a slow or unreachable server: use DegradedLookupTimeout.
	Degraded bool
	// Stdout, Cwd and Hostname are raw server text; callers sanitize them.
	Stdout   string
	ExitCode uint32 // clamped to 0..255
	Cwd      string
	Hostname string
	// Source is "ai", "ai_cached" or "local"; it is recorded as the command's
	// response_source together with GenerationID.
	Source       string
	GenerationID string
}

// Ask asks the server for a terminal reply to input within GenerateBudget. It
// answers only for an AI, AI_CACHED or LOCAL reply with a terminal body and no
// error; NONE, UNSPECIFIED, Unimplemented, any error, a nil reply or a missing
// body leave Answered false so the caller takes its legacy path. Blank input
// makes no call. The returned error is for logging only.
func Ask(gen Generate, protocol, guid, input string) (Outcome, error) {
	var out Outcome
	if gen == nil || strings.TrimSpace(input) == "" {
		return out, nil
	}
	reply, err := gen(&proto.GenerateRequest{
		Guid: guid, Protocol: protocol, Input: input, DeadlineMs: int32(GenerateBudget / time.Millisecond),
	}, GenerateBudget)
	if err != nil {
		out.Degraded = IsServerSlow(err)
		return out, err
	}
	source, ok := answeredSources[reply.GetSource()]
	term := reply.GetTerminal()
	if !ok || term == nil {
		return out, nil
	}
	code := term.GetExitCode()
	if code < 0 || code > 255 {
		code = 255
	}
	return Outcome{
		Answered:     true,
		Stdout:       term.GetStdout(),
		ExitCode:     uint32(code),
		Cwd:          term.GetCwd(),
		Hostname:     term.GetHostname(),
		Source:       source,
		GenerationID: reply.GetGenerationId(),
	}, nil
}

// IsServerSlow reports a generate failure that means the server is slow or
// unreachable, as opposed to Unimplemented, NONE or a reply-level error.
func IsServerSlow(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable:
		return true
	}
	return false
}
