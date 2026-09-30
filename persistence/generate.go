package persistence

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ErrUnimplemented means the server predates GenerateResponse. Callers fall back
// to GetCommandResponse; the memo below keeps that fallback to one extra RPC per
// unimplementedMemo instead of one per attacker command.
var ErrUnimplemented = errors.New("server does not implement GenerateResponse")

// unimplementedMemo is how long an Unimplemented answer is remembered.
const unimplementedMemo = 5 * time.Minute

var (
	// generateNow is the clock seam so tests can advance time.
	generateNow        = time.Now
	unimplementedMu    sync.Mutex
	unimplementedUntil time.Time
)

func resetUnimplemented() {
	unimplementedMu.Lock()
	unimplementedUntil = time.Time{}
	unimplementedMu.Unlock()
}

// GenerateResponse asks the server for an AI-generated reply within the given
// budget. Source NONE in the reply means "use your existing path". The memo only
// ever short-circuits with ErrUnimplemented; it never replays a reply, and every
// other error is returned unchanged.
func GenerateResponse(in *proto.GenerateRequest, within time.Duration) (*proto.GenerateReply, error) {
	if honeypotClient == nil {
		return nil, errors.New("honeypot client not connected")
	}
	if within <= 0 {
		return nil, errors.New("generate response timeout must be positive")
	}
	unimplementedMu.Lock()
	memoized := generateNow().Before(unimplementedUntil)
	unimplementedMu.Unlock()
	if memoized {
		return nil, ErrUnimplemented
	}
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, connMetadata)
	reply, err := honeypotClient.GenerateResponse(ctx, in)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			unimplementedMu.Lock()
			unimplementedUntil = generateNow().Add(unimplementedMemo)
			unimplementedMu.Unlock()
			return nil, ErrUnimplemented
		}
		return nil, err
	}
	return reply, nil
}
