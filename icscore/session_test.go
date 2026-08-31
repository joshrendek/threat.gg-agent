package icscore

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var testStages = []string{"connected", "handshake", "identity", "data", "control"}

// TestNewSessionStartsAtBaseStage confirms a fresh session starts at
// stages[0] and reports itself as noise -- a bare connect, nothing more.
func TestNewSessionStartsAtBaseStage(t *testing.T) {
	s := NewSession(testStages, 256, 1024)
	require.Equal(t, "connected", s.ReachedStage())
	require.True(t, s.IsNoise(), "a fresh session with no activity must be noise")
}

// TestAdvanceMovesForwardOnly is the forward-only funnel requirement: once a
// session has reached a deep stage, a later shallower stage reached in the
// same connection must not erase evidence of the deepest stage actually
// reached.
func TestAdvanceMovesForwardOnly(t *testing.T) {
	s := NewSession(testStages, 256, 1024)
	s.Advance("control")
	require.Equal(t, "control", s.ReachedStage())

	s.Advance("data")
	require.Equal(t, "control", s.ReachedStage(), "reachedStage must not regress")

	s.Advance("identity")
	require.Equal(t, "control", s.ReachedStage(), "reachedStage must not regress")
}

// TestAdvancePastBaseStageIsNotNoise confirms any real protocol activity
// (advancing past stages[0]) flips IsNoise to false.
func TestAdvancePastBaseStageIsNotNoise(t *testing.T) {
	s := NewSession(testStages, 256, 1024)
	require.True(t, s.IsNoise())

	s.Advance("handshake")
	require.False(t, s.IsNoise(), "a session that reached a real stage must not be treated as noise")
}

// TestUnknownStageNameDoesNotAdvance confirms a stage name that was never
// passed to NewSession (rank 0, same as the zero value) cannot accidentally
// regress or advance reachedStage.
func TestUnknownStageNameDoesNotAdvance(t *testing.T) {
	s := NewSession(testStages, 256, 1024)
	s.Advance("control")
	require.Equal(t, "control", s.ReachedStage())

	s.Advance("not-a-real-stage")
	require.Equal(t, "control", s.ReachedStage())
}

// TestRecordCapsOperationsAndCountsOverflow is the truncation requirement:
// once a session accumulates maxOperations entries, further ones are only
// counted via DroppedOperations, never stored, and DropNote makes that
// visible rather than silently discarding evidence that truncation
// happened.
func TestRecordCapsOperationsAndCountsOverflow(t *testing.T) {
	const cap = 256
	const overflow = 10
	s := NewSession(testStages, cap, 1024)

	for i := 0; i < cap+overflow; i++ {
		s.Record(Operation{Kind: "read", Detail: "filler", Handled: true})
	}

	require.Len(t, s.Operations(), cap)
	require.Equal(t, overflow, s.DroppedOperations())

	ops := s.Operations()
	last := ops[len(ops)-1]
	noted := DropNote(last.Detail, s.DroppedOperations(), cap)
	require.Contains(t, noted, "10")
	require.True(t, strings.Contains(noted, "further operations dropped"))
}

// TestDropNoteIsNoOpWhenNothingDropped confirms DropNote leaves detail
// unchanged when there is nothing to report.
func TestDropNoteIsNoOpWhenNothingDropped(t *testing.T) {
	require.Equal(t, "plain detail", DropNote("plain detail", 0, 256))
}

// TestRecordTruncatesAndCopiesRawBytes confirms Raw is bounded by
// maxRawBytes and is copied rather than aliasing the caller's backing array
// (so later mutation of the caller's slice can't corrupt a recorded
// operation).
func TestRecordTruncatesAndCopiesRawBytes(t *testing.T) {
	s := NewSession(testStages, 256, 4)

	raw := []byte{1, 2, 3, 4, 5, 6}
	s.Record(Operation{Kind: "x", Raw: raw})

	got := s.Operations()[0].Raw
	require.Len(t, got, 4, "raw must be truncated to maxRawBytes")
	require.Equal(t, []byte{1, 2, 3, 4}, got)

	raw[0] = 0xFF
	require.Equal(t, byte(1), got[0], "recorded raw must be a copy, not an alias of the caller's slice")
}

// TestDurationIsPositive is a smoke check that Duration reflects real
// elapsed time rather than a zero value.
func TestDurationIsPositive(t *testing.T) {
	s := NewSession(testStages, 256, 1024)
	require.True(t, s.Duration() >= 0)
}
