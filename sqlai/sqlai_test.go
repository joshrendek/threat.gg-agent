package sqlai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func rsReply(src proto.GenerateSource) *proto.GenerateReply {
	return &proto.GenerateReply{Source: src, GenerationId: "gen-1",
		Body: &proto.GenerateReply_ResultSet{ResultSet: &proto.ResultSet{CommandTag: "SELECT 0", Columns: []*proto.Column{{Name: "a", Type: "int4"}}}}}
}

// Review Focus 2 lives in the slow-first-call row.
func TestAskStateTransitions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		st         State
		reply      *proto.GenerateReply
		err        error
		wantState  State
		wantBudget time.Duration
		answered   bool
		degraded   bool
	}{
		{"first AI answer goes live", Unknown, rsReply(proto.GenerateSource_GENERATE_SOURCE_AI), nil, Live, FirstBudget, true, false},
		{"first local answer goes live", Unknown, rsReply(proto.GenerateSource_GENERATE_SOURCE_LOCAL), nil, Live, FirstBudget, true, false},
		{"first NONE with id goes live", Unknown, &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE, GenerationId: "g"}, nil, Live, FirstBudget, false, false},
		{"first NONE without id stops", Unknown, &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil, Off, FirstBudget, false, false},
		{"old server stops", Unknown, nil, persistence.ErrUnimplemented, Off, FirstBudget, false, false},
		{"slow first call stops and degrades", Unknown, nil, status.Error(codes.DeadlineExceeded, "slow"), Off, FirstBudget, false, true},
		{"live uses the long budget", Live, rsReply(proto.GenerateSource_GENERATE_SOURCE_AI_CACHED), nil, Live, LiveBudget, true, false},
		{"live NONE stays live", Live, &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil, Live, LiveBudget, false, false},
		{"live unavailable degrades", Live, nil, status.Error(codes.Unavailable, "down"), Live, LiveBudget, false, true},
		{"live context deadline degrades", Live, nil, fmt.Errorf("wrapped: %w", context.DeadlineExceeded), Live, LiveBudget, false, true},
		{"terminal body is not an answer", Live, &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_AI, Body: &proto.GenerateReply_Terminal{Terminal: &proto.Terminal{}}}, nil, Live, LiveBudget, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got *proto.GenerateRequest
			var within time.Duration
			out := Ask(func(in *proto.GenerateRequest, w time.Duration) (*proto.GenerateReply, error) {
				got, within = in, w
				return tc.reply, tc.err
			}, "postgres", "guid-1", "SELECT a FROM T", Session{State: tc.st})
			require.Equal(t, tc.wantState, out.State)
			require.Equal(t, tc.wantBudget, within)
			require.Equal(t, int32(tc.wantBudget/time.Millisecond), got.DeadlineMs)
			require.Equal(t, "postgres", got.Protocol)
			require.Equal(t, "guid-1", got.Guid)
			require.Equal(t, "SELECT a FROM T", got.Input, "the query is sent as the client typed it")
			require.Equal(t, tc.answered, out.ResultSet != nil)
			require.Equal(t, tc.degraded, out.Degraded)
			if tc.answered {
				require.Equal(t, "gen-1", out.GenerationID)
				require.NotEmpty(t, out.Source)
			}
		})
	}
}

// A brownout must not charge every query of a Live session LiveBudget plus
// the legacy lookup forever: MaxSlowErrors slow calls in a row turn it Off.
func TestAskLiveSessionTurnsOffAfterConsecutiveSlowErrors(t *testing.T) {
	calls := 0
	slow := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		calls++
		return nil, status.Error(codes.DeadlineExceeded, "slow")
	}
	s := Session{State: Live}
	for i := 1; i <= MaxSlowErrors; i++ {
		out := Ask(slow, "postgres", "g", "SELECT 1", s)
		require.True(t, out.Degraded, "call %d", i)
		s = out.Session
		if i < MaxSlowErrors {
			require.Equal(t, Live, s.State, "call %d: still live", i)
		}
	}
	require.Equal(t, 3, MaxSlowErrors)
	require.Equal(t, Off, s.State, "three slow errors in a row turn the session off")
	require.Equal(t, MaxSlowErrors, calls)
	out := Ask(slow, "postgres", "g", "SELECT 1", s)
	require.Equal(t, Off, out.State)
	require.Equal(t, MaxSlowErrors, calls, "no further calls once off")
}

func TestAskReplyResetsSlowErrorCount(t *testing.T) {
	var fail bool
	gen := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		if fail {
			return nil, status.Error(codes.Unavailable, "down")
		}
		return &proto.GenerateReply{Source: proto.GenerateSource_GENERATE_SOURCE_NONE}, nil
	}
	s := Session{State: Live}
	fail = true
	for i := 0; i < MaxSlowErrors-1; i++ {
		s = Ask(gen, "postgres", "g", "SELECT 1", s).Session
	}
	require.Equal(t, Session{State: Live, slowErrors: MaxSlowErrors - 1}, s)
	fail = false
	s = Ask(gen, "postgres", "g", "SELECT 1", s).Session
	require.Equal(t, Session{State: Live}, s, "a reply resets the count")
	fail = true
	for i := 0; i < MaxSlowErrors-1; i++ {
		s = Ask(gen, "postgres", "g", "SELECT 1", s).Session
	}
	require.Equal(t, Live, s.State, "the streak restarted, so two more slow errors keep it live")
}

func TestAskNeverCallsWhenOffOrBlank(t *testing.T) {
	calls := 0
	gen := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		calls++
		return nil, errors.New("x")
	}
	require.Equal(t, Off, Ask(gen, "mssql", "g", "SELECT 1", Session{State: Off}).State)
	require.Equal(t, Unknown, Ask(gen, "mssql", "g", "   ", Session{}).State)
	require.Equal(t, Unknown, Ask(nil, "mssql", "g", "SELECT 1", Session{}).State)
	require.Zero(t, calls)
}

// Ruling P7: an oversized query is never sent; the caller uses the legacy path.
func TestAskOversizedQueryMakesNoCall(t *testing.T) {
	calls := 0
	gen := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		calls++
		return rsReply(proto.GenerateSource_GENERATE_SOURCE_AI), nil
	}
	for _, st := range []State{Unknown, Live} {
		out := Ask(gen, "postgres", "g", "SELECT '"+strings.Repeat("a", MaxQueryBytes)+"'", Session{State: st})
		require.Equal(t, st, out.State, "state is unchanged")
		require.Nil(t, out.ResultSet)
		require.False(t, out.Degraded)
	}
	require.Zero(t, calls)
	atCap := "SELECT " + strings.Repeat("a", MaxQueryBytes-len("SELECT "))
	require.Equal(t, MaxQueryBytes, len(atCap))
	require.Equal(t, Live, Ask(gen, "postgres", "g", atCap, Session{}).State)
	require.Equal(t, 1, calls)
}

func TestClean(t *testing.T) {
	require.Equal(t, "red[31m text", Clean("red\x1b[31m text", true))
	require.Equal(t, "a\nb\tc", Clean("a\nb\tc", true))
	require.Equal(t, "abc", Clean("a\nb\tc", false))
	require.Equal(t, "xy", Clean("x\u0085\x7fy", false), "C1 and DEL dropped")
	require.Equal(t, "�", Clean("\xff", false))
	require.Equal(t, "🐘 ok", Clean("🐘 ok", false))
}

func TestSessions(t *testing.T) {
	s := NewSessions(2, time.Minute)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	require.Equal(t, Unknown, s.Get("a").State)
	s.Set("a", Session{State: Live})
	require.Equal(t, Live, s.Get("a").State)
	now = now.Add(2 * time.Minute)
	require.Equal(t, Unknown, s.Get("a").State, "expired after the TTL")
	s.Set("a", Session{State: Live})
	now = now.Add(time.Second)
	s.Set("b", Session{State: Off})
	now = now.Add(time.Second)
	s.Set("c", Session{State: Live})
	require.Equal(t, Unknown, s.Get("a").State, "the oldest entry is evicted past the bound")
	require.Equal(t, Off, s.Get("b").State)
	s.Reset()
	require.Equal(t, Unknown, s.Get("c").State)
}

// Attacker churn must not grow the map past the bound.
func TestSessionsStayBounded(t *testing.T) {
	s := NewSessions(50, time.Hour)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { now = now.Add(time.Millisecond); return now }
	for i := 0; i < 1000; i++ {
		s.Set(fmt.Sprintf("s%d", i), Session{State: Live})
	}
	require.LessOrEqual(t, len(s.items), 50)
	require.Equal(t, Live, s.Get("s999").State, "the newest survives")
}
