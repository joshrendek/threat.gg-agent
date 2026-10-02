package sqlai

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/stretchr/testify/require"
)

// Equal timestamps must evict the lexicographically smallest key every time,
// whatever order the map iterates in.
func TestSessionsTieEvictsSmallestKey(t *testing.T) {
	orders := [][]string{{"a", "b", "c"}, {"c", "b", "a"}, {"b", "c", "a"}}
	for i := 0; i < 50; i++ {
		s := NewSessions(3, time.Hour)
		now := time.Unix(1_800_000_000, 0)
		s.now = func() time.Time { return now }
		for _, id := range orders[i%len(orders)] {
			s.Set(id, Session{State: Live})
		}
		s.Set("d", Session{State: Live}) // same timestamp as the rest; one entry must go
		require.Equal(t, Unknown, s.Get("a").State, "iteration %d", i)
		require.Equal(t, Live, s.Get("b").State, "iteration %d", i)
		require.Equal(t, Live, s.Get("c").State, "iteration %d", i)
		require.Equal(t, Live, s.Get("d").State, "iteration %d: the new entry is kept", i)
	}
}

func TestSessionsGetRefreshesAge(t *testing.T) {
	s := NewSessions(10, time.Minute)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	s.Set("a", Session{State: Live})
	now = now.Add(50 * time.Second)
	require.Equal(t, Live, s.Get("a").State)
	now = now.Add(50 * time.Second) // 100s after Set, 50s after the last Get
	require.Equal(t, Live, s.Get("a").State, "a session in use does not expire mid-session")
	now = now.Add(61 * time.Second)
	require.Equal(t, Unknown, s.Get("a").State, "idle past the TTL expires")
}

func TestSessionsNonPositiveTTLUsesDefault(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		s := NewSessions(2, ttl)
		now := time.Unix(1_800_000_000, 0)
		s.now = func() time.Time { return now }
		s.Set("a", Session{State: Live})
		now = now.Add(DefaultSessionTTL - time.Second)
		require.Equal(t, Live, s.Get("a").State, "ttl %v", ttl)
		now = now.Add(DefaultSessionTTL + time.Second)
		require.Equal(t, Unknown, s.Get("a").State, "ttl %v", ttl)
	}
}

func TestCleanDropsFormatCharacters(t *testing.T) {
	require.Equal(t, "abc", Clean("a\xe2\x80\xaeb\xe2\x80\xacc", true), "bidi override and pop")
	require.Equal(t, "ab", Clean("a\xe2\x81\xa6b\xe2\x81\xa9", true), "bidi isolates")
	require.Equal(t, "ab", Clean("a\xe2\x80\x8bb", true), "zero-width space")
	require.Equal(t, "ab", Clean("\xef\xbb\xbfa\xe2\x80\x8fb", false), "BOM and RLM")
	require.Equal(t, "ab", Clean("a\xe2\x80\xa8b\xe2\x80\xa9", true), "line and paragraph separators")
	require.Equal(t, "a\nb", Clean("a\n\xe2\x80\xaeb", true), "cell newline survives")
}

// Run with -race: many sessions driven through Get / Ask / Set at once.
func TestSessionsConcurrent(t *testing.T) {
	s := NewSessions(16, time.Minute)
	gen := func(*proto.GenerateRequest, time.Duration) (*proto.GenerateReply, error) {
		return rsReply(proto.GenerateSource_GENERATE_SOURCE_AI), nil
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 3000; i++ {
				id := fmt.Sprintf("s%d", (g*7+i)%40)
				out := Ask(gen, "postgres", id, "SELECT 1", s.Get(id))
				s.Set(id, out.Session)
				if i%500 == 0 {
					s.Reset()
				}
			}
		}(g)
	}
	wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.LessOrEqual(t, len(s.items), 16)
}
