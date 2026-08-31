package icscore

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// testState is a minimal per-attacker value type standing in for what a real
// protocol keeps (s7comm's attackerState, Modbus's own equivalent): a small
// bit of mutable state behind its own lock, exactly the shape Store assumes
// T will have.
type testState struct {
	mu     sync.Mutex
	values map[string][]byte
}

func newTestState() *testState {
	return &testState{values: make(map[string][]byte)}
}

func (s *testState) write(key string, v []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = append([]byte(nil), v...)
}

func (s *testState) read(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	return v, ok
}

func newTestStore(max int) *Store[*testState] {
	return NewStore(max, func() *testState { return newTestState() })
}

// TestStoreIsolatesTwoDistinctAttackerIPs is the baseline isolation
// requirement (threat_gg-4zzd.6): attacker A writes a sentinel, attacker B
// reads the same key and must never see it.
func TestStoreIsolatesTwoDistinctAttackerIPs(t *testing.T) {
	store := newTestStore(2000)

	store.Get("10.0.0.1").write("sentinel", []byte{0xDE, 0xAD, 0xBE, 0xEF})

	_, ok := store.Get("10.0.0.2").read("sentinel")
	require.False(t, ok, "attacker B observed attacker A's write -- state is not IP-scoped")

	gotA, ok := store.Get("10.0.0.1").read("sentinel")
	require.True(t, ok)
	require.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, gotA, "attacker A must still see its own write")
}

// TestStoreIsolatesTwoDistinctIPv6Attackers is the extended coverage this
// package exists to guarantee: a key derivation that returned a constant, or
// that collapsed on parse failure, would pass every IPv4-only isolation test
// while leaving IPv6 attackers fully merged into one bucket -- which is
// exactly the bug s7comm's ".6" shipped, undetected, because its isolation
// tests at the time only ever used distinct IPv4 addresses.
//
// This test goes through RemoteHost itself (not a hand-picked string) for
// two DISTINCT IPv6 net.Addrs, so it exercises the real address -> key ->
// isolated-state pipeline every protocol built on icscore relies on.
func TestStoreIsolatesTwoDistinctIPv6Attackers(t *testing.T) {
	store := newTestStore(2000)

	a := RemoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8::a"), Port: 5001})
	b := RemoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8::b"), Port: 5002})
	require.NotEqual(t, a, b, "two distinct IPv6 attackers must not derive the same state key")

	store.Get(a).write("sentinel", []byte{0xCA, 0xFE})

	_, ok := store.Get(b).read("sentinel")
	require.False(t, ok,
		"attacker B observed attacker A's write over IPv6: per-IP scoping is not "+
			"effective for IPv6, so all IPv6 attackers share one bucket")

	gotA, ok := store.Get(a).read("sentinel")
	require.True(t, ok)
	require.Equal(t, []byte{0xCA, 0xFE}, gotA, "attacker A must still see its own write")
}

// TestStoreReusesSameKeyAcrossGets confirms Get is keyed on the string, not
// on call identity: two "connections" from the same attacker IP see the
// same value (a write from one call is visible to the other) -- the
// intended, deliberate opposite of the isolation tests above.
func TestStoreReusesSameKeyAcrossGets(t *testing.T) {
	store := newTestStore(2000)

	store.Get("192.168.1.50").write("k", []byte{0x01, 0x02})
	got, ok := store.Get("192.168.1.50").read("k")
	require.True(t, ok)
	require.Equal(t, []byte{0x01, 0x02}, got, "a second Get() for the same key must read the earlier write back")
}

// TestStoreEvictsLeastRecentlyUsedWhenFull confirms the max bound actually
// caps memory rather than being decorative.
func TestStoreEvictsLeastRecentlyUsedWhenFull(t *testing.T) {
	const max = 100
	store := newTestStore(max)

	keyForIndex := func(i int) string { return fmt.Sprintf("10.0.%d.%d", i/256%256, i%256) }

	for i := 0; i < max; i++ {
		store.Get(keyForIndex(i))
	}
	require.Equal(t, max, store.Len())

	// One more distinct key must evict the least-recently-used entry (key 0,
	// never touched again since its initial insert) rather than growing past
	// the cap.
	store.Get(keyForIndex(max))
	require.Equal(t, max, store.Len(), "store grew past its configured max")
	require.False(t, store.Contains(keyForIndex(0)), "least-recently-used entry was not evicted")
	require.True(t, store.Contains(keyForIndex(max)), "newly inserted entry should be present")
}

// TestStoreGetRefreshesRecency confirms that touching an entry via Get moves
// it back to the front of the LRU, protecting it from the next eviction --
// otherwise an attacker who returns periodically could still be evicted out
// from under an active session.
func TestStoreGetRefreshesRecency(t *testing.T) {
	const max = 3
	store := newTestStore(max)

	store.Get("a")
	store.Get("b")
	store.Get("c")

	// Touch "a" again so it is no longer the least-recently-used.
	store.Get("a")

	// Inserting a new key should now evict "b" (now the oldest untouched
	// entry), not "a".
	store.Get("d")

	require.True(t, store.Contains("a"), "recently re-touched entry must survive eviction")
	require.False(t, store.Contains("b"), "the actual least-recently-used entry should have been evicted")
}
