package s7comm

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestWriteIsolationBetweenAttackerIPs is the isolation regression test the
// brief calls for (threat_gg-4zzd.6): attacker A writes a sentinel value,
// attacker B reads the SAME address and must never see it.
//
// This test is written to genuinely exercise cross-IP visibility rather than
// just calling two methods and hoping: it fails immediately against a naive
// implementation where "the store" is one shared map keyed only by address
// (no IP dimension at all) -- swap store.get(ip) below for a single shared
// *attackerState and this test fails, because B's read would return A's
// sentinel instead of drifting simulated data.
func TestWriteIsolationBetweenAttackerIPs(t *testing.T) {
	store := newStateStore()
	addr := addressKey{area: areaDBForTest, db: 1, byteOffset: 100}
	sentinel := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	attackerA := store.get("10.0.0.1")
	attackerA.write(addr, sentinel)

	attackerB := store.get("10.0.0.2")
	gotB := attackerB.read(addr, len(sentinel))

	if bytes.Equal(gotB, sentinel) {
		t.Fatalf("attacker B observed attacker A's sentinel write % x at the same address -- writes are not IP-scoped", sentinel)
	}

	// A must still see its own write, unaffected by B's read.
	gotA := attackerA.read(addr, len(sentinel))
	if !bytes.Equal(gotA, sentinel) {
		t.Errorf("attacker A's own read = % x, want its own sentinel write % x back", gotA, sentinel)
	}
}

// TestSameIPReusesStateAcrossConnections confirms store.get is keyed on the
// IP string, not on connection identity: two "connections" from the same
// attacker IP see the same state (a write from one is visible to the other),
// which is the intended, deliberate opposite of the A/B isolation above.
func TestSameIPReusesStateAcrossConnections(t *testing.T) {
	store := newStateStore()
	addr := addressKey{area: areaDBForTest, db: 2, byteOffset: 0}
	sentinel := []byte{0x01, 0x02}

	store.get("192.168.1.50").write(addr, sentinel)
	got := store.get("192.168.1.50").read(addr, len(sentinel))

	if !bytes.Equal(got, sentinel) {
		t.Errorf("second get() for the same IP read % x, want the earlier write % x back", got, sentinel)
	}
}

// TestCPUModeIsolationBetweenAttackerIPs covers the brief's PLC-STOP
// isolation requirement directly at the state layer: attacker A stopping the
// "CPU" must not change what attacker B observes.
func TestCPUModeIsolationBetweenAttackerIPs(t *testing.T) {
	store := newStateStore()

	attackerA := store.get("172.16.0.1")
	attackerB := store.get("172.16.0.2")

	if attackerB.getMode() != modeRun {
		t.Fatalf("attacker B's initial mode = %v, want modeRun", attackerB.getMode())
	}

	attackerA.setMode(modeStop)

	if attackerA.getMode() != modeStop {
		t.Errorf("attacker A's mode = %v after its own STOP, want modeStop", attackerA.getMode())
	}
	if attackerB.getMode() != modeRun {
		t.Errorf("attacker B's mode = %v after attacker A's STOP, want modeRun (unaffected)", attackerB.getMode())
	}
}

// TestStateStoreEvictsLeastRecentlyUsedWhenFull confirms the bound in
// maxTrackedAttackers actually caps memory rather than just being decorative.
func TestStateStoreEvictsLeastRecentlyUsedWhenFull(t *testing.T) {
	store := newStateStore()
	for i := 0; i < maxTrackedAttackers; i++ {
		store.get(ipForIndex(i))
	}
	if store.lru.Len() != maxTrackedAttackers {
		t.Fatalf("store has %d entries after filling to capacity, want %d", store.lru.Len(), maxTrackedAttackers)
	}

	// One more distinct IP must evict the least-recently-used entry (IP 0,
	// never touched again since its initial insert) rather than growing
	// past the cap.
	store.get(ipForIndex(maxTrackedAttackers))
	if store.lru.Len() != maxTrackedAttackers {
		t.Fatalf("store has %d entries after exceeding capacity, want it capped at %d", store.lru.Len(), maxTrackedAttackers)
	}
	if _, stillPresent := store.items[ipForIndex(0)]; stillPresent {
		t.Error("least-recently-used entry was not evicted when the store exceeded capacity")
	}
}

func ipForIndex(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256)
}

// areaDBForTest is just the real S7 "Data blocks" area code, given a
// test-local name so these tests don't need to import pdu.go's constants.
const areaDBForTest = 0x84

func TestDriftValueChangesOverTime(t *testing.T) {
	realNow := nowFunc
	defer func() { nowFunc = realNow }()

	addr := addressKey{area: areaDBForTest, db: 1, byteOffset: 0}

	nowFunc = func() time.Time { return time.Unix(1_700_000_000, 0) }
	first := driftValue(addr, 8)

	nowFunc = func() time.Time { return time.Unix(1_700_000_000+120, 0) }
	second := driftValue(addr, 8)

	if bytes.Equal(first, second) {
		t.Fatal("driftValue returned identical bytes 120 seconds apart -- process data must drift over time")
	}
}

func TestDriftValueIsDeterministicForAGivenMoment(t *testing.T) {
	realNow := nowFunc
	defer func() { nowFunc = realNow }()
	nowFunc = func() time.Time { return time.Unix(1_700_000_000, 0) }

	addr := addressKey{area: areaDBForTest, db: 1, byteOffset: 0}
	a := driftValue(addr, 8)
	b := driftValue(addr, 8)
	if !bytes.Equal(a, b) {
		t.Errorf("driftValue at the same instant returned % x then % x, want identical (it is a pure function of address+time)", a, b)
	}
}

func TestDriftValueDiffersAcrossAddresses(t *testing.T) {
	realNow := nowFunc
	defer func() { nowFunc = realNow }()
	nowFunc = func() time.Time { return time.Unix(1_700_000_000, 0) }

	a := driftValue(addressKey{area: areaDBForTest, db: 1, byteOffset: 0}, 8)
	b := driftValue(addressKey{area: areaDBForTest, db: 1, byteOffset: 100}, 8)
	if bytes.Equal(a, b) {
		t.Error("driftValue returned identical bytes for two different addresses at the same instant")
	}
}

func TestReadWithoutWriteNeverAllZero(t *testing.T) {
	store := newStateStore()
	attacker := store.get("203.0.113.1")
	got := attacker.read(addressKey{area: areaDBForTest, db: 1, byteOffset: 0}, 16)

	allZero := true
	for _, b := range got {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("an unwritten address read back all zeros -- a real, executing PLC never does this")
	}
}

// Drift must be AUTOCORRELATED, not merely different-every-second.
//
// This is the guard the plain "changes over time" test cannot provide: a
// per-second random draw passes that one while being white noise, which is what
// an earlier implementation did. Real process data moves a little between
// adjacent samples and a lot over minutes; uniform jumps across the whole range
// every second are not physical, and an attacker polling a register at 1 Hz sees
// that immediately.
func TestDriftIsAutocorrelatedNotWhiteNoise(t *testing.T) {
	realNow := nowFunc
	defer func() { nowFunc = realNow }()

	addr := addressKey{area: 0x84, db: 1, byteOffset: 0}
	base := int64(1_700_000_000)

	sample := func(offset int64) int {
		nowFunc = func() time.Time { return time.Unix(base+offset, 0) }
		b := driftValue(addr, 2)
		return int(b[0])<<8 | int(b[1])
	}

	v0 := sample(0)
	v1 := sample(1)
	vFar := sample(150)

	adjacent := v1 - v0
	if adjacent < 0 {
		adjacent = -adjacent
	}
	distant := vFar - v0
	if distant < 0 {
		distant = -distant
	}

	// One second apart must be a small move. White noise over a ~1600-wide
	// swing would routinely exceed this; a slow sinusoid never will.
	if adjacent > 400 {
		t.Errorf("adjacent samples moved by %d (%d -> %d); process data should change "+
			"only slightly in one second -- a large jump means the value is being "+
			"redrawn at random rather than drifting", adjacent, v0, v1)
	}

	// Over a longer gap it must actually move, or the register is effectively
	// frozen and reads as a dead simulation.
	if distant == 0 {
		t.Errorf("value unchanged after 150s (%d); a register that never moves is "+
			"the static-memory tell this drift exists to avoid", v0)
	}

	// Values must stay inside a plausible band, never the 0x0000/0xFFFF
	// extremes a broken or unset simulation produces.
	for _, v := range []int{v0, v1, vFar} {
		if v == 0 || v == 0xFFFF {
			t.Errorf("drift produced an extreme value %#04x; these read as unset or broken", v)
		}
	}
}

// Distinct addresses must drift independently -- if every register returned the
// same waveform, reading two addresses would reveal one generator behind them.
func TestDriftDiffersBetweenAddresses(t *testing.T) {
	realNow := nowFunc
	defer func() { nowFunc = realNow }()
	nowFunc = func() time.Time { return time.Unix(1_700_000_000, 0) }

	a := driftValue(addressKey{area: 0x84, db: 1, byteOffset: 0}, 2)
	b := driftValue(addressKey{area: 0x84, db: 1, byteOffset: 8}, 2)
	c := driftValue(addressKey{area: 0x84, db: 7, byteOffset: 0}, 2)

	if bytes.Equal(a, b) {
		t.Error("two offsets in the same DB returned identical values at the same instant")
	}
	if bytes.Equal(a, c) {
		t.Error("the same offset in two different DBs returned identical values at the same instant")
	}
}
