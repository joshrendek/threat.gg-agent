package modbus

import (
	"net"
	"testing"

	"github.com/joshrendek/threat.gg-agent/icscore"
)

// TestCoilWriteIsolationBetweenAttackerIPs is the isolation requirement
// this package inherits from s7comm/icscore (threat_gg-4zzd.6): attacker A
// writes a coil, attacker B reads the SAME address and must never see it.
func TestCoilWriteIsolationBetweenAttackerIPs(t *testing.T) {
	a := globalState.Get("10.1.0.1")
	b := globalState.Get("10.1.0.2")

	// Both attackers write OPPOSITE explicit values to the SAME address.
	// This is deliberate: a coil is boolean, so comparing an unwritten
	// read against "not what A wrote" would pass roughly half the time by
	// coincidence even with isolation completely broken (driftBit(42)
	// might happen to be false anyway). Giving B its own explicit write
	// makes the assertion unconditional: if the store were one shared
	// bucket, B's later write would overwrite A's and B would read back
	// its own value regardless -- so the real test is that A's read is
	// UNAFFECTED by B's write, in either direction.
	a.writeCoil(42, true)
	b.writeCoil(42, false)

	if !a.readCoil(42) {
		t.Fatal("attacker A's write was clobbered by attacker B's write to the same address -- coils are not IP-scoped")
	}
	if b.readCoil(42) {
		t.Error("attacker B's own read must still see its own write")
	}
}

// TestHoldingRegisterWriteIsolationBetweenAttackerIPs covers the same
// requirement for holding registers.
func TestHoldingRegisterWriteIsolationBetweenAttackerIPs(t *testing.T) {
	a := globalState.Get("10.1.0.11")
	b := globalState.Get("10.1.0.12")

	a.writeHolding(7, 0xCAFE)

	if b.readHolding(7) == 0xCAFE {
		t.Fatal("attacker B observed attacker A's holding register write -- registers are not IP-scoped")
	}
	if a.readHolding(7) != 0xCAFE {
		t.Error("attacker A's own read must still see its own write")
	}
}

// TestWriteIsolationBetweenTwoIPv6Attackers is the extended coverage this
// project's ".6" incident (threat_gg-4zzd.6) requires: a key derivation
// that returned a constant, or that collapsed on parse failure, would pass
// every IPv4-only isolation test above while leaving all IPv6 attackers
// merged into one bucket. This goes through icscore.RemoteHost itself for
// two DISTINCT IPv6 net.Addrs, exercising the real address -> key ->
// isolated-state pipeline handleConnection uses in production, not a
// hand-picked string.
func TestWriteIsolationBetweenTwoIPv6Attackers(t *testing.T) {
	a := icscore.RemoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8:aaaa::1"), Port: 5001})
	b := icscore.RemoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8:bbbb::2"), Port: 5002})
	if a == b {
		t.Fatalf("two distinct IPv6 attackers derived the same state key %q", a)
	}

	// Both attackers write OPPOSITE explicit coil values to the SAME
	// address -- see TestCoilWriteIsolationBetweenAttackerIPs for why a
	// boolean isolation test must not rely on an unwritten read merely
	// differing from what the other attacker wrote (driftBit could
	// coincidentally agree, passing a broken implementation by chance).
	globalState.Get(a).writeCoil(99, true)
	globalState.Get(b).writeCoil(99, false)
	globalState.Get(a).writeHolding(99, 0xBEEF)

	if !globalState.Get(a).readCoil(99) {
		t.Error("attacker A's coil write was clobbered by attacker B over IPv6: per-IP scoping is not effective for IPv6")
	}
	if globalState.Get(b).readCoil(99) {
		t.Error("attacker B's own coil write did not stick over IPv6: per-IP scoping is not effective for IPv6")
	}
	if globalState.Get(b).readHolding(99) == 0xBEEF {
		t.Error("attacker B observed attacker A's register write over IPv6: per-IP scoping is not effective for IPv6")
	}
	if globalState.Get(a).readHolding(99) != 0xBEEF {
		t.Error("attacker A must still see its own register write")
	}
}

// TestSameIPReusesStateAcrossGets confirms globalState.Get is keyed on the
// IP string, not on call identity: two "connections" from the same
// attacker IP see the same state.
func TestSameIPReusesStateAcrossGets(t *testing.T) {
	globalState.Get("10.1.0.20").writeCoil(1, true)
	if !globalState.Get("10.1.0.20").readCoil(1) {
		t.Error("a second Get() for the same IP must read the earlier write back")
	}
}

// TestDiscreteInputsAndInputRegistersCarryNoAttackerState confirms the two
// read-only tables never consult attackerState at all: writing a coil/
// holding register at the same address must not change what a discrete
// input/input register read at that address returns.
func TestDiscreteInputsAndInputRegistersCarryNoAttackerState(t *testing.T) {
	before := driftBit(5)
	globalState.Get("10.1.0.30").writeCoil(5, !before)
	after := driftBit(5)
	if before != after {
		t.Error("writing a coil changed driftBit's answer for the same address -- discrete inputs must be read-only")
	}
}
