package s7comm

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// The per-attacker state key must be the BARE IP, distinct per attacker, for
// IPv4 and IPv6 alike.
//
// This is the requirement threat_gg-4zzd.6 calls out explicitly and that the
// original implementation shipped without: per-IP scoping built on a broken key
// derivation collapses every IPv6 attacker into one shared bucket, while every
// line of the scoping code above it still reads as correct. llmcore and etcd
// shipped exactly that collapse, via a ::1 fallback.
func TestRemoteHostYieldsDistinctBareIPs(t *testing.T) {
	cases := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"ipv4 with port", &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 1234}, "203.0.113.5"},
		{"ipv6 with port", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}, "2001:db8::1"},
		{"ipv6 other host", &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 1234}, "2001:db8::2"},
		{"ipv6 loopback", &net.TCPAddr{IP: net.ParseIP("::1"), Port: 102}, "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := remoteHost(tc.addr)
			require.Equal(t, tc.want, got)
			// The key must also be a parseable IP, so it survives the server's
			// own normalizedRemoteIP without degrading to the ::1 fallback.
			require.NotNil(t, net.ParseIP(got),
				"state key %q must parse as an IP, or the server stores it as ::1 and "+
					"attribution collapses", got)
		})
	}
}

// Two DIFFERENT IPv6 attackers must not share state. A key derivation that
// returned a constant, or that collapsed on parse failure, would pass every
// IPv4 isolation test while leaving IPv6 attackers fully merged.
func TestWriteIsolationBetweenTwoIPv6Attackers(t *testing.T) {
	a := remoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8::a"), Port: 5001})
	b := remoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8::b"), Port: 5002})
	require.NotEqual(t, a, b, "two distinct IPv6 attackers must not derive the same state key")

	addr := addressKey{area: 0x84, db: 1, byteOffset: 0}
	sentinel := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	globalState.get(a).write(addr, sentinel)

	gotB := globalState.get(b).read(addr, len(sentinel))
	require.NotEqual(t, sentinel, gotB,
		"attacker B observed attacker A's write over IPv6: per-IP scoping is not "+
			"effective for IPv6, so all IPv6 attackers share one bucket")

	gotA := globalState.get(a).read(addr, len(sentinel))
	require.Equal(t, sentinel, gotA, "attacker A must still see its own write")
}

// CPU run/stop mode is attacker-scoped too: a STOP from one IPv6 attacker must
// not appear to another.
func TestCPUModeIsolationBetweenTwoIPv6Attackers(t *testing.T) {
	a := remoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 6001})
	b := remoteHost(&net.TCPAddr{IP: net.ParseIP("2001:db8::11"), Port: 6002})

	globalState.get(a).setMode(modeStop)

	require.Equal(t, modeStop, globalState.get(a).getMode(), "attacker A stopped the CPU and must see it stopped")
	require.Equal(t, modeRun, globalState.get(b).getMode(),
		"attacker B saw attacker A's CPU STOP over IPv6: mode is not scoped per IPv6 attacker")
}
