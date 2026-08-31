package icscore

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// The per-attacker state key must be the BARE IP, distinct per attacker, for
// IPv4 and IPv6 alike.
//
// This is the requirement threat_gg-4zzd.6 calls out explicitly, and that
// s7comm's original implementation shipped without: per-IP scoping built on
// a broken key derivation collapses every IPv6 attacker into one shared
// bucket, while every line of the scoping code above it still reads as
// correct. llmcore and etcd shipped exactly that collapse, via a ::1
// fallback.
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
			got := RemoteHost(tc.addr)
			require.Equal(t, tc.want, got)
			// The key must also be a parseable IP, so it survives the server's
			// own normalizedRemoteIP without degrading to the ::1 fallback.
			require.NotNil(t, net.ParseIP(got),
				"state key %q must parse as an IP, or the server stores it as ::1 and "+
					"attribution collapses", got)
		})
	}
}

// A nil address (never expected in production, but defensive) must not
// panic, and must not silently produce a value that looks like a real host.
func TestRemoteHostNilAddrReturnsEmpty(t *testing.T) {
	require.Equal(t, "", RemoteHost(nil))
}
