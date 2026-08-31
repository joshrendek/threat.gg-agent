package icscore

import (
	"net"
	"strings"
)

// RemoteHost derives the per-attacker state key from a connection address.
//
// This is a SECURITY-RELEVANT function, not a formatting convenience
// (threat_gg-4zzd.6, and the reason it now lives here rather than being
// reimplemented per protocol). Every piece of attacker-scoped state an ICS
// honeypot keeps -- written data blocks/registers/coils, CPU run/stop mode,
// whatever else a given protocol invents -- is keyed on this function's
// return value, so two distinct attackers that map to the SAME key share
// state: one can then observe or clobber the other's writes, which both
// disarms the honeypot and proves it synthetic.
//
// IPv6 is where that goes wrong quietly. conn.RemoteAddr().String() renders
// an IPv6 peer as "[2001:db8::1]:54321"; SplitHostPort yields the bare
// "2001:db8::1", which is correct and distinct per attacker. Get this wrong
// -- return the bracketed form inconsistently, or fall back to a constant on
// a parse failure -- and every IPv6 attacker collapses into one shared
// bucket while all the scoping code built on top of it still looks correct.
// That collapse is exactly what llmcore and etcd shipped.
//
// Every protocol built on icscore MUST call this shared function rather than
// deriving its own key: re-deriving it per protocol is exactly how that bug
// recurs, quietly, in the next honeypot.
func RemoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	s := addr.String()
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		return host
	}
	// No port present: strip brackets from a bare IPv6 literal if any.
	return strings.Trim(s, "[]")
}
