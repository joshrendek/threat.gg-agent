// Package icscore holds the pieces of an ICS/SCADA protocol honeypot that do
// not belong to any single protocol: deriving the per-attacker state key from
// a connection (RemoteHost), a bounded per-attacker-IP state map (Store), and
// the session/capture scaffolding a protocol emulator accumulates one
// connection's activity into before persisting it (Session).
//
// This package was extracted from s7comm (the first ICS emulator built in
// this agent) once a second protocol (Modbus) needed the exact same
// machinery. Three things in particular are shared rather than reimplemented
// per protocol, because getting any of them wrong per-protocol has already
// cost this project real bugs:
//
//   - RemoteHost is SECURITY-RELEVANT, not a formatting convenience: every
//     piece of attacker-scoped state a protocol emulator keeps is keyed on its
//     return value, so two distinct attackers that map to the SAME key share
//     state -- llmcore and etcd both shipped exactly that collapse for IPv6
//     attackers, via a "::1" fallback that looked like ordinary defensive
//     coding.
//   - Store is the bounded LRU that makes per-attacker state actually
//     bounded; a protocol that rolls its own risks skipping the eviction bound
//     under load.
//   - Session is the stage-funnel + capped-operations + noise-boundary shape
//     that keeps a protocol's capture code honest about what to persist: a
//     bare TCP connect with no protocol activity is scan noise, not a row.
//
// Framing/wire-format code (S7comm's TPKT/COTP, Modbus's MBAP) is NOT here:
// it has no shared shape across protocols and belongs in each protocol's own
// package.
package icscore
