package modbus

import (
	"sync"

	"github.com/joshrendek/threat.gg-agent/icscore"
)

// maxTrackedAttackers bounds the per-IP state map, mirroring s7comm's
// precedent (threat_gg-4zzd.6): once full, the least-recently-touched
// attacker is evicted to make room for a new one, so a scan flood from many
// source IPs cannot grow this map without bound.
const maxTrackedAttackers = 2000

// attackerState is everything this honeypot remembers about ONE attacker
// IP: coils and holding registers it has written. It is never shared across
// IPs -- see globalState, the only way to obtain one, and icscore.Store,
// which enforces that.
//
// Discrete inputs and input registers carry NO attacker-scoped state at
// all: real Modbus has no write function code for either (they are
// physically read-only on real hardware), so there is nothing for an
// attacker to write and nothing to isolate -- reads of those two tables
// always go straight to driftWord/driftBit instead. Only coils and holding
// registers are writable, so only they need per-attacker isolation.
type attackerState struct {
	mu      sync.Mutex
	coils   map[uint16]bool
	holding map[uint16]uint16
}

// writeCoil records a coil write for this attacker only.
func (s *attackerState) writeCoil(addr uint16, v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.coils == nil {
		s.coils = make(map[uint16]bool)
	}
	s.coils[addr] = v
}

// readCoil returns this SAME attacker's previous write to addr, or --if this
// attacker never wrote there-- a value from driftBit. It never returns a
// value some OTHER attacker wrote.
func (s *attackerState) readCoil(addr uint16) bool {
	s.mu.Lock()
	v, ok := s.coils[addr]
	s.mu.Unlock()
	if ok {
		return v
	}
	return driftBit(addr)
}

// writeHolding records a holding-register write for this attacker only.
func (s *attackerState) writeHolding(addr uint16, v uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.holding == nil {
		s.holding = make(map[uint16]uint16)
	}
	s.holding[addr] = v
}

// readHolding returns this SAME attacker's previous write to addr, or -- if
// this attacker never wrote there -- a value from driftWord.
func (s *attackerState) readHolding(addr uint16) uint16 {
	s.mu.Lock()
	v, ok := s.holding[addr]
	s.mu.Unlock()
	if ok {
		return v
	}
	return driftWord(addr)
}

// globalState is the single per-IP state map this whole package's PDU
// handlers read and write through. The bounded-LRU mechanics live in
// icscore.Store (shared with s7comm and every other icscore-based
// protocol); this package only supplies its own per-attacker value type
// (attackerState above) and the bound (maxTrackedAttackers).
var globalState = icscore.NewStore(maxTrackedAttackers, func() *attackerState {
	return &attackerState{}
})
