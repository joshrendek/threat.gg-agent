package icscore

import (
	"container/list"
	"sync"
)

// Store is a process-wide, bounded, per-attacker-IP map of protocol-specific
// state. There should be exactly one instance per protocol (e.g. s7comm's
// globalState, modbus's globalState) -- it exists so a write, a mode change,
// or whatever else one attacker IP does is never visible to another
// (threat_gg-4zzd.6): the bug this shape must not repeat is an earlier
// honeypot's globally-shared mutable emulated state, which let any anonymous
// caller change what every later visitor saw.
//
// T is the per-attacker value type each protocol defines for itself (s7comm's
// *attackerState is the precedent; Modbus defines its own). Store does not
// know or care what T looks like -- it only keys, bounds, and evicts.
//
// Generics vs. an interface: an interface would work too, but would force
// every protocol to hand-roll a get-or-create-and-type-assert at each call
// site, and a typo in that boilerplate fails silently (you just get back the
// wrong type via a bad assertion, or a needless nil check). A generic Store
// keeps that logic here once, and keeps every protocol's Get() call fully
// typed -- no assertion, no `interface{}` anywhere in PDU-handling code.
//
// T's own methods -- not Store's -- are responsible for concurrency safety
// across multiple connections from the SAME attacker IP; Store only
// serializes access to the key->value map itself.
type Store[T any] struct {
	mu       sync.Mutex
	lru      *list.List // front = most recently used
	items    map[string]*list.Element
	max      int
	newValue func() T
}

type storeEntry[T any] struct {
	key   string
	value T
}

// NewStore builds a bounded per-attacker-IP store. newValue constructs a
// fresh zero-state value for an attacker key seen for the first time; max
// bounds how many attacker keys are tracked at once -- once full, the
// least-recently-touched key is evicted to make room for a new one, so a
// scan flood from many source IPs cannot grow this map without bound.
func NewStore[T any](max int, newValue func() T) *Store[T] {
	return &Store[T]{
		lru:      list.New(),
		items:    make(map[string]*list.Element),
		max:      max,
		newValue: newValue,
	}
}

// Get returns the value for key, creating one via newValue if this is a new
// attacker. If the store is at capacity, the least-recently-used entry is
// evicted first.
//
// key MUST be derived through RemoteHost, never rolled per protocol -- see
// RemoteHost's doc comment for why a broken key derivation silently
// collapses per-attacker isolation.
func (s *Store[T]) Get(key string) T {
	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.items[key]; ok {
		s.lru.MoveToFront(el)
		return el.Value.(*storeEntry[T]).value
	}

	if s.lru.Len() >= s.max {
		oldest := s.lru.Back()
		if oldest != nil {
			s.lru.Remove(oldest)
			delete(s.items, oldest.Value.(*storeEntry[T]).key)
		}
	}

	v := s.newValue()
	el := s.lru.PushFront(&storeEntry[T]{key: key, value: v})
	s.items[key] = el
	return v
}

// Len reports how many attacker keys are currently tracked. Exposed for
// tests that need to confirm the bound actually caps memory rather than
// being decorative.
func (s *Store[T]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lru.Len()
}

// Contains reports whether key is currently tracked, without creating an
// entry or disturbing LRU order -- unlike Get, which always creates on a
// miss. Exposed for tests that need to assert an entry was (or was not)
// evicted.
func (s *Store[T]) Contains(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.items[key]
	return ok
}
