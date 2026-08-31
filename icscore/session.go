package icscore

import (
	"fmt"
	"time"
)

// Operation is one handled or unhandled request a protocol honeypot
// answered (or couldn't) during a session. handled=false + Raw is
// deliberately an unhandled-request queue: any function/command/index the
// emulator could not answer, captured verbatim, so a future extension has
// real bytes to work from rather than a description of what was missed.
type Operation struct {
	Kind    string
	Detail  string
	Raw     []byte
	Handled bool
}

// Session accumulates everything one connection did, for a single record
// sent at disconnect. It is only ever meant to be touched by the one
// goroutine driving that connection -- unlike a Store[T] value, which IS
// shared across connections from the same attacker IP and must lock
// internally.
//
// Stage names and their relative order are supplied by the protocol at
// construction (S7comm: connected/cotp/setup/identity/data/control; Modbus
// has its own), because they differ per protocol -- Session only knows their
// relative order, not their meaning.
type Session struct {
	stageOrder   map[string]int
	baseStage    string
	reachedStage string

	operations        []Operation
	droppedOperations int
	maxOperations     int
	maxRawBytes       int

	startedAt time.Time
}

// NewSession starts a fresh accumulator at stages[0] -- which must be the
// bare "connection accepted, nothing else yet" stage; see IsNoise -- and
// ranks the rest of stages by their position in the slice. maxOperations and
// maxRawBytes bound how much one session accumulates before growth stops;
// see Record.
func NewSession(stages []string, maxOperations, maxRawBytes int) *Session {
	order := make(map[string]int, len(stages))
	for i, s := range stages {
		order[s] = i
	}
	var base string
	if len(stages) > 0 {
		base = stages[0]
	}
	return &Session{
		stageOrder:    order,
		baseStage:     base,
		reachedStage:  base,
		maxOperations: maxOperations,
		maxRawBytes:   maxRawBytes,
		startedAt:     time.Now(),
	}
}

// Advance moves the reached stage forward to stage if stage is further along
// than whatever has already been reached. It never regresses: a shallower
// stage reached later in the same connection (e.g. a data read served after
// a control-plane write) cannot erase evidence of the deepest stage actually
// reached.
func (s *Session) Advance(stage string) {
	if s.stageOrder[stage] > s.stageOrder[s.reachedStage] {
		s.reachedStage = stage
	}
}

// ReachedStage reports the deepest stage this session has reached.
func (s *Session) ReachedStage() string { return s.reachedStage }

// IsNoise reports whether this session never progressed past the bare
// baseline stage (stages[0] at construction) -- i.e. a TCP accept with no
// protocol activity at all. Persisting these repeats the mistake that filled
// a previous honeypot's tables with ~95% scan junk (threat_gg-4zzd.10, the
// llmcore/etcd noise filter): a bare connect on a well-known ICS port is scan
// noise, not a genuine protocol attempt.
func (s *Session) IsNoise() bool {
	return s.reachedStage == s.baseStage
}

// Record appends one operation, subject to the maxOperations cap: once a
// session is at capacity, further operations are only counted (see
// DroppedOperations), never stored, so a scripted flood within a single
// connection can't grow the eventual persisted record without bound. Raw is
// truncated to maxRawBytes and copied so later mutation of the caller's
// backing array can't corrupt what was recorded.
func (s *Session) Record(op Operation) {
	if len(s.operations) >= s.maxOperations {
		s.droppedOperations++
		return
	}
	if len(op.Raw) > s.maxRawBytes {
		op.Raw = op.Raw[:s.maxRawBytes]
	}
	if len(op.Raw) > 0 {
		op.Raw = append([]byte(nil), op.Raw...)
	}
	s.operations = append(s.operations, op)
}

// Operations returns the operations recorded so far, capped at
// maxOperations -- see Record.
func (s *Session) Operations() []Operation { return s.operations }

// DroppedOperations reports how many operations past the maxOperations cap
// were only counted, not stored.
func (s *Session) DroppedOperations() int { return s.droppedOperations }

// Duration reports how long this session has been open.
func (s *Session) Duration() time.Duration { return time.Since(s.startedAt) }

// DropNote folds a dropped-operations count into an operation's detail
// string, the way s7comm's original toProto did, so truncation is visible in
// the persisted record rather than silently lost. It returns detail
// unchanged when dropped is zero. Protocols call this themselves when
// building their own persistence message, since that message's shape and cap
// constant belong to the protocol, not icscore.
func DropNote(detail string, dropped, cap int) string {
	if dropped <= 0 {
		return detail
	}
	return fmt.Sprintf("%s [+%d further operations dropped past the %d-operation cap]", detail, dropped, cap)
}
