package modbus

import (
	"github.com/joshrendek/threat.gg-agent/icscore"
	"github.com/rs/zerolog"
)

// Session progression stages, in forward-only order -- see icscore.Session.
const (
	stageConnected = "connected" // TCP accept only, no valid MBAP+PDU frame yet
	stageEngaged   = "engaged"   // at least one valid MBAP+PDU frame was received, whatever its function code
	stageIdentity  = "identity"  // Read Device Identification served -- Modbus's fingerprinting equivalent of S7comm's SZL read
	stageRead      = "read"      // a coil/discrete-input/register read served
	stageWrite     = "write"     // a coil/register write served -- an attempt to change physical state, the high-signal capture
)

// sessionStages is the ordered stage list this package's sessions are built
// with -- passed to icscore.NewSession so it can rank them; stages[0] is
// the noise-boundary baseline (see icscore.Session.IsNoise).
var sessionStages = []string{stageConnected, stageEngaged, stageIdentity, stageRead, stageWrite}

const (
	// maxOperations caps how many operations one session accumulates.
	// Beyond this, further operations are only counted, never stored -- see
	// icscore.Session.Record.
	maxOperations = 256

	// maxRawBytes bounds how much of an unhandled request's verbatim bytes
	// one operation retains.
	maxRawBytes = 1024
)

// operation is an alias for icscore.Operation: one handled or unhandled
// Modbus request this honeypot answered (or couldn't) during a session.
// Handled=false + Raw is deliberately an unhandled-request queue: any
// function code, MEI type, or read-device-id code the emulator could not
// answer, captured verbatim.
type operation = icscore.Operation

// session accumulates everything one Modbus/TCP connection did, for a
// single record at disconnect. The stage funnel and capped operations list
// are icscore.Session's job; this type is a thin wrapper so call sites read
// the same way s7comm's session does. Like icscore.Session, it is only ever
// touched by the one goroutine driving handleConnection -- unlike
// state.go's attackerState, which is genuinely shared across connections
// from the same attacker IP.
type session struct {
	core *icscore.Session
}

// newSession starts a fresh accumulator at the "connected" stage: a bare
// TCP accept, nothing more yet.
func newSession() *session {
	return &session{core: icscore.NewSession(sessionStages, maxOperations, maxRawBytes)}
}

func (s *session) advance(stage string) { s.core.Advance(stage) }
func (s *session) record(op operation)  { s.core.Record(op) }

// persistSession applies the same noise boundary s7comm's persistSession
// does (a bare TCP connect with no genuine protocol activity is scan
// noise, not a row -- threat_gg-4zzd.10, the llmcore/etcd noise filter) and
// logs the outcome locally.
//
// TODO(capture): this does not yet send anything to the control plane. That
// requires a proto.ModbusSessionRequest message and a
// persistence.SaveModbusSession RPC, mirroring S7CommSessionRequest /
// SaveS7CommSession -- both server-side changes out of scope here (the
// brief is explicit: no proto message, no persistence/ changes in this
// commit). Once those exist, this function should build the request from
// sess (core.ReachedStage(), core.Operations(), core.DroppedOperations(),
// core.Duration() -- see s7comm/capture.go's toProto for the exact shape,
// including icscore.DropNote for folding a truncation count into the last
// operation's detail) and send it through the same package-var-save-func +
// bounded-persistSlots-channel pattern persistSession uses there, then
// delete this log line.
func persistSession(logger zerolog.Logger, remoteAddr string, sess *session) {
	if sess.core.IsNoise() {
		logger.Debug().Str("remote", remoteAddr).Msg("modbus: dropping bare-connect session (no valid PDU) as scan noise")
		return
	}

	logger.Info().
		Str("remote", remoteAddr).
		Str("reached_stage", sess.core.ReachedStage()).
		Int("operations", len(sess.core.Operations())).
		Int("dropped_operations", sess.core.DroppedOperations()).
		Msg("modbus: session ended (TODO(capture): not yet persisted to the control plane)")
}
