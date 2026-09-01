package modbus

import (
	"github.com/joshrendek/threat.gg-agent/icscore"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
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

	// persistSlotsN bounds how many sessions can be in flight to the control
	// plane at once, the same bounded-queue shape s7comm/mssql/kubelet use.
	persistSlotsN = 32

	// maxUnitIDs is the complete space of MBAP unit identifiers (one byte), so
	// this is a natural bound rather than a chosen one -- a session cannot
	// address more distinct units than exist. Matches maxModbusUnitIDs in the
	// server's grpc_server/modbus.go, which rejects anything above it.
	maxUnitIDs = 256
)

// saveModbusSession is a package var so tests can inject a fake without a
// gRPC client -- the same pattern s7comm/icsprobe/adb use for their save funcs.
var saveModbusSession = persistence.SaveModbusSession

// persistSlots bounds in-flight session persists; capacity persistSlotsN.
var persistSlots = make(chan struct{}, persistSlotsN)

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
// from the same attacker IP. That single-goroutine confinement is what lets
// the MBAP observation fields below be plain values with no mutex.
type session struct {
	core *icscore.Session

	// Raw MBAP observations, recorded uninterpreted. Modbus/TCP has no
	// handshake, so unlike s7comm there is no negotiated value to fingerprint
	// the client stack with -- these behavioural facts are the substitute, and
	// deliberately carry no agent-side classification. See
	// ModbusSessionRequest in honeypot.proto for the full reasoning.
	unitIDs      []uint32      // distinct, in order first seen, bounded by maxUnitIDs
	seenUnitID   map[byte]bool // dedup set for unitIDs
	firstTxID    uint16        // transaction id of the first valid frame
	lastTxID     uint16        // transaction id of the most recent valid frame
	requestCount uint32        // valid frames received, including those we declined to answer
}

// newSession starts a fresh accumulator at the "connected" stage: a bare
// TCP accept, nothing more yet.
func newSession() *session {
	return &session{
		core:       icscore.NewSession(sessionStages, maxOperations, maxRawBytes),
		seenUnitID: make(map[byte]bool),
	}
}

func (s *session) advance(stage string) { s.core.Advance(stage) }
func (s *session) record(op operation)  { s.core.Record(op) }

// recordFrame notes the MBAP-layer facts about one syntactically valid frame.
// It is called for every frame that parses, BEFORE dispatch decides whether
// the function code is one this honeypot implements -- a request we decline
// still tells us which unit the client was hunting for, and declining is
// itself part of what we want to measure.
//
// requestCount counts frames rather than answers for the same reason.
func (s *session) recordFrame(hdr mbapHeader) {
	if s.requestCount == 0 {
		s.firstTxID = hdr.transactionID
	}
	s.lastTxID = hdr.transactionID
	s.requestCount++

	// Distinct unit ids in first-seen order. The order is the point: a client
	// walking 0,1,2,3... is sweeping, one that opens on unit 1 and stays there
	// already knows the device. A sorted or set-shaped field would destroy
	// exactly the signal this is here to capture.
	if !s.seenUnitID[hdr.unitID] && len(s.unitIDs) < maxUnitIDs {
		s.seenUnitID[hdr.unitID] = true
		s.unitIDs = append(s.unitIDs, uint32(hdr.unitID))
	}
}

// toProto builds the wire request this session's activity is sent as.
func (s *session) toProto(remoteAddr, guid string) *proto.ModbusSessionRequest {
	coreOps := s.core.Operations()
	dropped := s.core.DroppedOperations()

	ops := make([]*proto.ModbusOperation, len(coreOps))
	for i, op := range coreOps {
		detail := op.Detail
		if dropped > 0 && i == len(coreOps)-1 {
			// Fold the drop into the last operation's detail rather than
			// dropping it silently -- the cap is real (maxOperations), but an
			// operator reading the record must be able to see that it was
			// hit, not just see a suspiciously round 256 and wonder.
			detail = icscore.DropNote(detail, dropped, maxOperations)
		}
		ops[i] = &proto.ModbusOperation{
			Kind:    op.Kind,
			Detail:  detail,
			Raw:     op.Raw,
			Handled: op.Handled,
		}
	}
	return &proto.ModbusSessionRequest{
		RemoteAddr:         remoteAddr,
		Guid:               guid,
		UnitIds:            s.unitIDs,
		FirstTransactionId: uint32(s.firstTxID),
		LastTransactionId:  uint32(s.lastTxID),
		RequestCount:       s.requestCount,
		ReachedStage:       s.core.ReachedStage(),
		Operations:         ops,
		DurationMs:         uint32(s.core.Duration().Milliseconds()),
	}
}

// persistSession sends sess if -- and only if -- the connection got past a
// bare TCP connect. A bare connect with no valid MBAP+PDU frame is scan
// noise; port 502 receives a great deal of it, and persisting every one of
// those would repeat the mistake that filled a previous honeypot's tables
// with ~95% junk (threat_gg-4zzd.10, the llmcore/etcd noise filter).
// Everything past "connected" is a genuine protocol attempt worth a row.
func persistSession(logger zerolog.Logger, remoteAddr string, sess *session) {
	if sess.core.IsNoise() {
		logger.Debug().Str("remote", remoteAddr).Msg("modbus: dropping bare-connect session (no valid PDU) as scan noise")
		return
	}

	guid := uuid.NewV4().String()
	req := sess.toProto(remoteAddr, guid)

	// Capture the package vars BEFORE spawning the goroutine (s7comm's
	// persistSession, kubelet/kubelet.go:135, mssql/mssql.go's persist).
	// Reading persistSlots/saveModbusSession from inside the goroutine is a
	// data race (threat_gg-x59t): tests swap these in setup and restore them
	// in t.Cleanup, so a goroutine still in flight from an earlier test would
	// otherwise read the var while the next test writes it.
	slots := persistSlots
	save := saveModbusSession
	select {
	case slots <- struct{}{}:
		go func() {
			defer func() { <-slots }()
			if err := save(req); err != nil {
				logger.Error().Err(err).Str("remote", remoteAddr).Msg("modbus: failed to persist session")
			}
		}()
	default:
		logger.Warn().Str("remote", remoteAddr).Msg("modbus: dropping session, persistence queue full")
	}
}
