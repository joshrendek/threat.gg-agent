package s7comm

import (
	"fmt"
	"strings"

	"github.com/joshrendek/threat.gg-agent/icscore"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
)

// Session progression stages, in forward-only order -- see icscore.Session.
// These mirror S7CommSessionRequest's own doc comment (proto/honeypot.proto):
// reached_stage is a funnel, and where a client stops is the fidelity signal
// this honeypot has no reference hardware to diff against instead.
const (
	stageConnected = "connected" // TCP accept only
	stageCOTP      = "cotp"      // COTP Connect Request seen
	stageSetup     = "setup"     // S7 Setup Communication done
	stageIdentity  = "identity"  // an SZL read served
	stageData      = "data"      // a read/write variable served
	stageControl   = "control"   // a CPU control function (STOP/START/copy-RAM-to-ROM) seen
)

// sessionStages is the ordered stage list this package's sessions are built
// with -- passed to icscore.NewSession so it can rank them; stages[0] is the
// noise-boundary baseline (see icscore.Session.IsNoise).
var sessionStages = []string{stageConnected, stageCOTP, stageSetup, stageIdentity, stageData, stageControl}

const (
	// maxOperations caps how many operations one session accumulates, to
	// match the server's own validation on S7CommSessionRequest.operations.
	// Beyond this, further operations are only counted (droppedOperations),
	// never stored -- see icscore.Session.Record and session.toProto.
	maxOperations = 256

	// maxRawBytes bounds how much of an unhandled request's verbatim bytes
	// one operation retains.
	maxRawBytes = 1024

	// persistSlotsN bounds how many sessions can be in flight to the
	// control plane at once, the same bounded-queue shape mssql/kubelet use.
	persistSlotsN = 32
)

// saveS7CommSession is a package var so tests can inject a fake without a
// gRPC client -- the same pattern icsprobe/adb use for their save funcs.
var saveS7CommSession = persistence.SaveS7CommSession

// persistSlots bounds in-flight session persists; capacity persistSlotsN.
var persistSlots = make(chan struct{}, persistSlotsN)

// operation is an alias for icscore.Operation: one handled or unhandled S7
// request this honeypot answered (or couldn't) during a session. Handled=
// false + Raw is deliberately an unhandled-request queue: any function code
// or SZL index the emulator could not answer, captured verbatim -- see
// S7CommOperation's own doc comment in the proto for why this is the
// highest-value output of the whole feature.
type operation = icscore.Operation

// session accumulates everything one S7comm TCP connection did, for a
// single record sent at disconnect (see persistSession). The stage funnel
// and capped operations list are icscore.Session's job (core, below); this
// type only adds the S7comm-specific fields icscore doesn't know about
// (negotiated TSAPs/PDU size). Like icscore.Session, it is only ever touched
// by the one goroutine driving handleConnection -- unlike state.go's
// attackerState, which is genuinely shared across connections from the same
// attacker IP.
type session struct {
	core *icscore.Session

	srcTSAP           string
	dstTSAP           string
	negotiatedPDUSize uint32
}

// newSession starts a fresh accumulator at the "connected" stage: a bare TCP
// accept, nothing more yet.
func newSession() *session {
	return &session{core: icscore.NewSession(sessionStages, maxOperations, maxRawBytes)}
}

// advance moves reachedStage forward to stage if stage is further along
// than whatever has already been reached. It never regresses: a shallower
// stage reached later in the same connection (e.g. a data read served after
// a CPU STOP) cannot erase evidence of the deepest stage actually reached.
func (s *session) advance(stage string) {
	s.core.Advance(stage)
}

// setTSAPs records the COTP-negotiated TSAP pair, hex-formatted the way the
// brief's own example shows ("0x0100"). COTP negotiates exactly once per
// connection, so this is only ever called once.
func (s *session) setTSAPs(src, dst []byte) {
	s.srcTSAP = hexTSAP(src)
	s.dstTSAP = hexTSAP(dst)
}

func (s *session) setNegotiatedPDUSize(n uint32) {
	s.negotiatedPDUSize = n
}

// record appends one operation. Once the session is at maxOperations, it
// stops growing the slice and only counts the drop -- see toProto, which
// folds the count into the last stored operation's detail so truncation is
// visible in the persisted record rather than silently losing data.
func (s *session) record(op operation) {
	s.core.Record(op)
}

// toProto builds the wire request this session's activity is sent as.
func (s *session) toProto(remoteAddr, guid string) *proto.S7CommSessionRequest {
	coreOps := s.core.Operations()
	dropped := s.core.DroppedOperations()

	ops := make([]*proto.S7CommOperation, len(coreOps))
	for i, op := range coreOps {
		detail := op.Detail
		if dropped > 0 && i == len(coreOps)-1 {
			// Fold the drop into the last operation's detail rather than
			// dropping it silently -- the cap is real (maxOperations), but an
			// operator reading the record must be able to see that it was
			// hit, not just see a suspiciously round 256 and wonder.
			detail = icscore.DropNote(detail, dropped, maxOperations)
		}
		ops[i] = &proto.S7CommOperation{
			Kind:    op.Kind,
			Detail:  detail,
			Raw:     op.Raw,
			Handled: op.Handled,
		}
	}
	return &proto.S7CommSessionRequest{
		RemoteAddr:        remoteAddr,
		Guid:              guid,
		SrcTsap:           s.srcTSAP,
		DstTsap:           s.dstTSAP,
		NegotiatedPduSize: s.negotiatedPDUSize,
		ReachedStage:      s.core.ReachedStage(),
		Operations:        ops,
		DurationMs:        uint32(s.core.Duration().Milliseconds()),
	}
}

// persistSession sends sess if -- and only if -- the connection got past a
// bare TCP connect. A bare connect with no COTP is scan noise; port 102
// receives a lot of it, and persisting every one of those would repeat the
// mistake that filled a previous honeypot's tables with ~95% junk
// (threat_gg-4zzd.10, the llmcore/etcd noise filter). Everything past
// "connected" (i.e. a real COTP Connect Request was seen) is a genuine
// protocol attempt worth a row.
func persistSession(logger zerolog.Logger, remoteAddr string, sess *session) {
	if sess.core.IsNoise() {
		logger.Debug().Str("remote", remoteAddr).Msg("s7comm: dropping bare-connect session (no COTP) as scan noise")
		return
	}

	guid := uuid.NewV4().String()
	req := sess.toProto(remoteAddr, guid)

	// Capture the package vars BEFORE spawning the goroutine (kubelet/
	// kubelet.go:135, mssql/mssql.go's persist). Reading persistSlots/
	// saveS7CommSession from inside the goroutine is a data race
	// (threat_gg-x59t): tests swap these in setup and restore them in
	// t.Cleanup, so a goroutine still in flight from an earlier test would
	// otherwise read the var while the next test writes it.
	slots := persistSlots
	save := saveS7CommSession
	select {
	case slots <- struct{}{}:
		go func() {
			defer func() { <-slots }()
			if err := save(req); err != nil {
				logger.Error().Err(err).Str("remote", remoteAddr).Msg("s7comm: failed to persist session")
			}
		}()
	default:
		logger.Warn().Str("remote", remoteAddr).Msg("s7comm: dropping session, persistence queue full")
	}
}

// hexTSAP renders a TSAP byte string the conventional way ("0x0100"). An
// empty/never-negotiated TSAP renders as "".
func hexTSAP(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return fmt.Sprintf("0x%X", b)
}

// s7AreaName maps an S7ANY area code to the short label real S7 addressing
// notation uses. Verified against s7comm_decode_param_item's own
// area_names table (packet-s7comm.h): 0x81 Inputs, 0x82 Outputs, 0x83
// Merkers/flags, 0x84 Data blocks (also used as the DB area code in
// state_test.go's areaDBForTest). This is only used to build a readable
// capture `detail` string -- it has no effect on wire behaviour.
func s7AreaName(area byte) string {
	switch area {
	case 0x81:
		return "I"
	case 0x82:
		return "Q"
	case 0x83:
		return "M"
	case 0x84:
		return "DB"
	default:
		return fmt.Sprintf("area(0x%02X)", area)
	}
}

// formatAddressDetail renders one S7ANY item address the way an operator
// expects to read it (e.g. "DB1.DBB0 len=4"), n being the byte length
// already resolved by the caller (itemByteLen for reads, the parsed wire
// length for writes).
func formatAddressDetail(item s7AnyItem, n int) string {
	name := s7AreaName(item.area)
	if name == "DB" {
		return fmt.Sprintf("DB%d.DBB%d len=%d", item.db, item.byteOffset, n)
	}
	return fmt.Sprintf("%s%d len=%d", name, item.byteOffset, n)
}

// maxListedItems bounds how many individual item addresses joinItemDetails
// spells out; a request with more items than this still gets a useful
// detail string, just not an unbounded one.
const maxListedItems = 8

// joinItemDetails builds one bounded detail string describing every item a
// Read/Write Var request touched. items and lens must be the same length
// (lens[i] is the resolved byte length for items[i]).
func joinItemDetails(items []s7AnyItem, lens []int) string {
	n := len(items)
	if n == 0 {
		return ""
	}
	listed := n
	if listed > maxListedItems {
		listed = maxListedItems
	}
	parts := make([]string, 0, listed)
	for i := 0; i < listed; i++ {
		parts = append(parts, formatAddressDetail(items[i], lens[i]))
	}
	detail := strings.Join(parts, "; ")
	if n > maxListedItems {
		detail += fmt.Sprintf(" (+%d more items)", n-maxListedItems)
	}
	return detail
}

// unsupportedSZLOperation builds the unhandled-request operation for an
// SZL-ID/Index this honeypot's szlLookup doesn't answer -- including the
// deliberately-withheld 0x001C/0x0009 (see persona.go). raw is the
// Userdata data section, which carries the SZL-ID/Index the caller asked
// for, capped by record() at maxRawBytes.
func unsupportedSZLOperation(szlID, szlIdx uint16, raw []byte) operation {
	return operation{
		Kind:    fmt.Sprintf("unsupported_szl=0x%04X/0x%04X", szlID, szlIdx),
		Detail:  fmt.Sprintf("szl_id=0x%04X index=0x%04X requested, not implemented by this honeypot", szlID, szlIdx),
		Raw:     raw,
		Handled: false,
	}
}
