package s7comm

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// installFakeSaveS7Comm swaps in a fake saveS7CommSession that forwards each
// captured session on a channel, restoring the real one at test cleanup --
// mirrors icsprobe's installFakeSave (icsprobe/icsprobe_test.go).
func installFakeSaveS7Comm(t *testing.T) chan *proto.S7CommSessionRequest {
	t.Helper()
	original := saveS7CommSession
	captured := make(chan *proto.S7CommSessionRequest, 4)
	saveS7CommSession = func(in *proto.S7CommSessionRequest) error {
		captured <- in
		return nil
	}
	t.Cleanup(func() { saveS7CommSession = original })
	return captured
}

func waitForS7CommCapture(t *testing.T, captured chan *proto.S7CommSessionRequest) *proto.S7CommSessionRequest {
	t.Helper()
	select {
	case req := <-captured:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("expected a captured s7comm session")
		return nil
	}
}

// assertNoS7CommCapture confirms nothing arrives on captured within a short
// window -- used for the noise-boundary case where a bare TCP connect must
// never reach persistSession's save call.
func assertNoS7CommCapture(t *testing.T, captured chan *proto.S7CommSessionRequest) {
	t.Helper()
	select {
	case req := <-captured:
		t.Fatalf("expected no captured session for a bare connect, got one with reachedStage=%q", req.ReachedStage)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestFullSessionProducesCaptureWithStageTSAPsAndOperations drives a
// realistic COTP handshake + Setup Communication + Read SZL exchange over a
// real TCP connection (the same shape as TestFullSessionOverRealTCP in
// s7comm_test.go) and confirms the session persisted on disconnect carries
// the right reachedStage, TSAPs, negotiated PDU size and operations.
func TestFullSessionProducesCaptureWithStageTSAPsAndOperations(t *testing.T) {
	addr := startTestHoneypot(t)
	captured := installFakeSaveS7Comm(t)
	conn := dialTest(t, addr)

	srcTSAP := []byte{0x01, 0x00}
	dstTSAP := []byte{0x03, 0x02}
	cr := buildTestCR(0xBEEF, srcTSAP, dstTSAP, 0x0A)
	exchange(t, conn, cr)

	setupParam := []byte{fnSetupComm, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xF0}
	exchange(t, conn, buildDT(buildS7Header(rosctrJob, 1, 0, 0, setupParam, nil)))

	szlReq := buildReadSZLRequest(2, szlComponentIdent, 0x0001)
	exchange(t, conn, buildDT(szlReq))

	conn.Close()

	req := waitForS7CommCapture(t, captured)

	if req.ReachedStage != stageIdentity {
		t.Errorf("reachedStage = %q, want %q", req.ReachedStage, stageIdentity)
	}
	if req.SrcTsap != "0x0100" || req.DstTsap != "0x0302" {
		t.Errorf("TSAPs = %q/%q, want 0x0100/0x0302", req.SrcTsap, req.DstTsap)
	}
	if req.NegotiatedPduSize != uint32(NegotiatedPDULength) {
		t.Errorf("negotiatedPduSize = %d, want %d", req.NegotiatedPduSize, NegotiatedPDULength)
	}
	if req.Guid == "" {
		t.Error("expected a non-empty guid")
	}
	if len(req.Operations) != 2 {
		t.Fatalf("operations = %d, want 2 (setup_comm, szl_read)", len(req.Operations))
	}
	if req.Operations[0].Kind != "setup_comm" || !req.Operations[0].Handled {
		t.Errorf("operations[0] = %+v, want a handled setup_comm", req.Operations[0])
	}
	if req.Operations[1].Kind != "szl_read" || !req.Operations[1].Handled {
		t.Errorf("operations[1] = %+v, want a handled szl_read", req.Operations[1])
	}
	if !strings.Contains(req.Operations[1].Detail, "0x001C") {
		t.Errorf("szl_read detail = %q, want it to mention the SZL id 0x001C", req.Operations[1].Detail)
	}
}

// TestBareConnectWithNoCOTPProducesNoCapture is the noise-boundary
// requirement: a bare TCP connect that never sends a COTP Connect Request
// is scan noise -- port 102 gets a lot of it -- and must never reach
// saveS7CommSession, matching the mistake this project already made once
// with a previous honeypot's globally-persisted noise (threat_gg-4zzd.10).
func TestBareConnectWithNoCOTPProducesNoCapture(t *testing.T) {
	addr := startTestHoneypot(t)
	captured := installFakeSaveS7Comm(t)

	conn := dialTest(t, addr)
	conn.Close() // bare connect: no COTP, no bytes at all

	assertNoS7CommCapture(t, captured)
}

// TestUnknownFunctionCodeCapturesUnhandledOperationWithRawBytes exercises
// the unhandled-request worklist for an S7 Job function code this honeypot
// does not implement: the operation must be handled=false, its kind must
// name the function code, and raw must carry the verbatim request bytes.
func TestUnknownFunctionCodeCapturesUnhandledOperationWithRawBytes(t *testing.T) {
	sess := newSession()
	param := []byte{0x77, 0xAA, 0xBB}
	data := []byte{0xCC, 0xDD}
	pdu := buildJobPDU(0x0030, param, data)

	_, ok := handlePDU(pdu, "192.0.2.50", sess)
	if !ok {
		t.Fatal("handlePDU closed the connection for a merely-unimplemented function, want it to stay open")
	}
	if len(sess.operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(sess.operations))
	}
	op := sess.operations[0]
	if op.handled {
		t.Error("an unknown function's operation must be handled=false")
	}
	if op.kind != "unknown_fn=0x77" {
		t.Errorf("kind = %q, want %q", op.kind, "unknown_fn=0x77")
	}
	wantRaw := append(append([]byte{}, param...), data...)
	if !bytes.Equal(op.raw, wantRaw) {
		t.Errorf("raw = % x, want the verbatim request % x", op.raw, wantRaw)
	}
}

// TestStageOnlyMovesForwardControlSurvivesLaterDataOp is the forward-only
// funnel requirement: once a session has reached "control" (the deepest,
// most valuable stage), a subsequent read/write must not regress
// reachedStage back to "data".
func TestStageOnlyMovesForwardControlSurvivesLaterDataOp(t *testing.T) {
	sess := newSession()
	ip := "192.0.2.51"

	stopParam := append([]byte{fnPLCStop}, []byte{0, 0, 0, 0, 0, 7, 'P', 'L', 'C', 'S', 'T', 'O', 'P'}...)
	if _, ok := handlePDU(buildJobPDU(1, stopParam, nil), ip, sess); !ok {
		t.Fatal("handlePDU(PLCStop) closed the connection")
	}
	if sess.reachedStage != stageControl {
		t.Fatalf("after PLC STOP, reachedStage = %q, want %q", sess.reachedStage, stageControl)
	}

	item := buildS7AnyItem(2 /* BYTE */, 4, 5, 0x84, 200*8)
	readParam := append([]byte{fnReadVar, 0x01}, item...)
	if _, ok := handlePDU(buildJobPDU(2, readParam, nil), ip, sess); !ok {
		t.Fatal("handlePDU(ReadVar) closed the connection")
	}

	if sess.reachedStage != stageControl {
		t.Errorf("reachedStage regressed to %q after a later data read, want it to stay %q", sess.reachedStage, stageControl)
	}
}

// TestOperationsCapAt256AndOverflowIsVisible is the truncation requirement:
// once a session accumulates maxOperations entries, further ones are only
// counted, and toProto folds that count into the last operation's detail
// rather than silently discarding evidence that truncation happened.
func TestOperationsCapAt256AndOverflowIsVisible(t *testing.T) {
	sess := newSession()
	const overflow = 10
	for i := 0; i < maxOperations+overflow; i++ {
		sess.record(operation{kind: "read_var", detail: "filler", handled: true})
	}
	if len(sess.operations) != maxOperations {
		t.Fatalf("operations = %d, want the cap %d", len(sess.operations), maxOperations)
	}
	if sess.droppedOperations != overflow {
		t.Fatalf("droppedOperations = %d, want %d", sess.droppedOperations, overflow)
	}

	req := sess.toProto("192.0.2.60", "guid-1")
	if len(req.Operations) != maxOperations {
		t.Fatalf("proto operations = %d, want the cap %d", len(req.Operations), maxOperations)
	}
	last := req.Operations[len(req.Operations)-1]
	if !strings.Contains(last.Detail, "10") {
		t.Errorf("last operation detail = %q, want it to mention the %d dropped operations", last.Detail, overflow)
	}
}

// TestPLCStopCapturedWithKindPlcStop confirms the CPU STOP request -- the
// headline capture -- is recorded with the exact expected kind.
func TestPLCStopCapturedWithKindPlcStop(t *testing.T) {
	sess := newSession()
	stopParam := append([]byte{fnPLCStop}, []byte{0, 0, 0, 0, 0, 7, 'P', 'L', 'C', 'S', 'T', 'O', 'P'}...)
	if _, ok := handlePDU(buildJobPDU(1, stopParam, nil), "192.0.2.52", sess); !ok {
		t.Fatal("handlePDU(PLCStop) closed the connection")
	}

	if len(sess.operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(sess.operations))
	}
	op := sess.operations[0]
	if op.kind != "plc_stop" || !op.handled {
		t.Errorf("operation = %+v, want a handled plc_stop", op)
	}
}

// TestUnsupportedSZLIndexCapturesUnhandledOperation covers the other named
// unhandled-request path: an SZL-ID/Index this honeypot's szlLookup doesn't
// answer (including the deliberately-withheld 0x001C/0x0009) must also
// produce a handled=false operation.
func TestUnsupportedSZLIndexCapturesUnhandledOperation(t *testing.T) {
	sess := newSession()
	pdu := buildReadSZLRequest(1, szlComponentIdent, 0x0009)
	if _, ok := handlePDU(pdu, "192.0.2.53", sess); !ok {
		t.Fatal("handlePDU(unsupported SZL) closed the connection")
	}

	if len(sess.operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(sess.operations))
	}
	op := sess.operations[0]
	if op.handled {
		t.Error("an unsupported SZL index's operation must be handled=false")
	}
	if !strings.Contains(op.kind, "0x001C") || !strings.Contains(op.kind, "0x0009") {
		t.Errorf("kind = %q, want it to identify SZL 0x001C/0x0009", op.kind)
	}
	if len(op.raw) == 0 {
		t.Error("expected raw bytes for the unsupported SZL request")
	}
}

// The unhandled-request queue is only worth anything if it is COMPLETE.
//
// Its purpose is to turn "what can our emulation not do?" from an unknown
// unknown into a ranked worklist. A request we could not answer that is NOT
// recorded is invisible -- and invisible is the exact failure the queue exists
// to prevent. So every path that declines a request must record one, not just
// the two obvious ones.
func TestEveryUnansweredRequestPathRecordsAnUnhandledOperation(t *testing.T) {
	cases := []struct {
		name        string
		payload     []byte
		wantKindSub string
	}{
		{
			// Userdata whose parameter is not the CPU-services marker.
			name:        "non_cpu_services_userdata",
			payload:     buildUserdataVariant(0x01, udFuncGroupCPU, udSubfReadSZL),
			wantKindSub: "unsupported_userdata_fn",
		},
		{
			// Userdata for a function group / subfunction we do not implement.
			name:        "unimplemented_userdata_subfunction",
			payload:     buildUserdataVariant(fnCPUServices, 0x02, 0x99),
			wantKindSub: "unsupported_userdata",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession()
			_, _ = handlePDU(tc.payload, "203.0.113.77", sess)

			var found bool
			for _, op := range sess.operations {
				if !op.handled && strings.Contains(op.kind, tc.wantKindSub) {
					found = true
					if len(op.raw) == 0 {
						t.Errorf("unhandled operation %q recorded no raw bytes; the verbatim "+
							"request is the point of the queue", op.kind)
					}
				}
			}
			if !found {
				var kinds []string
				for _, op := range sess.operations {
					kinds = append(kinds, op.kind)
				}
				t.Errorf("no unhandled operation containing %q was recorded; got kinds %v. "+
					"An unanswerable request that is not recorded is invisible.", tc.wantKindSub, kinds)
			}
		})
	}
}

// buildUserdataVariant builds a Userdata PDU with a caller-chosen parameter
// marker byte, function group and subfunction, so the decline paths can be
// exercised. buildReadSZLRequest in szl_test.go only produces the valid shape.
func buildUserdataVariant(marker byte, funcgroup, subfunc byte) []byte {
	param := []byte{
		marker, 0x01,
		varSpecType, 0x04, syntaxIDShort,
		(udTypeReq << 6) | funcgroup,
		subfunc,
		0x55,
	}
	data := make([]byte, 8)
	data[1] = dataTransportBStr
	binary.BigEndian.PutUint16(data[2:4], 4)
	binary.BigEndian.PutUint16(data[4:6], 0x0011)
	binary.BigEndian.PutUint16(data[6:8], 0x0001)
	return buildS7Header(rosctrUserdata, 1, 0, 0, param, data)
}
