package modbus

import (
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

// testLogger is a discard logger: these tests assert on what reaches the
// control plane, not on log output.
func testLogger() zerolog.Logger { return zerolog.Nop() }

// installFakeSaveModbus swaps in a fake saveModbusSession that forwards each
// captured session on a channel, restoring the real one at test cleanup --
// mirrors s7comm's installFakeSaveS7Comm.
func installFakeSaveModbus(t *testing.T) chan *proto.ModbusSessionRequest {
	t.Helper()
	original := saveModbusSession
	captured := make(chan *proto.ModbusSessionRequest, 4)
	saveModbusSession = func(in *proto.ModbusSessionRequest) error {
		captured <- in
		return nil
	}
	t.Cleanup(func() { saveModbusSession = original })
	return captured
}

func waitForModbusCapture(t *testing.T, captured chan *proto.ModbusSessionRequest) *proto.ModbusSessionRequest {
	t.Helper()
	select {
	case req := <-captured:
		return req
	case <-time.After(5 * time.Second):
		t.Fatal("expected a captured modbus session")
		return nil
	}
}

// assertNoModbusCapture confirms nothing arrives on captured within a short
// window -- used for the noise-boundary case where a bare TCP connect must
// never reach persistSession's save call.
func assertNoModbusCapture(t *testing.T, captured chan *proto.ModbusSessionRequest) {
	t.Helper()
	select {
	case req := <-captured:
		t.Fatalf("expected no captured session for a bare connect, got one with reachedStage=%q", req.ReachedStage)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestFullSessionProducesCaptureWithUnitIDsAndTransactionIDs drives a
// realistic read + write + device-id exchange over a real TCP connection and
// confirms the session persisted on disconnect carries the MBAP observations
// this honeypot exists to collect.
func TestFullSessionProducesCaptureWithUnitIDsAndTransactionIDs(t *testing.T) {
	addr := startTestHoneypot(t)
	captured := installFakeSaveModbus(t)
	conn := dialTest(t, addr)

	exchange(t, conn, buildRequest(0x0010, 0x01, []byte{fnReadHoldingRegs, 0x00, 0x0A, 0x00, 0x02}))
	exchange(t, conn, buildRequest(0x0011, 0x01, []byte{fnWriteSingleReg, 0x00, 0x0A, 0x12, 0x34}))
	exchange(t, conn, buildRequest(0x0012, 0x02, []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDBasic, 0x00}))
	conn.Close()

	req := waitForModbusCapture(t, captured)

	// A write happened, so the funnel must report its deepest stage even
	// though a device-id read (a shallower stage) came afterwards.
	if req.ReachedStage != stageWrite {
		t.Errorf("ReachedStage = %q, want %q", req.ReachedStage, stageWrite)
	}
	if got, want := len(req.UnitIds), 2; got != want {
		t.Fatalf("len(UnitIds) = %d, want %d (%v)", got, want, req.UnitIds)
	}
	if req.UnitIds[0] != 1 || req.UnitIds[1] != 2 {
		t.Errorf("UnitIds = %v, want [1 2] in first-seen order", req.UnitIds)
	}
	if req.FirstTransactionId != 0x0010 {
		t.Errorf("FirstTransactionId = %d, want %d", req.FirstTransactionId, 0x0010)
	}
	if req.LastTransactionId != 0x0012 {
		t.Errorf("LastTransactionId = %d, want %d", req.LastTransactionId, 0x0012)
	}
	if req.RequestCount != 3 {
		t.Errorf("RequestCount = %d, want 3", req.RequestCount)
	}
	if len(req.Operations) == 0 {
		t.Error("expected operations to be captured")
	}
	if req.Guid == "" {
		t.Error("expected a guid on the captured session")
	}
}

// TestBareConnectProducesNoCapture is the noise boundary: port 502 draws
// heavy scan traffic, and a TCP connect that never sends a valid frame must
// not become a row (threat_gg-4zzd.10).
func TestBareConnectProducesNoCapture(t *testing.T) {
	addr := startTestHoneypot(t)
	captured := installFakeSaveModbus(t)

	conn := dialTest(t, addr)
	conn.Close()

	assertNoModbusCapture(t, captured)
}

// TestDeclinedRequestStillContributesUnitIDAndCount pins the reason
// recordFrame runs before dispatch: a function code we do not implement still
// reveals which unit the client was hunting for, and that is signal we must
// not throw away just because we answered with an exception.
func TestDeclinedRequestStillContributesUnitIDAndCount(t *testing.T) {
	addr := startTestHoneypot(t)
	captured := installFakeSaveModbus(t)
	conn := dialTest(t, addr)

	// 0x64 is not a function code this honeypot implements.
	exchange(t, conn, buildRequest(0x0020, 0x2A, []byte{0x64, 0x00, 0x00, 0x00, 0x00}))
	conn.Close()

	req := waitForModbusCapture(t, captured)
	if req.RequestCount != 1 {
		t.Errorf("RequestCount = %d, want 1 -- a declined frame is still a frame", req.RequestCount)
	}
	if len(req.UnitIds) != 1 || req.UnitIds[0] != 0x2A {
		t.Errorf("UnitIds = %v, want [42] -- the addressed unit must survive a declined function", req.UnitIds)
	}
	// The whole point of the unhandled-request queue: this must be visible as
	// something we could not answer, with its bytes retained.
	var sawUnhandled bool
	for _, op := range req.Operations {
		if !op.Handled && len(op.Raw) > 0 {
			sawUnhandled = true
		}
	}
	if !sawUnhandled {
		t.Error("expected an unhandled operation with raw bytes for an unimplemented function code")
	}
}

// TestRecordFrameDedupesUnitIDsPreservingFirstSeenOrder exercises the
// ordering guarantee directly, without TCP. Order is the signal -- a client
// walking unit ids is sweeping, one that stays on a single id already knows
// the device -- so a sorted or set-shaped field would destroy the thing this
// is here to capture.
func TestRecordFrameDedupesUnitIDsPreservingFirstSeenOrder(t *testing.T) {
	sess := newSession()
	for _, hdr := range []mbapHeader{
		{transactionID: 5, unitID: 9},
		{transactionID: 6, unitID: 3},
		{transactionID: 7, unitID: 9}, // repeat -- must not appear twice
		{transactionID: 8, unitID: 1},
		{transactionID: 9, unitID: 3}, // repeat
	} {
		sess.recordFrame(hdr)
	}

	want := []uint32{9, 3, 1}
	if len(sess.unitIDs) != len(want) {
		t.Fatalf("unitIDs = %v, want %v", sess.unitIDs, want)
	}
	for i := range want {
		if sess.unitIDs[i] != want[i] {
			t.Fatalf("unitIDs = %v, want %v", sess.unitIDs, want)
		}
	}
	if sess.firstTxID != 5 {
		t.Errorf("firstTxID = %d, want 5", sess.firstTxID)
	}
	if sess.lastTxID != 9 {
		t.Errorf("lastTxID = %d, want 9", sess.lastTxID)
	}
	if sess.requestCount != 5 {
		t.Errorf("requestCount = %d, want 5 -- counts frames, not distinct units", sess.requestCount)
	}
}

// TestUnitIDsAreBoundedByTheCompleteByteSpace confirms the cap holds under a
// full sweep. A unit id is one byte, so 256 is the entire space -- the server
// rejects anything above it (maxModbusUnitIDs in grpc_server/modbus.go), and
// this is the agent-side half of that agreement.
func TestUnitIDsAreBoundedByTheCompleteByteSpace(t *testing.T) {
	sess := newSession()
	for i := 0; i < 300; i++ {
		sess.recordFrame(mbapHeader{transactionID: uint16(i), unitID: byte(i)})
	}
	if len(sess.unitIDs) > maxUnitIDs {
		t.Errorf("len(unitIDs) = %d, want <= %d", len(sess.unitIDs), maxUnitIDs)
	}
	if sess.requestCount != 300 {
		t.Errorf("requestCount = %d, want 300 -- the cap bounds distinct ids, not the frame count", sess.requestCount)
	}
}

// TestToProtoFoldsOperationDropCountIntoLastDetail keeps truncation visible.
// An operator reading a record capped at exactly maxOperations must be able to
// tell the cap was hit rather than see a suspiciously round number.
func TestToProtoFoldsOperationDropCountIntoLastDetail(t *testing.T) {
	sess := newSession()
	sess.advance(stageEngaged)
	for i := 0; i < maxOperations+5; i++ {
		sess.record(operation{Kind: "read_holding_regs", Detail: "addr=1 qty=1", Handled: true})
	}

	req := sess.toProto("192.0.2.10", "test-guid")
	if len(req.Operations) != maxOperations {
		t.Fatalf("len(Operations) = %d, want %d", len(req.Operations), maxOperations)
	}
	last := req.Operations[len(req.Operations)-1].Detail
	if last == "addr=1 qty=1" {
		t.Errorf("last operation detail = %q, want a visible drop note", last)
	}
}

// TestNoiseSessionIsNeverSent guards the boundary at the persistSession level
// rather than over TCP, so a future refactor that moves the IsNoise check
// still fails loudly here.
func TestNoiseSessionIsNeverSent(t *testing.T) {
	captured := installFakeSaveModbus(t)
	sess := newSession() // never advanced past "connected"

	persistSession(testLogger(), "192.0.2.99", sess)

	assertNoModbusCapture(t, captured)
}
