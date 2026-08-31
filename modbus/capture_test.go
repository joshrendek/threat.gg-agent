package modbus

import "testing"

// TestNewSessionStartsAtConnectedAndIsNoise confirms a fresh session starts
// at the "connected" baseline and reads as noise -- a bare TCP connect,
// nothing more.
func TestNewSessionStartsAtConnectedAndIsNoise(t *testing.T) {
	sess := newSession()
	if sess.core.ReachedStage() != stageConnected {
		t.Errorf("reachedStage = %q, want %q", sess.core.ReachedStage(), stageConnected)
	}
	if !sess.core.IsNoise() {
		t.Error("a fresh session with no activity must be noise")
	}
}

// TestWriteIsTheDeepestStageAndSurvivesLaterReads is the forward-only
// funnel requirement: once a session has reached "write" (the deepest,
// most valuable stage -- an attempt to change physical state), a
// subsequent read must not regress reachedStage back to "read".
func TestWriteIsTheDeepestStageAndSurvivesLaterReads(t *testing.T) {
	ip := "192.0.2.60"
	sess := newSession()

	writeReq := []byte{fnWriteSingleReg, 0x00, 0x00, 0x00, 0x01}
	handlePDU(writeReq, ip, sess)
	if sess.core.ReachedStage() != stageWrite {
		t.Fatalf("after a write, reachedStage = %q, want %q", sess.core.ReachedStage(), stageWrite)
	}

	readReq := []byte{fnReadHoldingRegs, 0x00, 0x00, 0x00, 0x01}
	handlePDU(readReq, ip, sess)
	if sess.core.ReachedStage() != stageWrite {
		t.Errorf("reachedStage regressed to %q after a later read, want it to stay %q", sess.core.ReachedStage(), stageWrite)
	}
}

// TestUnknownFunctionCodeIsNotNoise confirms a session that only ever sent
// an unsupported function code is NOT bare-connect noise: it still made a
// genuine protocol attempt (see modbus.go's stageEngaged advance), even
// though this honeypot couldn't answer the specific function.
//
// handlePDU itself doesn't call sess.advance(stageEngaged) -- that happens
// in handleConnection once MBAP framing succeeds -- so this test drives it
// explicitly, the same way handleConnection would.
func TestUnknownFunctionCodeIsNotNoise(t *testing.T) {
	sess := newSession()
	sess.advance(stageEngaged)
	handlePDU([]byte{0x2C, 0x00}, "192.0.2.61", sess)

	if sess.core.IsNoise() {
		t.Error("a session with a genuine (even if unsupported) protocol engagement must not read as noise")
	}
}

// TestReadDeviceIDAdvancesToIdentityStage confirms Read Device
// Identification -- the fingerprinting-equivalent probe -- registers as its
// own "identity" stage, distinct from an ordinary data read.
func TestReadDeviceIDAdvancesToIdentityStage(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadDeviceID, meiTypeReadDeviceID, readDeviceIDBasic, 0x00}
	handlePDU(req, "192.0.2.62", sess)

	if sess.core.ReachedStage() != stageIdentity {
		t.Errorf("reachedStage = %q, want %q", sess.core.ReachedStage(), stageIdentity)
	}
}

// TestOperationsCapAndDropCount mirrors s7comm's truncation coverage: once
// a session accumulates maxOperations entries, further ones are only
// counted, never stored.
func TestOperationsCapAndDropCount(t *testing.T) {
	sess := newSession()
	const overflow = 5
	for i := 0; i < maxOperations+overflow; i++ {
		sess.record(operation{Kind: "read_holding_regs", Detail: "filler", Handled: true})
	}
	if len(sess.core.Operations()) != maxOperations {
		t.Fatalf("operations = %d, want the cap %d", len(sess.core.Operations()), maxOperations)
	}
	if sess.core.DroppedOperations() != overflow {
		t.Fatalf("droppedOperations = %d, want %d", sess.core.DroppedOperations(), overflow)
	}
}

// TestMalformedRequestRecordsUnhandledOperationWithRawBytes exercises the
// unhandled-request worklist: a request this honeypot declines must be
// recorded with handled=false and its verbatim bytes, so a future
// extension has real bytes to work from.
func TestMalformedRequestRecordsUnhandledOperationWithRawBytes(t *testing.T) {
	sess := newSession()
	pdu := []byte{0x2C, 0xDE, 0xAD, 0xBE, 0xEF}
	handlePDU(pdu, "192.0.2.63", sess)

	ops := sess.core.Operations()
	if len(ops) != 1 {
		t.Fatalf("operations = %d, want 1", len(ops))
	}
	if ops[0].Handled {
		t.Error("an unknown function's operation must be handled=false")
	}
	if len(ops[0].Raw) == 0 {
		t.Error("expected the verbatim request bytes to be recorded")
	}
}
