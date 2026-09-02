package modbus

import (
	"encoding/binary"
	"testing"
)

// TestUnknownFunctionCodeReturnsExceptionNotSuccess is the "never ack an
// unsupported function as success" requirement this package was built to:
// s7comm's PI-Service switch had no default case and acked any unknown
// service. handlePDU must instead return an exception for a function this
// honeypot doesn't implement.
func TestUnknownFunctionCodeReturnsExceptionNotSuccess(t *testing.T) {
	sess := newSession()
	resp := handlePDU([]byte{0x2C, 0xAA}, "192.0.2.10", sess)

	if len(resp) != 2 {
		t.Fatalf("response = % x, want a 2-byte exception", resp)
	}
	if resp[0] != 0x2C|0x80 {
		t.Errorf("exception function byte = 0x%02X, want 0x%02X (0x2C|0x80)", resp[0], 0x2C|0x80)
	}
	if resp[1] != excIllegalFunction {
		t.Errorf("exception code = 0x%02X, want 0x%02X (illegal function)", resp[1], excIllegalFunction)
	}

	ops := sess.core.Operations()
	if len(ops) != 1 || ops[0].Handled {
		t.Fatalf("expected exactly one handled=false operation, got %+v", ops)
	}
}

func TestReadHoldingRegistersReturnsDataForRequestedQuantity(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadHoldingRegs, 0x00, 0x05, 0x00, 0x03} // addr=5, qty=3
	resp := handlePDU(req, "192.0.2.11", sess)

	if resp[0] != fnReadHoldingRegs || resp[1] != 6 {
		t.Fatalf("response = % x, want function=0x03 byteCount=6", resp)
	}
	if len(resp) != 8 {
		t.Fatalf("response length = %d, want 8 (function+count+6 data bytes)", len(resp))
	}
}

func TestReadCoilsPacksBitsLSBFirst(t *testing.T) {
	ip := "192.0.2.90"
	// Write coils 0 and 9 ON so the packing can be checked precisely: bit 0
	// of byte 0, and bit 1 of byte 1 (address 9 = byte 1, bit 1).
	globalState.Get(ip).writeCoil(0, true)
	globalState.Get(ip).writeCoil(9, true)

	sess := newSession()
	req := []byte{fnReadCoils, 0x00, 0x00, 0x00, 0x0A} // addr=0, qty=10
	resp := handlePDU(req, ip, sess)

	wantByteCount := byte(2) // ceil(10/8)
	if resp[0] != fnReadCoils || resp[1] != wantByteCount {
		t.Fatalf("response = % x, want function=0x01 byteCount=%d", resp, wantByteCount)
	}
	if resp[2]&0x01 == 0 {
		t.Errorf("byte 0 bit 0 (coil 0) not set: % 08b", resp[2])
	}
	if resp[3]&0x02 == 0 {
		t.Errorf("byte 1 bit 1 (coil 9) not set: % 08b", resp[3])
	}
}

// TestWriteSingleCoilOnOffAndEchoesResponse confirms 0xFF00/0x0000 map to
// ON/OFF and the response echoes the request, per Wireshark's dissector
// (which itself does not validate this -- the honeypot's own validation is
// what's under test here).
func TestWriteSingleCoilOnOffAndEchoesResponse(t *testing.T) {
	ip := "192.0.2.12"
	sess := newSession()

	onReq := []byte{fnWriteSingleCoil, 0x00, 0x01, 0xFF, 0x00}
	resp := handlePDU(onReq, ip, sess)
	if len(resp) != 5 || resp[3] != 0xFF || resp[4] != 0x00 {
		t.Fatalf("ON response = % x, want the request echoed back", resp)
	}
	if !globalState.Get(ip).readCoil(1) {
		t.Error("coil 1 was not set ON by 0xFF00")
	}

	offReq := []byte{fnWriteSingleCoil, 0x00, 0x01, 0x00, 0x00}
	resp = handlePDU(offReq, ip, sess)
	if len(resp) != 5 || resp[3] != 0x00 || resp[4] != 0x00 {
		t.Fatalf("OFF response = % x, want the request echoed back", resp)
	}
	if globalState.Get(ip).readCoil(1) {
		t.Error("coil 1 was not set OFF by 0x0000")
	}
}

// TestWriteSingleCoilRejectsNonStandardValue confirms a value that is
// neither 0xFF00 nor 0x0000 is rejected with an exception, not silently
// accepted as if it meant something.
func TestWriteSingleCoilRejectsNonStandardValue(t *testing.T) {
	sess := newSession()
	req := []byte{fnWriteSingleCoil, 0x00, 0x01, 0x12, 0x34}
	resp := handlePDU(req, "192.0.2.13", sess)

	if resp[0] != fnWriteSingleCoil|0x80 || resp[1] != excIllegalDataValue {
		t.Errorf("response = % x, want exception illegal_data_value", resp)
	}
}

func TestWriteSingleRegisterIsIsolatedPerAttackerIP(t *testing.T) {
	sessA := newSession()
	sessB := newSession()

	writeReq := []byte{fnWriteSingleReg, 0x00, 0x02, 0xBE, 0xEF}
	handlePDU(writeReq, "192.0.2.14", sessA)

	readReq := []byte{fnReadHoldingRegs, 0x00, 0x02, 0x00, 0x01}
	respB := handlePDU(readReq, "192.0.2.15", sessB)
	gotB := binary.BigEndian.Uint16(respB[2:4])
	if gotB == 0xBEEF {
		t.Error("attacker B observed attacker A's write -- holding registers are not IP-scoped")
	}

	respA := handlePDU(readReq, "192.0.2.14", sessA)
	gotA := binary.BigEndian.Uint16(respA[2:4])
	if gotA != 0xBEEF {
		t.Errorf("attacker A's own read = 0x%04X, want its own write 0xBEEF back", gotA)
	}
}

func TestWriteMultipleCoilsResponseHasNoByteCountOrValues(t *testing.T) {
	ip := "192.0.2.16"
	sess := newSession()
	// addr=0, qty=10, byteCount=2, values=0b00000011 0b00000001 (coils 0,1,8 ON)
	req := []byte{fnWriteMultipleCoils, 0x00, 0x00, 0x00, 0x0A, 0x02, 0x03, 0x01}
	resp := handlePDU(req, ip, sess)

	if len(resp) != 5 {
		t.Fatalf("response length = %d, want 5 (function+addr+qty, no byte count/values)", len(resp))
	}
	if resp[0] != fnWriteMultipleCoils {
		t.Errorf("function = 0x%02X, want 0x0F", resp[0])
	}
	gotAddr := binary.BigEndian.Uint16(resp[1:3])
	gotQty := binary.BigEndian.Uint16(resp[3:5])
	if gotAddr != 0 || gotQty != 10 {
		t.Errorf("response addr/qty = %d/%d, want 0/10", gotAddr, gotQty)
	}

	state := globalState.Get(ip)
	if !state.readCoil(0) || !state.readCoil(1) || !state.readCoil(8) {
		t.Error("expected coils 0, 1, and 8 to be ON after the write")
	}
	if state.readCoil(2) {
		t.Error("coil 2 should not have been set")
	}
}

func TestWriteMultipleCoilsRejectsMismatchedByteCount(t *testing.T) {
	sess := newSession()
	// qty=10 wants byteCount=2, but only 1 is declared/provided.
	req := []byte{fnWriteMultipleCoils, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x03}
	resp := handlePDU(req, "192.0.2.17", sess)
	if resp[0] != fnWriteMultipleCoils|0x80 || resp[1] != excIllegalDataValue {
		t.Errorf("response = % x, want exception illegal_data_value", resp)
	}
}

func TestWriteMultipleRegistersResponseHasNoByteCountOrValues(t *testing.T) {
	ip := "192.0.2.18"
	sess := newSession()
	req := []byte{fnWriteMultipleRegs, 0x00, 0x00, 0x00, 0x02, 0x04, 0x11, 0x11, 0x22, 0x22}
	resp := handlePDU(req, ip, sess)

	if len(resp) != 5 {
		t.Fatalf("response length = %d, want 5", len(resp))
	}
	gotQty := binary.BigEndian.Uint16(resp[3:5])
	if gotQty != 2 {
		t.Errorf("response qty = %d, want 2", gotQty)
	}

	state := globalState.Get(ip)
	if state.readHolding(0) != 0x1111 || state.readHolding(1) != 0x2222 {
		t.Errorf("holding[0]=0x%04X holding[1]=0x%04X, want 0x1111/0x2222", state.readHolding(0), state.readHolding(1))
	}
}

// TestQuantityLimitsAreEnforced covers the Modbus Application Protocol
// spec's per-function quantity ceilings: exceeding them must return
// ILLEGAL_DATA_VALUE, not be silently clamped or accepted.
func TestQuantityLimitsAreEnforced(t *testing.T) {
	cases := []struct {
		name string
		req  []byte
		fc   byte
	}{
		{"read_coils_over_2000", append([]byte{fnReadCoils, 0x00, 0x00}, be16(maxReadBitQuantity+1)...), fnReadCoils},
		{"read_holding_over_125", append([]byte{fnReadHoldingRegs, 0x00, 0x00}, be16(maxReadRegQuantity+1)...), fnReadHoldingRegs},
		{"read_coils_zero_qty", append([]byte{fnReadCoils, 0x00, 0x00}, be16(0)...), fnReadCoils},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := newSession()
			resp := handlePDU(tc.req, "192.0.2.19", sess)
			if resp[0] != tc.fc|0x80 || resp[1] != excIllegalDataValue {
				t.Errorf("response = % x, want exception illegal_data_value for %s", resp, tc.name)
			}
		})
	}
}

// TestAddressOutOfMappedRangeReturnsIllegalDataAddress confirms a
// syntactically valid but out-of-range request is rejected with
// ILLEGAL_DATA_ADDRESS, matching what a real device does when it doesn't
// have that many points mapped.
func TestAddressOutOfMappedRangeReturnsIllegalDataAddress(t *testing.T) {
	sess := newSession()
	req := []byte{fnReadHoldingRegs, 0x0F, 0xFF, 0x00, 0x01} // addr=0xFFF, well past mappedAddressSpace
	resp := handlePDU(req, "192.0.2.20", sess)
	if resp[0] != fnReadHoldingRegs|0x80 || resp[1] != excIllegalDataAddress {
		t.Errorf("response = % x, want exception illegal_data_address", resp)
	}
}

// TestMalformedPDUsDoNotPanic drives handlePDU directly with truncated and
// oversized PDU bodies for every function this package implements, and
// confirms none of them panic -- the PDU-level counterpart to
// modbus_test.go's MBAP-layer malformed/oversized/truncated coverage.
func TestMalformedPDUsDoNotPanic(t *testing.T) {
	cases := [][]byte{
		{fnReadCoils},
		{fnReadCoils, 0x00},
		{fnReadDiscreteInputs, 0x00, 0x00, 0x00},
		{fnReadHoldingRegs},
		{fnReadInputRegs, 0x00},
		{fnWriteSingleCoil, 0x00},
		{fnWriteSingleReg, 0x00, 0x00, 0x00},
		{fnWriteMultipleCoils},
		{fnWriteMultipleCoils, 0x00, 0x00, 0x00, 0x0A, 0x02}, // declares byteCount but sends no values
		{fnWriteMultipleRegs},
		{fnWriteMultipleRegs, 0x00, 0x00, 0x00, 0x02, 0x04, 0x11}, // declares 4 value bytes, sends 1
		{fnReadDeviceID},
		{fnReadDeviceID, meiTypeReadDeviceID},
		{0x99, 0x00, 0x00, 0x00}, // entirely unknown function code with a body
	}
	for _, pdu := range cases {
		t.Run("", func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handlePDU(% x) panicked: %v", pdu, r)
				}
			}()
			sess := newSession()
			resp := handlePDU(pdu, "192.0.2.21", sess)
			if len(resp) < 2 {
				t.Errorf("handlePDU(% x) = % x, want at least a 2-byte exception", pdu, resp)
			}
		})
	}
}

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// TestReportServerIDHappyPath confirms function 0x11 returns a well-formed
// response with the ProductCode identity and run indicator 0xFF.
func TestReportServerIDHappyPath(t *testing.T) {
	sess := newSession()
	req := []byte{fnReportServerID}
	resp := handlePDU(req, "192.0.2.30", sess)

	if resp[0] != fnReportServerID {
		t.Errorf("response function code = 0x%02X, want 0x%02X", resp[0], fnReportServerID)
	}

	expectedByteCount := byte(len(ProductCode) + 1)
	if resp[1] != expectedByteCount {
		t.Errorf("byte count = 0x%02X, want 0x%02X (len(serverID)+1)", resp[1], expectedByteCount)
	}

	serverIDBytes := resp[2 : 2+len(ProductCode)]
	if string(serverIDBytes) != ProductCode {
		t.Errorf("server ID = %s, want %s", string(serverIDBytes), ProductCode)
	}

	if resp[2+len(ProductCode)] != 0xFF {
		t.Errorf("run indicator = 0x%02X, want 0xFF", resp[2+len(ProductCode)])
	}

	ops := sess.core.Operations()
	if len(ops) != 1 || !ops[0].Handled {
		t.Fatalf("expected exactly one handled=true operation, got %+v", ops)
	}
}

// TestReportServerIDMalformedRejectsExtraBytes confirms that a request with
// more than just the function code is rejected with IllegalDataValue.
func TestReportServerIDMalformedRejectsExtraBytes(t *testing.T) {
	sess := newSession()
	req := []byte{fnReportServerID, 0x00, 0x01}
	resp := handlePDU(req, "192.0.2.31", sess)

	if resp[0] != fnReportServerID|0x80 || resp[1] != excIllegalDataValue {
		t.Errorf("response = % x, want exception illegal_data_value", resp)
	}

	ops := sess.core.Operations()
	if len(ops) != 1 || ops[0].Handled {
		t.Fatalf("expected exactly one handled=false operation, got %+v", ops)
	}
}

// TestReportServerIDNotException confirms function 0x11 no longer falls
// through to the unknown-function path and returns an IllegalFunction
// exception (it now returns a success response instead).
func TestReportServerIDNotException(t *testing.T) {
	sess := newSession()
	req := []byte{fnReportServerID}
	resp := handlePDU(req, "192.0.2.32", sess)

	// Should NOT be an exception (high bit set on the function code)
	if resp[0]&0x80 != 0 {
		t.Errorf("response function code 0x%02X has high bit set (exception), want success", resp[0])
	}

	// Should be a valid response with at least the server ID and run indicator
	if len(resp) < 4 {
		t.Errorf("response length = %d, want at least 4 bytes", len(resp))
	}
}

// --- unknown-function worklist labelling (threat_gg-4zzd.16) ---

// The 0x5A captures all share the shape 5A 00 <sub>, and splitting on that
// third byte is what turns "something hits 0x5A 61 times" into a ranked list
// of which specific commands are being hunted. These pin the real captured
// payloads, taken from production on 2026-09-02.
func TestUnknownVendorFunctionSplitsOnObservedSubByte(t *testing.T) {
	cases := map[string]struct {
		pdu      []byte
		wantKind string
	}{
		"5a000100": {[]byte{0x5A, 0x00, 0x01, 0x00}, "unknown_fn=0x5A/sub=0x01"},
		"5a0002":   {[]byte{0x5A, 0x00, 0x02}, "unknown_fn=0x5A/sub=0x02"},
		"5a000300": {[]byte{0x5A, 0x00, 0x03, 0x00}, "unknown_fn=0x5A/sub=0x03"},
		"5a0004":   {[]byte{0x5A, 0x00, 0x04}, "unknown_fn=0x5A/sub=0x04"},
		"5a000606": {[]byte{0x5A, 0x00, 0x06, 0x06}, "unknown_fn=0x5A/sub=0x06"},
		"5a0020":   {[]byte{0x5A, 0x00, 0x20, 0x00, 0x14}, "unknown_fn=0x5A/sub=0x20"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sess := newSession()
			resp := handlePDU(tc.pdu, "192.0.2.40", sess)

			// The response must be unchanged: still refused, never answered.
			if resp[0] != 0x5A|0x80 || resp[1] != excIllegalFunction {
				t.Errorf("response = % x, want IllegalFunction exception -- 0x5A must not be answered", resp)
			}

			ops := sess.core.Operations()
			if len(ops) != 1 {
				t.Fatalf("expected exactly one operation, got %d", len(ops))
			}
			if ops[0].Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", ops[0].Kind, tc.wantKind)
			}
			if ops[0].Handled {
				t.Error("an unimplemented function must never record Handled: true")
			}
			if len(ops[0].Raw) == 0 {
				t.Error("the verbatim request must be kept -- it is the evidence a future decision works from")
			}
		})
	}
}

// A 0x5A too short to carry a third byte must not index past the slice, and
// must fall back to the plain label rather than inventing a sub-function.
func TestUnknownVendorFunctionTooShortForSubByte(t *testing.T) {
	for _, pdu := range [][]byte{{0x5A}, {0x5A, 0x00}} {
		sess := newSession()
		resp := handlePDU(pdu, "192.0.2.41", sess)
		if resp[0] != 0x5A|0x80 {
			t.Errorf("pdu % x: want exception, got % x", pdu, resp)
		}
		ops := sess.core.Operations()
		if len(ops) != 1 || ops[0].Kind != "unknown_fn=0x5A" {
			t.Fatalf("pdu % x: kind = %+v, want plain unknown_fn=0x5A with no invented sub", pdu, ops)
		}
	}
}

// Every other unimplemented function keeps the original label: the split is
// specific to the one code whose captures actually show sub-structure.
func TestUnknownNonVendorFunctionKeepsPlainLabel(t *testing.T) {
	sess := newSession()
	handlePDU([]byte{0x42, 0x00, 0x07}, "192.0.2.42", sess)
	ops := sess.core.Operations()
	if len(ops) != 1 || ops[0].Kind != "unknown_fn=0x42" {
		t.Fatalf("kind = %+v, want plain unknown_fn=0x42", ops)
	}
}
