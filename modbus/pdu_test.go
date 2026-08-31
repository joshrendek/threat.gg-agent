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
