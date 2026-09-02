package modbus

import (
	"encoding/binary"
	"fmt"
)

// Function codes, verified against Wireshark's packet-mbtcp.c
// dissect_modbus_request/dissect_modbus_response switch statements.
const (
	fnReadCoils          = 0x01
	fnReadDiscreteInputs = 0x02
	fnReadHoldingRegs    = 0x03
	fnReadInputRegs      = 0x04
	fnWriteSingleCoil    = 0x05
	fnWriteSingleReg     = 0x06
	fnWriteMultipleCoils = 0x0F
	fnWriteMultipleRegs  = 0x10
	fnReportServerID     = 0x11 // Report Server ID
	fnReadDeviceID       = 0x2B // Encapsulated Interface Transport (MEI) -- see deviceid.go
)

// Exception codes. Verified against packet-mbtcp.c's exception_code_vals:
// the three this honeypot ever returns.
const (
	excIllegalFunction    = 0x01
	excIllegalDataAddress = 0x02
	excIllegalDataValue   = 0x03
)

// Read/write quantity limits, SOURCED from the Modbus Application Protocol
// Specification V1.1b3 (the public Modbus.org spec) tables for each
// function code. A real slave rejects a request outside these with
// ILLEGAL_DATA_VALUE; this honeypot does the same rather than silently
// accepting an out-of-spec quantity, which is exactly the class of
// never-ack-what-you-don't-support bug s7comm's PI-Service switch had (no
// default case, so any unknown service was acked as success).
const (
	maxReadBitQuantity  = 2000 // Read Coils / Read Discrete Inputs
	maxReadRegQuantity  = 125  // Read Holding Registers / Read Input Registers
	maxWriteBitQuantity = 1968 // Write Multiple Coils
	maxWriteRegQuantity = 123  // Write Multiple Registers
)

// mappedAddressSpace bounds the addresses this emulated device answers for,
// applied uniformly to all four data tables (coils, discrete inputs,
// holding registers, input registers).
//
// INVENTED. A real device maps only a modest, operator/program-defined
// slice of the full 16-bit (65536-point) address space to actual I/O or
// registers; nothing outside that map exists, and a real slave answers
// ILLEGAL_DATA_ADDRESS for it. There is no way to attest a specific real
// device's exact map, but accepting all 65536 addresses -- which no real
// device does -- would itself be a tell. 1000 points per table is a
// plausible, modest size for a small PLC like the persona in persona.go.
const mappedAddressSpace = 1000

// buildException builds a Modbus exception response PDU: the request's
// function code with the high bit set (packet-mbtcp.c:
// `function_exception_code & 0x80`), followed by a single exception-code
// byte.
func buildException(fc byte, code byte) []byte {
	return []byte{fc | 0x80, code}
}

// handleReportServerID answers Report Server ID (0x11). Request is exactly
// 1 byte (the function code itself). Response is: function code (1), byte
// count (1), server ID bytes, and run indicator (1).
func handleReportServerID(pdu []byte, sess *session) []byte {
	const fc = fnReportServerID

	if len(pdu) != 1 {
		sess.record(operation{Kind: "malformed_report_server_id", Detail: fmt.Sprintf("pdu %d bytes, want 1", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}

	serverID := ProductCode
	resp := make([]byte, 2+len(serverID)+1)
	resp[0] = fc
	resp[1] = byte(len(serverID) + 1)
	copy(resp[2:], []byte(serverID))
	resp[2+len(serverID)] = 0xFF

	sess.advance(stageIdentity)
	sess.record(operation{Kind: "report_server_id", Detail: fmt.Sprintf("server_id=%s", serverID), Handled: true})

	return resp
}

// handlePDU parses one Modbus PDU (the bytes an MBAP frame carried past the
// header) and returns the response PDU to send back. It never returns nil:
// every function code this honeypot doesn't implement gets an exception
// response rather than silence, matching the "a real device rejects what it
// does not support" requirement this package was built to.
//
// ip scopes all coil/holding-register write state to this one attacker --
// see state.go. sess accumulates this connection's activity for eventual
// persistence -- see capture.go; it is never nil.
func handlePDU(pdu []byte, ip string, sess *session) []byte {
	fc := pdu[0]

	switch fc {
	case fnReadCoils:
		return handleReadBits(fc, pdu, ip, sess)
	case fnReadDiscreteInputs:
		return handleReadBits(fc, pdu, ip, sess)
	case fnReadHoldingRegs:
		return handleReadRegs(fc, pdu, ip, sess)
	case fnReadInputRegs:
		return handleReadRegs(fc, pdu, ip, sess)
	case fnWriteSingleCoil:
		return handleWriteSingleCoil(pdu, ip, sess)
	case fnWriteSingleReg:
		return handleWriteSingleReg(pdu, ip, sess)
	case fnWriteMultipleCoils:
		return handleWriteMultipleCoils(pdu, ip, sess)
	case fnWriteMultipleRegs:
		return handleWriteMultipleRegs(pdu, ip, sess)
	case fnReportServerID:
		return handleReportServerID(pdu, sess)
	case fnReadDeviceID:
		return handleReadDeviceID(pdu, sess)
	default:
		// The unhandled-request worklist: capture the verbatim request so a
		// future extension has real bytes to work from, bounded by
		// record() at maxRawBytes.
		sess.record(operation{
			Kind:    fmt.Sprintf("unknown_fn=0x%02X", fc),
			Detail:  fmt.Sprintf("Modbus function 0x%02X is not implemented by this honeypot", fc),
			Raw:     pdu,
			Handled: false,
		})
		return buildException(fc, excIllegalFunction)
	}
}

// handleReadBits answers Read Coils (0x01) and Read Discrete Inputs (0x02).
// Request layout verified against packet-mbtcp.c: starting address(2,
// big-endian), quantity(2, big-endian). Response: byte count(1) then
// ceil(quantity/8) bytes of packed bit status, bit i of the response at
// byte i/8 bit i%8 (LSB-first within each byte, per the Modbus spec's
// coil/discrete-input packing convention) representing address start+i.
//
// Discrete inputs carry no attacker-scoped state (see state.go): they are
// read-only on real hardware, so every read goes straight to driftBit.
// Coils DO carry per-attacker state: a prior write from this SAME attacker
// is echoed back; an address this attacker never wrote also falls back to
// driftBit.
func handleReadBits(fc byte, pdu []byte, ip string, sess *session) []byte {
	kind := "read_coils"
	if fc == fnReadDiscreteInputs {
		kind = "read_discrete_inputs"
	}

	if len(pdu) != 5 {
		sess.record(operation{Kind: "malformed_" + kind, Detail: fmt.Sprintf("pdu %d bytes, want 5", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	start := binary.BigEndian.Uint16(pdu[1:3])
	qty := binary.BigEndian.Uint16(pdu[3:5])

	if qty == 0 || qty > maxReadBitQuantity {
		sess.record(operation{Kind: kind, Detail: fmt.Sprintf("addr=%d qty=%d outside valid range [1,%d]", start, qty, maxReadBitQuantity), Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	if int(start)+int(qty) > mappedAddressSpace {
		sess.record(operation{Kind: kind, Detail: fmt.Sprintf("addr=%d qty=%d exceeds this device's mapped range", start, qty), Handled: false})
		return buildException(fc, excIllegalDataAddress)
	}

	var state *attackerState
	if fc == fnReadCoils {
		state = globalState.Get(ip)
	}

	byteCount := int((qty + 7) / 8)
	resp := make([]byte, 2+byteCount)
	resp[0] = fc
	resp[1] = byte(byteCount)
	for i := uint16(0); i < qty; i++ {
		var bit bool
		if fc == fnReadDiscreteInputs {
			bit = driftBit(start + i)
		} else {
			bit = state.readCoil(start + i)
		}
		if bit {
			resp[2+i/8] |= 1 << (i % 8)
		}
	}

	sess.advance(stageRead)
	sess.record(operation{Kind: kind, Detail: fmt.Sprintf("addr=%d qty=%d", start, qty), Handled: true})
	return resp
}

// handleReadRegs answers Read Holding Registers (0x03) and Read Input
// Registers (0x04). Request layout: starting address(2), quantity(2).
// Response: byte count(1, == quantity*2) then quantity 16-bit big-endian
// register values.
//
// Input registers carry no attacker-scoped state (read-only on real
// hardware; see state.go) -- every read goes straight to driftWord. Holding
// registers DO carry per-attacker state, the same shape as coils above.
func handleReadRegs(fc byte, pdu []byte, ip string, sess *session) []byte {
	kind := "read_holding_regs"
	if fc == fnReadInputRegs {
		kind = "read_input_regs"
	}

	if len(pdu) != 5 {
		sess.record(operation{Kind: "malformed_" + kind, Detail: fmt.Sprintf("pdu %d bytes, want 5", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	start := binary.BigEndian.Uint16(pdu[1:3])
	qty := binary.BigEndian.Uint16(pdu[3:5])

	if qty == 0 || qty > maxReadRegQuantity {
		sess.record(operation{Kind: kind, Detail: fmt.Sprintf("addr=%d qty=%d outside valid range [1,%d]", start, qty, maxReadRegQuantity), Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	if int(start)+int(qty) > mappedAddressSpace {
		sess.record(operation{Kind: kind, Detail: fmt.Sprintf("addr=%d qty=%d exceeds this device's mapped range", start, qty), Handled: false})
		return buildException(fc, excIllegalDataAddress)
	}

	var state *attackerState
	if fc == fnReadHoldingRegs {
		state = globalState.Get(ip)
	}

	resp := make([]byte, 2+int(qty)*2)
	resp[0] = fc
	resp[1] = byte(qty * 2)
	for i := uint16(0); i < qty; i++ {
		var word uint16
		if fc == fnReadInputRegs {
			word = driftWord(start + i)
		} else {
			word = state.readHolding(start + i)
		}
		binary.BigEndian.PutUint16(resp[2+int(i)*2:], word)
	}

	sess.advance(stageRead)
	sess.record(operation{Kind: kind, Detail: fmt.Sprintf("addr=%d qty=%d", start, qty), Handled: true})
	return resp
}

// handleWriteSingleCoil answers Write Single Coil (0x05). Request/response
// layout (identical -- a real slave echoes the request verbatim):
// address(2), value(2). Value MUST be exactly 0xFF00 (ON) or 0x0000 (OFF);
// packet-mbtcp.c does not itself validate this (Wireshark just displays
// whatever bytes are present), but the Modbus Application Protocol spec
// requires a slave to reject any other value with ILLEGAL_DATA_VALUE, and a
// real device does -- silently accepting e.g. 0x1234 as if it meant
// something is exactly the "ack anything as success" bug this package must
// not repeat.
func handleWriteSingleCoil(pdu []byte, ip string, sess *session) []byte {
	const fc = fnWriteSingleCoil

	if len(pdu) != 5 {
		sess.record(operation{Kind: "malformed_write_single_coil", Detail: fmt.Sprintf("pdu %d bytes, want 5", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	addr := binary.BigEndian.Uint16(pdu[1:3])
	value := binary.BigEndian.Uint16(pdu[3:5])

	var v bool
	switch value {
	case 0xFF00:
		v = true
	case 0x0000:
		v = false
	default:
		sess.record(operation{Kind: "write_single_coil", Detail: fmt.Sprintf("addr=%d value=0x%04X is neither 0xFF00 nor 0x0000", addr, value), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	if int(addr) >= mappedAddressSpace {
		sess.record(operation{Kind: "write_single_coil", Detail: fmt.Sprintf("addr=%d exceeds this device's mapped range", addr), Handled: false})
		return buildException(fc, excIllegalDataAddress)
	}

	globalState.Get(ip).writeCoil(addr, v)

	sess.advance(stageWrite)
	sess.record(operation{Kind: "write_single_coil", Detail: fmt.Sprintf("addr=%d value=%v", addr, v), Handled: true})

	resp := make([]byte, 5)
	copy(resp, pdu)
	return resp
}

// handleWriteSingleReg answers Write Single Register (0x06). Request/
// response layout (identical, echoed): address(2), value(2) -- any 16-bit
// value is valid for a holding register, unlike a coil's ON/OFF pair.
func handleWriteSingleReg(pdu []byte, ip string, sess *session) []byte {
	const fc = fnWriteSingleReg

	if len(pdu) != 5 {
		sess.record(operation{Kind: "malformed_write_single_reg", Detail: fmt.Sprintf("pdu %d bytes, want 5", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	addr := binary.BigEndian.Uint16(pdu[1:3])
	value := binary.BigEndian.Uint16(pdu[3:5])

	if int(addr) >= mappedAddressSpace {
		sess.record(operation{Kind: "write_single_reg", Detail: fmt.Sprintf("addr=%d exceeds this device's mapped range", addr), Handled: false})
		return buildException(fc, excIllegalDataAddress)
	}

	globalState.Get(ip).writeHolding(addr, value)

	sess.advance(stageWrite)
	sess.record(operation{Kind: "write_single_reg", Detail: fmt.Sprintf("addr=%d value=0x%04X", addr, value), Handled: true})

	resp := make([]byte, 5)
	copy(resp, pdu)
	return resp
}

// handleWriteMultipleCoils answers Write Multiple Coils (0x0F). Request
// layout: starting address(2), quantity of outputs(2), byte count(1), then
// byte-count packed coil values (same LSB-first packing as a read coils
// response). Response, verified against packet-mbtcp.c's WRITE_MULT_COILS
// case: starting address(2), quantity of outputs(2) ONLY -- no byte count,
// no values echoed back.
func handleWriteMultipleCoils(pdu []byte, ip string, sess *session) []byte {
	const fc = fnWriteMultipleCoils

	if len(pdu) < 6 {
		sess.record(operation{Kind: "malformed_write_multiple_coils", Detail: fmt.Sprintf("pdu %d bytes, want >=6", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	start := binary.BigEndian.Uint16(pdu[1:3])
	qty := binary.BigEndian.Uint16(pdu[3:5])
	byteCount := int(pdu[5])
	wantByteCount := int((qty + 7) / 8)

	if qty == 0 || qty > maxWriteBitQuantity || byteCount != wantByteCount || len(pdu) != 6+byteCount {
		sess.record(operation{
			Kind:    "write_multiple_coils",
			Detail:  fmt.Sprintf("addr=%d qty=%d byteCount=%d (want %d) pduLen=%d", start, qty, byteCount, wantByteCount, len(pdu)),
			Raw:     pdu,
			Handled: false,
		})
		return buildException(fc, excIllegalDataValue)
	}
	if int(start)+int(qty) > mappedAddressSpace {
		sess.record(operation{Kind: "write_multiple_coils", Detail: fmt.Sprintf("addr=%d qty=%d exceeds this device's mapped range", start, qty), Handled: false})
		return buildException(fc, excIllegalDataAddress)
	}

	values := pdu[6 : 6+byteCount]
	state := globalState.Get(ip)
	for i := uint16(0); i < qty; i++ {
		bit := values[i/8]&(1<<(i%8)) != 0
		state.writeCoil(start+i, bit)
	}

	sess.advance(stageWrite)
	sess.record(operation{Kind: "write_multiple_coils", Detail: fmt.Sprintf("addr=%d qty=%d", start, qty), Handled: true})

	resp := make([]byte, 5)
	resp[0] = fc
	binary.BigEndian.PutUint16(resp[1:3], start)
	binary.BigEndian.PutUint16(resp[3:5], qty)
	return resp
}

// handleWriteMultipleRegs answers Write Multiple Registers (0x10). Request
// layout: starting address(2), quantity of registers(2), byte count(1, ==
// quantity*2), then that many bytes of 16-bit register values. Response,
// verified against packet-mbtcp.c's WRITE_MULT_REGS case: starting
// address(2), quantity of registers(2) ONLY -- no byte count, no values.
func handleWriteMultipleRegs(pdu []byte, ip string, sess *session) []byte {
	const fc = fnWriteMultipleRegs

	if len(pdu) < 6 {
		sess.record(operation{Kind: "malformed_write_multiple_regs", Detail: fmt.Sprintf("pdu %d bytes, want >=6", len(pdu)), Raw: pdu, Handled: false})
		return buildException(fc, excIllegalDataValue)
	}
	start := binary.BigEndian.Uint16(pdu[1:3])
	qty := binary.BigEndian.Uint16(pdu[3:5])
	byteCount := int(pdu[5])
	wantByteCount := int(qty) * 2

	if qty == 0 || qty > maxWriteRegQuantity || byteCount != wantByteCount || len(pdu) != 6+byteCount {
		sess.record(operation{
			Kind:    "write_multiple_regs",
			Detail:  fmt.Sprintf("addr=%d qty=%d byteCount=%d (want %d) pduLen=%d", start, qty, byteCount, wantByteCount, len(pdu)),
			Raw:     pdu,
			Handled: false,
		})
		return buildException(fc, excIllegalDataValue)
	}
	if int(start)+int(qty) > mappedAddressSpace {
		sess.record(operation{Kind: "write_multiple_regs", Detail: fmt.Sprintf("addr=%d qty=%d exceeds this device's mapped range", start, qty), Handled: false})
		return buildException(fc, excIllegalDataAddress)
	}

	values := pdu[6 : 6+byteCount]
	state := globalState.Get(ip)
	for i := uint16(0); i < qty; i++ {
		word := binary.BigEndian.Uint16(values[i*2:])
		state.writeHolding(start+i, word)
	}

	sess.advance(stageWrite)
	sess.record(operation{Kind: "write_multiple_regs", Detail: fmt.Sprintf("addr=%d qty=%d", start, qty), Handled: true})

	resp := make([]byte, 5)
	resp[0] = fc
	binary.BigEndian.PutUint16(resp[1:3], start)
	binary.BigEndian.PutUint16(resp[3:5], qty)
	return resp
}
