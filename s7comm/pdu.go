package s7comm

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// S7 header. Verified byte-for-byte against dissect_s7comm in
// packet-s7comm.c: protocol-id(1)=0x32, ROSCTR(1), redundancy-id(2,
// reserved), PDU-reference(2), parameter-length(2), data-length(2) -- 10
// bytes, extended to 12 for ROSCTR Ack/Ack_Data with error-class(1) +
// error-code(1) appended.
const (
	protID = 0x32

	rosctrJob      = 0x01
	rosctrAck      = 0x02
	rosctrAckData  = 0x03
	rosctrUserdata = 0x07

	s7HeaderLenShort = 10
	s7HeaderLenLong  = 12

	// Job/Ack_Data function codes (S7COMM_SERV_*/S7COMM_FUNC* in
	// packet-s7comm.c).
	fnSetupComm = 0xF0
	fnReadVar   = 0x04
	fnWriteVar  = 0x05
	fnPIService = 0x28
	fnPLCStop   = 0x29

	// fnCPUServices is the constant "function" byte at the start of every
	// Userdata parameter part (S7COMM_SERV_CPU in packet-s7comm.c) --
	// present regardless of which CPU sub-function (e.g. Read SZL) follows.
	fnCPUServices = 0x00

	// Header-level error classes/codes (errcls_names / param_errcode_names
	// in packet-s7comm.c).
	errclsNone                      = 0x00
	errclsApplication               = 0x81 // S7COMM_ERRCLS_APPREL
	errcodApplicationUnknownService = 0x8100
)

var errS7 = errors.New("malformed S7 PDU")

type s7Header struct {
	rosctr byte
	pduRef uint16
	parLen uint16
	datLen uint16
}

// parseS7Header parses the fixed S7 header and returns it along with the
// remaining bytes (parameter section followed by data section,
// concatenated -- callers slice using parLen/datLen). The declared
// parLen+datLen is validated against the bytes actually present before any
// handler touches them.
func parseS7Header(b []byte) (s7Header, []byte, error) {
	if len(b) < s7HeaderLenShort {
		return s7Header{}, nil, errS7
	}
	if b[0] != protID {
		return s7Header{}, nil, errS7
	}
	rosctr := b[1]
	if rosctr != rosctrJob && rosctr != rosctrAck && rosctr != rosctrAckData && rosctr != rosctrUserdata {
		return s7Header{}, nil, errS7
	}

	hlen := s7HeaderLenShort
	if rosctr == rosctrAck || rosctr == rosctrAckData {
		hlen = s7HeaderLenLong
	}
	if len(b) < hlen {
		return s7Header{}, nil, errS7
	}

	hdr := s7Header{
		rosctr: rosctr,
		pduRef: binary.BigEndian.Uint16(b[4:6]),
		parLen: binary.BigEndian.Uint16(b[6:8]),
		datLen: binary.BigEndian.Uint16(b[8:10]),
	}
	if int(hdr.parLen)+int(hdr.datLen)+hlen > len(b) {
		return s7Header{}, nil, errS7
	}
	return hdr, b[hlen:], nil
}

// buildS7Header assembles a complete S7 PDU: header + parameter section +
// data section. errcls/errcod are only written for Ack/Ack_Data ROSCTRs
// (ignored otherwise, matching dissect_s7comm's own hlen switch).
func buildS7Header(rosctr byte, pduRef uint16, errcls, errcod byte, param, data []byte) []byte {
	hlen := s7HeaderLenShort
	if rosctr == rosctrAck || rosctr == rosctrAckData {
		hlen = s7HeaderLenLong
	}
	b := make([]byte, hlen+len(param)+len(data))
	b[0] = protID
	b[1] = rosctr
	// b[2:4] redundancy id -- always reserved/zero.
	binary.BigEndian.PutUint16(b[4:6], pduRef)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(param)))
	binary.BigEndian.PutUint16(b[8:10], uint16(len(data)))
	if hlen == s7HeaderLenLong {
		b[10] = errcls
		b[11] = errcod
	}
	copy(b[hlen:hlen+len(param)], param)
	copy(b[hlen+len(param):], data)
	return b
}

// handlePDU parses one complete S7 PDU (the bytes a COTP DT TPDU carried)
// and returns the response to send back. ok=false means the PDU was
// malformed badly enough (at the S7-header layer) that the caller should
// close the connection rather than guess at a reply -- mirroring how TPKT
// and COTP framing errors are already handled one layer down. ok=true with a
// nil response means the PDU parsed but nothing plausible exists to answer
// with (e.g. an Ack/Ack_Data ROSCTR arriving as if it were a request, which
// no real client would ever send); the connection stays open.
//
// ip scopes all read/write/CPU-mode state to this one attacker -- see
// state.go. sess accumulates this connection's activity for eventual
// persistence -- see capture.go; it is never nil (handleConnection always
// supplies one, and tests use newSession()).
func handlePDU(payload []byte, ip string, sess *session) ([]byte, bool) {
	hdr, body, err := parseS7Header(payload)
	if err != nil {
		return nil, false
	}

	switch hdr.rosctr {
	case rosctrJob:
		return handleJob(hdr, body, ip, sess), true
	case rosctrUserdata:
		return handleUserdata(hdr, body, ip, sess), true
	default:
		return nil, true
	}
}

func handleJob(hdr s7Header, body []byte, ip string, sess *session) []byte {
	if hdr.parLen < 1 {
		return nil
	}
	param := body[:hdr.parLen]
	data := body[hdr.parLen : hdr.parLen+hdr.datLen]
	function := param[0]

	switch function {
	case fnSetupComm:
		return handleSetupComm(hdr, sess)
	case fnReadVar:
		return handleReadVar(hdr, param, ip, sess)
	case fnWriteVar:
		return handleWriteVar(hdr, param, data, ip, sess)
	case fnPIService:
		return handlePIService(hdr, param, ip, sess)
	case fnPLCStop:
		return handlePLCStop(hdr, ip, sess)
	default:
		// This is the unhandled-request worklist described on
		// S7CommOperation's doc comment: capture the verbatim request
		// (param+data, i.e. everything the Job PDU carried past the S7
		// header) so a future extension has real bytes to work from,
		// bounded by record() at maxRawBytes.
		sess.record(operation{
			Kind:    fmt.Sprintf("unknown_fn=0x%02X", function),
			Detail:  fmt.Sprintf("S7 Job function 0x%02X is not implemented by this honeypot", function),
			Raw:     body[:hdr.parLen+hdr.datLen],
			Handled: false,
		})
		// Wireshark's own dissector has no case for this function code
		// either at this point; a real CPU rejects a function it doesn't
		// implement with a header-level error rather than staying silent.
		// 0x8100 ("Service unknown to remote module") is the
		// param_errcode_names entry that matches this situation exactly.
		return buildS7Header(rosctrAckData, hdr.pduRef, errclsApplication, byte(errcodApplicationUnknownService&0xFF), nil, nil)
	}
}

// handleSetupComm answers S7 Setup Communication (function 0xF0). Request
// layout (unused by this honeypot -- see comment below) verified against
// s7comm_decode_pdu_setup_communication: reserved(1), max-AMQ-calling(2),
// max-AMQ-called(2), PDU-length(2).
//
// This honeypot doesn't negotiate down to whatever the client asked for: a
// real S7-300 always offers the same fixed capability regardless of what a
// client proposes (see persona.go: MaxAMQCalling/MaxAMQCalled/
// NegotiatedPDULength), so the request body isn't even inspected.
func handleSetupComm(hdr s7Header, sess *session) []byte {
	param := make([]byte, 8)
	param[0] = fnSetupComm
	param[1] = 0x00 // reserved
	binary.BigEndian.PutUint16(param[2:4], uint16(MaxAMQCalling))
	binary.BigEndian.PutUint16(param[4:6], uint16(MaxAMQCalled))
	binary.BigEndian.PutUint16(param[6:8], uint16(NegotiatedPDULength))

	sess.setNegotiatedPDUSize(uint32(NegotiatedPDULength))
	sess.advance(stageSetup)
	sess.record(operation{Kind: "setup_comm", Detail: fmt.Sprintf("negotiated_pdu_size=%d", NegotiatedPDULength), Handled: true})

	return buildS7Header(rosctrAckData, hdr.pduRef, errclsNone, 0, param, nil)
}

// ─── Read/Write Var ─────────────────────────────────────────────────────

// S7ANY item-specification constants and per-item data-header transport-size
// codes. Verified against s7comm_decode_param_item/s7comm_syntaxid_s7any and
// s7comm_decode_response_read_data respectively -- these are TWO DIFFERENT
// code spaces that happen to share small integer values, a genuine
// confusing overlap in the real protocol, not a mistake introduced here.
const (
	varSpecType   = 0x12 // item head "type", constant for every item kind
	syntaxIDS7Any = 0x10 // "S7ANY" addressing (DB1.DBX10.2-style), S7-300/400 classic

	s7AnyItemLen = 12 // type(1)+length(1)+syntaxid(1)+transportsize(1)+length(2)+db(2)+area(1)+address(3)

	// Per-item data-header transport-size codes (S7COMM_DATA_TRANSPORT_SIZE_*
	// in packet-s7comm.h/.c). BBIT/BBYTE/BINT carry their length IN BITS on
	// the wire -- a genuine, well-known S7comm quirk, not a bug: byte/word/
	// dword reads still report a bit count in the length field.
	dataTransportBBit  = 3
	dataTransportBByte = 4
	dataTransportBStr  = 9 // octet string, length in BYTES -- used for the SZL data header

	itemRetvalOK          = 0xFF // S7COMM_ITEM_RETVAL_DATA_OK
	itemRetvalObjNotExist = 0x0A // S7COMM_ITEM_RETVAL_DATA_ERR

	// maxItemsPerRequest/maxItemBytes bound how much work and memory one
	// read/write request can demand, independent of whatever length an
	// attacker's item spec claims.
	maxItemsPerRequest = 20
	maxItemBytes       = 4096
)

// s7AnyItem is one parsed S7ANY address item.
type s7AnyItem struct {
	transportSize byte   // request-side type enum (BIT/BYTE/WORD/...), NOT a dataTransport* code
	length        uint16 // element count, in the units implied by transportSize
	db            uint16
	area          byte
	byteOffset    uint32
	bitOffset     byte
}

// parseS7AnyItem parses one S7ANY item spec from the front of b and returns
// it along with the number of bytes consumed. Layout verified against
// s7comm_decode_param_item + s7comm_syntaxid_s7any: type(1)=0x12,
// length(1)=10, syntax-id(1)=0x10, transport-size(1), length(2),
// DB-number(2), area(1), address(3, packed byte*8+bit big-endian). This
// honeypot only implements the classic S7-300/400 S7ANY addressing mode --
// any other syntax id (S7-1200 symbolic, NCK, DB-read, ...) is reported as
// unsupported rather than guessed at.
func parseS7AnyItem(b []byte) (s7AnyItem, error) {
	if len(b) < 3 {
		return s7AnyItem{}, errS7
	}
	if b[0] != varSpecType || b[1] != 10 || b[2] != syntaxIDS7Any {
		return s7AnyItem{}, errS7
	}
	if len(b) < s7AnyItemLen {
		return s7AnyItem{}, errS7
	}

	addr := uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11])
	item := s7AnyItem{
		transportSize: b[3],
		length:        binary.BigEndian.Uint16(b[4:6]),
		db:            binary.BigEndian.Uint16(b[6:8]),
		area:          b[8],
		byteOffset:    addr >> 3,
		bitOffset:     byte(addr & 0x7),
	}
	return item, nil
}

// requestElementByteLen maps an S7ANY item's request-side transport-size
// enum to the number of bytes one addressed element occupies. INVENTED
// (simplification): a real device distinguishes INT/DINT/REAL by exact wire
// encoding; this honeypot only needs a plausible byte COUNT to read/write
// per address, not a faithful type system, so DWORD/DINT/REAL/DATE all
// collapse to 4 bytes and WORD/INT to 2. This is a scope reduction, not an
// unsourced guess -- the widths themselves (1/2/4) are the real S7 widths.
func requestElementByteLen(transportSize byte) int {
	switch transportSize {
	case 4, 5: // WORD, INT
		return 2
	case 6, 7, 8, 9: // DWORD, DINT, REAL, DATE
		return 4
	default: // BIT, BYTE, CHAR, and anything unrecognized
		return 1
	}
}

// itemByteLen returns how many bytes item's read/write covers, clamped to
// maxItemBytes so a claimed element count can never drive a large
// allocation.
func itemByteLen(item s7AnyItem) int {
	n := int(item.length) * requestElementByteLen(item.transportSize)
	if item.transportSize == 1 { // BIT: length is a bit count, not an element count
		n = 1
	}
	if n <= 0 {
		n = 1
	}
	if n > maxItemBytes {
		n = maxItemBytes
	}
	return n
}

// parseItemList parses up to maxItemsPerRequest S7ANY item specs from the
// front of param (starting right after the function+item-count bytes every
// caller has already consumed). A malformed or truncated item stops parsing
// -- whatever was already parsed is still answered.
func parseItemList(param []byte, itemCount int, offset int) []s7AnyItem {
	if itemCount > maxItemsPerRequest {
		itemCount = maxItemsPerRequest
	}
	items := make([]s7AnyItem, 0, itemCount)
	for i := 0; i < itemCount; i++ {
		if offset >= len(param) {
			break
		}
		item, err := parseS7AnyItem(param[offset:])
		if err != nil {
			break
		}
		items = append(items, item)
		offset += s7AnyItemLen // always 12 for S7ANY, always even -- no fill byte ever needed between item specs
	}
	return items
}

// handleReadVar answers Read Var (function 0x04). Response layout verified
// against s7comm_decode_response_read_data: parameter = function(1) +
// item-count(1); data = per item [return-code(1), transport-size(1),
// length-in-bits-or-bytes(2), payload, optional 1-byte fill if payload is an
// odd length and this isn't the last item].
func handleReadVar(hdr s7Header, param []byte, ip string, sess *session) []byte {
	if len(param) < 2 {
		return nil
	}
	items := parseItemList(param, int(param[1]), 2)
	state := globalState.Get(ip)

	var data []byte
	lens := make([]int, len(items))
	for i, item := range items {
		n := itemByteLen(item)
		lens[i] = n
		key := addressKey{area: item.area, db: item.db, byteOffset: item.byteOffset}
		payload := state.read(key, n)

		wireLen := n
		tsize := byte(dataTransportBByte)
		if item.transportSize == 1 {
			tsize = dataTransportBBit
			wireLen = 1
		} else {
			wireLen = n * 8 // BBYTE's length field is in BITS -- verified quirk, see const doc above
		}

		entry := make([]byte, 4+len(payload))
		entry[0] = itemRetvalOK
		entry[1] = tsize
		binary.BigEndian.PutUint16(entry[2:4], uint16(wireLen))
		copy(entry[4:], payload)
		data = append(data, entry...)

		if len(payload)%2 == 1 && i < len(items)-1 {
			data = append(data, 0x00)
		}
	}

	sess.advance(stageData)
	sess.record(operation{Kind: "read_var", Detail: joinItemDetails(items, lens), Handled: true})

	respParam := []byte{fnReadVar, byte(len(items))}
	return buildS7Header(rosctrAckData, hdr.pduRef, errclsNone, 0, respParam, data)
}

// handleWriteVar answers Write Var (function 0x05). Request data layout
// mirrors the read response: per item [return-code(1, ignored -- set by the
// requester, meaningless on a request), transport-size(1),
// length-in-bits-or-bytes(2), payload, optional fill byte]. Writes are
// scoped to ip via state.go -- this is threat_gg-4zzd.6's hard requirement:
// a write from one attacker must never become visible to another.
func handleWriteVar(hdr s7Header, param, data []byte, ip string, sess *session) []byte {
	if len(param) < 2 {
		return nil
	}
	itemCount := int(param[1])
	items := parseItemList(param, itemCount, 2)
	state := globalState.Get(ip)

	returnCodes := make([]byte, len(items))
	for i := range returnCodes {
		returnCodes[i] = itemRetvalObjNotExist
	}

	var writtenItems []s7AnyItem
	var writtenLens []int
	doff := 0
	for i, item := range items {
		if doff+4 > len(data) {
			break
		}
		tsize := data[doff+1]
		lenField := int(binary.BigEndian.Uint16(data[doff+2 : doff+4]))
		nbytes := lenField
		if tsize == dataTransportBBit || tsize == dataTransportBByte {
			nbytes = (lenField + 7) / 8 // bits -> bytes, rounding up
		}
		if nbytes > maxItemBytes {
			nbytes = maxItemBytes
		}
		doff += 4
		if doff+nbytes > len(data) {
			break
		}

		payload := data[doff : doff+nbytes]
		doff += nbytes
		if nbytes%2 == 1 && i < len(items)-1 {
			doff++
		}

		key := addressKey{area: item.area, db: item.db, byteOffset: item.byteOffset}
		state.write(key, payload)
		returnCodes[i] = itemRetvalOK
		writtenItems = append(writtenItems, item)
		writtenLens = append(writtenLens, nbytes)
	}

	sess.advance(stageData)
	sess.record(operation{Kind: "write_var", Detail: joinItemDetails(writtenItems, writtenLens), Handled: true})

	respParam := []byte{fnWriteVar, byte(len(items))}
	return buildS7Header(rosctrAckData, hdr.pduRef, errclsNone, 0, respParam, returnCodes)
}

// ─── PI Service / PLC Stop ──────────────────────────────────────────────

// handlePIService answers PI Service (function 0x28) requests -- the
// mechanism real S7 clients use for PLC START/warm-restart ("P_PROGRAM"),
// copy-RAM-to-ROM ("_MODU"), and compress-memory ("_GARB"). Request layout
// verified against s7comm_decode_pi_service: function(1, already consumed
// by the caller) + unknown(7) + parameter-block-length(2) +
// parameter-block(that many bytes) + service-name-length(1) +
// service-name(ASCII).
func handlePIService(hdr s7Header, param []byte, ip string, sess *session) []byte {
	const unsupported = errcodApplicationUnknownService
	if len(param) < 10 {
		sess.record(operation{Kind: "malformed_pi_service", Detail: fmt.Sprintf("param %d bytes, want >=10", len(param)), Raw: param, Handled: false})
		return buildS7Header(rosctrAckData, hdr.pduRef, errclsApplication, byte(unsupported&0xFF), nil, nil)
	}
	paramBlockLen := int(binary.BigEndian.Uint16(param[8:10]))
	pos := 10 + paramBlockLen
	if pos >= len(param) {
		sess.record(operation{Kind: "malformed_pi_service", Detail: "parameter block length runs past the parameter", Raw: param, Handled: false})
		return buildS7Header(rosctrAckData, hdr.pduRef, errclsApplication, byte(unsupported&0xFF), nil, nil)
	}
	nameLen := int(param[pos])
	pos++
	if pos+nameLen > len(param) {
		sess.record(operation{Kind: "malformed_pi_service", Detail: fmt.Sprintf("service name length %d runs past the parameter", nameLen), Raw: param, Handled: false})
		return buildS7Header(rosctrAckData, hdr.pduRef, errclsApplication, byte(unsupported&0xFF), nil, nil)
	}
	serviceName := string(param[pos : pos+nameLen])

	state := globalState.Get(ip)
	switch serviceName {
	case "P_PROGRAM":
		// A real P_PROGRAM call can mean either start or stop depending on
		// its argument; this honeypot only models the common case (no
		// argument / warm restart -> CPU ends up running), since a
		// dedicated STOP function (0x29, handlePLCStop) is what every real
		// client actually uses to stop a CPU.
		state.setMode(modeRun)
		sess.advance(stageControl)
		sess.record(operation{Kind: "plc_start", Detail: "P_PROGRAM (warm restart / start)", Handled: true})
	case "_MODU", "_GARB":
		// Copy-RAM-to-ROM / compress-memory: accepted, but neither changes
		// run/stop state, and this honeypot has no persistent "ROM" to
		// distinguish from "RAM" -- the request itself is the capture.
		//
		// _GARB (compress-memory) has no dedicated kind of its own in the
		// enumerated capture vocabulary -- it shares "copy_ram_to_rom" with
		// _MODU (both are PI Service maintenance calls handled by this one
		// branch), with the actual service name preserved in detail so the
		// two remain distinguishable.
		sess.advance(stageControl)
		sess.record(operation{Kind: "copy_ram_to_rom", Detail: fmt.Sprintf("service=%s", serviceName), Handled: true})
	default:
		// An unrecognised PI service is exactly what the unhandled-request
		// queue exists for: an attacker asked this CPU to run a program
		// invocation we do not model, and the service name tells us which one
		// to implement next.
		//
		// It previously fell through this switch silently and was acked as
		// SUCCESS, which is both an invisible capture gap and a fidelity bug --
		// a real CPU rejects a service it does not provide, so acking every
		// arbitrary name is a tell an attacker can probe for directly.
		sess.record(operation{Kind: fmt.Sprintf("unsupported_pi_service=%s", serviceName), Detail: "PI service not implemented", Raw: param, Handled: false})
		return buildS7Header(rosctrAckData, hdr.pduRef, errclsApplication, byte(unsupported&0xFF), nil, nil)
	}

	// Ack_Data parameter layout for PI Service verified against
	// s7comm_decode_req_resp's ACK_DATA branch: function(1) +
	// function-status(1), where 0x00 = no error (bit0=more data,
	// bit1=error -- both clear).
	respParam := []byte{fnPIService, 0x00}
	return buildS7Header(rosctrAckData, hdr.pduRef, errclsNone, 0, respParam, nil)
}

// handlePLCStop answers PLC Stop (function 0x29) -- the headline capture: an
// attacker stopping a PLC is unambiguous intent. The stopped state is
// recorded ONLY for ip (state.go), so it is never visible to any other
// attacker.
//
// The ack's exact wire shape is INVENTED: Wireshark's own dissector has no
// ACK_DATA case for function 0x29 (s7comm_decode_req_resp falls through to
// its generic "print unknown bytes" default for this function's response),
// so there is no source to verify against. Modeled on PI Service's ack
// (function byte + a single status byte, 0x00 = success) since that is the
// only sibling "simple control function" ack this protocol documents at
// all -- flagged per the brief's instruction to call out unsettled choices.
func handlePLCStop(hdr s7Header, ip string, sess *session) []byte {
	state := globalState.Get(ip)
	state.setMode(modeStop)

	sess.advance(stageControl)
	sess.record(operation{Kind: "plc_stop", Detail: "PLC STOP requested", Handled: true})

	respParam := []byte{fnPLCStop, 0x00}
	return buildS7Header(rosctrAckData, hdr.pduRef, errclsNone, 0, respParam, nil)
}

// ─── Userdata / Read SZL ────────────────────────────────────────────────

// Userdata parameter-part constants. Verified against s7comm_decode_ud
// (packet-s7comm.c): function(1)=0x00 + item-count(1)=0x01 + item head
// [type(1)=0x12, length(1), syntax-id(1)] + type/funcgroup(1) + subfunc(1) +
// seq-num(1), extended (length=8, syntax-id=EXT) with data-unit-ref(1) +
// last-data-unit(1) + error-code(2) appended -- 8 bytes standard, 12
// extended. The two syntax-id values (SHORT=0x11 for a plain request,
// EXT=0x12 for a fragmentable/erroring response) are a genuinely different
// code space from varSpecType (also 0x12) despite the numeric collision.
const (
	syntaxIDShort = 0x11
	syntaxIDExt   = 0x12

	udTypeReq = 0x01
	udTypeRes = 0x02

	udFuncGroupCPU = 0x04
	udSubfReadSZL  = 0x01

	// udLastDataUnitYes marks a Userdata response as complete (no more
	// fragments follow) -- S7COMM_UD_LASTDATAUNIT_YES in packet-s7comm.c.
	udLastDataUnitYes = 0x00

	// paramErrSZLNotAvailable is param_errcode_names' 0x8104: "This service
	// is not implemented on the module or a frame error was reported" --
	// used here for any SZL-ID/Index this honeypot doesn't answer,
	// including the deliberately-withheld 0x001C/0x0009 (see persona.go).
	paramErrSZLNotAvailable = 0x8104

	szl001CManufacturerProfile = 0x001C
	szl001CIdxManufacturer     = 0x0009
)

// handleUserdata answers ROSCTR Userdata (7) requests. Only CPU-function
// Read SZL is implemented; every other funcgroup/subfunc combination -- and
// every unsupported SZL-ID/Index within Read SZL -- gets the same
// "not implemented" answer a real CPU gives, rather than silence or a crash.
func handleUserdata(hdr s7Header, body []byte, ip string, sess *session) []byte {
	if hdr.parLen < 8 {
		sess.record(operation{Kind: "malformed_userdata", Detail: fmt.Sprintf("parLen=%d, want >=8", hdr.parLen), Raw: body, Handled: false})
		return nil
	}
	param := body[:hdr.parLen]
	data := body[hdr.parLen : hdr.parLen+hdr.datLen]

	if param[0] != fnCPUServices {
		// Only the CPU-services marker byte is a request we can plausibly
		// answer; a mode-transition-indication-shaped parameter (function
		// 0x01) is something a real CPU only ever SENDS, never receives, so
		// there's nothing genuine to reply with.
		sess.record(operation{Kind: fmt.Sprintf("unsupported_userdata_fn=0x%02X", param[0]), Detail: "parameter is not the CPU-services marker", Raw: param, Handled: false})
		return buildSZLNotAvailableResponse(hdr, 0)
	}
	funcgroup := param[5] & 0x3F
	subfunc := param[6]
	seqNum := param[7]

	if funcgroup != udFuncGroupCPU || subfunc != udSubfReadSZL {
		sess.record(operation{Kind: fmt.Sprintf("unsupported_userdata=fg0x%02X/sf0x%02X", funcgroup, subfunc), Detail: "userdata function group/subfunction not implemented", Raw: param, Handled: false})
		return buildSZLNotAvailableResponse(hdr, seqNum)
	}
	// The first 4 bytes of ANY Userdata data section are the common
	// return-code(1)/transport-size(1)/length(2) header (verified against
	// s7comm_decode_ud_data's own comment: "The first 4 bytes of the data
	// part of a userdata telegram are the same for all types"). The
	// SZL-ID/Index follow that header, not the start of the data section.
	if len(data) < 8 {
		sess.record(operation{Kind: "malformed_szl_request", Detail: fmt.Sprintf("data section %d bytes, want >=8", len(data)), Raw: data, Handled: false})
		return buildSZLNotAvailableResponse(hdr, seqNum)
	}

	szlID := binary.BigEndian.Uint16(data[4:6])
	szlIdx := binary.BigEndian.Uint16(data[6:8])

	if szlID == szl001CManufacturerProfile && szlIdx == szl001CIdxManufacturer {
		sess.record(unsupportedSZLOperation(szlID, szlIdx, data))
		return buildSZLNotAvailableResponse(hdr, seqNum)
	}

	recLen, records, ok := szlLookup(szlID, szlIdx)
	if !ok {
		sess.record(unsupportedSZLOperation(szlID, szlIdx, data))
		return buildSZLNotAvailableResponse(hdr, seqNum)
	}

	sess.advance(stageIdentity)
	sess.record(operation{Kind: "szl_read", Detail: fmt.Sprintf("szl_id=0x%04X index=0x%04X", szlID, szlIdx), Handled: true})
	return buildSZLSuccessResponse(hdr, seqNum, szlID, szlIdx, recLen, records)
}

// buildExtendedUserdataParam builds the 12-byte extended parameter section
// for a CPU/Read-SZL Userdata response, echoing subfunc and seqNum from the
// request. Layout verified against s7comm_decode_ud (the "if varspec_syntax_id
// == EXT" branch).
func buildExtendedUserdataParam(subfunc, seqNum byte, errorcode uint16) []byte {
	p := make([]byte, 12)
	p[0] = fnCPUServices
	p[1] = 0x01
	p[2] = varSpecType
	p[3] = 0x08 // extended var-spec length
	p[4] = syntaxIDExt
	p[5] = (udTypeRes << 6) | udFuncGroupCPU
	p[6] = subfunc
	p[7] = seqNum
	p[8] = 0x00 // data-unit-ref: unfragmented
	p[9] = udLastDataUnitYes
	binary.BigEndian.PutUint16(p[10:12], errorcode)
	return p
}

// buildSZLNotAvailableResponse answers an unsupported (or deliberately
// withheld) SZL-ID/Index the way a real CPU answers a list it doesn't
// support: an extended Userdata response carrying paramErrSZLNotAvailable,
// no data section. Verified against s7comm_decode_ud_data: dlength < 4 means
// there is no data part to dissect at all, which is the literal reading used
// here rather than inventing a data-section error shape alongside the
// parameter-level one.
func buildSZLNotAvailableResponse(hdr s7Header, seqNum byte) []byte {
	param := buildExtendedUserdataParam(udSubfReadSZL, seqNum, paramErrSZLNotAvailable)
	return buildS7Header(rosctrUserdata, hdr.pduRef, errclsNone, 0, param, nil)
}

// buildSZLSuccessResponse builds a successful Read SZL response. Data
// section layout verified against s7comm_decode_ud_cpu_szl_subfunc: a 4-byte
// data header [return-code=0xFF, transport-size=0x09 ("not definitely
// known", constant in real captures per the dissector's own comment,
// length in BYTES), length(2)], then SZL-ID(2), SZL-Index(2), list_len(2),
// list_count(2), and list_count records of list_len bytes each.
func buildSZLSuccessResponse(hdr s7Header, seqNum byte, id, idx uint16, recLen int, records []szlRecord) []byte {
	param := buildExtendedUserdataParam(udSubfReadSZL, seqNum, 0x0000)

	payload := make([]byte, 8+recLen*len(records))
	binary.BigEndian.PutUint16(payload[0:2], id)
	binary.BigEndian.PutUint16(payload[2:4], idx)
	binary.BigEndian.PutUint16(payload[4:6], uint16(recLen))
	binary.BigEndian.PutUint16(payload[6:8], uint16(len(records)))
	pos := 8
	for _, r := range records {
		copy(payload[pos:], r)
		pos += recLen
	}

	data := make([]byte, 4+len(payload))
	data[0] = itemRetvalOK
	data[1] = dataTransportBStr
	binary.BigEndian.PutUint16(data[2:4], uint16(len(payload)))
	copy(data[4:], payload)

	return buildS7Header(rosctrUserdata, hdr.pduRef, errclsNone, 0, param, data)
}
