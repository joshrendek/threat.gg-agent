package s7comm

import (
	"encoding/binary"
	"errors"
)

// COTP (ISO 8073 / ISO-TP over TCP, RFC 1006) TPDU type bytes. Verified
// against Wireshark's packet-ositp.c: the type nibble (CR=0xE, CC=0xD,
// DT=0xF) occupies the high nibble of the type byte, with the low nibble
// used for flow-control credit in classes 2-4. S7comm only ever runs over
// COTP class 0, where credit is always 0, so these are simply the full byte
// values class-0 traffic uses.
const (
	cotpCR = 0xE0
	cotpCC = 0xD0
	cotpDT = 0xF0

	// dtHeaderLen is LI(1) + type(1) + TPDU-NR/EOT(1) for a class-0/1 DT
	// TPDU (packet-ositp.c: LI_NORMAL_DT_CLASS_01 == 2, i.e. 2 bytes follow
	// the LI byte itself).
	dtHeaderLen = 3
	// dtEOT is the TPDU-NR/EOT byte we always send: bit 0x80 set means "this
	// is the last (only) fragment", TPDU-NR 0. S7 PDUs are always small
	// enough to fit in a single DT, so we never need to fragment.
	dtEOT = 0x80

	// COTP variable-part parameter codes (packet-ositp.c VP_* constants).
	vpTPDUSize = 0xC0
	vpSrcTSAP  = 0xC1
	vpDstTSAP  = 0xC2
)

var errCOTP = errors.New("malformed COTP frame")

// cotpConnectRequest is what parseCR extracts from a CR TPDU in order to
// build the matching CC.
type cotpConnectRequest struct {
	srcRef uint16 // the calling side's reference for this connection
	// tpduSizeByte is the raw VP_TPDU_SIZE value (a log2 exponent, e.g. 0x0A
	// -> 1024), or 0 if the client didn't send one.
	tpduSizeByte byte
	srcTSAP      []byte
	dstTSAP      []byte
}

// parseCR parses a COTP Connect Request TPDU. b must start at the LI byte
// (i.e. right after the TPKT header). Field order verified against
// ositp_decode_CR_CC in packet-ositp.c: LI(1), type(1), dst-ref(2),
// src-ref(2), class/option(1), then a TLV variable part running to the end
// of the TPDU (li - 6 bytes).
//
// Real S7 clients always send dst-ref 0x0000 on a fresh CR (it's assigned by
// the far end), so it is intentionally not extracted here.
func parseCR(b []byte) (cotpConnectRequest, error) {
	var cr cotpConnectRequest

	// LI + type + dst-ref(2) + src-ref(2) + class(1) = 7 bytes minimum.
	if len(b) < 7 {
		return cr, errCOTP
	}
	li := int(b[0])
	if li < 6 || li+1 > len(b) {
		return cr, errCOTP
	}
	if b[1] != cotpCR {
		return cr, errCOTP
	}
	cr.srcRef = binary.BigEndian.Uint16(b[4:6])
	// b[6] is the class/option byte. Real S7-300s only ever negotiate class
	// 0; this honeypot accepts whatever a scanner sends rather than
	// validating it, to maximize the chance of continuing the exchange.

	parseCOTPVariablePart(b[7:li+1], &cr)
	return cr, nil
}

// parseCOTPVariablePart walks the CR's TLV variable part (code(1),
// length(1), value(length)) and fills in the fields this honeypot cares
// about. A truncated or malformed entry stops the walk rather than erroring
// out the whole CR -- whatever was already parsed is still usable.
func parseCOTPVariablePart(vp []byte, cr *cotpConnectRequest) {
	for len(vp) >= 2 {
		code := vp[0]
		length := int(vp[1])
		if 2+length > len(vp) {
			return
		}
		val := vp[2 : 2+length]
		switch code {
		case vpTPDUSize:
			if length >= 1 {
				cr.tpduSizeByte = val[0]
			}
		case vpSrcTSAP:
			cr.srcTSAP = append([]byte(nil), val...)
		case vpDstTSAP:
			cr.dstTSAP = append([]byte(nil), val...)
		}
		vp = vp[2+length:]
	}
}

// buildCC builds a COTP Connect Confirm TPDU answering cr, with ourRef as
// this honeypot's newly chosen reference for the connection.
//
// Per COTP negotiation convention (and confirmed by ositp_decode_CR_CC,
// which dissects CR and CC with the same field layout): the CC's dst-ref
// echoes the CR's src-ref, and TSAPs are swapped -- our src-tsap is the
// dst-tsap the client asked for, our dst-tsap is the client's own src-tsap.
//
// INVENTED (behaviour, not layout): this honeypot accepts and echoes back
// ANY TSAP pair rather than validating a specific rack/slot. Captured
// traffic shows scanners trying multiple destination TSAPs while enumerating
// rack/slot combinations; refusing the ones a real CPU might reject would
// cut that reconnaissance short before it reaches the more interesting S7
// layer, and is exactly the kind of business-logic behaviour that isn't
// documented in Wireshark's dissector (which only decodes bytes, not CPU
// policy). Flagged here because neither the brief nor the dissector settled
// it either way.
func buildCC(cr cotpConnectRequest, ourRef uint16) []byte {
	var vp []byte
	if cr.tpduSizeByte != 0 {
		vp = append(vp, vpTPDUSize, 1, cr.tpduSizeByte)
	}
	if len(cr.dstTSAP) > 0 {
		vp = append(vp, vpSrcTSAP, byte(len(cr.dstTSAP)))
		vp = append(vp, cr.dstTSAP...)
	}
	if len(cr.srcTSAP) > 0 {
		vp = append(vp, vpDstTSAP, byte(len(cr.srcTSAP)))
		vp = append(vp, cr.srcTSAP...)
	}

	li := 6 + len(vp)
	b := make([]byte, 1+li)
	b[0] = byte(li)
	b[1] = cotpCC
	binary.BigEndian.PutUint16(b[2:4], cr.srcRef) // dst-ref = echo of the CR's src-ref
	binary.BigEndian.PutUint16(b[4:6], ourRef)    // src-ref = our new reference
	b[6] = 0x00                                   // class 0, no options
	copy(b[7:], vp)
	return b
}

// parseDT strips a class-0/1 COTP Data TPDU's 3-byte header and returns the
// enclosed S7 payload. Verified against packet-ositp.c: LI=0x02, type=0xF0,
// then one TPDU-NR/EOT byte.
func parseDT(b []byte) ([]byte, error) {
	if len(b) < dtHeaderLen {
		return nil, errCOTP
	}
	if b[0] != 0x02 || b[1] != cotpDT {
		return nil, errCOTP
	}
	// b[2] is TPDU-NR/EOT. This honeypot never fragments a response and
	// never needs to reassemble a fragmented request (S7 PDUs are always
	// far smaller than the negotiated TPDU size), so it is read but not
	// acted on: whatever follows is treated as one complete PDU.
	return b[dtHeaderLen:], nil
}

// buildDT wraps payload in a class-0/1 COTP Data TPDU.
func buildDT(payload []byte) []byte {
	b := make([]byte, dtHeaderLen+len(payload))
	b[0] = 0x02
	b[1] = cotpDT
	b[2] = dtEOT
	copy(b[3:], payload)
	return b
}
