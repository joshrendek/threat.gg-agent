package modbus

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// MBAP (Modbus Application Protocol) header layout, verified against
// Wireshark's packet-mbtcp.c dissect_mbtcp_pdu_common: transaction
// identifier(2, big-endian), protocol identifier(2, big-endian, MUST be
// 0x0000), length(2, big-endian, counting the unit identifier byte AND
// everything after it -- i.e. unit id + PDU, NOT the 6 bytes before it),
// unit identifier(1). 7 bytes total.
const (
	mbapHeaderLen = 7
	protocolID    = 0x0000

	// minLength/maxLength are the length field's valid range, per
	// ei_mbtcp_invalid_length in packet-mbtcp.c: length must cover at least
	// the unit id byte plus a 1-byte function code (2), and Modbus/TCP's
	// PDU is capped at 253 bytes, so unit id(1)+PDU(253) tops out at 254.
	minLength = 2
	maxLength = 254
)

var errMBAP = errors.New("malformed MBAP frame")

// mbapHeader is what a request's MBAP header carries that a response must
// echo back: the transaction identifier (so a client can match responses to
// requests on a connection with multiple in flight) and the unit identifier
// (the addressed sub-device on a serial gateway; meaningless for a directly
// IP-connected device, but real slaves echo it regardless).
type mbapHeader struct {
	transactionID uint16
	unitID        byte
}

// readMBAP reads one Modbus/TCP ADU (MBAP header + PDU) from r. It returns
// the header fields needed to answer, and the PDU bytes (function code +
// data) that followed. The declared length is validated -- against both a
// sane minimum and maxLength -- before any allocation beyond the fixed
// 7-byte header, so a crafted length prefix cannot force a large
// allocation, mirroring s7comm's readTPKT.
//
// A non-zero protocol identifier is also rejected: 0x0000 is the only value
// real Modbus/TCP ever uses (it identifies the payload as Modbus, not some
// other protocol multiplexed over the same TCP port), and a real slave
// would not know what to do with anything else either.
func readMBAP(r *bufio.Reader) (mbapHeader, []byte, error) {
	var hdr [mbapHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return mbapHeader{}, nil, err
	}

	transactionID := binary.BigEndian.Uint16(hdr[0:2])
	protoID := binary.BigEndian.Uint16(hdr[2:4])
	length := binary.BigEndian.Uint16(hdr[4:6])
	unitID := hdr[6]

	if protoID != protocolID {
		return mbapHeader{}, nil, errMBAP
	}
	if length < minLength || length > maxLength {
		return mbapHeader{}, nil, errMBAP
	}

	// length counts the unit id byte (already read above) plus the PDU, so
	// the PDU alone is length-1 bytes.
	pdu := make([]byte, int(length)-1)
	if _, err := io.ReadFull(r, pdu); err != nil {
		return mbapHeader{}, nil, err
	}

	return mbapHeader{transactionID: transactionID, unitID: unitID}, pdu, nil
}

// writeMBAP wraps pdu in an MBAP header answering hdr -- echoing the
// transaction id and unit id, exactly as a real slave does -- and writes
// the frame.
func writeMBAP(w io.Writer, hdr mbapHeader, pdu []byte) error {
	length := len(pdu) + 1 // + unit id
	if length > maxLength {
		// Can't happen for anything this package builds -- our responses
		// are at most a couple hundred bytes -- but never emit a frame
		// whose declared length the wire format can't represent.
		return errMBAP
	}

	buf := make([]byte, mbapHeaderLen+len(pdu))
	binary.BigEndian.PutUint16(buf[0:2], hdr.transactionID)
	binary.BigEndian.PutUint16(buf[2:4], protocolID)
	binary.BigEndian.PutUint16(buf[4:6], uint16(length))
	buf[6] = hdr.unitID
	copy(buf[mbapHeaderLen:], pdu)

	_, err := w.Write(buf)
	return err
}
