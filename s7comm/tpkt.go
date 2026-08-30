package s7comm

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

const (
	tpktHeaderLen = 4
	tpktVersion   = 3

	// maxTPKTLength bounds a single accepted TPKT frame. Real S7 PDUs we
	// implement (setup communication, read/write var, read SZL) are all well
	// under 1 KiB; this cap is generous headroom while still refusing to let
	// a hostile 2-byte length prefix drive a large up-front allocation.
	maxTPKTLength = 4096
)

var errTPKT = errors.New("malformed TPKT frame")

// readTPKT reads one TPKT-framed PDU (RFC 1006): version(1)=3, reserved(1),
// length(2, big-endian, INCLUDING the 4-byte header itself). It returns the
// payload after the header. The declared length is validated -- against both
// a sane minimum and maxTPKTLength -- before any allocation beyond the fixed
// 4-byte header, so a crafted length prefix cannot force a large allocation.
func readTPKT(r *bufio.Reader) ([]byte, error) {
	var hdr [tpktHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != tpktVersion {
		return nil, errTPKT
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < tpktHeaderLen || total > maxTPKTLength {
		return nil, errTPKT
	}

	payload := make([]byte, total-tpktHeaderLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// writeTPKT wraps payload in a TPKT header and writes the frame.
func writeTPKT(w io.Writer, payload []byte) error {
	if tpktHeaderLen+len(payload) > 0xFFFF {
		// Can't happen for anything this package builds -- our responses are
		// at most a few hundred bytes -- but never emit a truncated length.
		return errTPKT
	}
	buf := make([]byte, tpktHeaderLen+len(payload))
	buf[0] = tpktVersion
	buf[1] = 0
	binary.BigEndian.PutUint16(buf[2:4], uint16(tpktHeaderLen+len(payload)))
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}
