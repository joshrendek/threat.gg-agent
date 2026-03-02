package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	tpktVersion    = 0x03
	maxTPKTPayload = 16384 // 16KB max message size

	// X.224 PDU types
	x224TypeCR = 0xE0 // Connection Request
	x224TypeCC = 0xD0 // Connection Confirm

	// RDP negotiation types
	rdpNegReqType = 0x01

	// RDP protocol flags
	protocolRDP    uint32 = 0x00
	protocolSSL    uint32 = 0x01
	protocolHybrid uint32 = 0x02
)

type x224Request struct {
	cookie             string
	requestedProtocols uint32
	hasNegReq          bool
}

// readTPKT reads a TPKT packet from the reader and returns the payload (after the 4-byte header).
func readTPKT(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("reading TPKT header: %w", err)
	}

	if header[0] != tpktVersion {
		return nil, fmt.Errorf("invalid TPKT version: 0x%02x", header[0])
	}

	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 4 {
		return nil, fmt.Errorf("invalid TPKT length: %d", length)
	}
	if length > maxTPKTPayload {
		return nil, fmt.Errorf("TPKT payload too large: %d", length)
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("reading TPKT payload: %w", err)
	}

	return payload, nil
}

// parseX224Request parses an X.224 Connection Request PDU.
func parseX224Request(payload []byte) (*x224Request, error) {
	if len(payload) < 6 {
		return nil, fmt.Errorf("X.224 payload too short: %d bytes", len(payload))
	}

	// payload[0] = length indicator
	// payload[1] = CR (0xE0)
	// payload[2:4] = dst-ref
	// payload[4:6] = src-ref
	// payload[6] = class options

	pduType := payload[1]
	if pduType != x224TypeCR {
		return nil, fmt.Errorf("expected X.224 CR (0xE0), got 0x%02x", pduType)
	}

	req := &x224Request{}

	// Variable part starts at offset 7
	if len(payload) <= 7 {
		return req, nil
	}
	variable := payload[7:]

	// Extract cookie: look for "Cookie: mstshash=" ... "\r\n"
	cookiePrefix := []byte("Cookie: mstshash=")
	if idx := bytes.Index(variable, cookiePrefix); idx >= 0 {
		start := idx + len(cookiePrefix)
		rest := variable[start:]
		if end := bytes.Index(rest, []byte("\r\n")); end >= 0 {
			req.cookie = string(rest[:end])
			// Advance past the cookie line for RDP_NEG_REQ parsing
			variable = rest[end+2:]
		}
	}

	// Look for RDP_NEG_REQ structure: type(1) + flags(1) + length(2) + requestedProtocols(4) = 8 bytes
	for i := 0; i+8 <= len(variable); i++ {
		if variable[i] == rdpNegReqType {
			negLen := binary.LittleEndian.Uint16(variable[i+2 : i+4])
			if negLen == 0x0008 && i+8 <= len(variable) {
				req.requestedProtocols = binary.LittleEndian.Uint32(variable[i+4 : i+8])
				req.hasNegReq = true
				break
			}
		}
	}

	return req, nil
}

// writeX224Confirm writes a TPKT + X.224 Connection Confirm + RDP_NEG_RSP.
func writeX224Confirm(w io.Writer, selectedProtocol uint32) error {
	// X.224 Connection Confirm:
	//   LI(1) + CC(1) + dst-ref(2) + src-ref(2) + class(1) = 7 bytes fixed
	// RDP_NEG_RSP:
	//   type(1) + flags(1) + length(2) + selectedProtocol(4) = 8 bytes

	x224Len := 7 + 8
	tpktLen := 4 + x224Len

	var buf bytes.Buffer

	// TPKT header
	buf.WriteByte(tpktVersion)
	buf.WriteByte(0x00) // reserved
	binary.Write(&buf, binary.BigEndian, uint16(tpktLen))

	// X.224 CC
	buf.WriteByte(byte(x224Len - 1)) // length indicator (excludes itself)
	buf.WriteByte(x224TypeCC)         // CC
	binary.Write(&buf, binary.BigEndian, uint16(0x0000)) // dst-ref
	binary.Write(&buf, binary.BigEndian, uint16(0x0000)) // src-ref
	buf.WriteByte(0x00) // class

	// RDP_NEG_RSP
	buf.WriteByte(0x02) // type: RDP_NEG_RSP
	buf.WriteByte(0x00) // flags
	binary.Write(&buf, binary.LittleEndian, uint16(0x0008)) // length
	binary.Write(&buf, binary.LittleEndian, selectedProtocol)

	_, err := w.Write(buf.Bytes())
	return err
}
