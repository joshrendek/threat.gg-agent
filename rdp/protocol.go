package rdp

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
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
	protocolRDP      uint32 = 0x00
	protocolSSL      uint32 = 0x01
	protocolHybrid   uint32 = 0x02
	protocolRDSTLS   uint32 = 0x04
	protocolHybridEx uint32 = 0x08

	// Client data user-data block types.
	csCore uint16 = 0xC001
	csNet  uint16 = 0xC003

	maxClientChannels  = 32
	clientNameBytes    = 32
	channelNameBytes   = 8
	supportedProtocols = protocolSSL | protocolHybrid | protocolHybridEx
)

// Errors returned by bounded protocol parsers. Callers can use errors.Is
// to distinguish malformed input from a message exceeding a protocol cap.
var (
	ErrRDPMalformed = errors.New("malformed RDP data")
	ErrRDPTooLarge  = errors.New("RDP data too large")
	errRDPMalformed = ErrRDPMalformed
	errRDPTooLarge  = ErrRDPTooLarge
)

type x224Request struct {
	cookie             string
	requestedProtocols uint32
	hasNegReq          bool
}

// selectProtocol chooses the protocol advertised by an X.224 negotiation.
// A missing negotiation is the legacy Standard RDP path. A negotiation that
// contains any unknown bit is rejected rather than silently downgraded.
func selectProtocol(req x224Request) (uint32, error) {
	return selectRDPProtocol(req.hasNegReq, req.requestedProtocols)
}

// selectRDPProtocol is the value-level form of selectProtocol.
func selectRDPProtocol(hasNegReq bool, requestedProtocols uint32) (uint32, error) {
	if requestedProtocols&^supportedProtocols != 0 {
		return 0, fmt.Errorf("%w: unsupported protocol mask 0x%08x", errRDPMalformed, requestedProtocols)
	}
	if !hasNegReq {
		return protocolRDP, nil
	}
	if requestedProtocols&protocolHybrid != 0 {
		return protocolHybrid, nil
	}
	if requestedProtocols&protocolHybridEx != 0 {
		return 0, fmt.Errorf("%w: HybridEx requires unsupported extended NLA", errRDPMalformed)
	}
	if requestedProtocols&protocolSSL != 0 {
		return protocolSSL, nil
	}
	return protocolRDP, nil
}

// SelectProtocol exposes protocol selection to callers outside this package.
func SelectProtocol(hasNegReq bool, requestedProtocols uint32) (uint32, error) {
	return selectRDPProtocol(hasNegReq, requestedProtocols)
}

// readTPKT reads a TPKT packet from the reader and returns the payload (after the 4-byte header).
func readTPKT(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("reading TPKT header: %w", err)
	}

	if header[0] != tpktVersion {
		return nil, fmt.Errorf("%w: invalid TPKT version: 0x%02x", errRDPMalformed, header[0])
	}

	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 4 {
		return nil, fmt.Errorf("%w: invalid TPKT length %d", errRDPMalformed, length)
	}
	if length > maxTPKTPayload {
		return nil, fmt.Errorf("%w: TPKT length %d", errRDPTooLarge, length)
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("reading TPKT payload: %w", err)
	}

	return payload, nil
}

// parseX224Request parses an X.224 Connection Request PDU.
func parseX224Request(payload []byte) (*x224Request, error) {
	if len(payload) < 7 {
		return nil, fmt.Errorf("%w: X.224 payload too short: %d bytes", errRDPMalformed, len(payload))
	}
	li := int(payload[0])
	if li < 6 || li+1 != len(payload) {
		return nil, fmt.Errorf("%w: X.224 length indicator %d for %d-byte payload", errRDPMalformed, li, len(payload))
	}

	// payload[0] = length indicator
	// payload[1] = CR (0xE0)
	// payload[2:4] = dst-ref
	// payload[4:6] = src-ref
	// payload[6] = class options

	pduType := payload[1]
	if pduType != x224TypeCR {
		return nil, fmt.Errorf("%w: expected X.224 CR (0xE0), got 0x%02x", errRDPMalformed, pduType)
	}

	req := &x224Request{}

	// Variable part starts at offset 7.
	if len(payload) == 7 {
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

	// Look for RDP_NEG_REQ structure: type(1) + flags(1) + length(2) +
	// requestedProtocols(4) = 8 bytes. Once a negotiation marker is found,
	// malformed framing is an error; it must not silently become Standard RDP.
	for i := 0; i < len(variable); i++ {
		if variable[i] != rdpNegReqType {
			continue
		}
		if len(variable)-i < 4 {
			return nil, fmt.Errorf("%w: truncated RDP_NEG_REQ", errRDPMalformed)
		}
		negLen := binary.LittleEndian.Uint16(variable[i+2 : i+4])
		if negLen != 0x0008 {
			return nil, fmt.Errorf("%w: invalid RDP_NEG_REQ length %d", errRDPMalformed, negLen)
		}
		if len(variable)-i < int(negLen) {
			return nil, fmt.Errorf("%w: truncated RDP_NEG_REQ body", errRDPMalformed)
		}
		req.requestedProtocols = binary.LittleEndian.Uint32(variable[i+4 : i+8])
		req.hasNegReq = true
		break
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
	buf.WriteByte(byte(x224Len - 1))                     // length indicator (excludes itself)
	buf.WriteByte(x224TypeCC)                            // CC
	binary.Write(&buf, binary.BigEndian, uint16(0x0000)) // dst-ref
	binary.Write(&buf, binary.BigEndian, uint16(0x0000)) // src-ref
	buf.WriteByte(0x00)                                  // class

	// RDP_NEG_RSP
	buf.WriteByte(0x02)                                     // type: RDP_NEG_RSP
	buf.WriteByte(0x00)                                     // flags
	binary.Write(&buf, binary.LittleEndian, uint16(0x0008)) // length
	binary.Write(&buf, binary.LittleEndian, selectedProtocol)

	_, err := w.Write(buf.Bytes())
	return err
}

// clientData contains the bounded subset of GCC client data that is useful
// for a connection persona. Fields not listed here are intentionally ignored.
type clientData struct {
	Build          uint32
	ClientBuild    uint32
	Width          uint16
	DesktopWidth   uint16
	Height         uint16
	DesktopHeight  uint16
	KeyboardLayout string
	ClientName     string
	Channels       []string
}

// keyboardLayoutLabel returns a stable, bounded label. Unknown layouts retain
// their numeric identity in a fixed-width representation rather than copying
// attacker-controlled data.
func keyboardLayoutLabel(layout uint32) string {
	switch layout {
	case 0x00000409:
		return "en-US"
	case 0x00000809:
		return "en-GB"
	case 0x00000407:
		return "de-DE"
	case 0x0000040c:
		return "fr-FR"
	case 0x00000410:
		return "it-IT"
	case 0x0000040a:
		return "es-ES"
	case 0x00000416:
		return "pt-BR"
	case 0x00000411:
		return "ja-JP"
	case 0x00000412:
		return "ko-KR"
	case 0x00000419:
		return "ru-RU"
	case 0x0000040d:
		return "he-IL"
	case 0x0000040e:
		return "hu-HU"
	case 0x00000414:
		return "nb-NO"
	case 0x00000415:
		return "pl-PL"
	case 0x0000041d:
		return "sv-SE"
	default:
		return fmt.Sprintf("0x%08x", layout)
	}
}

func decodeFixedClientName(raw []byte) (string, error) {
	if len(raw) != clientNameBytes || len(raw)%2 != 0 {
		return "", fmt.Errorf("%w: client name length %d", errRDPMalformed, len(raw))
	}
	end := len(raw)
	for i := 0; i+1 < len(raw); i += 2 {
		if raw[i] == 0 && raw[i+1] == 0 {
			end = i
			break
		}
	}
	u16 := make([]uint16, end/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(raw[i*2:])
	}
	for i := 0; i < len(u16); i++ {
		switch {
		case u16[i] >= 0xD800 && u16[i] <= 0xDBFF:
			if i+1 >= len(u16) || u16[i+1] < 0xDC00 || u16[i+1] > 0xDFFF {
				return "", fmt.Errorf("%w: invalid UTF-16 client name", errRDPMalformed)
			}
			i++
		case u16[i] >= 0xDC00 && u16[i] <= 0xDFFF:
			return "", fmt.Errorf("%w: invalid UTF-16 client name", errRDPMalformed)
		}
	}
	if end == 0 {
		return "", nil
	}
	return string(utf16.Decode(u16)), nil
}

func decodeChannelName(raw []byte) (string, error) {
	end := len(raw)
	for i, b := range raw {
		if b == 0 {
			end = i
			break
		}
		if b < 0x20 || b > 0x7e {
			return "", fmt.Errorf("%w: invalid channel name byte 0x%02x", errRDPMalformed, b)
		}
	}
	return strings.TrimRight(string(raw[:end]), " "), nil
}

// parseClientData parses the TS_UD_CS_CORE and TS_UD_CS_NET blocks carried in
// the GCC Client Data portion of an MCS connection. Every block is length
// checked before its fixed-width fields are read.
func parseClientData(data []byte) (*clientData, error) {
	if len(data) > maxTPKTPayload {
		return nil, fmt.Errorf("%w: client data length %d", errRDPTooLarge, len(data))
	}
	result := &clientData{}
	for offset := 0; offset < len(data); {
		if len(data)-offset < 4 {
			return nil, fmt.Errorf("%w: truncated client-data header", errRDPMalformed)
		}
		blockType := binary.LittleEndian.Uint16(data[offset : offset+2])
		blockLen := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		if blockLen < 4 {
			return nil, fmt.Errorf("%w: client-data block length %d", errRDPMalformed, blockLen)
		}
		if blockLen > maxTPKTPayload {
			return nil, fmt.Errorf("%w: client-data block length %d", errRDPTooLarge, blockLen)
		}
		if blockLen > len(data)-offset {
			return nil, fmt.Errorf("%w: client-data block length %d exceeds remaining %d", errRDPMalformed, blockLen, len(data)-offset)
		}
		block := data[offset : offset+blockLen]
		switch blockType {
		case csCore:
			if err := parseCoreClientData(result, block); err != nil {
				return nil, err
			}
		case csNet:
			if err := parseNetworkClientData(result, block); err != nil {
				return nil, err
			}
		}
		offset += blockLen
	}
	return result, nil
}

func parseCoreClientData(result *clientData, block []byte) error {
	// Header plus version, dimensions, keyboard layout, build and fixed
	// 16-character UTF-16 client name.
	const minimumCoreLength = 4 + 20 + clientNameBytes
	if len(block) < minimumCoreLength {
		return fmt.Errorf("%w: CS_CORE length %d", errRDPMalformed, len(block))
	}
	keyboardLayout := binary.LittleEndian.Uint32(block[16:20])
	build := binary.LittleEndian.Uint32(block[20:24])
	name, err := decodeFixedClientName(block[24 : 24+clientNameBytes])
	if err != nil {
		return err
	}
	result.Build = build
	result.ClientBuild = build
	result.Width = binary.LittleEndian.Uint16(block[8:10])
	result.DesktopWidth = result.Width
	result.Height = binary.LittleEndian.Uint16(block[10:12])
	result.DesktopHeight = result.Height
	result.KeyboardLayout = keyboardLayoutLabel(keyboardLayout)
	result.ClientName = name
	return nil
}

func parseNetworkClientData(result *clientData, block []byte) error {
	const networkHeaderLength = 8
	if len(block) < networkHeaderLength {
		return fmt.Errorf("%w: CS_NET length %d", errRDPMalformed, len(block))
	}
	count := int(binary.LittleEndian.Uint16(block[6:8]))
	if count > maxClientChannels {
		return fmt.Errorf("%w: CS_NET channel count %d", errRDPTooLarge, count)
	}
	expected := networkHeaderLength + count*12
	if expected != len(block) {
		return fmt.Errorf("%w: CS_NET length %d for %d channels (want %d)", errRDPMalformed, len(block), count, expected)
	}
	seen := make(map[string]struct{}, count)
	for i := 0; i < count; i++ {
		start := networkHeaderLength + i*12
		name, err := decodeChannelName(block[start : start+channelNameBytes])
		if err != nil {
			return err
		}
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result.Channels = append(result.Channels, name)
	}
	return nil
}

// parseGCCClientData parses a block-aligned GCC user-data sequence.
func parseGCCClientData(data []byte) (*clientData, error) {
	return parseClientData(data)
}

// parseMCSClientData locates complete CS_CORE and CS_NET blocks in a bounded
// MCS packet. MCS/GCC packets contain X.224 and MCS headers before the user
// data, so the first block is not necessarily at offset zero.
func parseMCSClientData(data []byte) (*clientData, error) {
	if len(data) > maxTPKTPayload {
		return nil, fmt.Errorf("%w: MCS client data length %d", errRDPTooLarge, len(data))
	}
	// Client Core Data is the mandatory first TS_UD block in the GCC user-data
	// sequence. Use a fully valid core block as the anchor; marker-like bytes in
	// the X.224/MCS/PER prefix are ignored rather than treated as malformed GCC.
	for offset := 0; offset+4 <= len(data); offset++ {
		if binary.LittleEndian.Uint16(data[offset:offset+2]) != csCore {
			continue
		}
		blockLen := int(binary.LittleEndian.Uint16(data[offset+2 : offset+4]))
		if blockLen < 4+20+clientNameBytes || blockLen > maxTPKTPayload || blockLen > len(data)-offset {
			continue
		}
		result, err := parseClientData(data[offset:])
		if err == nil {
			return result, nil
		}
	}
	return nil, fmt.Errorf("%w: no complete GCC Client Core sequence", errRDPMalformed)
}

// clientFingerprint hashes only bounded protocol facts and capabilities.
// Credentials, cookies, and identity fields are deliberately not included.
func clientFingerprint(req x224Request, selected uint32, data *clientData) string {
	var material bytes.Buffer
	var fixed [4]byte
	binary.LittleEndian.PutUint32(fixed[:], req.requestedProtocols)
	material.Write(fixed[:])
	binary.LittleEndian.PutUint32(fixed[:], selected)
	material.Write(fixed[:])
	if req.hasNegReq {
		material.WriteByte(1)
	} else {
		material.WriteByte(0)
	}
	if data != nil {
		binary.LittleEndian.PutUint32(fixed[:], data.Build)
		material.Write(fixed[:])
		var dims [4]byte
		binary.LittleEndian.PutUint16(dims[0:2], data.Width)
		binary.LittleEndian.PutUint16(dims[2:4], data.Height)
		material.Write(dims[:])
		material.WriteString(data.KeyboardLayout)
		material.WriteByte(0)
		for _, channel := range data.Channels {
			material.WriteString(channel)
			material.WriteByte(0)
		}
	}
	sum := sha256.Sum256(material.Bytes())
	return hex.EncodeToString(sum[:])
}

// boundedConnectionReader keeps packet reads behind the TPKT cap. It does
// not buffer a caller-provided length, so malformed lengths cannot trigger an
// attacker-sized allocation.
type boundedConnectionReader struct {
	reader io.Reader
}

func newBoundedConnectionReader(reader io.Reader) *boundedConnectionReader {
	return &boundedConnectionReader{reader: reader}
}

func (r *boundedConnectionReader) readPacket() ([]byte, error) {
	if r == nil || r.reader == nil {
		return nil, fmt.Errorf("%w: nil connection reader", errRDPMalformed)
	}
	return readTPKT(r.reader)
}

func readBoundedConnection(reader io.Reader) ([]byte, error) {
	return newBoundedConnectionReader(reader).readPacket()
}

func readRDPConnection(reader io.Reader) ([]byte, error) {
	return readBoundedConnection(reader)
}
