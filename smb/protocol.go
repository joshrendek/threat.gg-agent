package smb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// NetBIOS session framing: 4-byte big-endian length prefix + payload.

// SMB2 header is 64 bytes.
const smb2HeaderSize = 64

// Magic bytes
var (
	smb1Magic = []byte{0xFF, 'S', 'M', 'B'}
	smb2Magic = []byte{0xFE, 'S', 'M', 'B'}
)

// SMB2 commands
const (
	smbCmdNegotiate      uint16 = 0x0000
	smbCmdSessionSetup   uint16 = 0x0001
	smbCmdLogoff         uint16 = 0x0002
	smbCmdTreeConnect    uint16 = 0x0003
	smbCmdTreeDisconnect uint16 = 0x0004
	smbCmdCreate         uint16 = 0x0005
	smbCmdClose          uint16 = 0x0006
	smbCmdRead           uint16 = 0x0008
	smbCmdIoctl          uint16 = 0x000B
	smbCmdQueryDirectory uint16 = 0x000E
)

// NT status codes
const (
	statusSuccess                uint32 = 0x00000000
	statusMoreProcessingRequired uint32 = 0xC0000016
	statusAccessDenied           uint32 = 0xC0000022
	statusNotSupported           uint32 = 0xC00000BB
	statusBadNetworkName         uint32 = 0xC00000CC
)

// smb2Header represents a parsed SMB2 packet header (64 bytes).
type smb2Header struct {
	ProtocolID    [4]byte
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	CreditRequest uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32 // ProcessId in async
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

// readNetBIOSFrame reads a NetBIOS session frame from the connection.
// Returns the payload after the 4-byte length prefix.
func readNetBIOSFrame(conn net.Conn, readTimeout time.Duration) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("reading netbios length: %w", err)
	}

	// Length is 3 bytes (the first byte has flags, typically 0 for session message).
	length := int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	if length <= 0 || length > 1<<20 { // max 1MB
		return nil, fmt.Errorf("invalid netbios frame length: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, fmt.Errorf("reading netbios payload: %w", err)
	}

	return payload, nil
}

// writeNetBIOSFrame writes a NetBIOS session frame (4-byte big-endian length prefix + payload).
func writeNetBIOSFrame(conn net.Conn, payload []byte) error {
	length := len(payload)
	frame := make([]byte, 4+length)
	frame[0] = 0x00 // session message type
	frame[1] = byte(length >> 16)
	frame[2] = byte(length >> 8)
	frame[3] = byte(length)
	copy(frame[4:], payload)
	_, err := conn.Write(frame)
	return err
}

// isSMB1 checks if the payload starts with the SMB1 magic bytes.
func isSMB1(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	return payload[0] == smb1Magic[0] && payload[1] == smb1Magic[1] &&
		payload[2] == smb1Magic[2] && payload[3] == smb1Magic[3]
}

// isSMB2 checks if the payload starts with the SMB2 magic bytes.
func isSMB2(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	return payload[0] == smb2Magic[0] && payload[1] == smb2Magic[1] &&
		payload[2] == smb2Magic[2] && payload[3] == smb2Magic[3]
}

// parseSMB2Header parses a 64-byte SMB2 header from the payload.
func parseSMB2Header(payload []byte) (*smb2Header, error) {
	if len(payload) < smb2HeaderSize {
		return nil, errors.New("payload too short for SMB2 header")
	}

	h := &smb2Header{}
	copy(h.ProtocolID[:], payload[0:4])
	h.StructureSize = binary.LittleEndian.Uint16(payload[4:6])
	h.CreditCharge = binary.LittleEndian.Uint16(payload[6:8])
	h.Status = binary.LittleEndian.Uint32(payload[8:12])
	h.Command = binary.LittleEndian.Uint16(payload[12:14])
	h.CreditRequest = binary.LittleEndian.Uint16(payload[14:16])
	h.Flags = binary.LittleEndian.Uint32(payload[16:20])
	h.NextCommand = binary.LittleEndian.Uint32(payload[20:24])
	h.MessageID = binary.LittleEndian.Uint64(payload[24:32])
	h.Reserved = binary.LittleEndian.Uint32(payload[32:36])
	h.TreeID = binary.LittleEndian.Uint32(payload[36:40])
	h.SessionID = binary.LittleEndian.Uint64(payload[40:48])
	copy(h.Signature[:], payload[48:64])

	return h, nil
}

// buildSMB2Header serializes an SMB2 header into 64 bytes.
func buildSMB2Header(h *smb2Header) []byte {
	buf := make([]byte, smb2HeaderSize)
	copy(buf[0:4], h.ProtocolID[:])
	binary.LittleEndian.PutUint16(buf[4:6], h.StructureSize)
	binary.LittleEndian.PutUint16(buf[6:8], h.CreditCharge)
	binary.LittleEndian.PutUint32(buf[8:12], h.Status)
	binary.LittleEndian.PutUint16(buf[12:14], h.Command)
	binary.LittleEndian.PutUint16(buf[14:16], h.CreditRequest)
	binary.LittleEndian.PutUint32(buf[16:20], h.Flags)
	binary.LittleEndian.PutUint32(buf[20:24], h.NextCommand)
	binary.LittleEndian.PutUint64(buf[24:32], h.MessageID)
	binary.LittleEndian.PutUint32(buf[32:36], h.Reserved)
	binary.LittleEndian.PutUint32(buf[36:40], h.TreeID)
	binary.LittleEndian.PutUint64(buf[40:48], h.SessionID)
	copy(buf[48:64], h.Signature[:])
	return buf
}

// newResponseHeader creates a response header from a request header.
func newResponseHeader(req *smb2Header, cmd uint16, status uint32) *smb2Header {
	resp := &smb2Header{}
	copy(resp.ProtocolID[:], smb2Magic)
	resp.StructureSize = 64
	resp.CreditCharge = 1
	resp.Status = status
	resp.Command = cmd
	resp.CreditRequest = 1
	resp.Flags = 0x00000001 // SMB2_FLAGS_SERVER_TO_REDIR (response)
	resp.MessageID = req.MessageID
	resp.SessionID = req.SessionID
	resp.TreeID = req.TreeID
	return resp
}
