package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"
)

// knownShares maps share names to their ShareType (0x01=Disk, 0x02=Named Pipe).
var knownShares = map[string]uint8{
	"IPC$":   0x02, // Named pipe
	"C$":     0x01, // Disk
	"ADMIN$": 0x01, // Disk
	"shared": 0x01, // Disk
	"Users":  0x01, // Disk
}

// buildSMB1NegotiateResponse builds a minimal SMB1 negotiate response that
// directs the client to use SMB2.
func buildSMB1NegotiateResponse() []byte {
	// SMB1 header (32 bytes) + negotiate response body
	var buf bytes.Buffer

	// SMB1 header
	buf.Write(smb1Magic)           // Protocol ID
	buf.WriteByte(0x72)            // Command: Negotiate
	buf.Write(make([]byte, 4))     // Status: SUCCESS
	buf.WriteByte(0x98)            // Flags: reply + case insensitive
	binary.Write(&buf, binary.LittleEndian, uint16(0xC853)) // Flags2
	buf.Write(make([]byte, 12))    // PID high, Signature, Reserved
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // TID
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // PID
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // UID
	binary.Write(&buf, binary.LittleEndian, uint16(0))      // MID

	// Negotiate response body (word count=17, standard SMB1 negotiate response)
	buf.WriteByte(0x11) // WordCount = 17 words
	// DialectIndex: selected dialect
	binary.Write(&buf, binary.LittleEndian, uint16(0x0000))  // Selected dialect index
	buf.WriteByte(0x03)                                       // SecurityMode
	binary.Write(&buf, binary.LittleEndian, uint16(1))        // MaxMpxCount
	binary.Write(&buf, binary.LittleEndian, uint16(1))        // MaxVCs
	binary.Write(&buf, binary.LittleEndian, uint32(16644))    // MaxBufferSize
	binary.Write(&buf, binary.LittleEndian, uint32(16644))    // MaxRawSize
	binary.Write(&buf, binary.LittleEndian, uint32(0))        // SessionKey
	binary.Write(&buf, binary.LittleEndian, uint32(0xF3F9))  // Capabilities
	buf.Write(make([]byte, 8))                                 // SystemTime
	binary.Write(&buf, binary.LittleEndian, uint16(0))        // ServerTimeZone
	buf.WriteByte(0)                                           // ChallengeLength

	// ByteCount
	binary.Write(&buf, binary.LittleEndian, uint16(0))

	return buf.Bytes()
}

// buildNegotiateResponse builds an SMB2 Negotiate response.
func buildNegotiateResponse(reqHeader *smb2Header) []byte {
	resp := newResponseHeader(reqHeader, smbCmdNegotiate, statusSuccess)

	// Generate a random server GUID
	var serverGUID [16]byte
	rand.Read(serverGUID[:])

	// Build SPNEGO init token with NTLMSSP OID hint
	securityBuffer := buildNegTokenInit()

	now := time.Now()

	// SMB2 Negotiate Response structure (65 bytes fixed + security buffer)
	var body bytes.Buffer

	binary.Write(&body, binary.LittleEndian, uint16(65))      // StructureSize
	binary.Write(&body, binary.LittleEndian, uint16(0x01))     // SecurityMode: signing enabled
	binary.Write(&body, binary.LittleEndian, uint16(0x0210))   // DialectRevision: SMB 2.1
	binary.Write(&body, binary.LittleEndian, uint16(0))        // NegotiateContextCount (reserved for 3.x)
	body.Write(serverGUID[:])                                   // ServerGuid (16)
	binary.Write(&body, binary.LittleEndian, uint32(0x2F))     // Capabilities
	binary.Write(&body, binary.LittleEndian, uint32(1048576))  // MaxTransactSize (1MB)
	binary.Write(&body, binary.LittleEndian, uint32(1048576))  // MaxReadSize (1MB)
	binary.Write(&body, binary.LittleEndian, uint32(1048576))  // MaxWriteSize (1MB)
	binary.Write(&body, binary.LittleEndian, windowsFileTime(now)) // SystemTime
	binary.Write(&body, binary.LittleEndian, windowsFileTime(now)) // ServerStartTime

	// SecurityBufferOffset from start of SMB2 header:
	// header(64) + fixed body so far(60) + SecurityBufferOffset(2) + SecurityBufferLength(2) + NegotiateContextOffset(4) = 132
	// Actually let's count: body so far = 2+2+2+2+16+4+4+4+4+8+8 = 56 bytes
	secBufOffset := uint16(smb2HeaderSize + 56 + 2 + 2 + 4) // = 128
	binary.Write(&body, binary.LittleEndian, secBufOffset)                    // SecurityBufferOffset
	binary.Write(&body, binary.LittleEndian, uint16(len(securityBuffer)))     // SecurityBufferLength
	binary.Write(&body, binary.LittleEndian, uint32(0))                       // NegotiateContextOffset (reserved)

	body.Write(securityBuffer)

	header := buildSMB2Header(resp)
	var result bytes.Buffer
	result.Write(header)
	result.Write(body.Bytes())
	return result.Bytes()
}

// buildNegTokenInit builds a minimal SPNEGO NegTokenInit with NTLMSSP OID.
func buildNegTokenInit() []byte {
	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	ntlmOID := []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}

	// MechTypeList (A0 tag + SEQUENCE of OIDs)
	mechTypeList := asn1Wrap(0x30, ntlmOID)
	mechListField := asn1Wrap(0xA0, mechTypeList)

	// NegTokenInit SEQUENCE
	negTokenInit := asn1Wrap(0x30, mechListField)

	// Wrap in context tag [0] for NegTokenInit
	negToken := asn1Wrap(0xA0, negTokenInit)

	// SPNEGO OID: 1.3.6.1.5.5.2
	spnegoOID := []byte{0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}

	// APPLICATION [0] containing OID + negToken
	var appContent bytes.Buffer
	appContent.Write(spnegoOID)
	appContent.Write(negToken)

	return asn1Wrap(0x60, appContent.Bytes())
}

// buildSessionSetupResponse builds an SMB2 Session Setup response wrapping a security blob.
func buildSessionSetupResponse(reqHeader *smb2Header, securityBlob []byte, status uint32) []byte {
	resp := newResponseHeader(reqHeader, smbCmdSessionSetup, status)
	if status == statusMoreProcessingRequired {
		// Assign a session ID for the ongoing negotiation
		if resp.SessionID == 0 {
			resp.SessionID = 0x0000400000000041 // arbitrary non-zero session ID
		}
	}

	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(9))    // StructureSize
	binary.Write(&body, binary.LittleEndian, uint16(0))    // SessionFlags
	// SecurityBufferOffset: header(64) + StructureSize(2) + SessionFlags(2) + Offset(2) + Length(2) = 72
	secBufOffset := uint16(smb2HeaderSize + 8)
	binary.Write(&body, binary.LittleEndian, secBufOffset)                  // SecurityBufferOffset
	binary.Write(&body, binary.LittleEndian, uint16(len(securityBlob)))     // SecurityBufferLength
	body.Write(securityBlob)

	header := buildSMB2Header(resp)
	var result bytes.Buffer
	result.Write(header)
	result.Write(body.Bytes())
	return result.Bytes()
}

// buildTreeConnectResponse builds an SMB2 Tree Connect response.
func buildTreeConnectResponse(reqHeader *smb2Header, shareType uint8) []byte {
	resp := newResponseHeader(reqHeader, smbCmdTreeConnect, statusSuccess)

	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(16))        // StructureSize
	body.WriteByte(shareType)                                    // ShareType
	body.WriteByte(0x00)                                         // Reserved
	binary.Write(&body, binary.LittleEndian, uint32(0x30))      // ShareFlags: manual caching
	binary.Write(&body, binary.LittleEndian, uint32(0x001F01FF)) // MaximalAccess

	header := buildSMB2Header(resp)
	var result bytes.Buffer
	result.Write(header)
	result.Write(body.Bytes())
	return result.Bytes()
}

// buildErrorResponse builds a minimal SMB2 error response.
func buildErrorResponse(reqHeader *smb2Header, cmd uint16, status uint32) []byte {
	resp := newResponseHeader(reqHeader, cmd, status)

	var body bytes.Buffer
	binary.Write(&body, binary.LittleEndian, uint16(9)) // StructureSize
	body.WriteByte(0)                                     // ErrorContextCount
	body.WriteByte(0)                                     // Reserved
	binary.Write(&body, binary.LittleEndian, uint32(0))  // ByteCount
	body.WriteByte(0)                                     // ErrorData (1 byte padding)

	header := buildSMB2Header(resp)
	var result bytes.Buffer
	result.Write(header)
	result.Write(body.Bytes())
	return result.Bytes()
}

// parseTreeConnectPath extracts the UNC share path from a Tree Connect request body.
// The body parameter is the full SMB2 packet (header + body).
func parseTreeConnectPath(fullPacket []byte) string {
	// Tree Connect request body starts after the 64-byte header:
	//   StructureSize (2) + Flags/Reserved (2) + PathOffset (2) + PathLength (2)
	if len(fullPacket) < smb2HeaderSize+8 {
		return ""
	}

	body := fullPacket[smb2HeaderSize:]
	pathOffset := binary.LittleEndian.Uint16(body[4:6])
	pathLength := binary.LittleEndian.Uint16(body[6:8])

	// PathOffset is from the beginning of the SMB2 header
	if int(pathOffset)+int(pathLength) > len(fullPacket) {
		return ""
	}

	pathBytes := fullPacket[pathOffset : pathOffset+pathLength]
	return decodeUTF16LEPath(pathBytes)
}

// decodeUTF16LEPath decodes a UTF-16LE encoded path.
func decodeUTF16LEPath(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

// extractShareName extracts the share name from a UNC path like \\server\share.
func extractShareName(uncPath string) string {
	// Remove leading backslashes
	path := strings.TrimLeft(uncPath, "\\")
	// Split by backslash: server\share
	parts := strings.SplitN(path, "\\", 2)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}
