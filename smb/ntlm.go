package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf16"
)

// NTLMSSP message types
const (
	ntlmNegotiate    uint32 = 1
	ntlmChallenge    uint32 = 2
	ntlmAuthenticate uint32 = 3
)

var ntlmsspSignature = []byte("NTLMSSP\x00")

// ntlmServer holds per-session NTLM state.
type ntlmServer struct {
	challenge [8]byte
}

// newNTLMServer creates a new NTLM server with a random 8-byte challenge.
func newNTLMServer() *ntlmServer {
	s := &ntlmServer{}
	rand.Read(s.challenge[:])
	return s
}

// isNTLMSSP checks if data starts with the "NTLMSSP\x00" signature.
func isNTLMSSP(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	return bytes.Equal(data[:8], ntlmsspSignature)
}

// getNTLMMessageType reads the message type at offset 8.
func getNTLMMessageType(data []byte) uint32 {
	if len(data) < 12 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[8:12])
}

// encodeUTF16LE encodes a string as UTF-16 little-endian bytes.
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

// decodeUTF16LE decodes UTF-16 little-endian bytes to a string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := range u16s {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

// buildType2Challenge constructs an NTLMSSP Type 2 (Challenge) message.
func buildType2Challenge(server *ntlmServer) []byte {
	targetName := encodeUTF16LE("WORKGROUP")
	computerName := encodeUTF16LE("SERVER")
	dnsDomain := encodeUTF16LE("workgroup")
	dnsComputer := encodeUTF16LE("server")

	// Build target info buffer
	var targetInfo bytes.Buffer

	// MsvAvNbDomainName (type 2)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0002)) // AvId
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(targetName)))
	targetInfo.Write(targetName)

	// MsvAvNbComputerName (type 1)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0001)) // AvId
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(computerName)))
	targetInfo.Write(computerName)

	// MsvAvDnsDomainName (type 4)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0004)) // AvId
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(dnsDomain)))
	targetInfo.Write(dnsDomain)

	// MsvAvDnsComputerName (type 3)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0003)) // AvId
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(dnsComputer)))
	targetInfo.Write(dnsComputer)

	// MsvAvTimestamp (type 7)
	// Windows FILETIME: 100-nanosecond intervals since January 1, 1601
	ft := windowsFileTime(time.Now())
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0007)) // AvId
	binary.Write(&targetInfo, binary.LittleEndian, uint16(8))
	binary.Write(&targetInfo, binary.LittleEndian, ft)

	// MsvAvEOL (type 0)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0000))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0))

	targetInfoBytes := targetInfo.Bytes()

	// NTLMSSP Challenge message layout:
	// Signature (8) + MessageType (4) + TargetNameFields (8) + NegotiateFlags (4) +
	// ServerChallenge (8) + Reserved (8) + TargetInfoFields (8) = 48 bytes header
	// Then: TargetName + TargetInfo

	targetNameOffset := uint32(48)                                   // right after the fixed header
	targetInfoOffset := targetNameOffset + uint32(len(targetName))

	var msg bytes.Buffer
	msg.Write(ntlmsspSignature)                                             // Signature (8)
	binary.Write(&msg, binary.LittleEndian, ntlmChallenge)                  // MessageType (4)

	// TargetNameFields: Len (2), MaxLen (2), Offset (4)
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&msg, binary.LittleEndian, targetNameOffset)

	// NegotiateFlags
	binary.Write(&msg, binary.LittleEndian, uint32(0x00028233))

	// ServerChallenge (8)
	msg.Write(server.challenge[:])

	// Reserved (8)
	msg.Write(make([]byte, 8))

	// TargetInfoFields: Len (2), MaxLen (2), Offset (4)
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetInfoBytes)))
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetInfoBytes)))
	binary.Write(&msg, binary.LittleEndian, targetInfoOffset)

	// TargetName
	msg.Write(targetName)

	// TargetInfo
	msg.Write(targetInfoBytes)

	return msg.Bytes()
}

// parseType3Auth extracts credentials from an NTLMSSP Type 3 (Authenticate) message.
func parseType3Auth(data []byte) (username, domain, workstation string, ntlmResponse []byte) {
	if len(data) < 52 {
		return
	}

	// LmChallengeResponseFields at offset 12: Len(2), MaxLen(2), Offset(4)
	// NtChallengeResponseFields at offset 20: Len(2), MaxLen(2), Offset(4)
	ntLen := binary.LittleEndian.Uint16(data[20:22])
	ntOffset := binary.LittleEndian.Uint32(data[24:28])

	// DomainNameFields at offset 28: Len(2), MaxLen(2), Offset(4)
	domainLen := binary.LittleEndian.Uint16(data[28:30])
	domainOffset := binary.LittleEndian.Uint32(data[32:36])

	// UserNameFields at offset 36: Len(2), MaxLen(2), Offset(4)
	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOffset := binary.LittleEndian.Uint32(data[40:44])

	// WorkstationFields at offset 44: Len(2), MaxLen(2), Offset(4)
	wsLen := binary.LittleEndian.Uint16(data[44:46])
	wsOffset := binary.LittleEndian.Uint32(data[48:52])

	if int(domainOffset)+int(domainLen) <= len(data) {
		domain = decodeUTF16LE(data[domainOffset : domainOffset+uint32(domainLen)])
	}

	if int(userOffset)+int(userLen) <= len(data) {
		username = decodeUTF16LE(data[userOffset : userOffset+uint32(userLen)])
	}

	if int(wsOffset)+int(wsLen) <= len(data) {
		workstation = decodeUTF16LE(data[wsOffset : wsOffset+uint32(wsLen)])
	}

	if int(ntOffset)+int(ntLen) <= len(data) {
		ntlmResponse = make([]byte, ntLen)
		copy(ntlmResponse, data[ntOffset:ntOffset+uint32(ntLen)])
	}

	return
}

// formatNetNTLMv2Hash formats credentials for hashcat mode 5600.
// Format: username::domain:hex(challenge):hex(ntResponse[:16]):hex(ntResponse[16:])
func formatNetNTLMv2Hash(username, domain string, challenge [8]byte, ntResponse []byte) string {
	if len(ntResponse) < 24 {
		return ""
	}

	return strings.Join([]string{
		username,
		"",
		domain,
		hex.EncodeToString(challenge[:]),
		hex.EncodeToString(ntResponse[:16]),
		hex.EncodeToString(ntResponse[16:]),
	}, ":")
}

// windowsFileTime converts a Go time to a Windows FILETIME (100-nanosecond intervals since 1601-01-01).
func windowsFileTime(t time.Time) uint64 {
	// Difference between 1601-01-01 and 1970-01-01 in 100-nanosecond intervals
	const epochDiff = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDiff
}

// --- SPNEGO wrapping/unwrapping ---

// unwrapSPNEGO scans for the NTLMSSP signature within a blob (typically SPNEGO-wrapped)
// and returns the data from that offset. This avoids full ASN.1 parsing.
func unwrapSPNEGO(blob []byte) []byte {
	idx := bytes.Index(blob, ntlmsspSignature)
	if idx < 0 {
		return nil
	}
	return blob[idx:]
}

// wrapSPNEGOChallenge wraps an NTLMSSP Type 2 blob in a minimal SPNEGO negTokenResp ASN.1 envelope.
func wrapSPNEGOChallenge(ntlmBlob []byte) []byte {
	// Build SPNEGO negTokenResp wrapping:
	//   A1 (context tag 1 - negTokenResp)
	//     30 (SEQUENCE)
	//       A0 03 0A 01 01  (negState: accept-incomplete)
	//       A1 0C 06 0A ...  (supportedMech: NTLMSSP OID 1.3.6.1.4.1.311.2.2.10)
	//       A2 (responseToken containing the NTLM blob)

	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	ntlmOID := []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}

	// Build responseToken (A2 tag + length + OCTET STRING of ntlmBlob)
	responseToken := asn1Wrap(0xA2, asn1Wrap(0x04, ntlmBlob))

	// Build supportedMech (A1 tag + OID)
	supportedMech := asn1Wrap(0xA1, ntlmOID)

	// Build negState (A0 tag + ENUMERATED accept-incomplete=1)
	negState := []byte{0xA0, 0x03, 0x0A, 0x01, 0x01}

	// Combine into SEQUENCE
	var seqContent bytes.Buffer
	seqContent.Write(negState)
	seqContent.Write(supportedMech)
	seqContent.Write(responseToken)

	sequence := asn1Wrap(0x30, seqContent.Bytes())
	return asn1Wrap(0xA1, sequence)
}

// wrapSPNEGOAccept wraps a minimal SPNEGO accept response for final Session Setup success.
func wrapSPNEGOAccept() []byte {
	// negTokenResp with negState = accept-completed (0)
	//   A1 (negTokenResp)
	//     30 (SEQUENCE)
	//       A0 03 0A 01 00  (negState: accept-completed)
	negState := []byte{0xA0, 0x03, 0x0A, 0x01, 0x00}
	sequence := asn1Wrap(0x30, negState)
	return asn1Wrap(0xA1, sequence)
}

// asn1Wrap wraps data in an ASN.1 TLV with the given tag.
func asn1Wrap(tag byte, data []byte) []byte {
	length := len(data)
	var buf bytes.Buffer
	buf.WriteByte(tag)
	if length < 0x80 {
		buf.WriteByte(byte(length))
	} else if length <= 0xFF {
		buf.WriteByte(0x81)
		buf.WriteByte(byte(length))
	} else {
		buf.WriteByte(0x82)
		buf.WriteByte(byte(length >> 8))
		buf.WriteByte(byte(length))
	}
	buf.Write(data)
	return buf.Bytes()
}
