package rdp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	ntlmNegotiate    uint32 = 1
	ntlmChallenge    uint32 = 2
	ntlmAuthenticate uint32 = 3
)

var ntlmsspSignature = []byte("NTLMSSP\x00")

type ntlmSession struct {
	challenge [8]byte
}

func newNTLMSession() *ntlmSession {
	s := &ntlmSession{}
	rand.Read(s.challenge[:])
	return s
}

// handleNTLM upgrades the connection to TLS and performs CredSSP/NTLM capture.
func handleNTLM(conn net.Conn, sess *session) {
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{sess.tlsCert},
	})
	defer tlsConn.Close()

	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		sess.logger.Debug().Err(err).Str("session", sess.guid).Msg("TLS handshake failed")
		return
	}

	ntlmSess := newNTLMSession()

	// Step 1: Read TSRequest containing NTLMSSP Type 1 (Negotiate)
	tsData, err := readTSRequest(tlsConn)
	if err != nil {
		sess.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read TSRequest 1")
		return
	}

	ntlmMsg := extractNTLMSSP(tsData)
	if ntlmMsg == nil || !isNTLMSSP(ntlmMsg) {
		sess.logger.Debug().Str("session", sess.guid).Msg("no NTLMSSP in TSRequest 1")
		return
	}

	if getNTLMMessageType(ntlmMsg) != ntlmNegotiate {
		sess.logger.Debug().Str("session", sess.guid).Msg("expected NTLMSSP Type 1")
		return
	}

	// Step 2: Send TSRequest containing NTLMSSP Type 2 (Challenge)
	challengeBlob := buildType2Challenge(ntlmSess)
	spnegoResp := wrapSPNEGOChallenge(challengeBlob)
	if err := writeTSRequest(tlsConn, spnegoResp); err != nil {
		sess.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to send challenge")
		return
	}

	// Step 3: Read TSRequest containing NTLMSSP Type 3 (Authenticate)
	tsData, err = readTSRequest(tlsConn)
	if err != nil {
		sess.logger.Debug().Err(err).Str("session", sess.guid).Msg("failed to read TSRequest 2")
		return
	}

	ntlmMsg = extractNTLMSSP(tsData)
	if ntlmMsg == nil || !isNTLMSSP(ntlmMsg) {
		sess.logger.Debug().Str("session", sess.guid).Msg("no NTLMSSP in TSRequest 2")
		return
	}

	if getNTLMMessageType(ntlmMsg) != ntlmAuthenticate {
		sess.logger.Debug().Str("session", sess.guid).Msg("expected NTLMSSP Type 3")
		return
	}

	username, domain, workstation, ntlmResponse := parseType3Auth(ntlmMsg)
	sess.ntlmUsername = username
	sess.ntlmDomain = domain
	sess.ntlmWorkstation = workstation
	sess.ntlmHash = formatNetNTLMv2Hash(username, domain, ntlmSess.challenge, ntlmResponse)

	sess.logger.Info().
		Str("session", sess.guid).
		Str("username", username).
		Str("domain", domain).
		Str("workstation", workstation).
		Bool("has_hash", sess.ntlmHash != "").
		Msg("NTLM authentication captured via RDP/NLA")
}

// readTSRequest reads an ASN.1-encoded TSRequest from the connection.
// Returns the raw bytes of the entire TSRequest.
func readTSRequest(conn net.Conn) ([]byte, error) {
	// Read first byte (ASN.1 tag, should be 0x30 for SEQUENCE)
	tagBuf := make([]byte, 1)
	if _, err := conn.Read(tagBuf); err != nil {
		return nil, fmt.Errorf("reading TSRequest tag: %w", err)
	}

	if tagBuf[0] != 0x30 {
		return nil, fmt.Errorf("expected ASN.1 SEQUENCE (0x30), got 0x%02x", tagBuf[0])
	}

	// Read length
	length, lenBytes, err := readASN1Length(conn)
	if err != nil {
		return nil, fmt.Errorf("reading TSRequest length: %w", err)
	}

	if length > maxTPKTPayload {
		return nil, fmt.Errorf("TSRequest too large: %d", length)
	}

	// Read the body
	body := make([]byte, length)
	if _, err := readFull(conn, body); err != nil {
		return nil, fmt.Errorf("reading TSRequest body: %w", err)
	}

	// Reconstruct full TLV
	var full bytes.Buffer
	full.WriteByte(0x30)
	full.Write(lenBytes)
	full.Write(body)

	return full.Bytes(), nil
}

// readFull reads exactly len(buf) bytes from the connection.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// readASN1Length reads an ASN.1 DER length from the connection.
// Returns the length value and the raw length bytes.
func readASN1Length(conn net.Conn) (int, []byte, error) {
	firstByte := make([]byte, 1)
	if _, err := conn.Read(firstByte); err != nil {
		return 0, nil, err
	}

	if firstByte[0] < 0x80 {
		return int(firstByte[0]), firstByte, nil
	}

	numBytes := int(firstByte[0] & 0x7F)
	if numBytes > 4 || numBytes == 0 {
		return 0, nil, fmt.Errorf("invalid ASN.1 length encoding: %d extra bytes", numBytes)
	}

	lenBytes := make([]byte, numBytes)
	if _, err := readFull(conn, lenBytes); err != nil {
		return 0, nil, err
	}

	length := 0
	for _, b := range lenBytes {
		length = (length << 8) | int(b)
	}

	raw := append(firstByte, lenBytes...)
	return length, raw, nil
}

// writeTSRequest writes a TSRequest containing a negoToken.
func writeTSRequest(conn net.Conn, negoToken []byte) error {
	// Build TSRequest:
	// SEQUENCE {
	//   [0] INTEGER 3  (version)
	//   [1] SEQUENCE OF { SEQUENCE { [0] OCTET STRING (negoToken) } }
	// }

	// version: [0] INTEGER 3
	versionInt := asn1Wrap(0x02, []byte{0x03})     // INTEGER 3
	versionField := asn1Wrap(0xA0, versionInt)       // context tag [0]

	// negoToken: [1] SEQUENCE OF { SEQUENCE { [0] OCTET STRING } }
	tokenOctet := asn1Wrap(0x04, negoToken)          // OCTET STRING
	tokenField := asn1Wrap(0xA0, tokenOctet)          // context tag [0]
	innerSeq := asn1Wrap(0x30, tokenField)            // SEQUENCE
	outerSeq := asn1Wrap(0x30, innerSeq)              // SEQUENCE OF
	negoTokensField := asn1Wrap(0xA1, outerSeq)       // context tag [1]

	var content bytes.Buffer
	content.Write(versionField)
	content.Write(negoTokensField)

	tsReq := asn1Wrap(0x30, content.Bytes())
	_, err := conn.Write(tsReq)
	return err
}

// extractNTLMSSP scans for the NTLMSSP signature within a blob.
func extractNTLMSSP(data []byte) []byte {
	idx := bytes.Index(data, ntlmsspSignature)
	if idx < 0 {
		return nil
	}
	return data[idx:]
}

func isNTLMSSP(data []byte) bool {
	return len(data) >= 8 && bytes.Equal(data[:8], ntlmsspSignature)
}

func getNTLMMessageType(data []byte) uint32 {
	if len(data) < 12 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[8:12])
}

func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

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

func buildType2Challenge(sess *ntlmSession) []byte {
	targetName := encodeUTF16LE("WORKGROUP")
	computerName := encodeUTF16LE("SERVER")
	dnsDomain := encodeUTF16LE("workgroup")
	dnsComputer := encodeUTF16LE("server")

	var targetInfo bytes.Buffer

	// MsvAvNbDomainName (type 2)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0002))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(targetName)))
	targetInfo.Write(targetName)

	// MsvAvNbComputerName (type 1)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0001))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(computerName)))
	targetInfo.Write(computerName)

	// MsvAvDnsDomainName (type 4)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0004))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(dnsDomain)))
	targetInfo.Write(dnsDomain)

	// MsvAvDnsComputerName (type 3)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0003))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(len(dnsComputer)))
	targetInfo.Write(dnsComputer)

	// MsvAvTimestamp (type 7)
	ft := windowsFileTime(time.Now())
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0007))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(8))
	binary.Write(&targetInfo, binary.LittleEndian, ft)

	// MsvAvEOL (type 0)
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0x0000))
	binary.Write(&targetInfo, binary.LittleEndian, uint16(0))

	targetInfoBytes := targetInfo.Bytes()

	targetNameOffset := uint32(48)
	targetInfoOffset := targetNameOffset + uint32(len(targetName))

	var msg bytes.Buffer
	msg.Write(ntlmsspSignature)
	binary.Write(&msg, binary.LittleEndian, ntlmChallenge)

	// TargetNameFields
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetName)))
	binary.Write(&msg, binary.LittleEndian, targetNameOffset)

	// NegotiateFlags
	binary.Write(&msg, binary.LittleEndian, uint32(0x00028233))

	// ServerChallenge
	msg.Write(sess.challenge[:])

	// Reserved
	msg.Write(make([]byte, 8))

	// TargetInfoFields
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetInfoBytes)))
	binary.Write(&msg, binary.LittleEndian, uint16(len(targetInfoBytes)))
	binary.Write(&msg, binary.LittleEndian, targetInfoOffset)

	msg.Write(targetName)
	msg.Write(targetInfoBytes)

	return msg.Bytes()
}

func parseType3Auth(data []byte) (username, domain, workstation string, ntlmResponse []byte) {
	if len(data) < 52 {
		return
	}

	ntLen := binary.LittleEndian.Uint16(data[20:22])
	ntOffset := binary.LittleEndian.Uint32(data[24:28])

	domainLen := binary.LittleEndian.Uint16(data[28:30])
	domainOffset := binary.LittleEndian.Uint32(data[32:36])

	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOffset := binary.LittleEndian.Uint32(data[40:44])

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

func windowsFileTime(t time.Time) uint64 {
	const epochDiff = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDiff
}

// wrapSPNEGOChallenge wraps an NTLMSSP Type 2 blob in a minimal SPNEGO negTokenResp.
func wrapSPNEGOChallenge(ntlmBlob []byte) []byte {
	ntlmOID := []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}

	responseToken := asn1Wrap(0xA2, asn1Wrap(0x04, ntlmBlob))
	supportedMech := asn1Wrap(0xA1, ntlmOID)
	negState := []byte{0xA0, 0x03, 0x0A, 0x01, 0x01}

	var seqContent bytes.Buffer
	seqContent.Write(negState)
	seqContent.Write(supportedMech)
	seqContent.Write(responseToken)

	sequence := asn1Wrap(0x30, seqContent.Bytes())
	return asn1Wrap(0xA1, sequence)
}

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

// generateSelfSignedCert creates an RSA 2048 self-signed certificate with a random hostname.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating RSA key: %w", err)
	}

	// Random hostname: WIN-<8 hex chars>
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	cn := fmt.Sprintf("WIN-%s", strings.ToUpper(hex.EncodeToString(randBytes)))

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
