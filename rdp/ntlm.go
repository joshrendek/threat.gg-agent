package rdp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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
	hostname  string
	domain    string
}

func newNTLMSession() *ntlmSession {
	s := &ntlmSession{}
	if _, err := rand.Read(s.challenge[:]); err != nil {
		return s
	}
	return s
}

// NTLMCaptureInput describes one independent CredSSP capture. The helper does
// not persist or log any credentials; callers decide how to retain the result.
type NTLMCaptureInput struct {
	Conn            net.Conn
	Certificate     tls.Certificate
	PersonaHostname string
	PersonaDomain   string
	Deadline        time.Time
}

type ntlmCaptureInput = NTLMCaptureInput

// NTLMCaptureAttempt is one accepted NTLMSSP Authenticate message.
type NTLMCaptureAttempt struct {
	GUID               string
	Offset             int64
	ObservedAtOffsetMs uint32
	Challenge          [8]byte
	Username           string
	Domain             string
	Workstation        string
	Hash               string
	Type3Flags         uint32
	NTLMVersion        string
	MIC                bool
	LMClass            string
}
type ntlmCaptureAttempt = NTLMCaptureAttempt

// NTLMCaptureResult contains bounded protocol telemetry and captured attempts.
type NTLMCaptureResult struct {
	TLSVersion      uint16
	TLSCipherSuite  uint16
	TLSFingerprint  string
	CredSSPVersion  uint32
	SPNEGOMechanism string
	Type1Flags      uint32
	Type3Flags      uint32
	NTLMVersion     string
	MIC             bool
	LMClass         string
	FailureClass    string
	BytesRead       int64
	Attempts        []NTLMCaptureAttempt
	Username        string
	Domain          string
	Workstation     string
	Hash            string

	Type1Seen     bool
	ChallengeSent bool
	CredSSPSeen   bool
}

type ntlmCaptureResult = NTLMCaptureResult

const (
	ntlmFailureTLS      = "tls"
	ntlmFailureRead     = "read"
	ntlmFailureWrite    = "write"
	ntlmFailureProtocol = "protocol"
	ntlmFailureClosed   = "closed"
	ntlmFailureDeadline = "deadline"
)

// CaptureNTLM upgrades conn to TLS and captures at most three CredSSP cycles.
func CaptureNTLM(input NTLMCaptureInput) NTLMCaptureResult {
	return captureNTLM(input)
}

func captureNTLM(input ntlmCaptureInput) ntlmCaptureResult {
	result := ntlmCaptureResult{}
	if input.Conn == nil {
		result.FailureClass = ntlmFailureRead
		return result
	}
	hostname := strings.TrimSpace(input.PersonaHostname)
	domain := strings.TrimSpace(input.PersonaDomain)
	if hostname == "" && len(input.Certificate.Certificate) != 0 {
		if cert, err := x509.ParseCertificate(input.Certificate.Certificate[0]); err == nil {
			hostname = cert.Subject.CommonName
			if hostname == "" && len(cert.DNSNames) != 0 {
				hostname = cert.DNSNames[0]
			}
		}
	}
	if hostname == "" {
		hostname = "server"
	}
	if domain == "" {
		domain = "workgroup"
	}
	if len(input.Certificate.Certificate) != 0 && !certificateMatchesHostname(input.Certificate, hostname) {
		result.FailureClass = ntlmFailureProtocol
		return result
	}
	if input.Deadline.IsZero() {
		input.Deadline = time.Now().Add(30 * time.Second)
	}
	started := time.Now()

	counted := &countingConn{Conn: input.Conn}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{input.Certificate},
		MinVersion:   tls.VersionTLS12,
	}
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		result.TLSFingerprint = fingerprintClientHello(hello)
		clone := cfg.Clone()
		clone.GetConfigForClient = nil
		return clone, nil
	}
	tlsConn := tls.Server(counted, cfg)
	defer tlsConn.Close()
	if err := tlsConn.SetDeadline(input.Deadline); err != nil {
		result.FailureClass = ntlmFailureDeadline
		return result
	}
	if err := tlsConn.Handshake(); err != nil {
		if classifyNTLMError(err) == ntlmFailureDeadline {
			result.FailureClass = ntlmFailureDeadline
		} else {
			result.FailureClass = ntlmFailureTLS
		}
		result.BytesRead = counted.read
		return result
	}
	state := tlsConn.ConnectionState()
	result.TLSVersion = state.Version
	result.TLSCipherSuite = state.CipherSuite

	cycles := 0
	for cycles < 3 {
		type1Data, err := readTSRequest(tlsConn)
		result.BytesRead = counted.read
		if err != nil {
			result.FailureClass = classifyNTLMError(err)
			break
		}
		if !validTSRequest(type1Data) {
			result.FailureClass = ntlmFailureProtocol
			break
		}
		result.CredSSPSeen = true
		version, mech := parseTSRequestMetadata(type1Data)
		if version != 0 {
			result.CredSSPVersion = version
		}
		if mech != "" {
			result.SPNEGOMechanism = mech
		}
		type1 := extractNTLMSSP(type1Data)
		if !isNTLMSSP(type1) || getNTLMMessageType(type1) != ntlmNegotiate {
			result.FailureClass = ntlmFailureProtocol
			break
		}
		result.Type1Seen = true
		if len(type1) >= 16 {
			result.Type1Flags = binary.LittleEndian.Uint32(type1[12:16])
		}
		cycles++

		ntlmSess := newNTLMSession()
		ntlmSess.hostname, ntlmSess.domain = hostname, domain
		if err := writeTSRequest(tlsConn, wrapSPNEGOChallenge(buildType2ChallengeForPersona(ntlmSess, hostname, domain))); err != nil {
			result.FailureClass = ntlmFailureWrite
			break
		}
		result.ChallengeSent = true
		type3Data, err := readTSRequest(tlsConn)
		result.BytesRead = counted.read
		if err != nil {
			result.FailureClass = classifyNTLMError(err)
			break
		}
		if !validTSRequest(type3Data) {
			result.FailureClass = ntlmFailureProtocol
			_ = writeTSRequestFailure(tlsConn)
			continue
		}
		version, mech = parseTSRequestMetadata(type3Data)
		if version != 0 {
			result.CredSSPVersion = version
		}
		if mech != "" {
			result.SPNEGOMechanism = mech
		}
		type3 := extractNTLMSSP(type3Data)
		if !isNTLMSSP(type3) || getNTLMMessageType(type3) != ntlmAuthenticate {
			result.FailureClass = ntlmFailureProtocol
			_ = writeTSRequestFailure(tlsConn)
			continue
		}
		parsed := parseType3Details(type3)
		offset := counted.read
		elapsed := time.Since(started).Milliseconds()
		if len(result.Attempts) != 0 && elapsed <= int64(result.Attempts[len(result.Attempts)-1].ObservedAtOffsetMs) {
			elapsed = int64(result.Attempts[len(result.Attempts)-1].ObservedAtOffsetMs) + 1
		}
		if elapsed > int64(^uint32(0)) {
			elapsed = int64(^uint32(0))
		}
		attempt := NTLMCaptureAttempt{
			GUID:               newNTLMGUID(),
			Offset:             offset,
			ObservedAtOffsetMs: uint32(elapsed),
			Challenge:          ntlmSess.challenge,
			Username:           parsed.username,
			Domain:             parsed.domain,
			Workstation:        parsed.workstation,
			Hash:               formatNetNTLMv2Hash(parsed.username, parsed.domain, ntlmSess.challenge, parsed.ntResponse),
			Type3Flags:         parsed.flags,
			NTLMVersion:        parsed.version,
			MIC:                parsed.mic,
			LMClass:            parsed.lmClass,
		}
		result.Attempts = append(result.Attempts, attempt)
		result.Type3Flags, result.NTLMVersion = parsed.flags, parsed.version
		result.MIC, result.LMClass = parsed.mic, parsed.lmClass
		result.Username, result.Domain, result.Workstation, result.Hash = attempt.Username, attempt.Domain, attempt.Workstation, attempt.Hash
		result.BytesRead = counted.read
		if err := writeTSRequestFailure(tlsConn); err != nil {
			result.FailureClass = ntlmFailureWrite
			break
		}
	}
	if cycles == 3 && result.FailureClass == "" {
		result.FailureClass = ntlmFailureProtocol
	}
	return result
}

type tlsCaptureInput struct {
	Conn        net.Conn
	Certificate tls.Certificate
	Deadline    time.Time
}

type TLSCaptureInput = tlsCaptureInput
type TLSCaptureResult = tlsCaptureResult

type tlsCaptureResult struct {
	Conn           *tls.Conn
	TLSVersion     uint16
	TLSCipherSuite uint16
	TLSFingerprint string
	BytesRead      int64
	FailureClass   string
}

// captureTLS performs only the bounded TLS handshake used by SSL MCS.
func captureTLS(input tlsCaptureInput) tlsCaptureResult {
	result := tlsCaptureResult{}
	if input.Conn == nil {
		result.FailureClass = ntlmFailureRead
		return result
	}
	if input.Deadline.IsZero() {
		input.Deadline = time.Now().Add(totalTimeout)
	}
	counted := &countingConn{Conn: input.Conn}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{input.Certificate},
		MinVersion:   tls.VersionTLS12,
	}
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		result.TLSFingerprint = fingerprintClientHello(hello)
		clone := cfg.Clone()
		clone.GetConfigForClient = nil
		return clone, nil
	}
	tlsConn := tls.Server(counted, cfg)
	if err := tlsConn.SetDeadline(input.Deadline); err != nil {
		result.FailureClass = ntlmFailureDeadline
		_ = tlsConn.Close()
		return result
	}
	if err := tlsConn.Handshake(); err != nil {
		if classifyNTLMError(err) == ntlmFailureDeadline {
			result.FailureClass = ntlmFailureDeadline
		} else {
			result.FailureClass = ntlmFailureTLS
		}
		result.BytesRead = counted.read
		_ = tlsConn.Close()
		return result
	}
	state := tlsConn.ConnectionState()
	result.Conn = tlsConn
	result.TLSVersion = state.Version
	result.TLSCipherSuite = state.CipherSuite
	result.BytesRead = counted.read
	return result
}

// CaptureTLS exposes bounded TLS-only telemetry and closes the live stream.
func CaptureTLS(input tlsCaptureInput) tlsCaptureResult {
	result := captureTLS(input)
	if result.Conn != nil {
		_ = result.Conn.Close()
		result.Conn = nil
	}
	return result
}

type countingConn struct {
	net.Conn
	read int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read += int64(n)
	return n, err
}

func classifyNTLMError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, net.ErrClosed) {
		return ntlmFailureClosed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ntlmFailureDeadline
	}
	return ntlmFailureRead
}

func newNTLMGUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012x", uint64(time.Now().UnixNano())&0xffffffffffff)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]), binary.BigEndian.Uint16(b[8:10]),
		binary.BigEndian.Uint64(b[8:16])&0xffffffffffff)
}

func fingerprintClientHello(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}
	var material bytes.Buffer
	put16 := func(v uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		material.Write(b[:])
	}
	putList16 := func(values []uint16) {
		put16(uint16(len(values)))
		for _, value := range values {
			put16(value)
		}
	}
	putList8 := func(values []uint8) {
		put16(uint16(len(values)))
		material.Write(values)
	}
	putListString := func(values []string) {
		put16(uint16(len(values)))
		for _, value := range values {
			if len(value) > 255 {
				value = value[:255]
			}
			material.WriteByte(byte(len(value)))
			material.WriteString(value)
		}
	}
	putList16(hello.SupportedVersions)
	putList16(hello.CipherSuites)
	curves := make([]uint16, len(hello.SupportedCurves))
	for i, curve := range hello.SupportedCurves {
		curves[i] = uint16(curve)
	}
	putList16(curves)
	putList8(hello.SupportedPoints)
	sigs := make([]uint16, len(hello.SignatureSchemes))
	for i, sig := range hello.SignatureSchemes {
		sigs[i] = uint16(sig)
	}
	putList16(sigs)
	putListString(hello.SupportedProtos)
	sum := sha256.Sum256(material.Bytes())
	return hex.EncodeToString(sum[:])
}

func parseTSRequestMetadata(data []byte) (uint32, string) {
	version := uint32(0)
	var walk func([]byte, int)
	walk = func(blob []byte, depth int) {
		if depth > 32 {
			return
		}
		for pos := 0; pos+2 <= len(blob); {
			tag := blob[pos]
			length, n, ok := parseDERLength(blob[pos+1:])
			if !ok || pos+1+n+length > len(blob) {
				return
			}
			value := blob[pos+1+n : pos+1+n+length]
			if tag == 0xa0 && len(value) >= 2 && value[0] == 0x02 {
				if integerLen, integerN, ok := parseDERLength(value[1:]); ok && 2+integerN+integerLen <= len(value) && integerLen <= 4 {
					version = 0
					for _, b := range value[2+integerN : 2+integerN+integerLen] {
						version = (version << 8) | uint32(b)
					}
				}
			}
			if tag&0x20 != 0 || tag >= 0xa0 {
				walk(value, depth+1)
			}
			pos += 1 + n + length
		}
	}
	walk(data, 0)
	oid := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	if bytes.Contains(data, oid) {
		return version, "NTLM"
	}
	return version, ""
}

func parseDERLength(data []byte) (int, int, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, true
	}
	n := int(data[0] & 0x7f)
	if n == 0 || n > 4 || len(data) < n+1 {
		return 0, 0, false
	}
	length := 0
	for _, b := range data[1 : n+1] {
		length = (length << 8) | int(b)
	}
	return length, n + 1, true
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) != 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return net.ErrClosed
		}
	}
	return nil
}

func writeTSRequestFailure(conn net.Conn) error {
	version := asn1Wrap(0xA0, asn1Wrap(0x02, []byte{0x03}))
	// STATUS_LOGON_FAILURE (0xc000006d) is an unsigned errorCode; DER INTEGER
	// needs a leading zero when the high bit is set.
	status := asn1Wrap(0xA4, asn1Wrap(0x02, []byte{0x00, 0xc0, 0x00, 0x00, 0x6d}))
	return writeFull(conn, asn1Wrap(0x30, append(version, status...)))
}
func certificateMatchesHostname(cert tls.Certificate, hostname string) bool {
	if len(cert.Certificate) == 0 {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	if len(leaf.DNSNames) == 0 && leaf.Subject.CommonName == "" {
		return false
	}
	if err := leaf.VerifyHostname(hostname); err == nil {
		return true
	}
	return strings.EqualFold(leaf.Subject.CommonName, hostname)
}

// readTSRequest reads an ASN.1-encoded TSRequest from the connection.
// Returns the raw bytes of the entire TSRequest.
func readTSRequest(conn net.Conn) ([]byte, error) {
	// Read first byte (ASN.1 tag, should be 0x30 for SEQUENCE)
	tagBuf := make([]byte, 1)
	if _, err := readFull(conn, tagBuf); err != nil {
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

func validTSRequest(data []byte) bool {
	if len(data) < 2 || data[0] != 0x30 {
		return false
	}
	length, n, ok := parseDERLength(data[1:])
	if !ok || 1+n+length != len(data) || length == 0 {
		return false
	}
	tag := data[1+n]
	return tag == 0xa0 || tag == 0xa1 || tag == 0xa2 || tag == 0xa3 || tag == 0xa4
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
	if _, err := readFull(conn, firstByte); err != nil {
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
	versionInt := asn1Wrap(0x02, []byte{0x03}) // INTEGER 3
	versionField := asn1Wrap(0xA0, versionInt) // context tag [0]

	// negoToken: [1] SEQUENCE OF { SEQUENCE { [0] OCTET STRING } }
	tokenOctet := asn1Wrap(0x04, negoToken)     // OCTET STRING
	tokenField := asn1Wrap(0xA0, tokenOctet)    // context tag [0]
	innerSeq := asn1Wrap(0x30, tokenField)      // SEQUENCE
	outerSeq := asn1Wrap(0x30, innerSeq)        // SEQUENCE OF
	negoTokensField := asn1Wrap(0xA1, outerSeq) // context tag [1]

	var content bytes.Buffer
	content.Write(versionField)
	content.Write(negoTokensField)

	tsReq := asn1Wrap(0x30, content.Bytes())
	return writeFull(conn, tsReq)
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
	return buildType2ChallengeForPersona(sess, sess.hostname, sess.domain)
}

func buildType2ChallengeForPersona(sess *ntlmSession, hostname, domain string) []byte {
	hostname = strings.TrimSpace(hostname)
	domain = strings.TrimSpace(domain)
	if hostname == "" {
		hostname = "server"
	}
	if domain == "" {
		domain = "workgroup"
	}
	nbComputer := strings.ToUpper(strings.SplitN(hostname, ".", 2)[0])
	nbDomain := strings.ToUpper(strings.SplitN(domain, ".", 2)[0])
	dnsComputer := strings.ToLower(hostname)
	dnsDomain := strings.ToLower(domain)
	targetName := encodeUTF16LE(nbDomain)
	computerName := encodeUTF16LE(nbComputer)
	dnsDomainValue := encodeUTF16LE(dnsDomain)
	dnsComputerValue := encodeUTF16LE(dnsComputer)

	var targetInfo bytes.Buffer
	writeAV := func(kind uint16, value []byte) {
		_ = binary.Write(&targetInfo, binary.LittleEndian, kind)
		_ = binary.Write(&targetInfo, binary.LittleEndian, uint16(len(value)))
		targetInfo.Write(value)
	}
	writeAV(0x0002, targetName)       // MsvAvNbDomainName
	writeAV(0x0001, computerName)     // MsvAvNbComputerName
	writeAV(0x0004, dnsDomainValue)   // MsvAvDnsDomainName
	writeAV(0x0003, dnsComputerValue) // MsvAvDnsComputerName
	var timestamp [8]byte
	binary.LittleEndian.PutUint64(timestamp[:], windowsFileTime(time.Now()))
	writeAV(0x0007, timestamp[:]) // MsvAvTimestamp
	writeAV(0x0000, nil)          // MsvAvEOL

	targetInfoBytes := targetInfo.Bytes()
	targetNameOffset := uint32(48)
	targetInfoOffset := targetNameOffset + uint32(len(targetName))
	var msg bytes.Buffer
	msg.Write(ntlmsspSignature)
	_ = binary.Write(&msg, binary.LittleEndian, ntlmChallenge)
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(targetName)))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(targetName)))
	_ = binary.Write(&msg, binary.LittleEndian, targetNameOffset)
	_ = binary.Write(&msg, binary.LittleEndian, uint32(0x00028233))
	msg.Write(sess.challenge[:])
	msg.Write(make([]byte, 8))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(targetInfoBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, uint16(len(targetInfoBytes)))
	_ = binary.Write(&msg, binary.LittleEndian, targetInfoOffset)
	msg.Write(targetName)
	msg.Write(targetInfoBytes)
	return msg.Bytes()
}

type parsedType3 struct {
	username, domain, workstation string
	ntResponse, lmResponse        []byte
	flags                         uint32
	version                       string
	mic                           bool
	lmClass                       string
}

func parseType3Details(data []byte) parsedType3 {
	var result parsedType3
	if len(data) < 64 || getNTLMMessageType(data) != ntlmAuthenticate {
		return result
	}
	readSec := func(at int) []byte {
		if at+8 > len(data) {
			return nil
		}
		length := int(binary.LittleEndian.Uint16(data[at : at+2]))
		offset := binary.LittleEndian.Uint32(data[at+4 : at+8])
		if length == 0 || offset < 64 || offset > uint32(len(data)) || length > len(data)-int(offset) {
			return nil
		}
		return append([]byte(nil), data[offset:uint32(int(offset)+length)]...)
	}
	result.lmResponse = readSec(12)
	result.ntResponse = readSec(20)
	result.domain = decodeUTF16LE(readSec(28))
	result.username = decodeUTF16LE(readSec(36))
	result.workstation = decodeUTF16LE(readSec(44))
	result.flags = binary.LittleEndian.Uint32(data[60:64])
	micStart := 64
	if result.flags&0x02000000 != 0 {
		micStart = 72
	}
	ntOffset := 0
	if len(data) >= 28 {
		ntOffset = int(binary.LittleEndian.Uint32(data[24:28]))
	}
	if ntOffset >= micStart+16 && len(data) >= micStart+16 {
		for _, b := range data[micStart : micStart+16] {
			if b != 0 {
				result.mic = true
				break
			}
		}
	}
	if isNetNTLMv2Response(result.ntResponse) {
		result.version = "NTLMv2"
		if len(result.lmResponse) == 24 {
			result.lmClass = "LMv2"
		} else {
			result.lmClass = "none"
		}
	} else if len(result.ntResponse) == 24 {
		result.version = "NTLMv1"
		if len(result.lmResponse) == 24 {
			result.lmClass = "LMv1"
		} else {
			result.lmClass = "none"
		}
	} else if len(result.lmResponse) == 24 {
		result.lmClass = "LM"
	} else {
		result.lmClass = "none"
	}
	return result
}

func parseType3Auth(data []byte) (username, domain, workstation string, ntlmResponse []byte) {
	parsed := parseType3Details(data)
	return parsed.username, parsed.domain, parsed.workstation, parsed.ntResponse
}

func isNetNTLMv2Response(response []byte) bool {
	// NT proof (16 bytes) followed by the NTLMv2 response blob. A valid blob
	// starts with respType=1 and hiRespType=1; this rejects NTLMv1's 24-byte
	// response and arbitrary long values.
	return len(response) >= 32 && response[16] == 0x01 && response[17] == 0x01
}

// formatNetNTLMv2Hash formats credentials for hashcat mode 5600.
func formatNetNTLMv2Hash(username, domain string, challenge [8]byte, ntResponse []byte) string {
	if !isNetNTLMv2Response(ntResponse) {
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
