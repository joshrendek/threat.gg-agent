package rdp

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWriteTSRequestFailureEncodesPositiveStatusLogonFailure(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		defer server.Close()
		errCh <- writeTSRequestFailure(server)
	}()

	_ = client.SetDeadline(time.Now().Add(time.Second))
	message, err := readTSRequest(client)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xa4, 0x07, 0x02, 0x05, 0x00, 0xc0, 0x00, 0x00, 0x6d}
	if !bytes.Contains(message, want) {
		t.Fatalf("TSRequest does not contain positive STATUS_LOGON_FAILURE: %x", message)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestType2TargetInfoUsesPersonaIdentity(t *testing.T) {
	session := &ntlmSession{challenge: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	message := buildType2ChallengeForPersona(session, "WIN-ABC123", "WORKGROUP")
	values := type2AVValues(t, message)
	assertAVText(t, values, 0x0001, "WIN-ABC123")
	assertAVText(t, values, 0x0002, "WORKGROUP")
	assertAVText(t, values, 0x0003, "win-abc123")
	assertAVText(t, values, 0x0004, "workgroup")
	for _, value := range values {
		if strings.Contains(strings.ToUpper(decodeUTF16LE(value)), "SERVER") {
			t.Fatalf("target info retained hardcoded SERVER identity: %q", decodeUTF16LE(value))
		}
	}
}

func TestFormatNetNTLMv2HashRequiresV2Blob(t *testing.T) {
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if got := formatNetNTLMv2Hash("user", "DOMAIN", challenge, make([]byte, 24)); got != "" {
		t.Fatalf("NTLMv1-shaped response accepted: %q", got)
	}
	wrong := make([]byte, 32)
	if got := formatNetNTLMv2Hash("user", "DOMAIN", challenge, wrong); got != "" {
		t.Fatalf("response without v2 blob signature accepted: %q", got)
	}
	valid := make([]byte, 32)
	valid[16], valid[17] = 1, 1
	got := formatNetNTLMv2Hash("user", "DOMAIN", challenge, valid)
	wantPrefix := "user::DOMAIN:" + hex.EncodeToString(challenge[:]) + ":"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("valid NetNTLMv2 response formatted as %q", got)
	}
}

func TestFingerprintClientHelloIsDeterministicAndOrdered(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SignatureSchemes:  []tls.SignatureScheme{tls.PSSWithSHA256},
		SupportedProtos:   []string{"credssp"},
	}
	first := fingerprintClientHello(hello)
	second := fingerprintClientHello(hello)
	if first == "" || first != second {
		t.Fatalf("fingerprint is not deterministic: %q %q", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 hex characters", len(first))
	}
	changed := *hello
	changed.CipherSuites = []uint16{tls.TLS_AES_256_GCM_SHA384, tls.TLS_AES_128_GCM_SHA256}
	if first == fingerprintClientHello(&changed) {
		t.Fatal("ordered ClientHello facts did not affect fingerprint")
	}
}

func TestCaptureNTLMRetainsThreeAttemptsAndReturnsFailures(t *testing.T) {
	persona, err := loadOrCreatePersona(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serverRaw, clientRaw := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	resultCh := make(chan NTLMCaptureResult, 1)
	go func() {
		resultCh <- CaptureNTLM(NTLMCaptureInput{
			Conn:            serverRaw,
			Certificate:     persona.tlsCert,
			PersonaHostname: persona.hostname,
			PersonaDomain:   persona.domain,
			Deadline:        deadline,
		})
	}()

	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	defer client.Close()
	_ = client.SetDeadline(deadline)
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := writeTSRequest(client, minimalType1()); err != nil {
			t.Fatal(err)
		}
		challengeRequest, err := readTSRequest(client)
		if err != nil {
			t.Fatal(err)
		}
		type2 := extractNTLMSSP(challengeRequest)
		if getNTLMMessageType(type2) != ntlmChallenge {
			t.Fatalf("cycle %d did not receive Type2", i)
		}
		values := type2AVValues(t, type2)
		assertAVText(t, values, 0x0001, persona.hostname)
		assertAVText(t, values, 0x0002, persona.domain)

		if err := writeTSRequest(client, minimalType3("operator", persona.domain, "CLIENT01")); err != nil {
			t.Fatal(err)
		}
		failure, err := readTSRequest(client)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Contains(failure, []byte{0xa4, 0x07, 0x02, 0x05, 0x00, 0xc0, 0x00, 0x00, 0x6d}) {
			t.Fatalf("cycle %d missing STATUS_LOGON_FAILURE: %x", i, failure)
		}
	}
	_ = clientRaw.Close()

	select {
	case result := <-resultCh:
		if len(result.Attempts) != 3 {
			t.Fatalf("captured attempts = %d, want 3", len(result.Attempts))
		}
		seen := map[string]struct{}{}
		var previousOffset int64
		for i, attempt := range result.Attempts {
			if attempt.GUID == "" {
				t.Fatalf("attempt %d has no GUID", i)
			}
			if _, duplicate := seen[attempt.GUID]; duplicate {
				t.Fatalf("duplicate GUID %q", attempt.GUID)
			}
			seen[attempt.GUID] = struct{}{}
			if attempt.Offset <= previousOffset {
				t.Fatalf("attempt offsets are not increasing: %d <= %d", attempt.Offset, previousOffset)
			}
			previousOffset = attempt.Offset
			if attempt.Hash == "" || attempt.NTLMVersion != "NTLMv2" || attempt.LMClass != "LMv2" {
				t.Fatalf("attempt %d metadata = %#v", i, attempt)
			}
		}
		if !result.CredSSPSeen || !result.Type1Seen || !result.ChallengeSent {
			t.Fatalf("capture stages missing: %#v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CaptureNTLM did not stop after three attempts")
	}
}

func minimalType1() []byte {
	message := make([]byte, 16)
	copy(message, ntlmsspSignature)
	binary.LittleEndian.PutUint32(message[8:12], ntlmNegotiate)
	binary.LittleEndian.PutUint32(message[12:16], 0x02088201)
	return message
}

func minimalType3(username, domain, workstation string) []byte {
	const headerLength = 88
	lm := bytes.Repeat([]byte{0x42}, 24)
	nt := bytes.Repeat([]byte{0x24}, 32)
	nt[16], nt[17] = 1, 1
	domainBytes := encodeUTF16LE(domain)
	userBytes := encodeUTF16LE(username)
	workstationBytes := encodeUTF16LE(workstation)
	message := make([]byte, headerLength+len(lm)+len(nt)+len(domainBytes)+len(userBytes)+len(workstationBytes))
	copy(message, ntlmsspSignature)
	binary.LittleEndian.PutUint32(message[8:12], ntlmAuthenticate)
	offset := headerLength
	putSecurityBuffer(message[12:20], len(lm), offset)
	copy(message[offset:], lm)
	offset += len(lm)
	putSecurityBuffer(message[20:28], len(nt), offset)
	copy(message[offset:], nt)
	offset += len(nt)
	putSecurityBuffer(message[28:36], len(domainBytes), offset)
	copy(message[offset:], domainBytes)
	offset += len(domainBytes)
	putSecurityBuffer(message[36:44], len(userBytes), offset)
	copy(message[offset:], userBytes)
	offset += len(userBytes)
	putSecurityBuffer(message[44:52], len(workstationBytes), offset)
	copy(message[offset:], workstationBytes)
	binary.LittleEndian.PutUint32(message[60:64], 0x02000001)
	message[64], message[65] = 10, 0
	binary.LittleEndian.PutUint16(message[66:68], 19041)
	message[71] = 15
	message[72] = 1
	return message
}

func putSecurityBuffer(target []byte, length, offset int) {
	binary.LittleEndian.PutUint16(target[0:2], uint16(length))
	binary.LittleEndian.PutUint16(target[2:4], uint16(length))
	binary.LittleEndian.PutUint32(target[4:8], uint32(offset))
}

func type2AVValues(t *testing.T, type2 []byte) map[uint16][]byte {
	t.Helper()
	if len(type2) < 48 || getNTLMMessageType(type2) != ntlmChallenge {
		t.Fatalf("invalid Type2 message: %x", type2)
	}
	length := int(binary.LittleEndian.Uint16(type2[40:42]))
	offset := int(binary.LittleEndian.Uint32(type2[44:48]))
	if offset < 48 || length < 4 || offset+length > len(type2) {
		t.Fatalf("invalid target-info buffer length=%d offset=%d total=%d", length, offset, len(type2))
	}
	values := map[uint16][]byte{}
	info := type2[offset : offset+length]
	for pos := 0; pos+4 <= len(info); {
		kind := binary.LittleEndian.Uint16(info[pos : pos+2])
		size := int(binary.LittleEndian.Uint16(info[pos+2 : pos+4]))
		pos += 4
		if pos+size > len(info) {
			t.Fatalf("invalid AV pair kind=%d size=%d", kind, size)
		}
		values[kind] = append([]byte(nil), info[pos:pos+size]...)
		pos += size
		if kind == 0 {
			break
		}
	}
	return values
}

func assertAVText(t *testing.T, values map[uint16][]byte, kind uint16, want string) {
	t.Helper()
	if got := decodeUTF16LE(values[kind]); got != want {
		t.Fatalf("AV pair %d = %q, want %q", kind, got, want)
	}
}

func TestClassifyNTLMErrorUnwrapsDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := readTSRequest(client); classifyNTLMError(err) != ntlmFailureDeadline {
		t.Fatalf("classifyNTLMError(%v) = %q, want %q", err, classifyNTLMError(err), ntlmFailureDeadline)
	}
}

func TestCaptureTLSClassifiesHandshakeDeadline(t *testing.T) {
	persona, err := loadOrCreatePersona(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	defer client.Close()
	result := CaptureTLS(TLSCaptureInput{
		Conn:        server,
		Certificate: persona.tlsCert,
		Deadline:    time.Now().Add(25 * time.Millisecond),
	})
	if result.FailureClass != ntlmFailureDeadline {
		t.Fatalf("failure class = %q, want %q", result.FailureClass, ntlmFailureDeadline)
	}
}
