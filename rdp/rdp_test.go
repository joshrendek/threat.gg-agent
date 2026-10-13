package rdp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

func TestSessionAdvanceIsMonotonic(t *testing.T) {
	s := &session{}
	s.advance(stageTLS)
	s.advance(stageX224)
	if s.reachedStage != stageTLS {
		t.Fatalf("reached stage = %q, want %q", s.reachedStage, stageTLS)
	}
	s.advance(stageAuthenticate)
	if s.reachedStage != stageAuthenticate {
		t.Fatalf("reached stage = %q, want %q", s.reachedStage, stageAuthenticate)
	}
}

func TestClientFingerprintExcludesIdentityFields(t *testing.T) {
	base := x224Request{hasNegReq: true, requestedProtocols: protocolHybrid, cookie: "cookie-a"}
	data := &clientData{Build: 19041, Width: 1920, Height: 1080, KeyboardLayout: "en-US", ClientName: "CLIENT", Channels: []string{"rdpdr"}}
	want := clientFingerprint(base, protocolHybrid, data)
	if len(want) != 64 {
		t.Fatalf("fingerprint length = %d, want 64 hex characters", len(want))
	}
	for _, mutate := range []func(*x224Request){
		func(r *x224Request) { r.cookie = "cookie-b" },
		func(r *x224Request) { r.cookie = "user-b" },
		func(r *x224Request) { r.cookie = "DOMAIN\\user" },
		func(r *x224Request) { r.cookie = "WORKSTATION" },
		func(r *x224Request) { r.cookie = "hash-material" },
	} {
		candidate := base
		mutate(&candidate)
		if got := clientFingerprint(candidate, protocolHybrid, data); got != want {
			t.Fatalf("fingerprint changed for identity-only input: %q != %q", got, want)
		}
	}
	renamed := *data
	renamed.ClientName = "ANOTHER-PC"
	if got := clientFingerprint(base, protocolHybrid, &renamed); got != want {
		t.Fatalf("fingerprint changed for client identity: %q != %q", got, want)
	}
}

func TestReadMCSExtractsOffsetClientData(t *testing.T) {
	core := make([]byte, 56)
	binary.LittleEndian.PutUint16(core[0:2], csCore)
	binary.LittleEndian.PutUint16(core[2:4], uint16(len(core)))
	binary.LittleEndian.PutUint16(core[8:10], 1280)
	binary.LittleEndian.PutUint16(core[10:12], 720)
	binary.LittleEndian.PutUint32(core[20:24], 19041)
	payload := append([]byte{0x01, 0xc0, 0x04, 0x00}, []byte("headers-before-client-data")...)
	payload = append(payload, core...)
	packet := make([]byte, 4+len(payload))
	packet[0] = tpktVersion
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:], payload)
	s := &session{}
	s.readMCS(bytes.NewReader(packet))
	if s.client == nil || s.client.Build != 19041 || s.client.Width != 1280 || s.client.Height != 720 {
		t.Fatalf("client data = %#v, stage = %q", s.client, s.reachedStage)
	}
	if s.reachedStage != stageCapabilities {
		t.Fatalf("stage = %q, want %q", s.reachedStage, stageCapabilities)
	}
}

func TestBuildRDPRequestMapsAttemptsAndLegacyFields(t *testing.T) {
	result := ntlmCaptureResult{Attempts: []ntlmCaptureAttempt{
		{GUID: "a", Username: "first", Domain: "D1", Workstation: "W1", Hash: "H1", Type3Flags: 1, NTLMVersion: "v2", MIC: true, LMClass: "none", Offset: 12, ObservedAtOffsetMs: 3},
		{GUID: "b", Username: "second", Domain: "D2", Workstation: "W2", Hash: "H2", Type3Flags: 2, NTLMVersion: "v2", Offset: 24, ObservedAtOffsetMs: 8},
		{GUID: "c", Username: "third", Domain: "D3", Workstation: "W3", Hash: "H3", Type3Flags: 3, NTLMVersion: "v2", Offset: 36, ObservedAtOffsetMs: 13},
	}}
	s := &session{guid: "g", ntlmResult: result, bytesRead: 30}
	req := buildRdpRequest(s)
	if req.RetryCount != 2 || len(req.AuthAttempts) != 3 {
		t.Fatalf("attempt count/retries = %d/%d", len(req.AuthAttempts), req.RetryCount)
	}
	if req.NtlmUsername != "first" || req.NtlmDomain != "D1" || req.NtlmWorkstation != "W1" || req.NtlmHash != "H1" || req.NtlmAuthenticateFlags != 1 {
		t.Fatalf("legacy fields do not use first attempt: %#v", req)
	}
	if req.AuthAttempts[2].ObservedAtOffsetMs != 13 || req.AuthAttempts[2].Username != "third" {
		t.Fatalf("mapped third attempt = %#v", req.AuthAttempts[2])
	}
}

func TestPersistSessionUsesImmutableRequestAndLowStage(t *testing.T) {
	old := saveRdpConnect
	defer func() { saveRdpConnect = old }()
	ch := make(chan *proto.RdpRequest, 1)
	saveRdpConnect = func(req *proto.RdpRequest) error { ch <- req; return nil }
	s := &session{guid: "g", remoteIP: "1.2.3.4", reachedStage: stageTCP, logger: zerolog.Nop(), startedAt: time.Now()}
	persistSession(s)
	s.guid, s.remoteIP, s.reachedStage = "changed", "changed", stageAuthenticate
	got := <-ch
	if got.Guid != "g" || got.RemoteAddr != "1.2.3.4" || got.ReachedStage != stageTCP {
		t.Fatalf("persisted request mutated or wrong low-stage snapshot: %#v", got)
	}
}
