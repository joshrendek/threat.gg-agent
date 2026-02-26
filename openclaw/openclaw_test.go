package openclaw

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func TestLimitMessagesEnforcesMaxMessageCount(t *testing.T) {
	messages := make([]string, 0, maxPersistedMessages+10)
	for i := 0; i < maxPersistedMessages+10; i++ {
		messages = append(messages, fmt.Sprintf("message-%d", i))
	}

	got := limitMessages(messages)
	if len(got) != maxPersistedMessages+1 {
		t.Fatalf("expected %d messages including truncation marker, got %d", maxPersistedMessages+1, len(got))
	}

	last := got[len(got)-1]
	if !strings.Contains(last, "truncated 10 message(s)") {
		t.Fatalf("expected truncation marker for 10 messages, got: %s", last)
	}
}

func TestLimitMessagesTruncatesLargeMessage(t *testing.T) {
	large := strings.Repeat("a", maxPersistedMessageBytes+25)
	got := limitMessages([]string{large})
	if len(got) != 1 {
		t.Fatalf("expected exactly one message, got %d", len(got))
	}

	if !strings.HasSuffix(got[0], "...[truncated]") {
		t.Fatalf("expected truncated suffix, got: %s", got[0])
	}
}

func TestPersistHTTPProbeCaptures(t *testing.T) {
	var captured *proto.OpenclawRequest
	orig := persistOpenclawConnect
	persistOpenclawConnect = func(in *proto.OpenclawRequest) error {
		captured = in
		return nil
	}
	defer func() { persistOpenclawConnect = orig }()

	h := &honeypot{logger: New().(*honeypot).logger}
	req := httptest.NewRequest(http.MethodGet, "/scan?q=test", nil)
	req.Header.Set("User-Agent", "scanner/1.0")
	req.RemoteAddr = "1.2.3.4:12345"

	h.persistHTTPProbe(req)

	if captured == nil {
		t.Fatal("expected persist to be called")
	}
	if captured.RemoteAddr != "1.2.3.4" {
		t.Fatalf("expected remote addr 1.2.3.4, got %s", captured.RemoteAddr)
	}
	if captured.ClientVersion != "scanner/1.0" {
		t.Fatalf("expected client version scanner/1.0, got %s", captured.ClientVersion)
	}
	if len(captured.Messages) < 1 {
		t.Fatal("expected at least one message with request line")
	}
	if !strings.Contains(captured.Messages[0], "GET /scan?q=test") {
		t.Fatalf("expected request line in first message, got: %s", captured.Messages[0])
	}
	if captured.Guid == "" {
		t.Fatal("expected non-empty GUID")
	}
}

func TestBuildEnrichedRequestCopiesPayloadAndLimitsMessages(t *testing.T) {
	var cm connectMsg
	cm.Payload.AuthToken = "auth-token"
	cm.Payload.ClientID = "client-id"
	cm.Payload.ClientVersion = "1.0.0"
	cm.Payload.ClientPlatform = "linux"
	cm.Payload.ClientMode = "prod"
	cm.Payload.Role = "guest"
	cm.Payload.Scopes = []string{"scope:read"}
	cm.Payload.DeviceID = "device-id"
	cm.Payload.DevicePublicKey = "pk"
	cm.Payload.MinProtocol = 1
	cm.Payload.MaxProtocol = 3

	messages := make([]string, 0, maxPersistedMessages+1)
	for i := 0; i < maxPersistedMessages+1; i++ {
		messages = append(messages, fmt.Sprintf("m-%d", i))
	}

	req := buildEnrichedRequest("session-guid", "10.1.1.1", cm, messages)
	if req.Guid != "session-guid" {
		t.Fatalf("unexpected guid: %s", req.Guid)
	}
	if req.RemoteAddr != "10.1.1.1" {
		t.Fatalf("unexpected remote addr: %s", req.RemoteAddr)
	}
	if req.AuthToken != "auth-token" || req.ClientId != "client-id" || req.Role != "guest" {
		t.Fatalf("payload fields were not copied correctly")
	}
	if len(req.Messages) != maxPersistedMessages+1 {
		t.Fatalf("expected capped messages plus truncation marker, got %d", len(req.Messages))
	}
}
