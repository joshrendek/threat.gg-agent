package personas

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

func serve(t *testing.T, h http.Handler, method, target, body, remote, session, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.RemoteAddr = remote
	if session != "" {
		r.AddCookie(&http.Cookie{Name: "persona_session", Value: session})
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestFingerprintsAndActionEvents(t *testing.T) {
	var events []*proto.PersonaEventRequest
	h := newEngine(specs["xweb"], func(e *proto.PersonaEventRequest) error { events = append(events, e); return nil })
	w := serve(t, h, http.MethodGet, "/api/device/status", "", "192.0.2.1:1234", "", " ")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "XWEB5000") || !strings.Contains(w.Body.String(), "XW-5000-04192") {
		t.Fatalf("fingerprint: %d %s", w.Code, w.Body.String())
	}
	w = serve(t, h, http.MethodPost, "/api/setpoint", "name=room_temperature&value=6.5", "192.0.2.1:1234", "", "application/x-www-form-urlencoded")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "6.5") {
		t.Fatalf("setpoint: %d %s", w.Code, w.Body.String())
	}
	if len(events) != 2 || events[1].Action != "setpoint_change" || events[1].PriorValue != "4.0" || events[1].RequestedValue != "6.5" {
		t.Fatalf("events: %+v", events)
	}
}

func TestSessionStateIsolatedBySourceAndSession(t *testing.T) {
	h := newEngine(specs["cloudai"], nil)
	mutate := func(ip, session, value string) {
		serve(t, h, http.MethodPost, "/api/services/enable", "service=chat&state="+value, ip, session, "application/x-www-form-urlencoded")
	}
	mutate("192.0.2.1:1", "s1", "enabled")
	first := h.(*engine).getState(h.(*engine).session(httptest.NewRequest("GET", "/", nil)))
	if first == nil {
		t.Fatal("missing state")
	}
	// Same source and cookie reuses state; a different cookie or source receives a fresh state.
	key1 := h.(*engine).session(requestWith("192.0.2.1:1", "s1"))
	key2 := h.(*engine).session(requestWith("192.0.2.1:1", "s2"))
	key3 := h.(*engine).session(requestWith("192.0.2.2:1", "s1"))
	if key1 == key2 || key1 == key3 {
		t.Fatal("state key crossed session or source boundary")
	}
	st := h.(*engine).getState(key1)
	st.mu.Lock()
	got := st.values["chat"]
	st.mu.Unlock()
	if got != "enabled" {
		t.Fatalf("session state=%q", got)
	}
	for _, key := range []string{key2, key3} {
		st = h.(*engine).getState(key)
		st.mu.Lock()
		got = st.values["chat"]
		st.mu.Unlock()
		if got != "" {
			t.Fatalf("state leaked to isolated key: %q", got)
		}
	}
}
func requestWith(remote, session string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	r.AddCookie(&http.Cookie{Name: "persona_session", Value: session})
	return r
}

func TestCredentialsAndPayloadsAreNotRetained(t *testing.T) {
	const secret = "do-not-retain-this-password-or-api-key"
	var event *proto.PersonaEventRequest
	h := newEngine(specs["cloudai"], func(e *proto.PersonaEventRequest) error { event = e; return nil })
	w := serve(t, h, http.MethodPost, "/v1/key/validate", `{"username":"operator","api_key":"`+secret+`"}`, "198.51.100.1:8", "", "application/json")
	if w.Code != 401 || event == nil || !event.CredentialAttempt || event.Username != "operator" {
		t.Fatalf("response/event: %d %+v", w.Code, event)
	}
	if strings.Contains(event.String(), secret) {
		t.Fatal("credential value reached persistence event")
	}
}

func TestMalformedAndDangerousRequestsRemainHarmless(t *testing.T) {
	var events []*proto.PersonaEventRequest
	h := newEngine(specs["phpfpm"], func(e *proto.PersonaEventRequest) error { events = append(events, e); return nil })
	w := serve(t, h, http.MethodPost, "/upload", "not-a-valid-multipart-body", "203.0.113.8:9", "", "multipart/form-data; boundary=missing")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "success") {
		t.Fatalf("malformed multipart: %d %s", w.Code, w.Body.String())
	}
	w = serve(t, h, http.MethodPost, "/shell/cmd", "cmd=touch%20/tmp/pwned", "203.0.113.8:9", "", "application/x-www-form-urlencoded")
	if w.Code != 200 || strings.Contains(w.Body.String(), "pwned") {
		t.Fatalf("shell response: %d %s", w.Code, w.Body.String())
	}
	if len(events) != 2 || events[0].Action != "multipart_upload_probe" || events[1].Action != "webshell_follow_on" || strings.Contains(events[1].String(), "touch") {
		t.Fatalf("unsafe or missing event capture: %+v", events)
	}
}

func TestCpanelBypassAndCloudModelFingerprints(t *testing.T) {
	var event *proto.PersonaEventRequest
	cp := newEngine(specs["cpanel"], func(e *proto.PersonaEventRequest) error { event = e; return nil })
	w := serve(t, cp, http.MethodGet, "/cpsrvd/security_token?mode=probe", "", "203.0.113.4:1", "", "")
	if w.Code != 200 || event == nil || !event.AuthBypass || event.Cve != "CVE-2023-29489" {
		t.Fatalf("cpanel bypass: %d %+v", w.Code, event)
	}
	ai := newEngine(specs["cloudai"], nil)
	w = serve(t, ai, http.MethodGet, "/v1/models", "", "203.0.113.4:1", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "gpt-4o-mini") {
		t.Fatalf("cloud models: %d %s", w.Code, w.Body.String())
	}
}
