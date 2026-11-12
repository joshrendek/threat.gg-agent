package personas

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	firstKey, _ := h.(*engine).session(httptest.NewRequest("GET", "/", nil), nil)
	first := h.(*engine).getState(firstKey)
	if first == nil {
		t.Fatal("missing state")
	}
	// Same source and cookie reuses state; a different cookie or source receives a fresh state.
	key1, _ := h.(*engine).session(requestWith("192.0.2.1:1", "s1"), nil)
	key2, _ := h.(*engine).session(requestWith("192.0.2.1:1", "s2"), nil)
	key3, _ := h.(*engine).session(requestWith("192.0.2.2:1", "s1"), nil)
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
	if w.Code != 401 || event == nil || event.Guid == "" || !event.CredentialAttempt || event.Username != "operator" {
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
	if len(events) != 2 || events[0].Action != "multipart_upload_probe" || events[1].Action != "confirmed_follow_on" || strings.Contains(events[1].String(), "touch") {
		t.Fatalf("unsafe or missing event capture: %+v", events)
	}
}

func TestCpanelBypassAndCloudModelFingerprints(t *testing.T) {
	var event *proto.PersonaEventRequest
	cp := newEngine(specs["cpanel"], func(e *proto.PersonaEventRequest) error { event = e; return nil })
	w := serve(t, cp, http.MethodGet, "/cpsrvd/security_token?mode=probe", "", "203.0.113.4:1", "", "")
	if w.Code != 200 || event == nil || !event.AuthBypass || event.Cve != "CVE-2026-41940" {
		t.Fatalf("cpanel bypass: %d %+v", w.Code, event)
	}
	ai := newEngine(specs["cloudai"], nil)
	w = serve(t, ai, http.MethodGet, "/v1/models", "", "203.0.113.4:1", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "gpt-4o-mini") {
		t.Fatalf("cloud models: %d %s", w.Code, w.Body.String())
	}
}

func TestPHPMetadataAndDefaultCredentialClassificationAreNormalized(t *testing.T) {
	var events []*proto.PersonaEventRequest
	php := newEngine(specs["phpfpm"], func(e *proto.PersonaEventRequest) error { events = append(events, e); return nil })
	body := "--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n--inner--\r\n--outer--"
	serve(t, php, http.MethodPost, "/upload", body, "203.0.113.5:1", "", "multipart/form-data; boundary=outer")
	if len(events) != 1 || events[0].Metadata["body_size"] == "" || events[0].Metadata["multipart_depth"] != "2" {
		t.Fatalf("missing normalized multipart metadata: %+v", events)
	}

	var login *proto.PersonaEventRequest
	cp := newEngine(specs["cpanel"], func(e *proto.PersonaEventRequest) error { login = e; return nil })
	serve(t, cp, http.MethodPost, "/login", "user=root&pass=changeme", "203.0.113.6:1", "", "application/x-www-form-urlencoded")
	if login == nil || login.Username != "root" || login.Metadata["credential_class"] != "default" || strings.Contains(login.String(), "changeme") {
		t.Fatalf("default credential classification leaked or missing: %+v", login)
	}
}

func TestPersistedPathRedactsCredentialSegments(t *testing.T) {
	var event *proto.PersonaEventRequest
	h := newEngine(specs["cloudai"], func(e *proto.PersonaEventRequest) error { event = e; return nil })
	serve(t, h, http.MethodPost, "/v1/keys/sk-live-secret/validate", "", "203.0.113.7:1", "", "application/json")
	if event == nil || strings.Contains(event.Path, "sk-live-secret") || !strings.Contains(event.Path, "[redacted]") {
		t.Fatalf("credential-bearing path was not redacted: %+v", event)
	}
}

func TestAsyncPersistenceIsBoundedAndNeverPinsHTTPHandler(t *testing.T) {
	release := make(chan struct{})
	h := newAsyncEngine(specs["cloudai"], func(*proto.PersonaEventRequest) error {
		<-release
		return nil
	}).(*engine)
	for i := 0; i < cap(h.saveSem)+10; i++ {
		w := serve(t, h, http.MethodGet, "/v1/models", "", "203.0.113.8:1", "", "")
		if w.Code != http.StatusOK {
			t.Fatalf("request %d blocked or failed: %d", i, w.Code)
		}
	}
	if got := len(h.saveSem); got != cap(h.saveSem) {
		t.Fatalf("active saves=%d, want bounded pool=%d", got, cap(h.saveSem))
	}
	close(release)
}

func TestPHP2Shell109618PersistsStructuralEvidence(t *testing.T) {
	const boundary = "B7kQpoc618"
	const harmlessPayload = "fixture-bytes-never-executed"
	body := multipartFixture(boundary,
		`Content-Disposition: form-data; name="payload"; filename="fixture.bin"\r\nContent-Type: application/octet-stream`, harmlessPayload,
	)
	var event *proto.PersonaEventRequest
	h := newEngine(specs["modphp"], func(e *proto.PersonaEventRequest) error { event = e; return nil })
	r := httptest.NewRequest(http.MethodPost, "/index.php", strings.NewReader(body))
	r.RemoteAddr = "203.0.113.18:49152"
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	r.Header.Set("User-Agent", "php2shell-scan/109618")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK || event == nil {
		t.Fatalf("response/event: %d %+v", w.Code, event)
	}
	if event.Action != "php2shell_oom_probe" || event.Cve != "CVE-2026-109618" {
		t.Fatalf("classification: %+v", event)
	}
	for key, want := range map[string]string{
		"content_type": "multipart/form-data", "body_size": fmt.Sprint(len(body)),
		"body_truncated": "false", "multipart_depth": "1", "multipart_fields": "payload",
		"multipart_file_parts": "1", "multipart_boundary_size": fmt.Sprint(len(boundary)),
	} {
		if event.Metadata[key] != want {
			t.Fatalf("metadata[%q]=%q, want %q; event=%+v", key, event.Metadata[key], want, event)
		}
	}
	if event.Metadata["body_sha256"] == "" || event.Metadata["multipart_boundary_sha256"] == "" {
		t.Fatalf("missing request hashes: %+v", event.Metadata)
	}
	if !strings.Contains(event.Evidence, "body_sha256=") || strings.Contains(event.String(), harmlessPayload) {
		t.Fatalf("evidence is not structural or retained payload: %+v", event)
	}
}

func TestPHP2Shell109619CorrelatesSessionWithoutPersistingIdentifier(t *testing.T) {
	const boundary = "safe-session-fixture"
	const sessionID = "secret-session-value-must-not-persist"
	body := multipartFixture(boundary,
		`Content-Disposition: form-data; name="PHPSESSID"`, sessionID,
		`Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"`, "safe-progress-marker",
		`Content-Disposition: form-data; name="file"; filename="fixture.txt"\r\nContent-Type: text/plain`, "not-php-and-never-written",
	)
	var events []*proto.PersonaEventRequest
	h := newEngine(specs["phpfpm"], func(e *proto.PersonaEventRequest) error { events = append(events, e); return nil })
	r := httptest.NewRequest(http.MethodPost, "/index.php", strings.NewReader(body))
	r.RemoteAddr = "203.0.113.19:49152"
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	follow := httptest.NewRequest(http.MethodPost, "/shell/cmd", strings.NewReader("cmd=ignored"))
	follow.RemoteAddr = r.RemoteAddr
	follow.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	follow.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: sessionID})
	h.ServeHTTP(httptest.NewRecorder(), follow)

	if len(events) != 2 {
		t.Fatalf("events=%d, want 2", len(events))
	}
	first, second := events[0], events[1]
	if first.Action != "php2shell_session_upload_probe" || first.Cve != "CVE-2026-109619" {
		t.Fatalf("classification: %+v", first)
	}
	if first.Metadata["php_session_upload_progress"] != "true" || first.Metadata["phpsessid_present"] != "true" || first.Metadata["session_correlation"] != "phpsessid_multipart_field" {
		t.Fatalf("session metadata: %+v", first.Metadata)
	}
	if second.Action != "confirmed_follow_on" || second.Cve != first.Cve || second.SessionId != first.SessionId {
		t.Fatalf("follow-on was not correlated: first=%+v second=%+v", first, second)
	}
	if strings.Contains(first.String(), sessionID) || strings.Contains(second.String(), sessionID) {
		t.Fatalf("PHP session identifier reached persistence: first=%+v second=%+v", first, second)
	}
}

func TestPHPBenignMultipartAndLoginControlsDoNotClassify(t *testing.T) {
	var phpEvent *proto.PersonaEventRequest
	php := newEngine(specs["phpfpm"], func(e *proto.PersonaEventRequest) error { phpEvent = e; return nil })
	body := multipartFixture("ordinary-boundary", `Content-Disposition: form-data; name="file"; filename="readme.txt"`, "hello")
	serve(t, php, http.MethodPost, "/upload", body, "203.0.113.20:1", "", "multipart/form-data; boundary=ordinary-boundary")
	if phpEvent == nil || phpEvent.Action != "multipart_upload_probe" || phpEvent.Cve != "" {
		t.Fatalf("benign multipart classified: %+v", phpEvent)
	}

	var loginEvent *proto.PersonaEventRequest
	login := newEngine(specs["modphp"], func(e *proto.PersonaEventRequest) error { loginEvent = e; return nil })
	serve(t, login, http.MethodPost, "/login", "username=operator&password=harmless-control", "203.0.113.20:2", "", "application/x-www-form-urlencoded")
	if loginEvent == nil || loginEvent.Action != "login_attempt" || loginEvent.Cve != "" {
		t.Fatalf("login control classified: %+v", loginEvent)
	}
}

func TestPHPBodyCapUsesPrefixHashAndNeverWritesOrExecutes(t *testing.T) {
	var event *proto.PersonaEventRequest
	h := newEngine(specs["phpfpm"], func(e *proto.PersonaEventRequest) error { event = e; return nil })
	requestedPath := filepath.Join(t.TempDir(), "must-not-exist")
	body := strings.Repeat("x", maxBody+128) + "&cmd=touch%20" + requestedPath
	w := serve(t, h, http.MethodPost, "/shell/cmd", body, "203.0.113.21:1", "", "application/x-www-form-urlencoded")
	if w.Code != http.StatusOK || event == nil {
		t.Fatalf("response/event: %d %+v", w.Code, event)
	}
	if event.Metadata["body_size"] != fmt.Sprint(maxBody) || event.Metadata["body_truncated"] != "true" || event.Metadata["body_prefix_sha256"] == "" || event.Metadata["body_sha256"] != "" {
		t.Fatalf("body cap metadata: %+v", event.Metadata)
	}
	if _, err := os.Stat(requestedPath); !os.IsNotExist(err) {
		t.Fatalf("request caused a file write: %v", err)
	}
	if strings.Contains(event.String(), requestedPath) {
		t.Fatalf("command value reached persistence: %+v", event)
	}
}

func multipartFixture(boundary string, headersAndValues ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(headersAndValues); i += 2 {
		headers := strings.ReplaceAll(headersAndValues[i], `\r\n`, "\r\n")
		fmt.Fprintf(&b, "--%s\r\n%s\r\n\r\n%s\r\n", boundary, headers, headersAndValues[i+1])
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}
