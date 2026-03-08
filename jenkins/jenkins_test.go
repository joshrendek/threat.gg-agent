package jenkins

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

func TestExtractCredentialsFromBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/j_spring_security_check", strings.NewReader("j_username=ignored&j_password=ignored"))
	req.SetBasicAuth("admin", "admin")

	username, password := extractCredentials(req, []byte("j_username=ignored&j_password=ignored"))
	if username != "admin" || password != "admin" {
		t.Fatalf("expected basic auth credentials, got %q/%q", username, password)
	}
}

func TestExtractCredentialsFromForm(t *testing.T) {
	body := []byte("j_username=jenkins&j_password=letmein")
	req := httptest.NewRequest(http.MethodPost, "/j_spring_security_check", strings.NewReader(string(body)))

	username, password := extractCredentials(req, body)
	if username != "jenkins" || password != "letmein" {
		t.Fatalf("expected form credentials, got %q/%q", username, password)
	}
}

func TestExtractScriptForScriptEndpoints(t *testing.T) {
	payload := []byte(url.Values{"script": {"println('owned')"}}.Encode())

	script := extractScript("/script", payload)
	if script != "println('owned')" {
		t.Fatalf("unexpected script value: %q", script)
	}

	script = extractScript("/", payload)
	if script != "" {
		t.Fatalf("expected empty script for non-script endpoint, got %q", script)
	}
}

func TestHandleRequestPersistsAndResponds(t *testing.T) {
	var captured *pb.JenkinsRequest
	h := &honeypot{
		logger: zerolog.Nop(),
		save: func(req *pb.JenkinsRequest) error {
			captured = req
			return nil
		},
	}

	body := "script=Runtime.getRuntime%28%29.exec%28%27id%27%29&j_username=admin&j_password=admin"
	req := httptest.NewRequest(http.MethodPost, "/script", strings.NewReader(body))
	req.RemoteAddr = "10.1.2.3:4567"
	rr := httptest.NewRecorder()

	h.handleRequest(rr, req)

	if captured == nil {
		t.Fatal("expected request to be captured")
	}
	if captured.RemoteAddr != "10.1.2.3" {
		t.Fatalf("expected remote addr 10.1.2.3, got %q", captured.RemoteAddr)
	}
	if captured.Path != "/script" || captured.Method != http.MethodPost {
		t.Fatalf("unexpected method/path: %s %s", captured.Method, captured.Path)
	}
	if captured.Username != "admin" || captured.Password != "admin" {
		t.Fatalf("unexpected credentials: %q/%q", captured.Username, captured.Password)
	}
	if !strings.Contains(captured.Script, "Runtime.getRuntime") {
		t.Fatalf("expected script capture, got %q", captured.Script)
	}
	if rr.Result().Header.Get("X-Jenkins") != "2.426.3" {
		t.Fatalf("expected X-Jenkins header, got %q", rr.Result().Header.Get("X-Jenkins"))
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
}
