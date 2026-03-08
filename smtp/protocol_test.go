package smtp

import (
	"encoding/base64"
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		input   string
		wantCmd string
		wantArg string
	}{
		{"EHLO example.com", "EHLO", "example.com"},
		{"HELO example.com", "HELO", "example.com"},
		{"ehlo example.com", "EHLO", "example.com"},
		{"MAIL FROM:<user@example.com>", "MAIL", "FROM:<user@example.com>"},
		{"RCPT TO:<admin@example.com>", "RCPT", "TO:<admin@example.com>"},
		{"DATA", "DATA", ""},
		{"QUIT", "QUIT", ""},
		{"AUTH LOGIN", "AUTH", "LOGIN"},
		{"AUTH PLAIN dGVzdAB0ZXN0AHBhc3M=", "AUTH", "PLAIN dGVzdAB0ZXN0AHBhc3M="},
		{"VRFY root", "VRFY", "root"},
		{"RSET\r\n", "RSET", ""},
	}
	for _, tt := range tests {
		cmd, args := parseCommand(tt.input)
		if cmd != tt.wantCmd {
			t.Errorf("parseCommand(%q) cmd = %q, want %q", tt.input, cmd, tt.wantCmd)
		}
		if args != tt.wantArg {
			t.Errorf("parseCommand(%q) args = %q, want %q", tt.input, args, tt.wantArg)
		}
	}
}

func TestParseAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"FROM:<user@example.com>", "user@example.com"},
		{"TO:<admin@test.com>", "admin@test.com"},
		{"FROM: <spaced@example.com>", "spaced@example.com"},
		{"FROM:bare@example.com", "bare@example.com"},
		{"<brackets@example.com>", "brackets@example.com"},
		{"plain@example.com", "plain@example.com"},
	}
	for _, tt := range tests {
		got := parseAddress(tt.input)
		if got != tt.want {
			t.Errorf("parseAddress(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDecodeAuthLogin(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{base64.StdEncoding.EncodeToString([]byte("admin")), "admin"},
		{base64.StdEncoding.EncodeToString([]byte("user@example.com")), "user@example.com"},
		{base64.StdEncoding.EncodeToString([]byte("password123")), "password123"},
		{"not-valid-base64!!!", "not-valid-base64!!!"},
	}
	for _, tt := range tests {
		got := decodeAuthLogin(tt.input)
		if got != tt.want {
			t.Errorf("decodeAuthLogin(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDecodeAuthPlain(t *testing.T) {
	tests := []struct {
		input    string
		wantUser string
		wantPass string
	}{
		{
			base64.StdEncoding.EncodeToString([]byte("\x00testuser\x00testpass")),
			"testuser", "testpass",
		},
		{
			base64.StdEncoding.EncodeToString([]byte("authzid\x00user\x00pass")),
			"user", "pass",
		},
		{"invalid!!!", "", ""},
	}
	for _, tt := range tests {
		user, pass := decodeAuthPlain(tt.input)
		if user != tt.wantUser || pass != tt.wantPass {
			t.Errorf("decodeAuthPlain(%q) = (%q, %q), want (%q, %q)",
				tt.input, user, pass, tt.wantUser, tt.wantPass)
		}
	}
}

func TestBuildEhloResponse(t *testing.T) {
	resp := buildEhloResponse("mail.corp.com")
	if resp == "" {
		t.Fatal("buildEhloResponse returned empty")
	}
	expected := "250-mail.corp.com\r\n250-AUTH LOGIN PLAIN\r\n250-SIZE 10485760\r\n250 OK"
	if resp != expected {
		t.Errorf("buildEhloResponse = %q, want %q", resp, expected)
	}
}

func TestExtractSubject(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{"Subject: Test Email\r\nFrom: a@b.com\r\n\r\nBody here", "Test Email"},
		{"From: a@b.com\r\nSubject: Hello World\r\n\r\nBody", "Hello World"},
		{"From: a@b.com\r\n\r\nNo subject header", ""},
		{"subject: lowercase\r\n\r\nbody", "lowercase"},
	}
	for _, tt := range tests {
		got := extractSubject(tt.body)
		if got != tt.want {
			t.Errorf("extractSubject(%q) = %q, want %q", tt.body, got, tt.want)
		}
	}
}
