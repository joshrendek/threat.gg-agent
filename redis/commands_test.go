package redis

import (
	"bytes"
	"strings"
	"testing"
)

func TestHandlePing(t *testing.T) {
	var buf bytes.Buffer
	handlePing([]string{"PING"}, &buf)
	if buf.String() != "+PONG\r\n" {
		t.Fatalf("expected +PONG, got %q", buf.String())
	}
}

func TestHandlePingWithMessage(t *testing.T) {
	var buf bytes.Buffer
	handlePing([]string{"PING", "hello"}, &buf)
	if !strings.Contains(buf.String(), "hello") {
		t.Fatalf("expected response to contain 'hello', got %q", buf.String())
	}
}

func TestHandleAuth(t *testing.T) {
	var buf bytes.Buffer
	sess := &session{}

	// AUTH with password only
	handleAuth([]string{"AUTH", "secret123"}, &buf, sess)
	if sess.password != "secret123" {
		t.Fatalf("expected password 'secret123', got %q", sess.password)
	}
	if !strings.Contains(buf.String(), "+OK") {
		t.Fatalf("expected +OK response, got %q", buf.String())
	}
}

func TestHandleAuthWithUsername(t *testing.T) {
	var buf bytes.Buffer
	sess := &session{}

	handleAuth([]string{"AUTH", "admin", "secret123"}, &buf, sess)
	if sess.username != "admin" {
		t.Fatalf("expected username 'admin', got %q", sess.username)
	}
	if sess.password != "secret123" {
		t.Fatalf("expected password 'secret123', got %q", sess.password)
	}
}

func TestHandleInfo(t *testing.T) {
	var buf bytes.Buffer
	handleInfo([]string{"INFO"}, &buf)
	result := buf.String()
	if !strings.Contains(result, "redis_version:7.2.4") {
		t.Fatalf("expected redis version in INFO response, got %q", result)
	}
	if !strings.Contains(result, "# Server") {
		t.Fatalf("expected Server section in INFO response")
	}
	if !strings.Contains(result, "# Keyspace") {
		t.Fatalf("expected Keyspace section in INFO response")
	}
}

func TestHandleInfoSection(t *testing.T) {
	var buf bytes.Buffer
	handleInfo([]string{"INFO", "server"}, &buf)
	result := buf.String()
	if !strings.Contains(result, "# Server") {
		t.Fatalf("expected Server section")
	}
	if strings.Contains(result, "# Keyspace") {
		t.Fatalf("should not contain Keyspace section when requesting only server")
	}
}

func TestHandleConfigGet(t *testing.T) {
	var buf bytes.Buffer
	handleConfigGet([]string{"CONFIG", "GET", "dir"}, &buf)
	result := buf.String()
	if !strings.Contains(result, "dir") {
		t.Fatalf("expected dir in config get response, got %q", result)
	}
	if !strings.Contains(result, "/var/lib/redis") {
		t.Fatalf("expected /var/lib/redis in config get response, got %q", result)
	}
}

func TestHandleConfigSet(t *testing.T) {
	var buf bytes.Buffer
	handleConfigSet([]string{"CONFIG", "SET", "dir", "/root/.ssh"}, &buf)
	if !strings.Contains(buf.String(), "+OK") {
		t.Fatalf("expected +OK, got %q", buf.String())
	}
	// Verify it was stored
	if fakeConfig["dir"] != "/root/.ssh" {
		t.Fatalf("expected dir to be set to /root/.ssh, got %q", fakeConfig["dir"])
	}
	// Restore
	fakeConfig["dir"] = "/var/lib/redis"
}

func TestHandleGet_KnownKey(t *testing.T) {
	var buf bytes.Buffer
	handleGet([]string{"GET", "session:admin"}, &buf)
	result := buf.String()
	if strings.Contains(result, "$-1") {
		t.Fatalf("expected non-null response for known key, got null")
	}
	if !strings.Contains(result, "admin") {
		t.Fatalf("expected admin in response, got %q", result)
	}
}

func TestHandleGet_UnknownKey(t *testing.T) {
	var buf bytes.Buffer
	handleGet([]string{"GET", "nonexistent"}, &buf)
	if buf.String() != "$-1\r\n" {
		t.Fatalf("expected null bulk string for unknown key, got %q", buf.String())
	}
}

func TestHandleKeys(t *testing.T) {
	var buf bytes.Buffer
	handleKeys([]string{"KEYS", "*"}, &buf)
	result := buf.String()
	if !strings.Contains(result, "session:admin") {
		t.Fatalf("expected session:admin in KEYS response, got %q", result)
	}
	if !strings.Contains(result, "api_key:prod") {
		t.Fatalf("expected api_key:prod in KEYS response, got %q", result)
	}
}

func TestHandleDbsize(t *testing.T) {
	var buf bytes.Buffer
	handleDbsize(&buf)
	if buf.String() != ":47\r\n" {
		t.Fatalf("expected :47, got %q", buf.String())
	}
}

func TestHandleSlaveof(t *testing.T) {
	var buf bytes.Buffer
	handleSlaveof(&buf)
	if !strings.Contains(buf.String(), "+OK") {
		t.Fatalf("expected +OK for SLAVEOF, got %q", buf.String())
	}
}

func TestHandleModuleLoad(t *testing.T) {
	var buf bytes.Buffer
	handleModuleLoad(&buf)
	if !strings.Contains(buf.String(), "-ERR") {
		t.Fatalf("expected error for MODULE LOAD, got %q", buf.String())
	}
}

func TestHandleEval(t *testing.T) {
	var buf bytes.Buffer
	handleEval(&buf)
	if !strings.Contains(buf.String(), "NOSCRIPT") {
		t.Fatalf("expected NOSCRIPT error for EVAL, got %q", buf.String())
	}
}

func TestHandleUnknown(t *testing.T) {
	var buf bytes.Buffer
	handleUnknown("FOOBAR", &buf)
	if !strings.Contains(buf.String(), "unknown command") {
		t.Fatalf("expected unknown command error, got %q", buf.String())
	}
}

func TestHandleClient_SetName(t *testing.T) {
	var buf bytes.Buffer
	handleClient([]string{"CLIENT", "SETNAME", "myconn"}, &buf)
	if !strings.Contains(buf.String(), "+OK") {
		t.Fatalf("expected +OK, got %q", buf.String())
	}
}

func TestHandleSelect(t *testing.T) {
	var buf bytes.Buffer
	handleSelect(&buf)
	if !strings.Contains(buf.String(), "+OK") {
		t.Fatalf("expected +OK, got %q", buf.String())
	}
}
