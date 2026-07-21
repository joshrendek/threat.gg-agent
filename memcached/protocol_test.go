package memcached

import (
	"strings"
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantName string
		wantArgs []string
	}{
		{"version", "version", "version", nil},
		{"uppercased verb is lowercased", "VERSION", "version", nil},
		{"trailing cr stripped", "version\r", "version", nil},
		{"get with key", "get foo", "get", []string{"foo"}},
		{"gets multi key", "gets a b c", "gets", []string{"a", "b", "c"}},
		{"stats subcommand", "stats items", "stats", []string{"items"}},
		{"set with meta", "set k 0 0 5", "set", []string{"k", "0", "0", "5"}},
		{"empty line", "", "", nil},
		{"whitespace collapses", "get   foo", "get", []string{"foo"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCommand(tt.line)
			if got.name != tt.wantName {
				t.Errorf("name = %q, want %q", got.name, tt.wantName)
			}
			if len(got.args) != len(tt.wantArgs) {
				t.Fatalf("args = %v, want %v", got.args, tt.wantArgs)
			}
			for i := range tt.wantArgs {
				if got.args[i] != tt.wantArgs[i] {
					t.Errorf("args[%d] = %q, want %q", i, got.args[i], tt.wantArgs[i])
				}
			}
		})
	}
}

func TestIsStorageCommand(t *testing.T) {
	for _, name := range []string{"set", "add", "replace", "append", "prepend", "cas"} {
		if !isStorageCommand(name) {
			t.Errorf("isStorageCommand(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"get", "gets", "delete", "stats", "version", "quit", ""} {
		if isStorageCommand(name) {
			t.Errorf("isStorageCommand(%q) = true, want false", name)
		}
	}
}

func TestStorageDataBytes(t *testing.T) {
	// set <key> <flags> <exptime> <bytes> [noreply]
	c := parseCommand("set mykey 0 3600 10")
	n, ok := c.storageDataBytes()
	if !ok || n != 10 {
		t.Fatalf("storageDataBytes = (%d,%v), want (10,true)", n, ok)
	}

	// cas has an extra cas-unique token but <bytes> is still the 4th arg
	c = parseCommand("cas mykey 0 3600 7 42")
	n, ok = c.storageDataBytes()
	if !ok || n != 7 {
		t.Fatalf("cas storageDataBytes = (%d,%v), want (7,true)", n, ok)
	}

	// malformed / missing bytes field
	c = parseCommand("set mykey 0 0")
	if _, ok := c.storageDataBytes(); ok {
		t.Fatal("storageDataBytes ok=true for malformed set, want false")
	}
}

func TestHasNoReply(t *testing.T) {
	if !parseCommand("set k 0 0 5 noreply").hasNoReply() {
		t.Fatal("noreply not detected")
	}
	if parseCommand("set k 0 0 5").hasNoReply() {
		t.Fatal("noreply falsely detected")
	}
}

func TestDefaultResponse(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantPrefix  string
		wantClose   bool
		wantExactfn func(string) bool
	}{
		{name: "version", line: "version", wantPrefix: "VERSION "},
		{name: "get miss returns END", line: "get foo", wantExactfn: func(s string) bool { return s == "END\r\n" }},
		{name: "gets miss returns END", line: "gets nope", wantExactfn: func(s string) bool { return s == "END\r\n" }},
		{name: "unknown command returns ERROR", line: "bogus", wantExactfn: func(s string) bool { return s == "ERROR\r\n" }},
		{name: "empty command returns ERROR", line: "", wantExactfn: func(s string) bool { return s == "ERROR\r\n" }},
		{name: "set returns STORED", line: "set k 0 0 5", wantExactfn: func(s string) bool { return s == "STORED\r\n" }},
		{name: "set noreply is silent", line: "set k 0 0 5 noreply", wantExactfn: func(s string) bool { return s == "" }},
		{name: "flush_all returns OK", line: "flush_all", wantExactfn: func(s string) bool { return s == "OK\r\n" }},
		{name: "delete miss returns NOT_FOUND", line: "delete foo", wantExactfn: func(s string) bool { return s == "NOT_FOUND\r\n" }},
		{name: "quit closes", line: "quit", wantClose: true, wantExactfn: func(s string) bool { return s == "" }},
		{name: "stats ends with END", line: "stats", wantExactfn: func(s string) bool { return strings.HasSuffix(s, "END\r\n") && strings.Contains(s, "STAT ") }},
		{name: "stats items ends with END", line: "stats items", wantExactfn: func(s string) bool { return strings.HasSuffix(s, "END\r\n") }},
		{name: "stats slabs ends with END", line: "stats slabs", wantExactfn: func(s string) bool { return strings.HasSuffix(s, "END\r\n") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, closeConn := defaultResponse(parseCommand(tt.line))
			if closeConn != tt.wantClose {
				t.Errorf("closeConn = %v, want %v", closeConn, tt.wantClose)
			}
			if tt.wantPrefix != "" && !strings.HasPrefix(resp, tt.wantPrefix) {
				t.Errorf("resp = %q, want prefix %q", resp, tt.wantPrefix)
			}
			if tt.wantExactfn != nil && !tt.wantExactfn(resp) {
				t.Errorf("resp = %q failed expectation", resp)
			}
		})
	}
}

// A get on a known enticing key returns a VALUE block terminated by END so
// scanners that dump keys see plausible loot.
func TestGetKnownKeyReturnsValue(t *testing.T) {
	var hitKey string
	for k := range fakeItems {
		hitKey = k
		break
	}
	if hitKey == "" {
		t.Skip("no fake items defined")
	}
	resp, _ := defaultResponse(parseCommand("get " + hitKey))
	if !strings.HasPrefix(resp, "VALUE "+hitKey+" ") {
		t.Errorf("resp = %q, want VALUE block for %q", resp, hitKey)
	}
	if !strings.HasSuffix(resp, "END\r\n") {
		t.Errorf("resp = %q, want END terminator", resp)
	}
}
