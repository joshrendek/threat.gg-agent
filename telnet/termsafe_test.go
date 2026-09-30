package telnet

import (
	"os"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/termsafe"
)

// Authored telnet rows are written raw today; pin that the one write site is sanitised.
func TestTelnetResponseWriteIsSanitised(t *testing.T) {
	src, err := os.ReadFile("telnet.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "fmt.Fprint(conn, termsafe.Sanitize(response))") {
		t.Fatal("telnet response write must go through termsafe.Sanitize")
	}
	if strings.Contains(string(src), "fmt.Fprint(conn, response)") {
		t.Fatal("raw response write still present")
	}
	if !strings.Contains(string(src), `fmt.Fprint(conn, "~ # ")`) {
		t.Fatal("prompt write must stay unchanged")
	}
}

// The sanitiser applied to a server response carrying colour and OSC codes
// leaves no ESC byte for the attacker's terminal.
func TestTelnetResponseSanitisedOutputHasNoEscape(t *testing.T) {
	out := termsafe.Sanitize("\x1b[31mroot\x1b[0m\n\x1b]0;pwn\x07ok\n")
	if strings.ContainsRune(out, 0x1b) || out != "root\r\nok\r\n" {
		t.Fatalf("got %q", out)
	}
}
