package telnet

import (
	"os"
	"strings"
	"testing"

	"github.com/joshrendek/threat.gg-agent/termsafe"
)

// Authored telnet rows were written raw; pin that the one response write is
// sanitised and that our own prompt writes are not.
func TestTelnetResponseWriteIsSanitised(t *testing.T) {
	src, err := os.ReadFile("telnet.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	if n := strings.Count(body, "termsafe.Sanitize("); n != 1 {
		t.Fatalf("want exactly one termsafe.Sanitize( call, got %d", n)
	}
	if !strings.Contains(body, "fmt.Fprint(conn, termsafe.Sanitize(response))") {
		t.Fatal("telnet response write must go through termsafe.Sanitize")
	}
	if strings.Contains(body, "fmt.Fprint(conn, response)") {
		t.Fatal("raw response write still present")
	}
	prompt := `fmt.Fprint(conn, "~ # ")`
	if n := strings.Count(body, prompt); n < 1 {
		t.Fatal("prompt writes missing")
	}
	if strings.Contains(body, "termsafe.Sanitize(\"~ # \")") {
		t.Fatal("prompt write must not be wrapped in Sanitize")
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
