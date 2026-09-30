package sshd

import (
	"os"
	"strings"
	"testing"
)

// Source pin: every server-supplied byte written to the attacker's terminal in
// sshd.go goes through termsafe.Sanitize. The only other term.Write allowed is
// the prompt, whose server-supplied fields are sanitized in commandReply.
func TestServerTextWritesAreSanitised(t *testing.T) {
	raw, err := os.ReadFile("sshd.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if n := strings.Count(src, "termsafe.Sanitize("); n < 2 {
		t.Fatalf("want termsafe.Sanitize on both exec and shell paths, found %d", n)
	}
	for _, forbidden := range []string{"term.Write([]byte(resp.Response))", "term.Write([]byte(reply.Output))"} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("unsanitised server text write: %s", forbidden)
		}
	}
	for i, line := range strings.Split(src, "\n") {
		if !strings.Contains(line, "term.Write(") {
			continue
		}
		if !strings.Contains(line, "termsafe.Sanitize(") && !strings.Contains(line, "term.Write([]byte(prompt()))") {
			t.Errorf("sshd.go:%d writes to the terminal without termsafe.Sanitize: %s", i+1, strings.TrimSpace(line))
		}
	}
}
