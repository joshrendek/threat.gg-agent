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

// Wider pin: any direct write to the channel or a formatted write in the SSH
// server sources must be sanitised, or be one of the two known writes that
// carry no server-supplied text. A new unsanitised write fails here.
func TestNoUnsanitisedChannelWrites(t *testing.T) {
	writers := []string{"channel.Write(", "fmt.Fprint(", "fmt.Fprintf(", "io.WriteString("}
	// Stable substrings of the two allowed lines: the scp NUL acknowledgement
	// and the direct-tcpip proxy relaying the upstream response body.
	allowed := []string{`[]byte("\x00")`, "Write(body)"}
	for _, file := range []string{"sshd.go", "commands.go"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			hit := false
			for _, w := range writers {
				if strings.Contains(line, w) {
					hit = true
				}
			}
			if !hit || strings.Contains(line, "termsafe.Sanitize(") {
				continue
			}
			ok := false
			for _, a := range allowed {
				if strings.Contains(line, a) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s:%d writes without termsafe.Sanitize and is not allowlisted: %s", file, i+1, strings.TrimSpace(line))
			}
		}
	}
}
