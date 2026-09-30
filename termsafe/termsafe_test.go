package termsafe

import (
	"math/rand"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain crlf kept", "a\r\nb\r\n", "a\r\nb\r\n"},
		{"lone lf becomes crlf", "a\nb\n", "a\r\nb\r\n"},
		{"tab kept", "a\tb\n", "a\tb\r\n"},
		{"csi stripped", "\x1b[31mred\x1b[0m\n", "red\r\n"},
		{"csi with params", "\x1b[1;32mok\x1b[m\n", "ok\r\n"},
		{"osc dropped to bel", "\x1b]0;title\x07after\n", "after\r\n"},
		{"osc dropped to st", "\x1b]52;c;aGk=\x1b\\after\n", "after\r\n"},
		{"bare control bytes removed", "a\x07b\x00c\x1fd\n", "abcd\r\n"},
		{"dangling esc removed", "a\x1b", "a"},
		{"utf8 preserved", "héllo → ✓\n", "héllo → ✓\r\n"},
		{"empty", "", ""},
		{"unterminated csi dropped", "ok\x1b[31", "ok"},
		{"unterminated osc drops rest", "ok\x1b]0;title and more\nx", "ok"},
		{"existing crlf unchanged", "a\r\nb\r\n\r\nc", "a\r\nb\r\n\r\nc"},
		{"multibyte", "é中\n", "é中\r\n"},
		{"nul removed", "a\x00b", "ab"},
	}
	for _, c := range cases {
		if got := Sanitize(c.in); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestSanitizeNeverEmitsEscape(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("\x1b[]\\\x07\r\n\tm;0123AZa~ \x00\x7f")
	for i := 0; i < 20000; i++ {
		buf := make([]byte, rng.Intn(40))
		for j := range buf {
			if rng.Intn(3) == 0 {
				buf[j] = byte(rng.Intn(256))
			} else {
				buf[j] = alphabet[rng.Intn(len(alphabet))]
			}
		}
		out := Sanitize(string(buf))
		if strings.ContainsRune(out, 0x1b) {
			t.Fatalf("ESC in output for %q: %q", buf, out)
		}
		for k := 0; k < len(out); k++ {
			c := out[k]
			if (c < 0x20 && c != '\n' && c != '\t' && c != '\r') || c == 0x7f {
				t.Fatalf("control byte %#x in output for %q: %q", c, buf, out)
			}
			if c == '\n' && (k == 0 || out[k-1] != '\r') {
				t.Fatalf("lone LF in output for %q: %q", buf, out)
			}
		}
	}
}
