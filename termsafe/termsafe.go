// Package termsafe makes server-supplied text safe to write to an attacker's
// terminal: no colour or cursor control, no OSC (title/clipboard/hyperlink), no
// stray control bytes, and CRLF line endings the terminal expects.
package termsafe

import (
	"strings"
	"unicode/utf8"
)

// Sanitize strips CSI sequences, drops OSC sequences entirely, removes every
// control byte except \n and \t, and normalizes line endings to \r\n. The
// output never contains an ESC byte.
func Sanitize(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0x1b:
			if i+1 >= len(s) {
				return b.String()
			}
			switch s[i+1] {
			case '[': // CSI: skip to final byte 0x40..0x7E; unterminated drops the rest
				j := i + 2
				for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
					j++
				}
				i = j
			case ']': // OSC: skip to BEL or ESC \; unterminated drops the rest
				j := i + 2
				for j < len(s) {
					if s[j] == 0x07 {
						break
					}
					if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
						j++
						break
					}
					j++
				}
				i = j
			default: // two-byte escape
				i++
			}
		case c == '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				b.WriteString("\r\n")
				i++
			}
			// lone CR dropped
		case c == '\n':
			b.WriteString("\r\n")
		case c == '\t':
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			// drop
		case c >= 0x80:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				if c > 0x9f {
					b.WriteByte(c)
					continue
				}
				// bare C1 byte: honoured by 8-bit terminals, treat like the rune
				r = rune(c)
			}
			switch {
			case r == 0x9b: // C1 CSI: skip to final byte
				j := i + size
				for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
					j++
				}
				i = j
			case r == 0x9d: // C1 OSC: skip to BEL, ESC \ or C1 ST
				j := i + size
				for j < len(s) {
					if s[j] == 0x07 || s[j] == 0x9c {
						break
					}
					if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' {
						j++
						break
					}
					if s[j] == 0xc2 && j+1 < len(s) && s[j+1] == 0x9c {
						j++
						break
					}
					j++
				}
				i = j
			case r >= 0x80 && r <= 0x9f: // other C1 controls dropped
				i += size - 1
			default:
				b.WriteString(s[i : i+size])
				i += size - 1
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
