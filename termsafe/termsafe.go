// Package termsafe makes server-supplied text safe to write to an attacker's
// terminal: no colour or cursor control, no OSC (title/clipboard/hyperlink), no
// stray control bytes, and CRLF line endings the terminal expects.
package termsafe

import "strings"

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
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
