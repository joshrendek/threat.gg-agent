package redis

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// This decoder exists so the tests can assert that what we put on the wire is a complete,
// well-formed RESP2 frame rather than merely containing an expected substring. It is
// written independently of respscan.go on purpose: if the production frame walker had an
// off-by-one, reusing it here would let the bug cancel itself out.

type respNode struct {
	typ   byte // '+' simple, '-' error, ':' integer, '$' bulk, '*' array
	str   string
	num   int64
	null  bool
	items []respNode
}

func (n respNode) String() string {
	switch n.typ {
	case '*':
		if n.null {
			return "*nil"
		}
		parts := make([]string, len(n.items))
		for i, it := range n.items {
			parts[i] = it.String()
		}
		return "[" + strings.Join(parts, " ") + "]"
	case ':':
		return strconv.FormatInt(n.num, 10)
	case '$':
		if n.null {
			return "$nil"
		}
		return strconv.Quote(n.str)
	default:
		return string(n.typ) + n.str
	}
}

func decodeRESP(b []byte, off int) (respNode, int, error) {
	if off >= len(b) {
		return respNode{}, 0, fmt.Errorf("value starts at %d, past end of %d bytes", off, len(b))
	}
	crlf := strings.Index(string(b[off:]), "\r\n")
	if crlf < 0 {
		return respNode{}, 0, fmt.Errorf("no CRLF terminating the line at offset %d", off)
	}
	head := string(b[off+1 : off+crlf])
	next := off + crlf + 2

	switch b[off] {
	case '+', '-':
		return respNode{typ: b[off], str: head}, next, nil

	case ':':
		n, err := strconv.ParseInt(head, 10, 64)
		if err != nil {
			return respNode{}, 0, fmt.Errorf("bad integer %q at %d", head, off)
		}
		return respNode{typ: ':', num: n}, next, nil

	case '$':
		n, err := strconv.Atoi(head)
		if err != nil {
			return respNode{}, 0, fmt.Errorf("bad bulk length %q at %d", head, off)
		}
		if n < 0 {
			return respNode{typ: '$', null: true}, next, nil
		}
		if next+n+2 > len(b) {
			return respNode{}, 0, fmt.Errorf("bulk at %d declares %d bytes but only %d remain", off, n, len(b)-next)
		}
		if b[next+n] != '\r' || b[next+n+1] != '\n' {
			return respNode{}, 0, fmt.Errorf("bulk at %d is not CRLF-terminated at its declared length %d", off, n)
		}
		return respNode{typ: '$', str: string(b[next : next+n])}, next + n + 2, nil

	case '*':
		n, err := strconv.Atoi(head)
		if err != nil {
			return respNode{}, 0, fmt.Errorf("bad array count %q at %d", head, off)
		}
		if n < 0 {
			return respNode{typ: '*', null: true}, next, nil
		}
		node := respNode{typ: '*', items: make([]respNode, 0, n)}
		cur := next
		for i := 0; i < n; i++ {
			child, end, err := decodeRESP(b, cur)
			if err != nil {
				return respNode{}, 0, fmt.Errorf("array at %d, element %d/%d: %w", off, i, n, err)
			}
			node.items = append(node.items, child)
			cur = end
		}
		return node, cur, nil

	default:
		return respNode{}, 0, fmt.Errorf("unknown type byte %q at offset %d", b[off], off)
	}
}

// mustDecodeFrame decodes exactly one RESP frame from b and fails the test unless the frame
// is well-formed AND consumes every byte. Trailing bytes would desynchronise a real client
// on the next command, so "zero trailing bytes" is the assertion that matters most here.
func mustDecodeFrame(t *testing.T, b []byte) respNode {
	t.Helper()
	if len(b) == 0 {
		t.Fatal("no response written")
	}
	node, end, err := decodeRESP(b, 0)
	if err != nil {
		t.Fatalf("malformed RESP frame: %v\nraw: %q", err, b)
	}
	if end != len(b) {
		t.Fatalf("frame decoded %d of %d bytes, %d trailing: %q", end, len(b), len(b)-end, b[end:])
	}
	return node
}

// TestDecoderRejectsMalformedFrames guards the guard: the assertions in every other test are
// only meaningful if this decoder actually rejects bad framing.
func TestDecoderRejectsMalformedFrames(t *testing.T) {
	bad := map[string]string{
		"bulk length too long":  "$5\r\nabc\r\n",
		"bulk length too short": "$2\r\nabcdef\r\n",
		"array short by one":    "*2\r\n$1\r\na\r\n",
		"unterminated line":     "*1",
		"unknown type byte":     "!oops\r\n",
		"non-numeric bulk len":  "$x\r\nabc\r\n",
	}
	for name, frame := range bad {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeRESP([]byte(frame), 0); err == nil {
				t.Fatalf("decoder accepted malformed frame %q", frame)
			}
		})
	}

	// A well-formed frame with junk appended must be caught by the trailing-byte check
	// rather than the decoder itself.
	node, end, err := decodeRESP([]byte("+OK\r\nGARBAGE"), 0)
	if err != nil || node.str != "OK" {
		t.Fatalf("decode of +OK failed: node=%v err=%v", node, err)
	}
	if end == len("+OK\r\nGARBAGE") {
		t.Fatal("decoder consumed trailing garbage; the zero-trailing-bytes assertion would be vacuous")
	}
}
