package redis

import (
	"errors"
	"fmt"
	"strconv"
)

// respscan walks already-encoded RESP2 frames.
//
// The COMMAND table is embedded as the exact bytes a real redis 7.2.4 puts on the wire
// (see commandtable.go). Every reply derived from it — COMMAND COUNT, COMMAND LIST,
// COMMAND INFO <name>, COMMAND GETKEYS — is sliced out of that one blob and re-emitted
// verbatim rather than re-encoded from a hand-written table. That is what makes the derived
// answers incapable of disagreeing with the table they describe, and it is why no length
// prefix in any of them is ever computed by hand.

// respMaxDepth bounds nesting while walking a frame. The real table nests five deep
// (table > entry > key_specs > spec > find_keys spec); 32 is slack without being unbounded.
const respMaxDepth = 32

var errBadFrame = errors.New("malformed RESP frame")

// respHeader locates the CRLF terminating the type line that starts at off, returning the
// offset of the CR and the offset of the first byte after the LF.
func respHeader(b []byte, off int) (headEnd, next int, err error) {
	for i := off; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i, i + 2, nil
		}
	}
	return 0, 0, errBadFrame
}

// respValueEnd returns the offset just past the single RESP value beginning at off.
func respValueEnd(b []byte, off, depth int) (int, error) {
	if depth > respMaxDepth {
		return 0, fmt.Errorf("%w: nesting deeper than %d", errBadFrame, respMaxDepth)
	}
	if off >= len(b) {
		return 0, fmt.Errorf("%w: value starts past end of frame", errBadFrame)
	}

	headEnd, next, err := respHeader(b, off)
	if err != nil {
		return 0, err
	}

	switch b[off] {
	case '+', '-', ':':
		return next, nil

	case '$':
		n, err := strconv.Atoi(string(b[off+1 : headEnd]))
		if err != nil {
			return 0, fmt.Errorf("%w: bad bulk length %q", errBadFrame, b[off+1:headEnd])
		}
		if n < 0 {
			return next, nil // null bulk string, no payload follows
		}
		end := next + n + 2
		if end > len(b) || b[end-2] != '\r' || b[end-1] != '\n' {
			return 0, fmt.Errorf("%w: bulk of %d bytes is truncated or unterminated", errBadFrame, n)
		}
		return end, nil

	case '*':
		n, err := strconv.Atoi(string(b[off+1 : headEnd]))
		if err != nil {
			return 0, fmt.Errorf("%w: bad array count %q", errBadFrame, b[off+1:headEnd])
		}
		if n < 0 {
			return next, nil // null array
		}
		cur := next
		for i := 0; i < n; i++ {
			cur, err = respValueEnd(b, cur, depth+1)
			if err != nil {
				return 0, err
			}
		}
		return cur, nil
	}

	return 0, fmt.Errorf("%w: unknown type byte %q", errBadFrame, b[off])
}

// respElements splits the RESP array frame in b into the raw frames of its elements. It
// fails unless b holds exactly one well-formed array and nothing else, so a truncated or
// over-long fixture cannot slip through as a short element list.
func respElements(b []byte) ([][]byte, error) {
	if len(b) == 0 || b[0] != '*' {
		return nil, fmt.Errorf("%w: not an array", errBadFrame)
	}
	headEnd, next, err := respHeader(b, 0)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(string(b[1:headEnd]))
	if err != nil || n < 0 {
		return nil, fmt.Errorf("%w: bad array count %q", errBadFrame, b[1:headEnd])
	}

	out := make([][]byte, 0, n)
	cur := next
	for i := 0; i < n; i++ {
		end, err := respValueEnd(b, cur, 0)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		out = append(out, b[cur:end])
		cur = end
	}
	if cur != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes after array", errBadFrame, len(b)-cur)
	}
	return out, nil
}

// respBulkValue returns the payload of a bulk-string frame.
func respBulkValue(b []byte) (string, bool) {
	if len(b) == 0 || b[0] != '$' {
		return "", false
	}
	headEnd, next, err := respHeader(b, 0)
	if err != nil {
		return "", false
	}
	n, err := strconv.Atoi(string(b[1:headEnd]))
	if err != nil || n < 0 || next+n+2 != len(b) {
		return "", false
	}
	return string(b[next : next+n]), true
}

// respSimpleValue returns the payload of a simple-string frame. The command table stores
// flags and ACL categories as simple strings, not bulk strings.
func respSimpleValue(b []byte) (string, bool) {
	if len(b) == 0 || b[0] != '+' {
		return "", false
	}
	headEnd, next, err := respHeader(b, 0)
	if err != nil || next != len(b) {
		return "", false
	}
	return string(b[1:headEnd]), true
}

// respIntValue returns the value of an integer frame.
func respIntValue(b []byte) (int64, bool) {
	if len(b) == 0 || b[0] != ':' {
		return 0, false
	}
	headEnd, next, err := respHeader(b, 0)
	if err != nil || next != len(b) {
		return 0, false
	}
	n, err := strconv.ParseInt(string(b[1:headEnd]), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
