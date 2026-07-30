package redis

// globMatch is a port of redis's stringmatchlen() (util.c, 7.2 branch) so that KEYS and
// SCAN MATCH filter the decoy keyspace with exactly the semantics a real redis has.
//
// This replaced path.Match, which differs from redis in ways that are observable from the
// wire: Go's '*' and '?' refuse to cross a '/', Go rejects an unterminated '[' with
// ErrBadPattern (the caller then silently dropped the key) where redis matches it
// literally, and Go has no equivalent of redis's backslash escaping inside a class.
//
// The pattern only ever selects from the hardcoded decoy key list; nothing here executes,
// evaluates or reflects attacker input.
//
// Deliberate deviation: redis compares class ranges as C `char`, which is signed on the
// platforms we impersonate, so ranges spanning bytes >= 0x80 behave differently there.
// We compare unsigned bytes. Every decoy key is ASCII, so this is unobservable.

// globMaxDepth bounds the recursion an adversarial pattern (e.g. "*a*a*a*a*a*a*b" against a
// long run of 'a') can force, mirroring redis's own depth guard.
const globMaxDepth = 1000

// globMatch reports whether s matches the redis glob pattern.
func globMatch(pattern, s string) bool {
	skipLongerMatches := false
	return globMatchImpl(pattern, s, 0, 0, &skipLongerMatches, 0)
}

// globMatchImpl walks pattern from pi and s from si. It carries indices rather than
// reslicing because redis's unterminated-class branch rewinds the pattern by one byte.
func globMatchImpl(pattern, s string, pi, si int, skipLongerMatches *bool, depth int) bool {
	if depth > globMaxDepth {
		return false
	}

	for pi < len(pattern) && si < len(s) {
		switch pattern[pi] {
		case '*':
			// Collapse runs of '*'; a trailing '*' matches the rest of the string.
			for pi+1 < len(pattern) && pattern[pi+1] == '*' {
				pi++
			}
			if len(pattern)-pi == 1 {
				return true
			}
			for si < len(s) {
				if globMatchImpl(pattern, s, pi+1, si, skipLongerMatches, depth+1) {
					return true
				}
				// The tail of the pattern matches nowhere in the rest of the string, so
				// no earlier '*' can be stretched into a match either. redis sets this
				// flag to cut the search short; it is an optimisation, not a semantic.
				if *skipLongerMatches {
					return false
				}
				si++
			}
			*skipLongerMatches = true
			return false

		case '?':
			si++

		case '[':
			pi++
			negate := pi < len(pattern) && pattern[pi] == '^'
			if negate {
				pi++
			}
			match := false
			for {
				if pi+1 < len(pattern) && pattern[pi] == '\\' {
					// Escaped member: the next byte is always literal.
					pi++
					if pattern[pi] == s[si] {
						match = true
					}
				} else if pi < len(pattern) && pattern[pi] == ']' {
					// Class closed normally; leave pi on the ']' for the outer pi++.
					break
				} else if pi >= len(pattern) {
					// Unterminated class. redis rewinds one byte so that the outer
					// pi++ below lands exactly at the end of the pattern.
					pi--
					break
				} else if len(pattern)-pi >= 3 && pattern[pi+1] == '-' {
					lo, hi := pattern[pi], pattern[pi+2]
					if lo > hi {
						lo, hi = hi, lo
					}
					pi += 2
					if c := s[si]; c >= lo && c <= hi {
						match = true
					}
				} else if pattern[pi] == s[si] {
					match = true
				}
				pi++
			}
			if negate {
				match = !match
			}
			if !match {
				return false
			}
			si++

		case '\\':
			if len(pattern)-pi >= 2 {
				pi++
			}
			fallthrough

		default:
			if pattern[pi] != s[si] {
				return false
			}
			si++
		}

		pi++
		if si == len(s) {
			// String exhausted: a tail of '*' can still match nothing.
			for pi < len(pattern) && pattern[pi] == '*' {
				pi++
			}
			break
		}
	}

	return pi == len(pattern) && si == len(s)
}

// globMatchAll reports whether the pattern is the "match everything" fast path. redis's
// keysCommand and scanGenericCommand both special-case a bare "*" and skip the matcher
// entirely, which is why a real redis returns a zero-length key for KEYS * but not for
// KEYS ?* (stringmatchlen("*", "") is false on its own).
func globMatchAll(pattern string) bool {
	return pattern == "*"
}

// globFilter returns the decoy keys matching pattern, preserving the declaration order of
// the key list so repeated requests are stable.
func globFilter(keys []string, pattern string) []string {
	out := make([]string, 0, len(keys))
	all := globMatchAll(pattern)
	for _, key := range keys {
		if all || globMatch(pattern, key) {
			out = append(out, key)
		}
	}
	return out
}
