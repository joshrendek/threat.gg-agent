package redis

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestGlobMatch pins redis's stringmatchlen semantics. The expectations were cross-checked
// against a real redis:7.2.4 by storing each subject key and issuing KEYS <pattern>.
func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		subject string
		want    bool
	}{
		// Literals.
		{"", "", true},
		{"", "a", false},
		{"a", "a", true},
		{"a", "b", false},
		{"abc", "abc", true},
		{"abc", "abcd", false},

		// Star.
		{"*", "anything", true},
		{"*", "", false}, // stringmatchlen alone; KEYS * short-circuits, see globMatchAll
		{"a*", "abc", true},
		{"*c", "abc", true},
		{"*b*", "abc", true},
		{"a*c", "abc", true},
		{"a*c", "abd", false},
		{"**", "abc", true},
		{"a**c", "abbbc", true},
		{"user:*", "user:1:token", true},
		{"user:*", "session:admin", false},
		{"*token*", "user:1:token", true},
		{"*token*", "api_key:prod", false},

		// Star crosses '/' where Go's path.Match would not. This is the concrete
		// behavioural difference that motivated replacing path.Match.
		{"*", "a/b/c", true},
		{"a*c", "a/b/c", true},
		{"?", "/", true},

		// Question mark: exactly one byte, never zero.
		{"?", "a", true},
		{"?", "", false},
		{"?", "ab", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"???", "abc", true},

		// Character classes.
		{"[abc]", "b", true},
		{"[abc]", "d", false},
		{"[a-z]", "q", true},
		{"[a-z]", "Q", false},
		{"[a-z]*", "user:1", true},
		{"[^a]", "b", true},
		{"[^a]", "a", false},
		{"[^a-z]", "5", true},
		// Reversed ranges are normalised rather than rejected.
		{"[z-a]", "m", true},
		{"user:[0-9]:*", "user:1:token", true},
		{"user:[0-9]:*", "user:x:token", false},

		// Escapes.
		{`\*`, "*", true},
		{`\*`, "a", false},
		{`\?`, "?", true},
		{`\[`, "[", true},
		{`a\*b`, "a*b", true},
		{`a\*b`, "axb", false},
		{`[\]]`, "]", true},

		// Unterminated class: redis matches it, it does not error out. Go's path.Match
		// returned ErrBadPattern here and the old caller silently dropped every key.
		{"[abc", "a", true},
		{"[abc", "d", false},
		{"[", "x", false},

		// Trailing stars can match the empty remainder.
		{"abc*", "abc", true},
		{"abc**", "abc", true},
		{"abc*d", "abc", false},
	}

	for _, tc := range tests {
		name := tc.pattern + "~" + tc.subject
		t.Run(name, func(t *testing.T) {
			if got := globMatch(tc.pattern, tc.subject); got != tc.want {
				t.Fatalf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.subject, got, tc.want)
			}
		})
	}
}

// TestGlobMatchTerminates guards against the catastrophic backtracking a scanner could
// trigger with a pathological pattern. The pattern is attacker-supplied, so a hang here
// would be a denial of service on the honeypot itself.
func TestGlobMatchTerminates(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		subject := strings.Repeat("a", 400) + "b"
		done <- globMatch(strings.Repeat("*a", 40)+"c", subject)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("globMatch did not terminate on a pathological pattern")
	}
}

// TestHandleKeysHonorsPattern is the regression for the reported defect: KEYS used to ignore
// its argument and dump all ten decoy keys, so one targeted glob exposed the whole bait set
// and revealed the pattern was never evaluated.
func TestHandleKeysHonorsPattern(t *testing.T) {
	// The expected frames are byte-exact and match the KEYS rows in the server's
	// seed_command_responses_redis_deepen.sql, so the seeded answer and the built-in
	// fallback cannot diverge for these patterns.
	tests := []struct {
		pattern string
		want    string
	}{
		{"user:*", "*2\r\n$12\r\nuser:1:token\r\n$20\r\nuser:1:password_hash\r\n"},
		{"session:*", "*1\r\n$13\r\nsession:admin\r\n"},
		{"secret:*", "*1\r\n$22\r\nsecret:jwt_signing_key\r\n"},
		{"*token*", "*1\r\n$12\r\nuser:1:token\r\n"},
		{"aws:*", "*1\r\n$17\r\naws:access_key_id\r\n"},
		{"nomatch*", "*0\r\n"},
		{"user:?:token", "*1\r\n$12\r\nuser:1:token\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			var buf bytes.Buffer
			if err := handleKeys([]string{"KEYS", tc.pattern}, &buf); err != nil {
				t.Fatal(err)
			}
			mustDecodeFrame(t, buf.Bytes())
			if buf.String() != tc.want {
				t.Fatalf("KEYS %s\n got %q\nwant %q", tc.pattern, buf.String(), tc.want)
			}
		})
	}

	// A bare "*" still returns the whole decoy set.
	var all bytes.Buffer
	if err := handleKeys([]string{"KEYS", "*"}, &all); err != nil {
		t.Fatal(err)
	}
	got := mustDecodeFrame(t, all.Bytes())
	if len(got.items) != len(fakeKeys) {
		t.Fatalf("KEYS * returned %d keys, want all %d", len(got.items), len(fakeKeys))
	}
}

func TestHandleKeysArity(t *testing.T) {
	for _, args := range [][]string{{"KEYS"}, {"KEYS", "a", "b"}} {
		var buf bytes.Buffer
		if err := handleKeys(args, &buf); err != nil {
			t.Fatal(err)
		}
		got := mustDecodeFrame(t, buf.Bytes())
		if got.typ != '-' || got.str != "ERR wrong number of arguments for 'keys' command" {
			t.Fatalf("%v: got %v, want the arity error", args, got)
		}
	}
}

// TestKeysAndScanAgreeOnPattern: two answers from us that disagree about which keys exist
// are detectable without any external reference, so they share one matcher.
func TestKeysAndScanAgreeOnPattern(t *testing.T) {
	for _, pattern := range []string{"*", "user:*", "*token*", "[as]*", "nope*", "?????:*"} {
		var keys bytes.Buffer
		if err := handleKeys([]string{"KEYS", pattern}, &keys); err != nil {
			t.Fatal(err)
		}
		fromKeys := mustDecodeFrame(t, keys.Bytes())

		var scan bytes.Buffer
		handled, err := statefulResponse([]string{"SCAN", "0", "MATCH", pattern}, &scan, &session{})
		if !handled || err != nil {
			t.Fatalf("SCAN MATCH %s handled=%v err=%v", pattern, handled, err)
		}
		fromScan := mustDecodeFrame(t, scan.Bytes())
		if len(fromScan.items) != 2 || fromScan.items[0].str != "0" {
			t.Fatalf("SCAN reply shape wrong: %v", fromScan)
		}
		if fromKeys.String() != fromScan.items[1].String() {
			t.Fatalf("pattern %q: KEYS returned %s but SCAN returned %s",
				pattern, fromKeys, fromScan.items[1])
		}
	}
}

// TestGlobNeverExposesUnlistedKeys: the matcher only ever selects from the decoy list, it
// never reflects the pattern back as if it were a key.
func TestGlobNeverExposesUnlistedKeys(t *testing.T) {
	known := map[string]bool{}
	for _, k := range fakeKeys {
		known[k] = true
	}
	for _, pattern := range []string{"*", "*/*", "[", `\`, "**", "injected-key", "*\r\n*"} {
		var buf bytes.Buffer
		if err := handleKeys([]string{"KEYS", pattern}, &buf); err != nil {
			t.Fatal(err)
		}
		reply := mustDecodeFrame(t, buf.Bytes())
		for _, item := range reply.items {
			if !known[item.str] {
				t.Fatalf("KEYS %q returned %q, which is not a decoy key", pattern, item.str)
			}
		}
	}
}
