package memcached

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// serverVersion is reported by `version` and the `stats` block. Kept consistent so a
// scanner fingerprinting the banner and the stats output sees the same build.
const serverVersion = "1.6.21"

// fakeItems are enticing keys a scanner may stumble onto with `get`; every value is
// obviously fabricated honeypot bait. Anything not listed here is a miss (END).
var fakeItems = map[string]string{
	"session":       `{"user_id":1,"role":"admin","token":"eyJhbGciOiJIUzI1NiJ9.fake"}`,
	"user:1:token":  "tok_8f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c",
	"config:db_dsn": "postgres://admin:s3cret@10.0.1.5:5432/production",
	"api_key":       "rk_live_HONEYPOT_FAKE_KEY_0000000",
}

// command is a parsed memcached text-protocol request line.
type command struct {
	name string   // lowercased verb (e.g. "get", "set", "stats")
	args []string // remaining whitespace-separated tokens
	raw  string   // original line with CR/LF trimmed
}

// parseCommand splits a single memcached text-protocol line into a verb and its args.
// The verb is lowercased; args preserve their original casing (keys are case-sensitive).
func parseCommand(line string) command {
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return command{raw: line}
	}
	return command{name: strings.ToLower(fields[0]), args: fields[1:], raw: line}
}

var storageCommands = map[string]bool{
	"set": true, "add": true, "replace": true, "append": true, "prepend": true, "cas": true,
}

// isStorageCommand reports whether the verb is followed by a data block on the wire.
func isStorageCommand(name string) bool {
	return storageCommands[name]
}

// storageDataBytes returns the declared payload length for a storage command. For every
// storage verb the <bytes> field is the 4th argument (key, flags, exptime, bytes, ...),
// including `cas` whose trailing cas-unique token comes after <bytes>.
func (c command) storageDataBytes() (int, bool) {
	if !isStorageCommand(c.name) || len(c.args) < 4 {
		return 0, false
	}
	n, err := strconv.Atoi(c.args[3])
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// hasNoReply reports whether the client appended the "noreply" token, which suppresses
// the storage acknowledgement.
func (c command) hasNoReply() bool {
	return len(c.args) > 0 && c.args[len(c.args)-1] == "noreply"
}

// defaultResponse returns the hardcoded canned reply for a parsed command and whether the
// connection should be closed afterwards. It is only consulted when no admin-authored
// command_responses row matched (see the connection loop).
func defaultResponse(c command) (response string, closeConn bool) {
	switch c.name {
	case "":
		return "ERROR\r\n", false
	case "version":
		return "VERSION " + serverVersion + "\r\n", false
	case "quit":
		return "", true
	case "get", "gets":
		return getResponse(c), false
	case "set", "add", "replace", "append", "prepend", "cas":
		if c.hasNoReply() {
			return "", false
		}
		return "STORED\r\n", false
	case "delete":
		if len(c.args) > 0 {
			if _, ok := fakeItems[c.args[0]]; ok {
				return "DELETED\r\n", false
			}
		}
		return "NOT_FOUND\r\n", false
	case "incr", "decr":
		return "NOT_FOUND\r\n", false
	case "touch":
		return "NOT_FOUND\r\n", false
	case "flush_all":
		return "OK\r\n", false
	case "verbosity":
		return "OK\r\n", false
	case "stats":
		return statsResponse(c), false
	default:
		return "ERROR\r\n", false
	}
}

// getResponse renders VALUE blocks for any requested keys that exist in fakeItems and
// always terminates with END, matching real memcached (misses simply produce END).
func getResponse(c command) string {
	var sb strings.Builder
	for _, key := range c.args {
		if val, ok := fakeItems[key]; ok {
			fmt.Fprintf(&sb, "VALUE %s 0 %d\r\n%s\r\n", key, len(val), val)
		}
	}
	sb.WriteString("END\r\n")
	return sb.String()
}

// statsResponse renders the STAT block for `stats`, `stats items`, and `stats slabs`.
// Every variant terminates with END like the real server.
func statsResponse(c command) string {
	sub := ""
	if len(c.args) > 0 {
		sub = strings.ToLower(c.args[0])
	}
	switch sub {
	case "items":
		return "STAT items:1:number 3\r\n" +
			"STAT items:1:age 620\r\n" +
			"STAT items:1:evicted 0\r\n" +
			"STAT items:1:outofmemory 0\r\n" +
			"END\r\n"
	case "slabs":
		return "STAT 1:chunk_size 96\r\n" +
			"STAT 1:chunks_per_page 10922\r\n" +
			"STAT 1:total_pages 1\r\n" +
			"STAT 1:used_chunks 3\r\n" +
			"STAT active_slabs 1\r\n" +
			"STAT total_malloced 1048512\r\n" +
			"END\r\n"
	case "":
		return generalStats()
	default:
		// Unknown stats subcommand: real memcached returns just END.
		return "END\r\n"
	}
}

func generalStats() string {
	now := time.Now().Unix()
	var sb strings.Builder
	stats := [][2]string{
		{"pid", "2342"},
		{"uptime", "1892734"},
		{"time", strconv.FormatInt(now, 10)},
		{"version", serverVersion},
		{"pointer_size", "64"},
		{"curr_connections", "5"},
		{"total_connections", "1023"},
		{"cmd_get", "48213"},
		{"cmd_set", "12030"},
		{"get_hits", "39217"},
		{"get_misses", "8996"},
		{"delete_hits", "12"},
		{"delete_misses", "40"},
		{"curr_items", "1523"},
		{"total_items", "88123"},
		{"bytes", "4587213"},
		{"limit_maxbytes", "67108864"},
		{"threads", "4"},
		{"evictions", "0"},
	}
	for _, kv := range stats {
		fmt.Fprintf(&sb, "STAT %s %s\r\n", kv[0], kv[1])
	}
	sb.WriteString("END\r\n")
	return sb.String()
}
