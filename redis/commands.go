package redis

import (
	"fmt"
	"io"
	"strings"
)

// Fake key names designed to attract attacker interest
var fakeKeys = []string{
	"session:admin",
	"user:1:token",
	"api_key:prod",
	"config:database_url",
	"cache:credentials",
	"backup:latest",
	"secret:jwt_signing_key",
	"user:1:password_hash",
	"stripe:sk_live_key",
	"aws:access_key_id",
}

// Fake values for known keys
var fakeValues = map[string]string{
	"session:admin":          `{"user_id":1,"role":"admin","token":"eyJhbGciOiJIUzI1NiJ9.fake"}`,
	"user:1:token":           "tok_8f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c",
	"api_key:prod":           "rk_live_HONEYPOT_FAKE_KEY_0000000",
	"config:database_url":    "postgres://admin:s3cret@10.0.1.5:5432/production",
	"cache:credentials":      `{"aws_key":"AKIA...FAKE","aws_secret":"wJalr...FAKE"}`,
	"backup:latest":          "/var/backups/db-2026-03-01.sql.gz",
	"secret:jwt_signing_key": "super-secret-jwt-key-do-not-share-2026",
	"user:1:password_hash":   "$2a$10$fakehashfakehashfakehashfakehashfakehash",
	"stripe:sk_live_key":     "rk_live_HONEYPOT_FAKE_KEY_1111111",
	"aws:access_key_id":      "AKIAFAKEACCESSKEYID00",
}

// Fake config values
var fakeConfig = map[string]string{
	"dir":              "/var/lib/redis",
	"dbfilename":       "dump.rdb",
	"save":             "3600 1 300 100 60 10000",
	"maxmemory":        "268435456",
	"maxmemory-policy": "allkeys-lru",
	"requirepass":      "",
	"bind":             "0.0.0.0",
	"port":             "6379",
	"loglevel":         "notice",
	"databases":        "16",
	"tcp-keepalive":    "300",
	"timeout":          "0",
	"protected-mode":   "no",
}

func handlePing(args []string, w io.Writer) error {
	if len(args) > 1 {
		return writeBulkString(w, args[1])
	}
	return writeSimpleString(w, "PONG")
}

func handleAuth(args []string, w io.Writer, sess *session) error {
	if len(args) >= 3 {
		sess.username = args[1]
		sess.password = args[2]
	} else if len(args) == 2 {
		sess.password = args[1]
	}
	return writeSimpleString(w, "OK")
}

func handleInfo(args []string, w io.Writer, sess *session) error {
	return writeBulkString(w, buildInfoResponse(args[1:], sess))
}

// infoSection is one INFO section. Builders take the session because some sections embed
// live per-connection state — notably Replication, whose role flips after SLAVEOF.
type infoSection struct {
	name      string
	inDefault bool
	build     func(*session) string
}

// infoSectionOrder is redis 7.2.4's own emission order. Real redis renders sections in this
// order no matter what order the caller asked for them in (INFO clients server answers
// Server then Clients), so the order lives here and a request only selects from it.
//
// Commandstats and Latencystats are the two sections excluded from the default set: they
// appear for INFO all / INFO everything but not for bare INFO. Verified against 7.2.4.
var infoSectionOrder = []infoSection{
	{"server", true, buildServerInfo},
	{"clients", true, buildClientsInfo},
	{"memory", true, buildMemoryInfo},
	{"persistence", true, buildPersistenceInfo},
	{"stats", true, buildStatsInfo},
	{"replication", true, buildReplicationInfo},
	{"cpu", true, buildCPUInfo},
	{"modules", true, buildModulesInfo},
	{"commandstats", false, buildCommandstatsInfo},
	{"errorstats", true, buildErrorstatsInfo},
	{"latencystats", false, buildLatencystatsInfo},
	{"cluster", true, buildClusterInfo},
	{"keyspace", true, buildKeyspaceInfo},
}

// infoStatefulSections are the sections whose content depends on what the attacker has
// already done on this connection. Any INFO request touching one of them has to be answered
// by the agent rather than by a frozen command_responses row — see statefulResponse.
var infoStatefulSections = map[string]bool{
	"replication": true,
	"persistence": true,
}

// buildInfoResponse renders the requested INFO sections. An empty request means the default
// set, matching bare INFO.
//
// Sections are joined by a blank line with none appended after the last, which is what a
// real 7.2.4 does: a single-section INFO ends on its final field. That also matches what
// buildReplicationInfo and buildPersistenceInfo already put on the wire, so no two of our
// own INFO answers are framed differently from each other.
//
// An unrecognised section name contributes nothing, so INFO bogus returns an empty bulk
// string — also real behaviour, and now distinguishable from the sections we implement.
func buildInfoResponse(requested []string, sess *session) string {
	if len(requested) == 0 {
		requested = []string{"default"}
	}

	everything := false
	want := make(map[string]bool, len(requested))
	for _, r := range requested {
		switch strings.ToLower(r) {
		case "default":
			for _, s := range infoSectionOrder {
				if s.inDefault {
					want[s.name] = true
				}
			}
		case "all", "everything":
			everything = true
		default:
			want[strings.ToLower(r)] = true
		}
	}

	sections := make([]string, 0, len(infoSectionOrder))
	for _, s := range infoSectionOrder {
		if everything || want[s.name] {
			sections = append(sections, s.build(sess))
		}
	}
	return strings.Join(sections, "\r\n")
}

func buildServerInfo(*session) string {
	return "# Server\r\n" +
		"redis_version:7.2.4\r\n" +
		"redis_git_sha1:00000000\r\n" +
		"redis_git_dirty:0\r\n" +
		"redis_build_id:a1b2c3d4e5f6a7b8\r\n" +
		"redis_mode:standalone\r\n" +
		"os:Linux 5.15.0-91-generic x86_64\r\n" +
		"arch_bits:64\r\n" +
		"tcp_port:6379\r\n" +
		"uptime_in_seconds:1847293\r\n" +
		"uptime_in_days:21\r\n" +
		"hz:10\r\n" +
		"configured_hz:10\r\n" +
		"lru_clock:14892741\r\n"
}

func buildClientsInfo(*session) string {
	return "# Clients\r\n" +
		"connected_clients:3\r\n" +
		"cluster_connections:0\r\n" +
		"maxclients:10000\r\n" +
		"blocked_clients:0\r\n"
}

func buildMemoryInfo(*session) string {
	return "# Memory\r\n" +
		"used_memory:2147483648\r\n" +
		"used_memory_human:2.00G\r\n" +
		"used_memory_rss:2415919104\r\n" +
		"used_memory_rss_human:2.25G\r\n" +
		"used_memory_peak:2684354560\r\n" +
		"used_memory_peak_human:2.50G\r\n" +
		"maxmemory:268435456\r\n" +
		"maxmemory_human:256.00M\r\n" +
		"maxmemory_policy:allkeys-lru\r\n"
}

// buildStatsInfo, buildCPUInfo, buildCommandstatsInfo, buildLatencystatsInfo,
// buildErrorstatsInfo and buildClusterInfo carry the values byte-for-byte from
// seed_command_responses_redis_deepen.sql in the server repo, which seeds the same six
// sections as standalone command_responses rows. Those rows are looked up before this
// fallback, so keeping the numbers identical is what stops the two sources from ever
// contradicting each other while both exist.
//
// The counters cross-reference each other on purpose: cmdstat_get.calls equals
// keyspace_hits, cmdstat_ping.calls equals total_connections_received, and expired_keys
// squares with the expires count in Keyspace.
func buildStatsInfo(*session) string {
	return "# Stats\r\n" +
		"total_connections_received:9241\r\n" +
		"total_commands_processed:1387422\r\n" +
		"instantaneous_ops_per_sec:7\r\n" +
		"total_net_input_bytes:184729301\r\n" +
		"total_net_output_bytes:2947183920\r\n" +
		"instantaneous_input_kbps:1.42\r\n" +
		"instantaneous_output_kbps:18.07\r\n" +
		"rejected_connections:0\r\n" +
		"sync_full:0\r\n" +
		"sync_partial_ok:0\r\n" +
		"sync_partial_err:0\r\n" +
		"expired_keys:1204\r\n" +
		"expired_stale_perc:0.00\r\n" +
		"expired_time_cap_reached_count:0\r\n" +
		"expire_cycle_cpu_milliseconds:14829\r\n" +
		"evicted_keys:0\r\n" +
		"evicted_clients:0\r\n" +
		"keyspace_hits:918273\r\n" +
		"keyspace_misses:44192\r\n" +
		"pubsub_channels:0\r\n" +
		"pubsub_patterns:0\r\n" +
		"pubsubshard_channels:0\r\n" +
		"latest_fork_usec:842\r\n" +
		"total_forks:612\r\n" +
		"migrate_cached_sockets:0\r\n" +
		"total_reads_processed:1396663\r\n" +
		"total_writes_processed:1387421\r\n"
}

func buildCPUInfo(*session) string {
	return "# CPU\r\n" +
		"used_cpu_sys:1284.472103\r\n" +
		"used_cpu_user:2941.118736\r\n" +
		"used_cpu_sys_children:12.884219\r\n" +
		"used_cpu_user_children:41.229183\r\n" +
		"used_cpu_sys_main_thread:1281.930447\r\n" +
		"used_cpu_user_main_thread:2938.442110\r\n"
}

// buildModulesInfo is header-only. A real redis with no modules loaded emits exactly this,
// and it agrees with the MODULE LIST row that answers with an empty array.
func buildModulesInfo(*session) string {
	return "# Modules\r\n"
}

func buildCommandstatsInfo(*session) string {
	return "# Commandstats\r\n" +
		"cmdstat_get:calls=918273,usec=1284729,usec_per_call=1.40,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_set:calls=412884,usec=942018,usec_per_call=2.28,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_del:calls=12048,usec=15927,usec_per_call=1.32,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_expire:calls=41029,usec=48213,usec_per_call=1.18,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_ping:calls=9241,usec=4712,usec_per_call=0.51,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_info:calls=1842,usec=112947,usec_per_call=61.32,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_config|get:calls=204,usec=9182,usec_per_call=45.01,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_client|setname:calls=88,usec=291,usec_per_call=3.31,rejected_calls=0,failed_calls=0\r\n"
}

func buildErrorstatsInfo(*session) string {
	return "# Errorstats\r\n" +
		"errorstat_ERR:count=37\r\n"
}

func buildLatencystatsInfo(*session) string {
	return "# Latencystats\r\n" +
		"latency_percentiles_usec_get:p50=1.003,p99=2.007,p99.9=4.015\r\n" +
		"latency_percentiles_usec_set:p50=2.007,p99=4.015,p99.9=8.031\r\n" +
		"latency_percentiles_usec_del:p50=1.003,p99=3.007,p99.9=6.015\r\n" +
		"latency_percentiles_usec_ping:p50=0.001,p99=1.003,p99.9=1.003\r\n" +
		"latency_percentiles_usec_info:p50=58.111,p99=105.983,p99.9=131.071\r\n"
}

// buildClusterInfo agrees with the seeded CLUSTER INFO row, which also reports
// cluster_enabled:0.
func buildClusterInfo(*session) string {
	return "# Cluster\r\n" +
		"cluster_enabled:0\r\n"
}

func buildKeyspaceInfo(*session) string {
	return "# Keyspace\r\n" +
		"db0:keys=47,expires=12,avg_ttl=3612451\r\n"
}

func handleConfigGet(args []string, w io.Writer) error {
	if len(args) < 3 {
		return writeArray(w, nil)
	}
	pattern := strings.ToLower(args[2])

	var result []string
	if pattern == "*" {
		for k, v := range fakeConfig {
			result = append(result, k, v)
		}
	} else {
		if v, ok := fakeConfig[pattern]; ok {
			result = []string{pattern, v}
		}
	}

	if len(result) == 0 {
		return writeArray(w, []string{})
	}
	return writeArray(w, result)
}

func handleConfigSet(args []string, w io.Writer) error {
	// Accept the config set — this is critical for SSH key injection detection
	if len(args) >= 4 {
		fakeConfig[strings.ToLower(args[2])] = args[3]
	}
	return writeSimpleString(w, "OK")
}

func handleGet(args []string, w io.Writer) error {
	if len(args) < 2 {
		return writeError(w, "wrong number of arguments for 'get' command")
	}
	key := args[1]
	if v, ok := fakeValues[key]; ok {
		return writeBulkString(w, v)
	}
	return writeNullBulkString(w)
}

func handleSet(args []string, w io.Writer) error {
	if len(args) < 3 {
		return writeError(w, "wrong number of arguments for 'set' command")
	}
	return writeSimpleString(w, "OK")
}

func handleDel(args []string, w io.Writer) error {
	if len(args) < 2 {
		return writeError(w, "wrong number of arguments for 'del' command")
	}
	return writeInteger(w, int64(len(args)-1))
}

// handleKeys filters the decoy keyspace by the requested glob. It previously ignored the
// pattern and dumped all ten decoy keys for any argument, which exposed the whole bait set
// to a single targeted glob and told the caller the pattern was never evaluated.
//
// KEYS takes exactly one argument in real redis (arity 2), so a bare KEYS is an arity error
// rather than a listing.
func handleKeys(args []string, w io.Writer) error {
	if len(args) != 2 {
		return writeError(w, "wrong number of arguments for 'keys' command")
	}
	return writeArray(w, globFilter(fakeKeys, args[1]))
}

func handleDbsize(w io.Writer) error {
	return writeInteger(w, 47)
}

func handleSelect(w io.Writer) error {
	return writeSimpleString(w, "OK")
}

func handleClient(args []string, w io.Writer) error {
	if len(args) < 2 {
		return writeError(w, "wrong number of arguments for 'client' command")
	}
	sub := strings.ToUpper(args[1])
	switch sub {
	case "SETNAME":
		return writeSimpleString(w, "OK")
	case "GETNAME":
		return writeNullBulkString(w)
	case "LIST":
		return writeBulkString(w, "id=1 addr=127.0.0.1:6379 fd=8 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=26 qbuf-free=32742 argv-mem=10 obl=0 oll=0 omem=0 tot-mem=61466 events=r cmd=client user=default\n")
	case "ID":
		return writeInteger(w, 1)
	default:
		return writeError(w, fmt.Sprintf("unknown subcommand '%s'", sub))
	}
}

func handleSlaveof(w io.Writer) error {
	// Accept — this is for replication-based RCE detection
	return writeSimpleString(w, "OK")
}

func handleModuleLoad(w io.Writer) error {
	// Reject but log — this is for malicious module detection
	return writeError(w, "ERR Module loading is disabled")
}

func handleEval(w io.Writer) error {
	// Reject with NOSCRIPT — log the Lua script attempt
	return writeError(w, "NOSCRIPT No matching script")
}

func handleQuit(w io.Writer) error {
	return writeSimpleString(w, "OK")
}

func handleUnknown(cmd string, w io.Writer) error {
	return writeError(w, fmt.Sprintf("unknown command '%s'", cmd))
}
