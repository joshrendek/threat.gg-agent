package redis

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// infoBody issues an INFO request through the same two-stage path a connection takes —
// statefulResponse first, then the local handler — and returns the decoded bulk string.
// The command_responses lookup sits between the two and is not exercised here.
func infoBody(t *testing.T, sess *session, args ...string) string {
	t.Helper()
	var buf bytes.Buffer
	if handled, err := statefulResponse(args, &buf, sess); handled {
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	} else if err := handleInfo(args, &buf, sess); err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	node := mustDecodeFrame(t, buf.Bytes())
	if node.typ != '$' {
		t.Fatalf("%v answered type %q, want a bulk string", args, node.typ)
	}
	return node.str
}

func infoHeaders(body string) []string {
	return regexp.MustCompile(`(?m)^# (\w+)`).FindAllString(body, -1)
}

// TestInfoImplementsEverySection is the regression for the reported defect: buildInfoResponse
// only knew server/clients/memory/keyspace, so INFO stats, cpu, commandstats, latencystats,
// errorstats and cluster all returned an empty bulk string. No real redis does that.
func TestInfoImplementsEverySection(t *testing.T) {
	sections := map[string]string{
		"server":       "# Server",
		"clients":      "# Clients",
		"memory":       "# Memory",
		"persistence":  "# Persistence",
		"stats":        "# Stats",
		"replication":  "# Replication",
		"cpu":          "# CPU",
		"modules":      "# Modules",
		"commandstats": "# Commandstats",
		"errorstats":   "# Errorstats",
		"latencystats": "# Latencystats",
		"cluster":      "# Cluster",
		"keyspace":     "# Keyspace",
	}
	for section, header := range sections {
		t.Run(section, func(t *testing.T) {
			body := infoBody(t, &session{}, "INFO", section)
			if body == "" {
				t.Fatalf("INFO %s returned an empty bulk string", section)
			}
			if !strings.HasPrefix(body, header+"\r\n") {
				t.Fatalf("INFO %s should start with %q, got %q", section, header, body)
			}
			// Section names are case-insensitive in real redis.
			if upper := infoBody(t, &session{}, "INFO", strings.ToUpper(section)); upper != body {
				t.Fatalf("INFO %s and INFO %s disagree", section, strings.ToUpper(section))
			}
		})
	}
}

// TestInfoUnknownSectionIsEmpty: an empty reply is correct for a section that does not
// exist, which is exactly why the old behaviour was a tell — it made every unimplemented
// section indistinguishable from a typo.
func TestInfoUnknownSectionIsEmpty(t *testing.T) {
	for _, section := range []string{"bogus", "BOGUS", "sentinel", ""} {
		if body := infoBody(t, &session{}, "INFO", section); body != "" {
			t.Fatalf("INFO %q returned %q, want an empty bulk string", section, body)
		}
	}
}

// TestInfoSectionFraming pins the layout rule: sections are separated by a blank line and
// none is appended after the last one, so a single-section INFO ends on its final field.
// Verified against redis 7.2.4.
func TestInfoSectionFraming(t *testing.T) {
	single := infoBody(t, &session{}, "INFO", "errorstats")
	if strings.HasSuffix(single, "\r\n\r\n") {
		t.Fatalf("single-section INFO must not end with a blank line: %q", single)
	}
	if single != "# Errorstats\r\nerrorstat_ERR:count=37\r\n" {
		t.Fatalf("INFO errorstats = %q", single)
	}

	multi := infoBody(t, &session{}, "INFO", "server", "clients")
	if strings.HasSuffix(multi, "\r\n\r\n") {
		t.Fatalf("multi-section INFO must not end with a blank line: %q", multi[len(multi)-40:])
	}
	if !strings.Contains(multi, "lru_clock:14892741\r\n\r\n# Clients\r\n") {
		t.Fatalf("sections must be separated by exactly one blank line: %q", multi)
	}

	// Every section that stands alone must be framed the same way, including the two the
	// stateful path answers. Two of our own INFO answers framed differently from each
	// other is detectable with two requests and no external reference.
	for _, s := range infoSectionOrder {
		body := infoBody(t, &session{}, "INFO", s.name)
		if strings.HasSuffix(body, "\r\n\r\n") {
			t.Fatalf("INFO %s ends with a blank line, unlike the other sections", s.name)
		}
	}
}

// TestInfoSectionOrderIsCanonical: real redis emits sections in its own fixed order no
// matter what order the caller listed them in.
func TestInfoSectionOrderIsCanonical(t *testing.T) {
	forward := infoHeaders(infoBody(t, &session{}, "INFO", "server", "clients"))
	reverse := infoHeaders(infoBody(t, &session{}, "INFO", "clients", "server"))
	want := []string{"# Server", "# Clients"}
	for _, got := range [][]string{forward, reverse} {
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestInfoDefaultAndAllSectionSets pins which sections each form returns, matching 7.2.4:
// commandstats and latencystats appear only for INFO all / INFO everything.
func TestInfoDefaultAndAllSectionSets(t *testing.T) {
	defaultSet := []string{
		"# Server", "# Clients", "# Memory", "# Persistence", "# Stats",
		"# Replication", "# CPU", "# Modules", "# Errorstats", "# Cluster", "# Keyspace",
	}
	allSet := []string{
		"# Server", "# Clients", "# Memory", "# Persistence", "# Stats",
		"# Replication", "# CPU", "# Modules", "# Commandstats", "# Errorstats",
		"# Latencystats", "# Cluster", "# Keyspace",
	}

	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"INFO"}, defaultSet},
		{[]string{"INFO", "default"}, defaultSet},
		{[]string{"INFO", "all"}, allSet},
		{[]string{"INFO", "everything"}, allSet},
	} {
		got := infoHeaders(infoBody(t, &session{}, tc.args...))
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("%v sections:\n got %v\nwant %v", tc.args, got, tc.want)
		}
	}
}

// TestInfoMatchesSeededRows is the guard against the binary and the server's
// seed_command_responses_redis_deepen.sql drifting apart. Those rows are looked up before
// this fallback, so if someone edits the numbers on one side only, two callers get two
// different answers to the same question depending on whether the server was reachable.
//
// The seed rows carry one extra trailing blank line, a convention copied from the old
// buildInfoResponse. Real redis does not emit it and neither do INFO replication and INFO
// persistence, so the binary drops it and the rows should be retired; everything else must
// match byte for byte.
func TestInfoMatchesSeededRows(t *testing.T) {
	for section, seeded := range seededInfoSectionBodies {
		t.Run(section, func(t *testing.T) {
			got := infoBody(t, &session{}, "INFO", section)
			if got == seeded {
				return
			}
			if got+"\r\n" == seeded {
				return // the documented trailing-blank-line difference
			}
			t.Fatalf("INFO %s disagrees with the seeded row beyond the trailing blank line:\n binary %q\n seed   %q",
				section, got, seeded)
		})
	}
}

// seededInfoSectionBodies is transcribed from seed_command_responses_redis_deepen.sql in the
// server repo (generated from the file, not hand-typed). Each value is the seeded bulk body
// minus nothing: it still carries the trailing blank line the rows include.
var seededInfoSectionBodies = map[string]string{
	// stats: 700 bytes in the seed row, including its trailing blank line.
	"stats": "# Stats\r\n" +
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
		"total_writes_processed:1387421\r\n" +
		"\r\n",
	// cpu: 206 bytes in the seed row, including its trailing blank line.
	"cpu": "# CPU\r\n" +
		"used_cpu_sys:1284.472103\r\n" +
		"used_cpu_user:2941.118736\r\n" +
		"used_cpu_sys_children:12.884219\r\n" +
		"used_cpu_user_children:41.229183\r\n" +
		"used_cpu_sys_main_thread:1281.930447\r\n" +
		"used_cpu_user_main_thread:2938.442110\r\n" +
		"\r\n",
	// commandstats: 734 bytes in the seed row, including its trailing blank line.
	"commandstats": "# Commandstats\r\n" +
		"cmdstat_get:calls=918273,usec=1284729,usec_per_call=1.40,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_set:calls=412884,usec=942018,usec_per_call=2.28,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_del:calls=12048,usec=15927,usec_per_call=1.32,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_expire:calls=41029,usec=48213,usec_per_call=1.18,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_ping:calls=9241,usec=4712,usec_per_call=0.51,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_info:calls=1842,usec=112947,usec_per_call=61.32,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_config|get:calls=204,usec=9182,usec_per_call=45.01,rejected_calls=0,failed_calls=0\r\n" +
		"cmdstat_client|setname:calls=88,usec=291,usec_per_call=3.31,rejected_calls=0,failed_calls=0\r\n" +
		"\r\n",
	// latencystats: 335 bytes in the seed row, including its trailing blank line.
	"latencystats": "# Latencystats\r\n" +
		"latency_percentiles_usec_get:p50=1.003,p99=2.007,p99.9=4.015\r\n" +
		"latency_percentiles_usec_set:p50=2.007,p99=4.015,p99.9=8.031\r\n" +
		"latency_percentiles_usec_del:p50=1.003,p99=3.007,p99.9=6.015\r\n" +
		"latency_percentiles_usec_ping:p50=0.001,p99=1.003,p99.9=1.003\r\n" +
		"latency_percentiles_usec_info:p50=58.111,p99=105.983,p99.9=131.071\r\n" +
		"\r\n",
	// errorstats: 40 bytes in the seed row, including its trailing blank line.
	"errorstats": "# Errorstats\r\n" +
		"errorstat_ERR:count=37\r\n" +
		"\r\n",
	// cluster: 32 bytes in the seed row, including its trailing blank line.
	"cluster": "# Cluster\r\n" +
		"cluster_enabled:0\r\n" +
		"\r\n",
}

// TestInfoRoleStaysConsistentAfterSlaveof is the constraint that motivated routing the
// multi-section INFO forms through statefulResponse: after SLAVEOF, every answer that
// mentions the replication role has to say the same thing. Disagreement between two of our
// own replies is detectable in two requests with no external reference.
func TestInfoRoleStaysConsistentAfterSlaveof(t *testing.T) {
	sess := &session{role: "master"}

	for _, args := range [][]string{{"INFO"}, {"INFO", "all"}, {"INFO", "everything"}, {"INFO", "replication"}} {
		if body := infoBody(t, sess, args...); !strings.Contains(body, "role:master\r\n") {
			t.Fatalf("%v does not report role:master before SLAVEOF", args)
		}
	}
	var roleBuf bytes.Buffer
	if handled, err := statefulResponse([]string{"ROLE"}, &roleBuf, sess); !handled || err != nil {
		t.Fatalf("ROLE handled=%v err=%v", handled, err)
	}
	if got := mustDecodeFrame(t, roleBuf.Bytes()); got.items[0].str != "master" {
		t.Fatalf("ROLE says %q before SLAVEOF", got.items[0].str)
	}

	updateSessionState([]string{"SLAVEOF", "194.238.26.34", "6666"}, sess)

	for _, args := range [][]string{{"INFO"}, {"INFO", "all"}, {"INFO", "everything"}, {"INFO", "replication"}} {
		body := infoBody(t, sess, args...)
		for _, want := range []string{"role:slave\r\n", "master_host:194.238.26.34\r\n", "master_port:6666\r\n"} {
			if !strings.Contains(body, want) {
				t.Fatalf("%v is missing %q after SLAVEOF; a frozen row would look like this", args, want)
			}
		}
		if strings.Contains(body, "role:master") {
			t.Fatalf("%v still reports role:master after SLAVEOF", args)
		}
	}

	roleBuf.Reset()
	if handled, err := statefulResponse([]string{"ROLE"}, &roleBuf, sess); !handled || err != nil {
		t.Fatalf("ROLE handled=%v err=%v", handled, err)
	}
	role := mustDecodeFrame(t, roleBuf.Bytes())
	if role.String() != `["slave" "194.238.26.34" 6666 "connected" `+strconv.Itoa(replOffset)+`]` {
		t.Fatalf("ROLE after SLAVEOF = %s", role)
	}
	// ROLE and INFO replication must quote the same replication offset.
	if !strings.Contains(infoBody(t, sess, "INFO", "replication"), "slave_repl_offset:"+strconv.Itoa(replOffset)) {
		t.Fatal("INFO replication and ROLE disagree on the replication offset")
	}
}

// TestStatefulRoutingCoversStateBearingInfo: any INFO form that renders a state-bearing
// section must be answered before the command_responses lookup, and forms that render only
// static sections must fall through so they stay admin-tunable.
func TestStatefulRoutingCoversStateBearingInfo(t *testing.T) {
	intercepted := [][]string{
		{"INFO"},
		{"INFO", "default"},
		{"INFO", "all"},
		{"INFO", "everything"},
		{"INFO", "replication"},
		{"INFO", "persistence"},
		{"INFO", "server", "replication"}, // a static section alongside a stateful one
		{"ROLE"},
		{"TIME"},
	}
	for _, args := range intercepted {
		var buf bytes.Buffer
		handled, err := statefulResponse(args, &buf, &session{})
		if !handled || err != nil {
			t.Fatalf("%v must be answered from session state: handled=%v err=%v", args, handled, err)
		}
		mustDecodeFrame(t, buf.Bytes())
	}

	fallThrough := [][]string{
		{"INFO", "stats"},
		{"INFO", "cpu"},
		{"INFO", "commandstats"},
		{"INFO", "latencystats"},
		{"INFO", "errorstats"},
		{"INFO", "cluster"},
		{"INFO", "server"},
		{"INFO", "memory"},
		{"INFO", "bogus"},
	}
	for _, args := range fallThrough {
		var buf bytes.Buffer
		handled, err := statefulResponse(args, &buf, &session{})
		if handled || err != nil || buf.Len() != 0 {
			t.Fatalf("%v holds no session state and must stay admin-tunable: handled=%v wrote=%q", args, handled, buf.String())
		}
	}
}

func TestRoleMasterFrame(t *testing.T) {
	var buf bytes.Buffer
	if handled, err := statefulResponse([]string{"ROLE"}, &buf, &session{role: "master"}); !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	got := mustDecodeFrame(t, buf.Bytes())
	if got.String() != `["master" `+strconv.Itoa(replOffset)+` []]` {
		t.Fatalf("ROLE = %s, want the three-element master shape", got)
	}
}

// TestRoleHandlesUnparseablePort: SLAVEOF's port is attacker-supplied text but ROLE reports
// it as an integer, so it must not be able to corrupt the frame.
func TestRoleHandlesUnparseablePort(t *testing.T) {
	sess := &session{role: "slave", masterHost: "h", masterPort: "not-a-port\r\n:9999", replicationUp: true}
	var buf bytes.Buffer
	if handled, err := statefulResponse([]string{"ROLE"}, &buf, sess); !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	got := mustDecodeFrame(t, buf.Bytes())
	if got.items[2].typ != ':' || got.items[2].num != 0 {
		t.Fatalf("unparseable port became %v, want the integer 0", got.items[2])
	}
}

func TestTimeFrame(t *testing.T) {
	var buf bytes.Buffer
	if handled, err := statefulResponse([]string{"TIME"}, &buf, &session{}); !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	got := mustDecodeFrame(t, buf.Bytes())
	if len(got.items) != 2 || got.items[0].typ != '$' || got.items[1].typ != '$' {
		t.Fatalf("TIME = %s, want two bulk strings", got)
	}
	secs, err := strconv.ParseInt(got.items[0].str, 10, 64)
	if err != nil {
		t.Fatalf("TIME seconds %q is not an integer", got.items[0].str)
	}
	if delta := time.Since(time.Unix(secs, 0)); delta > time.Minute || delta < -time.Minute {
		t.Fatalf("TIME reports %v, which is not the current clock", time.Unix(secs, 0))
	}
	micros, err := strconv.Atoi(got.items[1].str)
	if err != nil || micros < 0 || micros > 999999 {
		t.Fatalf("TIME microseconds %q is out of range", got.items[1].str)
	}
}

// TestInfoRepliesAreWellFormedFrames sweeps the INFO surface for framing defects, including
// argument shapes designed to break a hand-computed length prefix.
func TestInfoRepliesAreWellFormedFrames(t *testing.T) {
	sess := &session{role: "slave", masterHost: "10.0.0.1", masterPort: "6379", replicationUp: true}
	vectors := [][]string{
		{"INFO"}, {"INFO", "all"}, {"INFO", "everything"}, {"INFO", "default"},
		{"INFO", "stats"}, {"INFO", "replication"}, {"INFO", "persistence"},
		{"INFO", "server", "clients", "memory"},
		{"INFO", "bogus"}, {"INFO", ""}, {"INFO", "stats", "stats", "stats"},
		{"INFO", strings.Repeat("x", 70000)},
		{"INFO", "all", "bogus"},
	}
	for _, args := range vectors {
		name := strings.Join(args, " ")
		if len(name) > 50 {
			name = name[:50] + "..."
		}
		t.Run(name, func(t *testing.T) {
			body := infoBody(t, sess, args...)
			// Nothing the caller sent may be reflected into the reply.
			if strings.Contains(body, "xxxxxxxxxx") || strings.Contains(body, "bogus") {
				t.Fatalf("INFO reflected caller input: %q", body)
			}
		})
	}
}
