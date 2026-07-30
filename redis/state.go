package redis

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func updateSessionState(args []string, sess *session) {
	if len(args) == 0 {
		return
	}

	switch strings.ToUpper(args[0]) {
	case "SAVE", "BGSAVE":
		sess.lastSaveUnix = time.Now().Unix()
		sess.lastBgsaveStatus = "ok"
	case "SLAVEOF", "REPLICAOF":
		if len(args) >= 3 && strings.EqualFold(args[1], "NO") && strings.EqualFold(args[2], "ONE") {
			sess.role = "master"
			sess.replicationUp = false
			sess.masterHost = ""
			sess.masterPort = ""
			return
		}
		if len(args) >= 3 {
			sess.role = "slave"
			sess.masterHost = args[1]
			sess.masterPort = args[2]
			sess.replicationUp = true
			sess.replicaSyncDone = true
		}
	}
}

func statefulResponse(args []string, w io.Writer, sess *session) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}

	cmd := strings.ToUpper(args[0])
	switch cmd {
	case "INFO":
		if infoNeedsSession(args[1:]) {
			return true, writeBulkString(w, buildInfoResponse(args[1:], sess))
		}
		return false, nil
	case "ROLE":
		// ROLE reports the same replication role INFO replication does, so it has to be
		// built from the session for the same reason: SLAVEOF flips it mid-connection and
		// a frozen row would contradict the INFO answer one request later.
		return true, writeRole(w, sess)
	case "TIME":
		return true, writeTime(w)
	case "LASTSAVE":
		lastSave := sess.lastSaveUnix
		if lastSave == 0 {
			lastSave = time.Now().Add(-15 * time.Minute).Unix()
		}
		return true, writeInteger(w, lastSave)
	case "SCAN":
		return true, writeScanResult(w, scanKeys(args))
	case "MODULE":
		if len(args) >= 3 && strings.EqualFold(args[1], "LOAD") && sess.replicaSyncDone && strings.HasSuffix(strings.ToLower(args[2]), "/exp.so") {
			sess.moduleLoaded = true
			return true, writeSimpleString(w, "OK")
		}
	case "SYSTEM.EXEC":
		if sess.moduleLoaded {
			// The observed payloads either background the command or remove the staged
			// module, both of which produce an empty stdout result.
			return true, writeBulkString(w, "")
		}
	}

	return false, nil
}

// infoNeedsSession reports whether an INFO request renders any section that embeds live
// connection state, in which case it must be answered here, ahead of the command_responses
// lookup, because a frozen row would contradict the session history.
//
// Bare INFO and INFO default/all/everything qualify: they all include the Replication
// section, whose role flips to slave after SLAVEOF. Requests naming only static sections
// (INFO stats, INFO cpu, ...) fall through so they stay admin-tunable.
func infoNeedsSession(requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	for _, r := range requested {
		switch section := strings.ToLower(r); section {
		case "default", "all", "everything":
			return true
		default:
			if infoStatefulSections[section] {
				return true
			}
		}
	}
	return false
}

// replOffset is the replication stream offset this persona reports. ROLE and INFO
// replication both read it so the two can never quote different offsets.
const replOffset = 18432

func buildReplicationInfo(sess *session) string {
	role := sess.role
	if role == "" {
		role = "master"
	}

	var b strings.Builder
	b.WriteString("# Replication\r\n")
	fmt.Fprintf(&b, "role:%s\r\n", role)
	if role == "slave" {
		fmt.Fprintf(&b, "master_host:%s\r\n", sess.masterHost)
		fmt.Fprintf(&b, "master_port:%s\r\n", sess.masterPort)
		if sess.replicationUp {
			b.WriteString("master_link_status:up\r\n")
			b.WriteString("master_sync_in_progress:0\r\n")
			b.WriteString("master_last_io_seconds_ago:0\r\n")
		} else {
			b.WriteString("master_link_status:down\r\n")
		}
		fmt.Fprintf(&b, "slave_repl_offset:%d\r\n", replOffset)
	} else {
		b.WriteString("connected_slaves:0\r\n")
		fmt.Fprintf(&b, "master_repl_offset:%d\r\n", replOffset)
	}
	b.WriteString("master_replid:8d5a7b3c1e9f02468ace13579bdf2468ace13579\r\n")
	b.WriteString("master_replid2:0000000000000000000000000000000000000000\r\n")
	return b.String()
}

// writeRole answers ROLE, which real redis shapes differently per role: three elements for
// a master (role, offset, replica list) and five for a replica (role, master host, master
// port, link state, offset). Both are assembled through the RESP writers, so no length
// prefix is written by hand.
func writeRole(w io.Writer, sess *session) error {
	if sess.role != "slave" {
		if _, err := fmt.Fprint(w, "*3\r\n"); err != nil {
			return err
		}
		if err := writeBulkString(w, "master"); err != nil {
			return err
		}
		if err := writeInteger(w, replOffset); err != nil {
			return err
		}
		return writeArray(w, nil) // no connected replicas
	}

	// The link state mirrors master_link_status in the Replication section.
	link := "connect"
	if sess.replicationUp {
		link = "connected"
	}
	if _, err := fmt.Fprint(w, "*5\r\n"); err != nil {
		return err
	}
	if err := writeBulkString(w, "slave"); err != nil {
		return err
	}
	if err := writeBulkString(w, sess.masterHost); err != nil {
		return err
	}
	// SLAVEOF's port argument is attacker-supplied text; ROLE reports it as an integer, so
	// anything unparseable becomes 0 rather than corrupting the frame.
	port, _ := strconv.ParseInt(sess.masterPort, 10, 64)
	if err := writeInteger(w, port); err != nil {
		return err
	}
	if err := writeBulkString(w, link); err != nil {
		return err
	}
	return writeInteger(w, replOffset)
}

// writeTime answers TIME, which tracks the wall clock and so can never be a frozen row.
// redis returns both fields as bulk strings and does not zero-pad the microseconds.
func writeTime(w io.Writer) error {
	now := time.Now()
	if _, err := fmt.Fprint(w, "*2\r\n"); err != nil {
		return err
	}
	if err := writeBulkString(w, strconv.FormatInt(now.Unix(), 10)); err != nil {
		return err
	}
	return writeBulkString(w, strconv.Itoa(now.Nanosecond()/1000))
}

func buildPersistenceInfo(sess *session) string {
	lastSave := sess.lastSaveUnix
	if lastSave == 0 {
		lastSave = time.Now().Add(-15 * time.Minute).Unix()
	}
	status := sess.lastBgsaveStatus
	if status == "" {
		status = "ok"
	}

	return fmt.Sprintf("# Persistence\r\nloading:0\r\nrdb_changes_since_last_save:0\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:%d\r\nrdb_last_bgsave_status:%s\r\nrdb_last_bgsave_time_sec:0\r\naof_enabled:0\r\n", lastSave, status)
}

func scanKeys(args []string) []string {
	pattern := "*"
	for i := 2; i+1 < len(args); i++ {
		if strings.EqualFold(args[i], "MATCH") {
			pattern = args[i+1]
			break
		}
	}
	// Uses redis's own glob semantics rather than path.Match, so SCAN MATCH and KEYS agree
	// with each other and with a real redis. See glob.go.
	return globFilter(fakeKeys, pattern)
}

func writeScanResult(w io.Writer, keys []string) error {
	if _, err := fmt.Fprint(w, "*2\r\n$1\r\n0\r\n"); err != nil {
		return err
	}
	return writeArray(w, keys)
}
