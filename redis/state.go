package redis

import (
	"fmt"
	"io"
	"path"
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
		if len(args) < 2 {
			return false, nil
		}
		switch strings.ToLower(args[1]) {
		case "replication":
			return true, writeBulkString(w, buildReplicationInfo(sess))
		case "persistence":
			return true, writeBulkString(w, buildPersistenceInfo(sess))
		default:
			return false, nil
		}
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
		b.WriteString("slave_repl_offset:18432\r\n")
	} else {
		b.WriteString("connected_slaves:0\r\n")
		b.WriteString("master_repl_offset:18432\r\n")
	}
	b.WriteString("master_replid:8d5a7b3c1e9f02468ace13579bdf2468ace13579\r\n")
	b.WriteString("master_replid2:0000000000000000000000000000000000000000\r\n")
	return b.String()
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

	keys := make([]string, 0, len(fakeKeys))
	for _, key := range fakeKeys {
		matched, err := path.Match(pattern, key)
		if err == nil && matched {
			keys = append(keys, key)
		}
	}
	return keys
}

func writeScanResult(w io.Writer, keys []string) error {
	if _, err := fmt.Fprint(w, "*2\r\n$1\r\n0\r\n"); err != nil {
		return err
	}
	return writeArray(w, keys)
}
