package redis

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPhoenixReplicationWorkflowAdvancesWithoutPolling(t *testing.T) {
	sess := &session{
		role:             "master",
		lastSaveUnix:     time.Now().Add(-time.Hour).Unix(),
		lastBgsaveStatus: "ok",
	}

	updateSessionState([]string{"BGSAVE"}, sess)
	var persistence bytes.Buffer
	handled, err := statefulResponse([]string{"INFO", "persistence"}, &persistence, sess)
	if !handled || err != nil {
		t.Fatalf("INFO persistence handled=%v err=%v", handled, err)
	}
	for _, field := range []string{"rdb_bgsave_in_progress:0", "rdb_last_bgsave_status:ok"} {
		if !strings.Contains(persistence.String(), field) {
			t.Fatalf("INFO persistence missing %q: %q", field, persistence.String())
		}
	}

	updateSessionState([]string{"SLAVEOF", "194.238.26.34", "6666"}, sess)
	var replication bytes.Buffer
	handled, err = statefulResponse([]string{"INFO", "replication"}, &replication, sess)
	if !handled || err != nil {
		t.Fatalf("INFO replication handled=%v err=%v", handled, err)
	}
	for _, field := range []string{"role:slave", "master_host:194.238.26.34", "master_link_status:up", "master_sync_in_progress:0"} {
		if !strings.Contains(replication.String(), field) {
			t.Fatalf("INFO replication missing %q: %q", field, replication.String())
		}
	}

	updateSessionState([]string{"SLAVEOF", "NO", "ONE"}, sess)
	var module bytes.Buffer
	handled, err = statefulResponse([]string{"MODULE", "LOAD", "/dev/shm/exp.so", "wallet", "worker"}, &module, sess)
	if !handled || err != nil || module.String() != "+OK\r\n" {
		t.Fatalf("MODULE LOAD handled=%v err=%v response=%q", handled, err, module.String())
	}

	var systemExec bytes.Buffer
	handled, err = statefulResponse([]string{"system.exec", "rm -f /tmp/exp.so"}, &systemExec, sess)
	if !handled || err != nil || systemExec.String() != "$0\r\n\r\n" {
		t.Fatalf("system.exec handled=%v err=%v response=%q", handled, err, systemExec.String())
	}
}

func TestLastSaveAndScanAreRESPValid(t *testing.T) {
	sess := &session{lastSaveUnix: 1784567890}

	var lastSave bytes.Buffer
	handled, err := statefulResponse([]string{"LASTSAVE"}, &lastSave, sess)
	if !handled || err != nil || lastSave.String() != ":1784567890\r\n" {
		t.Fatalf("LASTSAVE handled=%v err=%v response=%q", handled, err, lastSave.String())
	}

	var scan bytes.Buffer
	handled, err = statefulResponse([]string{"SCAN", "0", "MATCH", "*token*", "COUNT", "100"}, &scan, sess)
	if !handled || err != nil {
		t.Fatalf("SCAN handled=%v err=%v", handled, err)
	}
	if !strings.HasPrefix(scan.String(), "*2\r\n$1\r\n0\r\n*") || !strings.Contains(scan.String(), "user:1:token") {
		t.Fatalf("invalid SCAN response %q", scan.String())
	}
}

func TestModuleLoadStillFailsBeforeReplication(t *testing.T) {
	var response bytes.Buffer
	handled, err := statefulResponse([]string{"MODULE", "LOAD", "/tmp/exp.so"}, &response, &session{})
	if handled || err != nil || response.Len() != 0 {
		t.Fatalf("handled=%v err=%v response=%q", handled, err, response.String())
	}
}
