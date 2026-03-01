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
	"session:admin":         `{"user_id":1,"role":"admin","token":"eyJhbGciOiJIUzI1NiJ9.fake"}`,
	"user:1:token":          "tok_8f3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c",
	"api_key:prod":          "rk_live_HONEYPOT_FAKE_KEY_0000000",
	"config:database_url":   "postgres://admin:s3cret@10.0.1.5:5432/production",
	"cache:credentials":     `{"aws_key":"AKIA...FAKE","aws_secret":"wJalr...FAKE"}`,
	"backup:latest":         "/var/backups/db-2026-03-01.sql.gz",
	"secret:jwt_signing_key": "super-secret-jwt-key-do-not-share-2026",
	"user:1:password_hash":  "$2a$10$fakehashfakehashfakehashfakehashfakehash",
	"stripe:sk_live_key":    "rk_live_HONEYPOT_FAKE_KEY_1111111",
	"aws:access_key_id":     "AKIAFAKEACCESSKEYID00",
}

// Fake config values
var fakeConfig = map[string]string{
	"dir":                "/var/lib/redis",
	"dbfilename":         "dump.rdb",
	"save":               "3600 1 300 100 60 10000",
	"maxmemory":          "268435456",
	"maxmemory-policy":   "allkeys-lru",
	"requirepass":        "",
	"bind":               "0.0.0.0",
	"port":               "6379",
	"loglevel":           "notice",
	"databases":          "16",
	"tcp-keepalive":      "300",
	"timeout":            "0",
	"protected-mode":     "no",
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

func handleInfo(args []string, w io.Writer) error {
	section := "all"
	if len(args) > 1 {
		section = strings.ToLower(args[1])
	}

	info := buildInfoResponse(section)
	return writeBulkString(w, info)
}

func buildInfoResponse(section string) string {
	var sb strings.Builder

	if section == "all" || section == "server" {
		sb.WriteString("# Server\r\n")
		sb.WriteString("redis_version:7.2.4\r\n")
		sb.WriteString("redis_git_sha1:00000000\r\n")
		sb.WriteString("redis_git_dirty:0\r\n")
		sb.WriteString("redis_build_id:a1b2c3d4e5f6a7b8\r\n")
		sb.WriteString("redis_mode:standalone\r\n")
		sb.WriteString("os:Linux 5.15.0-91-generic x86_64\r\n")
		sb.WriteString("arch_bits:64\r\n")
		sb.WriteString("tcp_port:6379\r\n")
		sb.WriteString("uptime_in_seconds:1847293\r\n")
		sb.WriteString("uptime_in_days:21\r\n")
		sb.WriteString("hz:10\r\n")
		sb.WriteString("configured_hz:10\r\n")
		sb.WriteString("lru_clock:14892741\r\n")
		sb.WriteString("\r\n")
	}

	if section == "all" || section == "clients" {
		sb.WriteString("# Clients\r\n")
		sb.WriteString("connected_clients:3\r\n")
		sb.WriteString("cluster_connections:0\r\n")
		sb.WriteString("maxclients:10000\r\n")
		sb.WriteString("blocked_clients:0\r\n")
		sb.WriteString("\r\n")
	}

	if section == "all" || section == "memory" {
		sb.WriteString("# Memory\r\n")
		sb.WriteString("used_memory:2147483648\r\n")
		sb.WriteString("used_memory_human:2.00G\r\n")
		sb.WriteString("used_memory_rss:2415919104\r\n")
		sb.WriteString("used_memory_rss_human:2.25G\r\n")
		sb.WriteString("used_memory_peak:2684354560\r\n")
		sb.WriteString("used_memory_peak_human:2.50G\r\n")
		sb.WriteString("maxmemory:268435456\r\n")
		sb.WriteString("maxmemory_human:256.00M\r\n")
		sb.WriteString("maxmemory_policy:allkeys-lru\r\n")
		sb.WriteString("\r\n")
	}

	if section == "all" || section == "keyspace" {
		sb.WriteString("# Keyspace\r\n")
		sb.WriteString("db0:keys=47,expires=12,avg_ttl=3612451\r\n")
		sb.WriteString("\r\n")
	}

	return sb.String()
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

func handleKeys(args []string, w io.Writer) error {
	return writeArray(w, fakeKeys)
}

func handleDbsize(w io.Writer) error {
	return writeInteger(w, 47)
}

func handleSelect(w io.Writer) error {
	return writeSimpleString(w, "OK")
}

func handleCommand(args []string, w io.Writer) error {
	if len(args) > 1 && strings.ToUpper(args[1]) == "DOCS" {
		return writeArray(w, []string{})
	}
	// Return count of supported commands
	return writeInteger(w, 20)
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
