package mysql

import (
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/joshrendek/threat.gg-agent/proto"
)

// threat_gg-cb0. The MySQL honeypot parsed the client's auth response and every query
// and then threw both away: persistSession hardcoded Password: "" and sess.queries was
// only ever counted for a log line. Production confirmed it -- 68 captured usernames and
// zero passwords, against 2,320 for mssql.
//
// These tests pin the two capture paths and the credential format.

// TestNativePasswordArtifact covers the format decision. A mysql_native_password reply is
// SHA1(pw) XOR SHA1(scramble || SHA1(SHA1(pw))), so the client's 20 bytes are worthless on
// their own -- cracking needs the server scramble that produced them, which the honeypot
// used to generate and discard. We emit both in hashcat's -m 11200 format so the artifact
// is self-describing (nobody mistakes it for a plaintext password) and directly usable.
func TestNativePasswordArtifact(t *testing.T) {
	scramble := make([]byte, 20)
	authData := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(i)
		authData[i] = byte(0xF0 + i%16)
	}

	got := nativePasswordArtifact(scramble, authData)
	want := "$mysqlna$" + hex.EncodeToString(scramble) + "*" + hex.EncodeToString(authData)
	if got != want {
		t.Errorf("artifact = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "$mysqlna$") {
		t.Error("artifact must carry the $mysqlna$ tag so it is never read as a plaintext password")
	}
}

func TestNativePasswordArtifactRejectsUnusableInput(t *testing.T) {
	full := make([]byte, 20)
	cases := []struct {
		name               string
		scramble, authData []byte
	}{
		// An empty auth response is an anonymous / no-password login, not a credential.
		{"empty auth response", full, nil},
		// Without the scramble the response cannot be cracked, so emitting it would imply
		// a usable artifact we do not have.
		{"missing scramble", nil, full},
		// Any length but 20 means the client negotiated a different auth plugin
		// (caching_sha2_password, etc.); the mysqlna format would be a lie.
		{"short auth response", full, make([]byte, 8)},
		{"long auth response", full, make([]byte, 32)},
		{"short scramble", make([]byte, 8), full},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nativePasswordArtifact(c.scramble, c.authData); got != "" {
				t.Errorf("artifact = %q, want empty", got)
			}
		})
	}
}

// TestSendHandshakeReturnsScramble pins the plumbing the artifact depends on: the scramble
// must escape sendHandshake, since it is generated per connection and is otherwise lost.
func TestSendHandshakeReturnsScramble(t *testing.T) {
	var first, second strings.Builder
	s1, err := sendHandshake(&first, 1)
	if err != nil {
		t.Fatalf("sendHandshake: %v", err)
	}
	if len(s1) != 20 {
		t.Fatalf("scramble length = %d, want 20", len(s1))
	}
	if !strings.Contains(first.String(), string(s1[:8])) {
		t.Error("the returned scramble is not the one written in the greeting")
	}

	s2, err := sendHandshake(&second, 2)
	if err != nil {
		t.Fatalf("sendHandshake: %v", err)
	}
	if string(s1) == string(s2) {
		t.Error("scramble must be per-connection; a fixed salt makes every capture correlatable")
	}
}

type recorder struct {
	mu      sync.Mutex
	logins  []*proto.MysqlRequest
	queries []*proto.QueryRequest
}

func (r *recorder) login(in *proto.MysqlRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logins = append(r.logins, in)
	return nil
}

func (r *recorder) query(in *proto.QueryRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, in)
	return nil
}

func withRecorder(t *testing.T) *recorder {
	t.Helper()
	rec := &recorder{}
	origLogin, origQuery := saveMysqlLogin, saveQuery
	saveMysqlLogin, saveQuery = rec.login, rec.query
	t.Cleanup(func() { saveMysqlLogin, saveQuery = origLogin, origQuery })
	return rec
}

func TestPersistSessionSavesPasswordAndQueries(t *testing.T) {
	rec := withRecorder(t)
	h := &honeypot{}

	scramble := make([]byte, 20)
	authData := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(i + 1)
		authData[i] = byte(i + 100)
	}

	sess := &session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000001",
		username: "root",
		database: "mysql",
		remoteIP: "203.0.113.7",
		scramble: scramble,
		authData: authData,
		queries: []string{
			"select @@version",
			"CREATE USER 'evil'@'%' IDENTIFIED BY 'hunter2'",
			"USE information_schema",
		},
	}
	h.persistSession(sess)

	if len(rec.logins) != 1 {
		t.Fatalf("logins saved = %d, want 1", len(rec.logins))
	}
	login := rec.logins[0]
	if login.Username != "root" || login.RemoteAddr != "203.0.113.7" || login.Guid != sess.guid {
		t.Errorf("login fields wrong: %+v", login)
	}
	want := "$mysqlna$" + hex.EncodeToString(scramble) + "*" + hex.EncodeToString(authData)
	if login.Password != want {
		t.Errorf("password = %q, want %q", login.Password, want)
	}

	if len(rec.queries) != 3 {
		t.Fatalf("queries saved = %d, want 3", len(rec.queries))
	}
	for i, q := range rec.queries {
		if q.CommandType != "mysql" {
			t.Errorf("query %d command_type = %q, want mysql (the server rejects anything else)", i, q.CommandType)
		}
		if q.Guid != sess.guid {
			t.Errorf("query %d guid = %q, want %q", i, q.Guid, sess.guid)
		}
	}
	// The credential-setting statement is the highest-value capture and used to be the
	// one guaranteed to be dropped, because the only telemetry path skipped it.
	if got := rec.queries[1].Query; got != "CREATE USER 'evil'@'%' IDENTIFIED BY 'hunter2'" {
		t.Errorf("credential statement not captured verbatim, got %q", got)
	}
}

// TestPersistSessionSkipsQueriesWhenLoginFails keeps command rows from being orphaned:
// the server derives the attacker row from the login, so a command saved without one
// would reference a guid that never materializes.
func TestPersistSessionSkipsQueriesWhenLoginFails(t *testing.T) {
	rec := withRecorder(t)
	origLogin := saveMysqlLogin
	saveMysqlLogin = func(*proto.MysqlRequest) error { return errors.New("grpc down") }
	t.Cleanup(func() { saveMysqlLogin = origLogin })

	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000002",
		username: "root",
		remoteIP: "203.0.113.8",
		queries:  []string{"select 1"},
	})

	if len(rec.queries) != 0 {
		t.Errorf("queries saved = %d, want 0 when the login failed", len(rec.queries))
	}
}

func TestPersistSessionSkipsEmptySessions(t *testing.T) {
	rec := withRecorder(t)
	h := &honeypot{}
	h.persistSession(&session{guid: "3f2a1b4c-0000-4000-8000-000000000003", remoteIP: "203.0.113.9"})

	if len(rec.logins) != 0 || len(rec.queries) != 0 {
		t.Errorf("bare connection persisted: %d logins, %d queries", len(rec.logins), len(rec.queries))
	}
}

// A no-password login must still record the session; it just carries no credential.
func TestPersistSessionAnonymousLoginHasEmptyPassword(t *testing.T) {
	rec := withRecorder(t)
	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000004",
		username: "root",
		remoteIP: "203.0.113.10",
		scramble: make([]byte, 20),
	})

	if len(rec.logins) != 1 {
		t.Fatalf("logins saved = %d, want 1", len(rec.logins))
	}
	if rec.logins[0].Password != "" {
		t.Errorf("password = %q, want empty for an anonymous login", rec.logins[0].Password)
	}
}
