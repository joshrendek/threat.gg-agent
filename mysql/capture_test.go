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

	got := nativePasswordArtifact(scramble, authData, "")
	want := "$mysqlna$" + hex.EncodeToString(scramble) + "*" + hex.EncodeToString(authData)
	if got != want {
		t.Errorf("artifact = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "$mysqlna$") {
		t.Error("artifact must carry the $mysqlna$ tag so it is never read as a plaintext password")
	}
}

// TestNativePasswordArtifactRejectsUnusableInput pins the cases where we hold half an
// exchange or something that is not one at all, and must say so by storing nothing rather
// than inventing a credential.
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
			if got := nativePasswordArtifact(c.scramble, c.authData, ""); got != "" {
				t.Errorf("artifact = %q, want empty", got)
			}
		})
	}
}

// TestNativePasswordArtifactRejectsOtherPlugins is the reason the artifact takes the
// negotiated plugin rather than trusting the 20-byte length. mysql_clear_password sends
// the password itself: a 20-character one would otherwise be hex-encoded under a
// $mysqlna$ label, mislabelling a plaintext as a digest and burying it from anyone
// reading the column.
func TestNativePasswordArtifactRejectsOtherPlugins(t *testing.T) {
	scramble := make([]byte, 20)
	clearPassword := []byte("correcthorsebattery1") // exactly 20 bytes
	for i := range scramble {
		scramble[i] = byte(i)
	}

	for _, plugin := range []string{"mysql_clear_password", "caching_sha2_password", "sha256_password"} {
		t.Run(plugin, func(t *testing.T) {
			if got := nativePasswordArtifact(scramble, clearPassword, plugin); got != "" {
				t.Errorf("artifact = %q, want empty for plugin %q", got, plugin)
			}
		})
	}

	// The plugin we actually advertise, and a client that names none, both stand.
	for _, plugin := range []string{"", authPluginName} {
		if got := nativePasswordArtifact(scramble, clearPassword, plugin); got == "" {
			t.Errorf("artifact empty for plugin %q, want the mysqlna form", plugin)
		}
	}
}

// TestParseHandshakeResponseReadsAuthPlugin pins the parsing the check above depends on.
func TestParseHandshakeResponseReadsAuthPlugin(t *testing.T) {
	authData := make([]byte, 20)
	pkt := buildClientAuthPacket("root", authData)
	pkt = append(pkt, "mysql_clear_password"...)
	pkt = append(pkt, 0x00)

	creds := parseHandshakeResponse(pkt)
	if creds.authPlugin != "mysql_clear_password" {
		t.Errorf("authPlugin = %q, want mysql_clear_password", creds.authPlugin)
	}
	if creds.username != "root" {
		t.Errorf("username = %q, want root", creds.username)
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
	var loginCalls int
	saveMysqlLogin = func(*proto.MysqlRequest) error {
		loginCalls++
		return errors.New("grpc down")
	}
	t.Cleanup(func() { saveMysqlLogin = origLogin })

	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000002",
		username: "root",
		remoteIP: "203.0.113.8",
		queries:  []string{"select 1"},
	})

	if loginCalls != 1 {
		t.Errorf("SaveMysqlLogin called %d times, want 1; the test must exercise the failing "+
			"login rather than pass by returning before it", loginCalls)
	}
	if len(rec.queries) != 0 {
		t.Errorf("queries saved = %d, want 0 when the login failed", len(rec.queries))
	}
}

// TestPersistSessionAbandonsQueriesWhenTheBackendIsDown bounds the persistence goroutine.
// Without it, a session holding maxCommands queries against a stalled backend would work
// through every one at saveTimeout apiece -- roughly 42 minutes of retained goroutine and
// captured payload for no successful write.
func TestPersistSessionAbandonsQueriesWhenTheBackendIsDown(t *testing.T) {
	withRecorder(t)
	origQuery := saveQuery
	var calls int
	saveQuery = func(*proto.QueryRequest) error {
		calls++
		return errors.New("backend unavailable")
	}
	t.Cleanup(func() { saveQuery = origQuery })

	queries := make([]string, 50)
	for i := range queries {
		queries[i] = "select 1"
	}
	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000006",
		username: "root",
		remoteIP: "203.0.113.12",
		queries:  queries,
	})

	if calls != maxConsecutivePersistFailures {
		t.Errorf("SaveQuery called %d times, want %d before abandoning", calls, maxConsecutivePersistFailures)
	}
}

// TestPersistSessionResetsFailureCountOnSuccess proves the counter is consecutive rather
// than cumulative. Without the reset, scattered transient failures would eventually add up
// to the abandon threshold and silently truncate a session that was persisting fine.
func TestPersistSessionResetsFailureCountOnSuccess(t *testing.T) {
	rec := withRecorder(t)
	origQuery := saveQuery
	var calls int
	saveQuery = func(in *proto.QueryRequest) error {
		calls++
		// Fail on every other call: never three in a row, so the loop must run to the end.
		if calls%2 == 1 {
			return errors.New("transient grpc failure")
		}
		return rec.query(in)
	}
	t.Cleanup(func() { saveQuery = origQuery })

	queries := make([]string, 9)
	for i := range queries {
		queries[i] = "select 1"
	}
	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000008",
		username: "root",
		remoteIP: "203.0.113.14",
		queries:  queries,
	})

	if calls != len(queries) {
		t.Errorf("SaveQuery called %d times, want %d; interleaved failures must not accumulate "+
			"toward the abandon threshold", calls, len(queries))
	}
}

// TestPersistSessionRecordsQueryOnlySessions covers the documented case where a session
// produced queries but no username: the guard keeps it, since an unauthenticated query is
// still worth having.
func TestPersistSessionRecordsQueryOnlySessions(t *testing.T) {
	rec := withRecorder(t)
	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000007",
		remoteIP: "203.0.113.13",
		queries:  []string{"select @@version"},
	})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.logins) != 1 {
		t.Fatalf("logins = %d, want 1 for a query-only session", len(rec.logins))
	}
	if len(rec.queries) != 1 {
		t.Fatalf("queries = %d, want 1", len(rec.queries))
	}
	if rec.logins[0].Username != "" || rec.logins[0].Password != "" {
		t.Errorf("query-only login should carry no credential, got %+v", rec.logins[0])
	}
	if rec.queries[0].Guid != rec.logins[0].Guid {
		t.Errorf("query guid %q does not match login guid %q", rec.queries[0].Guid, rec.logins[0].Guid)
	}
}

// One failing SaveQuery must not abandon the rest of the session: the interesting
// statement is as likely to be the last as the first.
func TestPersistSessionContinuesAfterAQueryFails(t *testing.T) {
	rec := withRecorder(t)
	origQuery := saveQuery
	var calls int
	saveQuery = func(in *proto.QueryRequest) error {
		calls++
		if calls == 2 {
			return errors.New("transient grpc failure")
		}
		return rec.query(in)
	}
	t.Cleanup(func() { saveQuery = origQuery })

	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000005",
		username: "root",
		remoteIP: "203.0.113.11",
		queries:  []string{"select 1", "select 2", "DROP TABLE users"},
	})

	if calls != 3 {
		t.Errorf("SaveQuery called %d times, want 3 (the loop must not abort on error)", calls)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.queries) != 2 {
		t.Fatalf("queries recorded = %d, want 2 (the middle one failed)", len(rec.queries))
	}
	if rec.queries[1].Query != "DROP TABLE users" {
		t.Errorf("the query after the failure was lost; got %q", rec.queries[1].Query)
	}
}

// TestPersistSessionRecordsAnonymousCredential covers the case the empty-session guard
// used to swallow. MySQL allows anonymous accounts, so a client can authenticate with an
// empty username and still send a real native-password response; keying the guard on the
// username alone threw that credential away for want of a name to file it under.
func TestPersistSessionRecordsAnonymousCredential(t *testing.T) {
	rec := withRecorder(t)
	scramble := make([]byte, 20)
	authData := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(i + 7)
		authData[i] = byte(i + 11)
	}

	h := &honeypot{}
	h.persistSession(&session{
		guid:     "3f2a1b4c-0000-4000-8000-000000000009",
		remoteIP: "203.0.113.15",
		scramble: scramble,
		authData: authData,
	})

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.logins) != 1 {
		t.Fatalf("logins = %d, want 1 for an anonymous login carrying a credential", len(rec.logins))
	}
	want := "$mysqlna$" + hex.EncodeToString(scramble) + "*" + hex.EncodeToString(authData)
	if got := rec.logins[0].Password; got != want {
		t.Errorf("password = %q, want %q", got, want)
	}
	if rec.logins[0].Username != "" {
		t.Errorf("username = %q, want empty", rec.logins[0].Username)
	}
}

// A connection that produced nothing at all -- no username, no credential, no query -- is
// an ordinary port scan and must not manufacture an attacker row.
func TestPersistSessionSkipsEmptySessions(t *testing.T) {
	rec := withRecorder(t)
	h := &honeypot{}
	h.persistSession(&session{guid: "3f2a1b4c-0000-4000-8000-000000000003", remoteIP: "203.0.113.9"})

	if len(rec.logins) != 0 || len(rec.queries) != 0 {
		t.Errorf("bare connection persisted: %d logins, %d queries", len(rec.logins), len(rec.queries))
	}
}

// A login that supplies no password must still record the session; it just carries no
// credential artifact.
func TestPersistSessionNoPasswordLoginHasEmptyPassword(t *testing.T) {
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
