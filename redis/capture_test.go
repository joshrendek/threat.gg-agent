package redis

import (
	"bufio"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog"
)

// threat_gg-vz7m. The QUIT case returned straight out of handleConnection, skipping the
// persistSession call at the bottom of the function. Every client that disconnected
// politely -- redis-cli and effectively every real client library send QUIT on close --
// had its entire session discarded: commands, credentials, all of it. Only sessions that
// timed out, errored, or hit the command cap were ever persisted, so the honeypot was
// keeping the abrupt scans and dropping the well-behaved tooling.
//
// Same bug class as the two found in mysql (threat_gg-cb0), and the reason these tests
// drive a real connection: a unit test that builds a session by hand cannot see it.

type recorder struct {
	mu       sync.Mutex
	connects []*proto.RedisConnectRequest
	commands []*proto.RedisCommandRequest
}

func (r *recorder) connect(in *proto.RedisConnectRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connects = append(r.connects, in)
	return nil
}

func (r *recorder) command(in *proto.RedisCommandRequest) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, in)
	return nil
}

func withRecorder(t *testing.T) *recorder {
	t.Helper()
	rec := &recorder{}
	origConnect, origCommand := saveRedisConnect, saveRedisCommand
	saveRedisConnect, saveRedisCommand = rec.connect, rec.command
	t.Cleanup(func() { saveRedisConnect, saveRedisCommand = origConnect, origCommand })
	return rec
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// runSession drives a connection through the honeypot, sending each inline command and
// reading whatever comes back, then waits for the handler to finish.
func runSession(t *testing.T, commands ...string) *recorder {
	t.Helper()
	rec := withRecorder(t)
	done := make(chan struct{})

	server, client := net.Pipe()
	h := &honeypot{logger: zerolog.Nop()}
	go func() {
		h.handleConnection(server)
		close(done)
	}()

	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	// Drain concurrently: replies are unread otherwise and net.Pipe is unbuffered, so the
	// handler would block writing instead of reaching the next command.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	writer := bufio.NewWriter(client)
	for _, cmd := range commands {
		if _, err := writer.WriteString(cmd + "\r\n"); err != nil {
			t.Fatalf("write %q: %v", cmd, err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatalf("flush %q: %v", cmd, err)
		}
	}

	// Hang up. A session ended by QUIT has already returned by now; one that was not needs
	// the disconnect, otherwise the handler sits waiting for the next command until its
	// idle timeout.
	client.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleConnection did not return")
	}
	return rec
}

// TestSessionEndingInQuitIsPersisted is the regression: QUIT is the polite disconnect, so
// it must not be the one path that discards the session.
func TestSessionEndingInQuitIsPersisted(t *testing.T) {
	rec := runSession(t, "AUTH hunter2", "SET foo bar", "QUIT")

	waitFor(t, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.connects) == 1
	}, "the QUIT session to be persisted")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.connects) != 1 {
		t.Fatalf("connects = %d, want 1", len(rec.connects))
	}
	if rec.connects[0].Password != "hunter2" {
		t.Errorf("password = %q, want hunter2; the credential must survive a polite disconnect",
			rec.connects[0].Password)
	}
	// AUTH, SET and QUIT are all recorded before dispatch, so all three should persist.
	if len(rec.commands) != 3 {
		t.Fatalf("commands = %d, want 3", len(rec.commands))
	}
	for i, c := range rec.commands {
		if c.Guid != rec.connects[0].Guid {
			t.Errorf("command %d guid %q does not match the connect guid %q", i, c.Guid, rec.connects[0].Guid)
		}
	}
	if rec.commands[1].Command != "SET foo bar" {
		t.Errorf("command 1 = %q, want %q", rec.commands[1].Command, "SET foo bar")
	}
}

// A session that ends by disconnecting rather than by QUIT already worked; this pins it so
// the fix does not trade one path for the other.
func TestSessionEndingInDisconnectIsPersisted(t *testing.T) {
	rec := runSession(t, "SET foo bar")

	waitFor(t, func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return len(rec.connects) == 1
	}, "the disconnected session to be persisted")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.commands) != 1 || rec.commands[0].Command != "SET foo bar" {
		t.Errorf("commands = %+v, want one SET foo bar", rec.commands)
	}
}

// A bare connection that issues nothing must not manufacture an attacker row.
func TestConnectionWithNoCommandsPersistsNothing(t *testing.T) {
	rec := runSession(t)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.connects) != 0 || len(rec.commands) != 0 {
		t.Errorf("bare connection persisted %d connects, %d commands", len(rec.connects), len(rec.commands))
	}
}
