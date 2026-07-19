package telnet

import "testing"

// TestExecuteCommand_FallsBackWhenServerUnavailable verifies the no-regression
// guarantee: with no gRPC client connected (honeypotClient is nil in unit tests), the
// server-authored response lookup errors and executeCommand falls back to the local
// hardcoded handlers exactly as before.
func TestExecuteCommand_FallsBackWhenServerUnavailable(t *testing.T) {
	if out, exit := executeCommand("exit"); out != "" || !exit {
		t.Fatalf(`executeCommand("exit") = %q, %v; want "", true`, out, exit)
	}

	if out, exit := executeCommand("whoami"); out != "root\r\n" || exit {
		t.Fatalf(`executeCommand("whoami") = %q, %v; want "root\r\n", false`, out, exit)
	}

	if out, exit := executeCommand("nosuchcmd"); out != "-sh: nosuchcmd: not found\r\n" || exit {
		t.Fatalf(`executeCommand("nosuchcmd") = %q, %v; want "-sh: nosuchcmd: not found\r\n", false`, out, exit)
	}
}
