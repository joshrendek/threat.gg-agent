package unrealircd

import (
	"bufio"
	"strings"
	"testing"
)

func newSession() *session {
	return &session{id: "test-session", remote: "203.0.113.60"}
}

func TestRegistrationAndCapabilitiesProgressWithinSession(t *testing.T) {
	state := newSession()
	state.sequence = 1
	capEvent, replies := classifyLine(state, "CAP LS 302")
	if capEvent.Action != "capability_negotiation" || len(replies) != 1 || !strings.Contains(replies[0], "message-tags") {
		t.Fatalf("CAP: event=%+v replies=%v", capEvent, replies)
	}
	state.sequence++
	nickEvent, _ := classifyLine(state, "NICK secret-nick-must-not-persist")
	state.sequence++
	userEvent, replies := classifyLine(state, "USER secret-user 0 * :secret-realname")
	if nickEvent.Metadata["registered"] != "false" || userEvent.Metadata["registered"] != "true" || len(replies) != 2 {
		t.Fatalf("registration progression: nick=%+v user=%+v replies=%v", nickEvent, userEvent, replies)
	}
	for _, event := range []*protoPersonaAlias{wrap(nickEvent), wrap(userEvent)} {
		if strings.Contains(event.String(), "secret-") {
			t.Fatalf("registration values reached persistence: %s", event.String())
		}
	}
}

// protoPersonaAlias keeps the assertion helper compact without teaching the
// production package about test-only formatting.
type protoPersonaAlias struct{ value interface{ String() string } }

func wrap(value interface{ String() string }) *protoPersonaAlias {
	return &protoPersonaAlias{value: value}
}
func (value *protoPersonaAlias) String() string { return value.value.String() }

func TestLabeledResponseDelimiterAbuseIsHashedAndBlocked(t *testing.T) {
	state := newSession()
	state.sequence = 7
	const secretLabel = `campaign-secret\r\nOPER root password`
	event, replies := classifyLine(state, "@label="+secretLabel+" PRIVMSG #ops :harmless")
	if event.Action != "labeled_response_delimiter_probe" || event.Cve != "CVE-2026-114713" || !event.AuthBypass || event.StatusCode != 400 {
		t.Fatalf("classification: %+v", event)
	}
	if event.Metadata["label_sha256"] == "" || event.Metadata["label_size"] == "" || event.Metadata["delimiter_abuse"] != "true" {
		t.Fatalf("metadata: %+v", event.Metadata)
	}
	if len(replies) != 1 || !strings.Contains(replies[0], "Malformed") || strings.Contains(event.String(), "campaign-secret") {
		t.Fatalf("unsafe event/reply: event=%+v replies=%v", event, replies)
	}
}

func TestTruncatedLabelLineIsClassifiedBeforeInjectedCommand(t *testing.T) {
	state := newSession()
	state.sequence = 1
	event, replies := classifyLine(state, "@label=split-command")
	if event.Cve != "CVE-2026-114713" || event.Action != "labeled_response_delimiter_probe" || len(replies) != 1 {
		t.Fatalf("truncated label was not classified: event=%+v replies=%v", event, replies)
	}
	state.sequence++
	follow, replies := classifyLine(state, "OPER root secret")
	if follow.Action != "operator_command_blocked" || len(replies) != 1 {
		t.Fatalf("injected follow-on was not blocked: event=%+v replies=%v", follow, replies)
	}
}

func TestOrdinaryMessageTagsAreNegativeControl(t *testing.T) {
	state := newSession()
	state.sequence = 1
	event, _ := classifyLine(state, "@label=safe123;time=2026-11-14T12:00:00Z PRIVMSG #ops :hello")
	if event.Cve != "" || event.AuthBypass || event.Action != "message" || event.Metadata["tag_names"] != "label,time" {
		t.Fatalf("ordinary tags misclassified: %+v", event)
	}
}

func TestOperatorAndLinkCommandsAreNeverExecuted(t *testing.T) {
	for _, command := range []string{"OPER root password", "CONNECT evil.example", "LINK evil.example", "SQUIT example.net"} {
		state := newSession()
		state.sequence = 1
		event, replies := classifyLine(state, command)
		if event.Action != "operator_command_blocked" || len(replies) != 1 || !strings.Contains(replies[0], "481") {
			t.Fatalf("command %q was not blocked: event=%+v replies=%v", command, event, replies)
		}
		if strings.Contains(event.String(), "evil.example") || strings.Contains(event.String(), "password") {
			t.Fatalf("command parameters reached persistence: %+v", event)
		}
	}
}

func TestReadBoundedLineRejectsOversizedInput(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", maxLine+1)+"\n"), maxLine+1)
	if _, err := readBoundedLine(reader); err == nil {
		t.Fatal("oversized IRC line accepted")
	}
}

func FuzzParseLine(f *testing.F) {
	f.Add("@label=safe PRIVMSG #test :hello")
	f.Add(`@label=x\r\nOPER root password PRIVMSG #test :hello`)
	f.Fuzz(func(t *testing.T, line string) {
		if len(line) > maxLine+1 {
			line = line[:maxLine+1]
		}
		parsed := parseLine(line)
		if len(parsed.tagNames) > 64 || len(parsed.command) > maxLine+1 {
			t.Fatalf("unbounded parse result: %+v", parsed)
		}
	})
}
