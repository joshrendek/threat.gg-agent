package sshd

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/termsafe"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// lookupCommandResponse is the legacy lookup with a caller-chosen deadline.
// Swappable for tests.
var lookupCommandResponse = persistence.GetCommandResponseWithin

// lookupTimeout is the normal legacy lookup deadline. degradedLookupTimeout
// replaces it after the generate call already timed out, so a degraded server
// costs an attacker generateBudget plus a short lookup, not two full waits.
const (
	lookupTimeout         = 3 * time.Second
	degradedLookupTimeout = 600 * time.Millisecond
)

// primeBudget bounds the hostname lookup made before the first shell prompt.
const primeBudget = 1500 * time.Millisecond

// generateResponse is the AI-first path. Swappable for tests.
var generateResponse = persistence.GenerateResponse

// generateBudget bounds how long an attacker waits for an AI reply before the
// legacy path answers instead.
const generateBudget = 3 * time.Second

// maxPromptField caps a server-supplied cwd or hostname shown in the prompt.
const maxPromptField = 256

// shellReply is what the exec and shell paths write and record.
type shellReply struct {
	Output   string // raw server text; callers sanitize before writing
	ExitCode uint32
	// Cwd and Hostname are sanitized single-line prompt fields, empty when the
	// reply supplied none (or a hostile one): the caller keeps its current value.
	Cwd      string
	Hostname string
	// Source is "ai", "ai_cached" or "local" for a GenerateResponse answer and
	// "" for the legacy path; it is recorded as ShellCommandRequest.ResponseSource.
	Source       string
	GenerationID string
}

// generatedSources maps the GenerateResponse sources that carry an answer to
// their capture label. NONE and UNSPECIFIED are absent: they mean fall back.
var generatedSources = map[proto.GenerateSource]string{
	proto.GenerateSource_GENERATE_SOURCE_AI:        "ai",
	proto.GenerateSource_GENERATE_SOURCE_AI_CACHED: "ai_cached",
	proto.GenerateSource_GENERATE_SOURCE_LOCAL:     "local",
}

// commandReply asks the server for a generated reply first and falls back to
// commandResponse on NONE, Unimplemented, any error, or a reply without a
// terminal body. It never fails: the worst case is today's behaviour. When the
// generate call itself timed out or the server is unreachable the legacy path
// runs with a short lookup deadline so the worst case stays bounded.
func commandReply(guid, command string) shellReply {
	lookup := lookupTimeout
	if strings.TrimSpace(command) != "" {
		reply, err := generateResponse(&proto.GenerateRequest{
			Guid: guid, Protocol: "ssh", Input: command, DeadlineMs: int32(generateBudget / time.Millisecond),
		}, generateBudget)
		if isServerSlow(err) {
			lookup = degradedLookupTimeout
		}
		if err != nil && !errors.Is(err, persistence.ErrUnimplemented) {
			logger.Debug().Err(err).Msg("generate response unavailable; using legacy path")
		}
		if source, ok := generatedSources[reply.GetSource()]; err == nil && ok && reply.GetTerminal() != nil {
			term := reply.GetTerminal()
			code := term.GetExitCode()
			if code < 0 || code > 255 {
				code = 255
			}
			return shellReply{
				Output:       term.GetStdout(),
				ExitCode:     uint32(code),
				Cwd:          promptField(term.GetCwd()),
				Hostname:     promptField(term.GetHostname()),
				Source:       source,
				GenerationID: reply.GetGenerationId(),
			}
		}
	}
	out := shellReply{ExitCode: 127}
	resp, err := commandResponseWithin(command, lookup)
	if err != nil {
		logger.Error().Err(err).Msg("error getting command response")
		return out
	}
	if resp != nil {
		out.Output = resp.Response
		if resp.Matched {
			out.ExitCode = 0
		}
	}
	return out
}

// isServerSlow reports a generate failure that means the server is slow or
// unreachable, as opposed to Unimplemented, NONE or a reply-level error.
func isServerSlow(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable:
		return true
	}
	return false
}

// primePrompt asks for the persona hostname and cwd before the first prompt so
// an AI session never shows a placeholder prompt that later changes. The reply
// text is discarded and nothing is recorded: the prime is not attacker input.
// Anything but an AI reply with a terminal body keeps the legacy defaults.
func primePrompt(guid string) (hostname, cwd string) {
	reply, err := generateResponse(&proto.GenerateRequest{
		Guid: guid, Protocol: "ssh", Input: "hostname", DeadlineMs: int32(primeBudget / time.Millisecond),
	}, primeBudget)
	if err != nil {
		return "", ""
	}
	switch reply.GetSource() {
	case proto.GenerateSource_GENERATE_SOURCE_AI, proto.GenerateSource_GENERATE_SOURCE_AI_CACHED:
	default:
		return "", ""
	}
	term := reply.GetTerminal()
	if term == nil {
		return "", ""
	}
	return promptField(term.GetHostname()), promptField(term.GetCwd())
}

// promptField sanitizes a server-supplied prompt component. Anything that is
// not a short single line is rejected (empty) so it can never forge a second
// prompt line or smuggle control sequences into the attacker's terminal.
func promptField(s string) string {
	s = termsafe.Sanitize(s)
	if len(s) > maxPromptField || strings.ContainsAny(s, "\r\n\t") {
		return ""
	}
	return s
}

// terminalBytes prepares already-sanitized text for terminal.Terminal.Write,
// which expands every \n to \r\n itself. Sanitize emits \r\n and never a lone
// \r, so collapsing back to \n is lossless and avoids a doubled \r.
func terminalBytes(sanitized string) []byte {
	return []byte(strings.ReplaceAll(sanitized, "\r\n", "\n"))
}

// This is deliberately a tiny shell grammar, never a call to a local shell.
// Redirection to /dev/null and the failure branch do not affect a successful
// uname. Resolve the canonical command through the server to retain its persona.
var unameValidator = regexp.MustCompile(`^uname[ \t]+-a[ \t]+2>[ \t]*/dev/null(?:[ \t]*\|\|[ \t]*echo[ \t]+(?:'Unknown'|"Unknown"|Unknown))?[ \t]*$`)
var echoValidator = regexp.MustCompile(`^echo(?:[ \t]+(?:[A-Za-z0-9_./:-]+|"[A-Za-z0-9_ ./:-]*"|'[A-Za-z0-9_ ./:-]*'))*[ \t]*$`)
var echoWord = regexp.MustCompile(`"[^"]*"|'[^']*'|[^ \t]+`)

func commandResponse(command string) (*proto.CommandResponse, error) {
	return commandResponseWithin(command, lookupTimeout)
}

func commandResponseWithin(command string, within time.Duration) (*proto.CommandResponse, error) {
	response, err := lookupCommandResponse(&proto.CommandRequest{Command: command, CommandType: "ssh"}, within)
	if err == nil && response != nil && response.Matched {
		return response, nil
	}
	if len(command) > 4096 {
		return response, err
	}
	clean := strings.TrimSpace(command)
	if unameValidator.MatchString(clean) {
		canonical, lookupErr := lookupCommandResponse(&proto.CommandRequest{Command: "uname -a", CommandType: "ssh"}, within)
		if lookupErr == nil && canonical != nil && canonical.Matched {
			return canonical, nil
		}
	}
	if echoValidator.MatchString(clean) {
		words := echoWord.FindAllString(clean, -1)[1:]
		for i, word := range words {
			words[i] = strings.Trim(word, "\"'")
			// Options need their own escape/flag semantics; leave them to authored rows.
			if strings.HasPrefix(words[i], "-") {
				return response, err
			}
		}
		return &proto.CommandResponse{Response: strings.Join(words, " ") + "\r\n", Matched: true}, nil
	}
	return response, err
}
