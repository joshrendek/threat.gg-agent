package sshd

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/termsafe"
)

var lookupCommandResponse = persistence.GetCommandResponse

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
// terminal body. It never fails: the worst case is today's behaviour. cwd is
// only used to fill Cwd when nothing better is known.
func commandReply(guid, command, cwd string) shellReply {
	if strings.TrimSpace(command) != "" {
		reply, err := generateResponse(&proto.GenerateRequest{
			Guid: guid, Protocol: "ssh", Input: command, DeadlineMs: int32(generateBudget / time.Millisecond),
		}, generateBudget)
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
	out := shellReply{ExitCode: 127, Cwd: cwd}
	resp, err := commandResponse(command)
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
	response, err := lookupCommandResponse(&proto.CommandRequest{Command: command, CommandType: "ssh"})
	if err == nil && response != nil && response.Matched {
		return response, nil
	}
	if len(command) > 4096 {
		return response, err
	}
	clean := strings.TrimSpace(command)
	if unameValidator.MatchString(clean) {
		canonical, lookupErr := lookupCommandResponse(&proto.CommandRequest{Command: "uname -a", CommandType: "ssh"})
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
