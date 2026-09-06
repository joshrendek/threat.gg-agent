package sshd

import (
	"regexp"
	"strings"

	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
)

var lookupCommandResponse = persistence.GetCommandResponse

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
