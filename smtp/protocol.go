package smtp

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func parseCommand(line string) (cmd string, args string) {
	line = strings.TrimRight(line, "\r\n")
	idx := strings.IndexByte(line, ' ')
	if idx < 0 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:idx]), line[idx+1:]
}

func parseAddress(arg string) string {
	arg = strings.TrimSpace(arg)
	// Handle MAIL FROM:<addr> and RCPT TO:<addr>
	if idx := strings.IndexByte(arg, ':'); idx >= 0 {
		arg = strings.TrimSpace(arg[idx+1:])
	}
	if strings.HasPrefix(arg, "<") && strings.HasSuffix(arg, ">") {
		return arg[1 : len(arg)-1]
	}
	return arg
}

func decodeAuthLogin(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return encoded
	}
	return string(decoded)
}

func decodeAuthPlain(encoded string) (user, pass string) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", ""
	}
	// AUTH PLAIN format: \0username\0password
	parts := strings.SplitN(string(decoded), "\x00", 3)
	switch len(parts) {
	case 3:
		return parts[1], parts[2]
	case 2:
		return parts[0], parts[1]
	default:
		return string(decoded), ""
	}
}

func buildEhloResponse(hostname string) string {
	return fmt.Sprintf("250-%s\r\n250-AUTH LOGIN PLAIN\r\n250-SIZE 10485760\r\n250 OK", hostname)
}

func extractSubject(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // end of headers
		}
		if strings.HasPrefix(strings.ToLower(line), "subject:") {
			return strings.TrimSpace(line[len("subject:"):])
		}
	}
	return ""
}
