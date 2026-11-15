// Package unrealircd serves a bounded IRC persona for observing registration,
// capability negotiation, message tags, and CVE-2026-114713-shaped delimiter
// abuse. It never links to another IRC server or executes operator commands.
package unrealircd

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/joshrendek/threat.gg-agent/honeypots"
	"github.com/joshrendek/threat.gg-agent/persistence"
	"github.com/joshrendek/threat.gg-agent/proto"
	"github.com/rs/zerolog/log"
	uuid "github.com/satori/go.uuid"
)

const (
	defaultPort = "6667"
	maxLine     = 4096
	maxCommands = 128
	idleTimeout = 30 * time.Second
	serverName  = "irc.example.net"
)

var saveEvent = persistence.SavePersonaEvent
var saveSem = make(chan struct{}, 64)

type honeypot struct{ port string }

type session struct {
	id         string
	remote     string
	sequence   int
	nickSeen   bool
	userSeen   bool
	registered bool
}

func New() honeypots.Honeypot {
	port := os.Getenv("UNREALIRCD_HONEYPOT_PORT")
	if port == "" {
		port = defaultPort
	}
	return &honeypot{port: port}
}

func (h *honeypot) Name() string { return "unrealircd" }

func (h *honeypot) Start() {
	listener, err := net.Listen("tcp", ":"+h.port)
	if err != nil {
		log.Error().Err(err).Str("port", h.port).Msg("UnrealIRCd listen error")
		return
	}
	log.Info().Str("port", h.port).Msg("starting UnrealIRCd honeypot")
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Error().Err(err).Msg("UnrealIRCd accept error")
			continue
		}
		go handleConnection(connection)
	}
}

func handleConnection(connection net.Conn) {
	defer connection.Close()
	remote := remoteHost(connection.RemoteAddr().String())
	sessionHash := sha256.Sum256([]byte(remote + "\x00" + uuid.NewV4().String()))
	state := &session{id: hex.EncodeToString(sessionHash[:12]), remote: remote}
	reader := bufio.NewReaderSize(connection, maxLine+1)
	_, _ = fmt.Fprintf(connection, ":%s NOTICE * :*** Looking up your hostname...\r\n", serverName)
	for state.sequence < maxCommands {
		_ = connection.SetDeadline(time.Now().Add(idleTimeout))
		line, err := readBoundedLine(reader)
		if err != nil {
			return
		}
		state.sequence++
		event, responses := classifyLine(state, line)
		for _, response := range responses {
			_, _ = fmt.Fprintf(connection, "%s\r\n", response)
		}
		persist(event)
		if event != nil && event.Action == "quit" {
			return
		}
	}
}

func persist(event *proto.PersonaEventRequest) {
	if event == nil || saveEvent == nil {
		return
	}
	select {
	case saveSem <- struct{}{}:
		go func() {
			defer func() { <-saveSem }()
			if err := saveEvent(event); err != nil {
				log.Error().Err(err).Msg("failed to save UnrealIRCd event")
			}
		}()
	default:
		// Drop telemetry rather than create an unbounded queue while the control
		// plane is unavailable.
	}
}

func readBoundedLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxLine {
		return "", errors.New("IRC line exceeds limit")
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), nil
}

type parsedLine struct {
	command        string
	tagNames       []string
	labelHash      string
	labelSize      int
	delimiterAbuse bool
}

func parseLine(line string) parsedLine {
	result := parsedLine{}
	rest := line
	if strings.HasPrefix(rest, "@") {
		tagSection, remaining, found := strings.Cut(rest[1:], " ")
		if !found {
			tagSection = rest[1:]
			remaining = ""
			result.delimiterAbuse = true
		}
		rest = strings.TrimLeft(remaining, " ")
		seen := map[string]bool{}
		parts := strings.Split(tagSection, ";")
		if len(parts) > 64 || strings.Contains(tagSection, ";;") {
			result.delimiterAbuse = true
		}
		for _, tag := range parts {
			name, value, hasValue := strings.Cut(tag, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if !validTagName(name) {
				result.delimiterAbuse = true
				continue
			}
			if !seen[name] {
				result.tagNames = append(result.tagNames, name)
				seen[name] = true
			} else if name == "label" {
				result.delimiterAbuse = true
			}
			if name == "label" && hasValue {
				result.labelSize = len(value)
				hash := sha256.Sum256([]byte(value))
				result.labelHash = hex.EncodeToString(hash[:])
				lower := strings.ToLower(value)
				if strings.ContainsAny(value, "\r\n \x00") || strings.Contains(lower, `\r`) || strings.Contains(lower, `\n`) || strings.Contains(value, ";") {
					result.delimiterAbuse = true
				}
			}
		}
		sort.Strings(result.tagNames)
	}
	fields := strings.Fields(rest)
	if len(fields) > 0 {
		result.command = safeCommand(fields[0])
	}
	return result
}

func validTagName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || strings.ContainsRune("-./", char) {
			continue
		}
		return false
	}
	return true
}

func safeCommand(value string) string {
	value = strings.ToUpper(value)
	if value == "" || len(value) > 32 {
		return "UNKNOWN"
	}
	for _, char := range value {
		if (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		return "UNKNOWN"
	}
	return value
}

func classifyLine(state *session, line string) (*proto.PersonaEventRequest, []string) {
	parsed := parseLine(line)
	command := parsed.command
	if command == "" {
		command = "UNKNOWN"
	}
	responses := []string{}
	action, cve, status := strings.ToLower(command), "", 200
	switch command {
	case "CAP":
		action = "capability_negotiation"
		responses = append(responses, ":"+serverName+" CAP * LS :message-tags labeled-response server-time")
	case "NICK":
		state.nickSeen = true
		action = "registration_nick"
	case "USER":
		state.userSeen = true
		action = "registration_user"
	case "PING":
		responses = append(responses, "PONG :"+serverName)
	case "PRIVMSG", "NOTICE":
		action = "message"
	case "OPER", "CONNECT", "LINK", "SQUIT":
		action, status = "operator_command_blocked", 481
		responses = append(responses, ":"+serverName+" 481 * :Permission Denied- You're not an IRC operator")
	case "QUIT":
		action = "quit"
	default:
		status = 421
		responses = append(responses, ":"+serverName+" 421 * "+bounded(command, 32)+" :Unknown command")
	}
	if parsed.delimiterAbuse && parsed.labelHash != "" {
		action, cve, status = "labeled_response_delimiter_probe", "CVE-2026-114713", 400
		responses = []string{"ERROR :Malformed message tags"}
	}
	if !state.registered && state.nickSeen && state.userSeen {
		state.registered = true
		responses = append(responses,
			":"+serverName+" 001 guest :Welcome to the ExampleNet IRC Network guest",
			":"+serverName+" 004 guest "+serverName+" UnrealIRCd-6.2.7 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikraqbeIOLM",
		)
	}
	metadata := map[string]string{
		"command":             bounded(command, 32),
		"sequence":            strconv.Itoa(state.sequence),
		"registered":          strconv.FormatBool(state.registered),
		"tag_names":           bounded(strings.Join(parsed.tagNames, ","), 1024),
		"tag_count":           strconv.Itoa(len(parsed.tagNames)),
		"label_present":       strconv.FormatBool(parsed.labelHash != ""),
		"delimiter_abuse":     strconv.FormatBool(parsed.delimiterAbuse),
		"response_line_count": strconv.Itoa(len(responses)),
	}
	if parsed.labelHash != "" {
		metadata["label_sha256"] = parsed.labelHash
		metadata["label_size"] = strconv.Itoa(parsed.labelSize)
	}
	event := &proto.PersonaEventRequest{
		RemoteAddr: state.remote, Guid: uuid.NewV4().String(), SessionId: state.id,
		Persona: "unrealircd", Family: "unrealircd-irc", Version: "UnrealIRCd-6.2.7", Action: action,
		Method: command, Path: "irc:" + strings.ToLower(command), AuthBypass: cve != "", Cve: cve,
		Evidence: bounded(structuralEvidence(metadata), 1024), StatusCode: int32(status), Metadata: metadata,
	}
	return event, responses
}

func remoteHost(address string) string {
	if host, _, err := net.SplitHostPort(address); err == nil {
		return bounded(host, 128)
	}
	return bounded(address, 128)
}

func structuralEvidence(metadata map[string]string) string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+metadata[key])
	}
	return strings.Join(parts, " ")
}

func bounded(value string, limit int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
