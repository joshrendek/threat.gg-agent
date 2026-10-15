package telnet

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"

	"github.com/joshrendek/threat.gg-agent/persistence"
	pb "github.com/joshrendek/threat.gg-agent/proto"
	"github.com/joshrendek/threat.gg-agent/shellai"
)

// maxServerLookupLen bounds the attacker-controlled command we forward to the server
// (generate and the authored lookup); anything longer goes straight to the local handlers.
const maxServerLookupLen = 4096

// generateResponse is the AI path and lookupCommandResponse the authored
// command_responses lookup with a caller-chosen deadline. Both are seams over
// the gRPC calls so every branch is unit-testable without a live server.
var (
	generateResponse      = persistence.GenerateResponse
	lookupCommandResponse = persistence.GetCommandResponseWithin
)

var commandHandlers = map[string]func(args []string) string{
	"uname":      handleUname,
	"ls":         handleLs,
	"cat":        handleCat,
	"id":         handleId,
	"whoami":     handleWhoami,
	"pwd":        handlePwd,
	"cd":         handleCd,
	"echo":       handleEcho,
	"wget":       handleWget,
	"curl":       handleCurl,
	"tftp":       handleTftp,
	"busybox":    handleBusybox,
	"sh":         handleSh,
	"enable":     handleEnable,
	"system":     handleSystem,
	"shell":      handleShell,
	"linuxshell": handleShell,
}

// shellVerbs are the bare words bots send to escape a vendor CLI into a shell
// before probing it. A real device answers them with nothing, and bots check
// for exactly that, so they are answered locally and never sent to the server.
var shellVerbs = map[string]bool{"enable": true, "system": true, "shell": true, "sh": true, "linuxshell": true}

// telnetReply is what one command writes and records.
type telnetReply struct {
	Output string // raw text; the caller sanitizes before writing
	Exit   bool
	// Source is "ai", "ai_cached" or "local" for a generated answer and "" for
	// every other path, the same vocabulary as ssh; it is recorded as
	// TelnetCommandRequest.ResponseSource together with GenerationID.
	Source       string
	GenerationID string
}

// commandReply answers one command line. Order: exit; the deterministic bot
// probes (bare shell verbs and every /bin/busybox applet call), which never
// reach the server; then the AI; then the authored lookup; then the local
// handlers. It never fails: with no AI and no server it is the legacy
// behaviour. After a slow or unreachable generate call the authored lookup
// uses the short degraded deadline so an attacker's wait stays bounded.
func commandReply(guid, line string) telnetReply {
	// Bot shell probes often append NUL after the verb. Normalize only terminal
	// padding here; persistence still receives the original command, and embedded
	// controls must not join two command fragments into a different command.
	input := strings.TrimSpace(strings.TrimRightFunc(line, func(r rune) bool {
		return unicode.IsSpace(r) || r < 0x20 || r == 0x7f
	}))
	if input == "" {
		return telnetReply{}
	}

	parts := strings.Fields(input)
	cmd := parts[0]
	args := parts[1:]

	if cmd == "exit" || cmd == "quit" || cmd == "logout" {
		return telnetReply{Exit: true}
	}
	if out, ok := probeReply(cmd, args); ok {
		return telnetReply{Output: out}
	}

	// Input is length-bounded so an oversized command is never forwarded to the server.
	if len(input) <= maxServerLookupLen {
		ai, err := shellai.Ask(generateResponse, "telnet", guid, input)
		if err != nil && !errors.Is(err, persistence.ErrUnimplemented) {
			log.Debug().Err(err).Msg("telnet generate response unavailable; using legacy path")
		}
		if ai.Answered {
			return telnetReply{Output: ai.Stdout, Source: ai.Source, GenerationID: ai.GenerationID}
		}
		lookup := shellai.LookupTimeout
		if ai.Degraded {
			lookup = shellai.DegradedLookupTimeout
		}

		// Server-authored response override (admin-editable command_responses, scoped
		// to command_type="telnet"). Matched distinguishes an intentionally-empty
		// response from a miss; on a miss or any error we fall through to the local
		// handlers below, so behaviour never regresses if the server is unreachable.
		resp, err := lookupCommandResponse(&pb.CommandRequest{Command: input, CommandType: "telnet"}, lookup)
		if err == nil && resp != nil && resp.Matched {
			return telnetReply{Output: resp.Response}
		}
	}

	handler, ok := commandHandlers[cmd]
	if !ok {
		return telnetReply{Output: fmt.Sprintf("-sh: %s: not found\r\n", cmd)}
	}
	return telnetReply{Output: handler(args)}
}

// probeReply answers the bot probes whose reply must be exact and never vary:
// a bare shell verb prints nothing, a known /bin/busybox applet runs its
// handler, and an unknown one prints the applet-specific error bots use to
// confirm command execution (they send a random marker and look for it).
func probeReply(cmd string, args []string) (string, bool) {
	if len(args) == 0 && shellVerbs[cmd] {
		return "", true
	}
	if cmd == "/bin/busybox" && len(args) > 0 {
		applet := args[0]
		if handler, ok := commandHandlers[applet]; ok {
			return handler(args[1:]), true
		}
		return fmt.Sprintf("%s: applet not found\r\n", printableAppletName(applet)), true
	}
	return "", false
}

func printableAppletName(applet string) string {
	const maxAppletNameLen = 128

	var out strings.Builder
	for i := 0; i < len(applet) && out.Len() < maxAppletNameLen; i++ {
		if applet[i] >= 0x21 && applet[i] <= 0x7e {
			out.WriteByte(applet[i])
		} else {
			out.WriteByte('?')
		}
	}
	return out.String()
}

func handleUname(args []string) string {
	for _, a := range args {
		if strings.Contains(a, "a") {
			return "Linux device 4.14.151 #1 SMP Tue Nov 5 12:38:07 UTC 2024 armv7l GNU/Linux\r\n"
		}
	}
	return "Linux\r\n"
}

func handleLs(args []string) string {
	return "bin      etc      lib      proc     sys      usr\r\ndev      home     mnt      root     tmp      var\r\n"
}

func handleCat(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "/etc/passwd":
		return "root:x:0:0:root:/root:/bin/sh\r\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\r\ndaemon:x:1:1:daemon:/usr/sbin:/bin/false\r\n"
	case "/proc/mounts":
		return "rootfs / rootfs rw 0 0\r\nproc /proc proc rw,nosuid,nodev,noexec 0 0\r\nsysfs /sys sysfs rw,nosuid,nodev,noexec 0 0\r\ntmpfs /tmp tmpfs rw,nosuid,nodev 0 0\r\n"
	case "/proc/cpuinfo":
		return "processor\t: 0\r\nmodel name\t: ARMv7 Processor rev 4 (v7l)\r\nBogoMIPS\t: 38.40\r\nHardware\t: Generic DT based system\r\n"
	default:
		return fmt.Sprintf("cat: %s: No such file or directory\r\n", args[0])
	}
}

func handleId(args []string) string {
	return "uid=0(root) gid=0(root) groups=0(root)\r\n"
}

func handleWhoami(args []string) string {
	return "root\r\n"
}

func handlePwd(args []string) string {
	return "/root\r\n"
}

func handleCd(args []string) string {
	return ""
}

func handleEcho(args []string) string {
	return strings.Join(args, " ") + "\r\n"
}

func handleWget(args []string) string {
	if len(args) == 0 {
		return "wget: missing URL\r\n"
	}
	return fmt.Sprintf("Connecting to %s... connection timed out.\r\n", args[len(args)-1])
}

func handleCurl(args []string) string {
	if len(args) == 0 {
		return "curl: no URL specified\r\n"
	}
	return "curl: (28) Connection timed out after 10000 milliseconds\r\n"
}

func handleTftp(args []string) string {
	return "tftp: timeout\r\n"
}

func handleBusybox(args []string) string {
	return "BusyBox v1.30.1 () multi-call binary.\r\nCurrently defined functions:\r\n\tcat, cp, echo, grep, id, ifconfig, kill, ls, mkdir, mount,\r\n\tmv, ps, pwd, rm, sh, telnet, tftp, top, uname, wget\r\n"
}

func handleSh(args []string) string {
	return ""
}

func handleEnable(args []string) string {
	return ""
}

func handleSystem(args []string) string {
	return ""
}

func handleShell(args []string) string {
	return ""
}
