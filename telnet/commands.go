package telnet

import (
	"fmt"
	"strings"
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

func executeCommand(input string) (string, bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", false
	}

	parts := strings.Fields(input)
	cmd := parts[0]
	args := parts[1:]

	// Check for exit commands
	if cmd == "exit" || cmd == "quit" || cmd == "logout" {
		return "", true
	}

	// Handle /bin/busybox prefix
	if cmd == "/bin/busybox" && len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}

	handler, ok := commandHandlers[cmd]
	if !ok {
		return fmt.Sprintf("-sh: %s: not found\r\n", cmd), false
	}
	return handler(args), false
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
