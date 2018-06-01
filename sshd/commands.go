package sshd

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

type CommandHandler struct {
	Terminal *terminal.Terminal
	Commands []Command
}

func NewCommandHandler(term *terminal.Terminal) *CommandHandler {
	return &CommandHandler{Terminal: term, Commands: []Command{}}
}

func (ch *CommandHandler) Register(commands ...Command) {
	for _, c := range commands {
		ch.Commands = append(ch.Commands, c)
	}
}

func (ch *CommandHandler) MatchAndRun(in string) (string, bool) {
	for _, c := range ch.Commands {
		if c.Match(strings.TrimSpace(in)) {
			return c.Run(in)
		}
	}
	return fmt.Sprintf("bash: %s: command not found", in), false
}

type Command interface {
	Match(string) bool
	Run(string) (string, bool)
}

type Echo struct{}

func (c *Echo) Match(in string) bool {
	return strings.Contains(in, "echo")
}

func (c *Echo) Run(in string) (string, bool) {
	x := strings.Split(in, " ")
	newLine := true
	if len(x) >= 2 {
		if x[1] == "-n" {
			newLine = false
		}
	}
	if len(x) == 1 {
		return "", true
	}
	startPos := 1
	if strings.Contains(x[1], "-") {
		if len(x) >= 2 {
			startPos = 2
		}
	}

	log.Printf("%+v | Start Pos: %d", x, startPos)
	return strings.Join(x[startPos:len(x)], " "), newLine
}

type Pwd struct{}

func (c *Pwd) Match(in string) bool {
	return in == "pwd"
}

func (c *Pwd) Run(in string) (string, bool) {
	return "/", true
}

type UnsetHistory struct{}

func (c *UnsetHistory) Match(in string) bool {
	return in == "unset HISTFILE"
}

func (c *UnsetHistory) Run(in string) (string, bool) {
	return "", true
}

type Ls struct{}

func (c *Ls) Match(in string) bool {
	return in == "ls"
}

func (c *Ls) Run(in string) (string, bool) {
	out := "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
	return out, true
}

type LsAl struct{}

func (c *LsAl) Match(in string) bool {
	return in == "ls -al"
}

func (c *LsAl) Run(in string) (string, bool) {
	out := []string{"total 72",
		"drwxr-xr-x  32 root root 4096 Apr 19 02:51 .\r",
		"drwxr-xr-x  32 root root 4096 Apr 19 02:51 ..\r",
		"-rwxr-xr-x   1 root root    0 Apr 19 02:51 .dockerenv\r",
		"-rwxr-xr-x   1 root root    0 Apr 19 02:51 .dockerinit\r",
		"drwxr-xr-x   2 root root 4096 Oct 28 04:34 bin\r",
		"drwxr-xr-x   2 root root 4096 Apr 10  2014 boot\r",
		"drwxr-xr-x   5 root root  380 Apr 19 02:51 dev\r",
		"drwxr-xr-x  64 root root 4096 Apr 19 02:51 etc\r",
		"drwxr-xr-x   2 root root 4096 Apr 10  2014 home\r",
		"drwxr-xr-x  12 root root 4096 Oct 28 04:34 lib\r",
		"drwxr-xr-x   2 root root 4096 Oct 28 04:33 lib64\r",
		"drwxr-xr-x   2 root root 4096 Oct 28 04:33 media\r",
		"drwxr-xr-x   2 root root 4096 Apr 10  2014 mnt\r",
		"drwxr-xr-x   2 root root 4096 Oct 28 04:33 opt\r",
		"dr-xr-xr-x 128 root root    0 Apr 19 02:51 proc\r",
		"drwx------   2 root root 4096 Oct 28 04:34 root\r",
		"drwxr-xr-x   7 root root 4096 Oct 28 04:34 run\r",
		"drwxr-xr-x   2 root root 4096 Nov 10 00:35 sbin\r",
		"drwxr-xr-x   2 root root 4096 Oct 28 04:33 srv\r",
		"dr-xr-xr-x  13 root root    0 Apr 19 02:51 sys\r",
		"drwxrwxrwt   2 root root 4096 Oct 28 04:34 tmp\r",
		"drwxr-xr-x  11 root root 4096 Nov 10 00:35 usr\r",
		"drwxr-xr-x  12 root root 4096 Nov 10 00:35 var\r"}
	return strings.Join(out, "\r\n"), true
}

type Uname struct{}

func (c *Uname) Match(in string) bool {
	return in == "uname"
}

func (c *Uname) Run(in string) (string, bool) {
	return "Linux", true
}

type Whoami struct {
	User string
}

func (c *Whoami) Match(in string) bool {
	return in == "whoami"
}

func (c *Whoami) Run(in string) (string, bool) {
	return c.User, true
}

type Help struct{}

func (c *Help) Match(in string) bool {
	return in == "help"
}

func (c *Help) Run(in string) (string, bool) {
	out := []string{"GNU bash, version 4.3.11(1)-release (x86_64-pc-linux-gnu)",
		"These shell commands are defined internally.  Type 'help' to see this list.",
		"Type 'help name' to find out more about the function 'name'.",
		"Use 'info bash' to find out more about the shell in general.",
		"Use 'man -k' or 'info' to find out more about commands not in this list.",
		"",
		"A star (*) next to a name means that the command is disabled.",
		"job_spec [&]                                                                                                                    history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]",
		"(( expression ))                                                                                                                if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi",
		". filename [arguments]                                                                                                          jobs [-lnprs] [jobspec ...] or jobs -x command [args]",
		":                                                                                                                               kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]",
		"[ arg... ]                                                                                                                      let arg [arg ...]",
		"[[ expression ]]                                                                                                                local [option] name[=value] ...",
		"alias [-p] [name[=value] ... ]                                                                                                  logout [n]",
		"bg [job_spec ...]                                                                                                               mapfile [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]",
		"bind [-lpsvPSVX] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-command] [keyseq:readline-functio>  popd [-n] [+N | -N]",
		"break [n]                                                                                                                       printf [-v var] format [arguments]",
		"builtin [shell-builtin [arg ...]]                                                                                               pushd [-n] [+N | -N | dir]",
		"caller [expr]                                                                                                                   pwd [-LP]",
		"case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac                                                                      read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]",
		"cd [-L|[-P [-e]] [-@]] [dir]                                                                                                    readarray [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]",
		"command [-pVv] command [arg ...]                                                                                                readonly [-aAf] [name[=value] ...] or readonly -p",
		"compgen [-abcdefgjksuv] [-o option]  [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filterpat] [-P pr>  return [n]",
		"complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F function] [-C command] [-X filte>  select NAME [in WORDS ... ;] do COMMANDS; done",
		"compopt [-o|+o option] [-DE] [name ...]                                                                                         set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]",
		"continue [n]                                                                                                                    shift [n]",
		"coproc [NAME] command [redirections]                                                                                            shopt [-pqsu] [-o] [optname ...]",
		"declare [-aAfFgilnrtux] [-p] [name[=value] ...]                                                                                 source filename [arguments]",
		"dirs [-clpv] [+N] [-N]                                                                                                          suspend [-f]",
		"disown [-h] [-ar] [jobspec ...]                                                                                                 test [expr]",
		"echo [-neE] [arg ...]                                                                                                           time [-p] pipeline",
		"enable [-a] [-dnps] [-f filename] [name ...]                                                                                    times",
		"eval [arg ...]                                                                                                                  trap [-lp] [[arg] signal_spec ...]",
		"exec [-cl] [-a name] [command [arguments ...]] [redirection ...]                                                                true",
		"exit [n]                                                                                                                        type [-afptP] name [name ...]",
		"export [-fn] [name[=value] ...] or export -p                                                                                    typeset [-aAfFgilrtux] [-p] name[=value] ...",
		"false                                                                                                                           ulimit [-SHabcdefilmnpqrstuvxT] [limit]",
		"fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]                                                                umask [-p] [-S] [mode]",
		"fg [job_spec]                                                                                                                   unalias [-a] name [name ...]",
		"for NAME [in WORDS ... ] ; do COMMANDS; done                                                                                    unset [-f] [-v] [-n] [name ...]",
		"for (( exp1; exp2; exp3 )); do COMMANDS; done                                                                                   until COMMANDS; do COMMANDS; done",
		"function name { COMMANDS ; } or name () { COMMANDS ; }                                                                          variables - Names and meanings of some shell variables",
		"getopts optstring name [arg]                                                                                                    wait [-n] [id ...]",
		"hash [-lr] [-p pathname] [-dt] [name ...]                                                                                       while COMMANDS; do COMMANDS; done",
		"help [-dms] [pattern ...]                                                                                                       { COMMANDS ; }",
	}
	return strings.Join(out, "\r\n"), true
}
