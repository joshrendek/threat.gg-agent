package redis

import (
	"bytes"
	"strings"
	"testing"
)

// run issues one COMMAND-family request and returns the bytes written, after asserting the
// handler claimed it.
func runCommand(t *testing.T, args ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	handled, err := commandTableResponse(args, &buf)
	if !handled {
		t.Fatalf("commandTableResponse(%v) did not handle the command", args)
	}
	if err != nil {
		t.Fatalf("commandTableResponse(%v): %v", args, err)
	}
	return buf.Bytes()
}

func TestCommandTableFixturesParse(t *testing.T) {
	if commandTableErr != nil {
		t.Fatalf("embedded command fixtures failed to parse: %v", commandTableErr)
	}
	if len(commandTopLevel) != 241 {
		t.Fatalf("top-level commands = %d, want 241 (redis 7.2.4)", len(commandTopLevel))
	}
	if len(commandListNames) != 370 {
		t.Fatalf("listable names = %d, want 370 (241 commands + 129 subcommands)", len(commandListNames))
	}
	if len(commandDocsByName) != 241 {
		t.Fatalf("doc entries = %d, want 241", len(commandDocsByName))
	}
}

// TestCommandFixturesAreCompleteFrames decodes the embedded blobs end to end. They are
// written to the socket verbatim, so a truncated or over-long fixture would desynchronise
// every client that reads one.
func TestCommandFixturesAreCompleteFrames(t *testing.T) {
	table := mustDecodeFrame(t, commandTableFrame)
	if table.typ != '*' {
		t.Fatalf("command table is type %q, want an array", table.typ)
	}
	if len(table.items) != len(commandTopLevel) {
		t.Fatalf("decoded %d entries but indexed %d", len(table.items), len(commandTopLevel))
	}

	for _, entry := range table.items {
		if entry.typ != '*' || len(entry.items) != 10 {
			t.Fatalf("entry is not a 10-field array: %v", entry)
		}
		name, arity, flags := entry.items[0], entry.items[1], entry.items[2]
		if name.typ != '$' {
			t.Fatalf("%v: name must be a bulk string, got %q", entry, name.typ)
		}
		if arity.typ != ':' {
			t.Fatalf("%s: arity must be an integer, got %q", name.str, arity.typ)
		}
		if flags.typ != '*' {
			t.Fatalf("%s: flags must be an array, got %q", name.str, flags.typ)
		}
		// The simple-vs-bulk distinction here is the detail no hand-written table gets
		// right, so pin it: redis emits command flags as SIMPLE strings.
		for _, f := range flags.items {
			if f.typ != '+' {
				t.Fatalf("%s: flag %v must be a simple string, got %q", name.str, f, f.typ)
			}
		}
		// ...and command tips as BULK strings.
		for _, tip := range entry.items[7].items {
			if tip.typ != '$' {
				t.Fatalf("%s: tip %v must be a bulk string, got %q", name.str, tip, tip.typ)
			}
		}
	}

	docs := mustDecodeFrame(t, commandDocsFrame)
	if len(docs.items) != 2*len(commandDocsByName) {
		t.Fatalf("docs has %d elements, want %d name/value pairs", len(docs.items), 2*len(commandDocsByName))
	}
}

// TestCommandIsAnArrayNotAnInteger is the regression for the reported defect: COMMAND used
// to answer ":20", an integer where RESP requires an array of command specs.
func TestCommandIsAnArrayNotAnInteger(t *testing.T) {
	reply := mustDecodeFrame(t, runCommand(t, "COMMAND"))
	if reply.typ == ':' {
		t.Fatal("COMMAND answered an integer; RESP requires an array of command specs")
	}
	if reply.typ != '*' {
		t.Fatalf("COMMAND answered type %q, want an array", reply.typ)
	}
	if len(reply.items) != 241 {
		t.Fatalf("COMMAND returned %d specs, want 241", len(reply.items))
	}
	if got := reply.items[0].items[0].str; got == "" {
		t.Fatal("first spec has an empty command name")
	}
}

// TestCommandCountAgreesWithCommandTable is the internal-consistency invariant: whatever
// COMMAND COUNT claims must be exactly the number of specs bare COMMAND actually returns.
// The two disagreeing is a worse tell than either value being wrong.
func TestCommandCountAgreesWithCommandTable(t *testing.T) {
	count := mustDecodeFrame(t, runCommand(t, "COMMAND", "COUNT"))
	if count.typ != ':' {
		t.Fatalf("COMMAND COUNT answered type %q, want an integer", count.typ)
	}
	table := mustDecodeFrame(t, runCommand(t, "COMMAND"))
	if count.num != int64(len(table.items)) {
		t.Fatalf("COMMAND COUNT says %d but COMMAND returns %d specs", count.num, len(table.items))
	}
	if count.num != 241 {
		t.Fatalf("COMMAND COUNT = %d, want 241 for redis 7.2.4", count.num)
	}
}

// TestCommandListAgreesWithCommandTable pins the other half of the relationship: LIST
// enumerates commands *and* subcommands, so it is legitimately larger than COUNT, and every
// name it returns must resolve through COMMAND INFO.
func TestCommandListAgreesWithCommandTable(t *testing.T) {
	list := mustDecodeFrame(t, runCommand(t, "COMMAND", "LIST"))
	if list.typ != '*' {
		t.Fatalf("COMMAND LIST answered type %q, want an array", list.typ)
	}
	if len(list.items) != 370 {
		t.Fatalf("COMMAND LIST returned %d names, want 370", len(list.items))
	}

	table := mustDecodeFrame(t, runCommand(t, "COMMAND"))
	topLevel := map[string]bool{}
	for _, e := range table.items {
		topLevel[e.items[0].str] = true
	}

	subcommands := 0
	for _, n := range list.items {
		if n.typ != '$' {
			t.Fatalf("LIST element %v must be a bulk string", n)
		}
		if !topLevel[n.str] {
			if !strings.Contains(n.str, "|") {
				t.Fatalf("LIST name %q is neither a top-level command nor a subcommand", n.str)
			}
			subcommands++
		}
		info := mustDecodeFrame(t, runCommand(t, "COMMAND", "INFO", n.str))
		if len(info.items) != 1 || info.items[0].null {
			t.Fatalf("COMMAND INFO %s returned no spec though LIST advertises it", n.str)
		}
	}
	if want := 370 - len(topLevel); subcommands != want {
		t.Fatalf("LIST held %d subcommands, want %d", subcommands, want)
	}
}

func TestCommandInfoNamed(t *testing.T) {
	get := mustDecodeFrame(t, runCommand(t, "COMMAND", "INFO", "get"))
	if len(get.items) != 1 {
		t.Fatalf("COMMAND INFO get returned %d elements, want 1", len(get.items))
	}
	spec := get.items[0]
	if spec.items[0].str != "get" || spec.items[1].num != 2 {
		t.Fatalf("COMMAND INFO get returned %v, want name get with arity 2", spec)
	}

	// Names are matched case-insensitively but answered with the canonical lowercase name.
	upper := mustDecodeFrame(t, runCommand(t, "COMMAND", "INFO", "GET"))
	if upper.items[0].items[0].str != "get" {
		t.Fatalf("COMMAND INFO GET answered %q, want the canonical \"get\"", upper.items[0].items[0].str)
	}

	// Unknown names occupy their slot with a null, they are not dropped.
	mixed := mustDecodeFrame(t, runCommand(t, "COMMAND", "INFO", "get", "nosuchcmd", "set"))
	if len(mixed.items) != 3 {
		t.Fatalf("COMMAND INFO with 3 names returned %d elements", len(mixed.items))
	}
	if !mixed.items[1].null {
		t.Fatalf("unknown command should be a null element, got %v", mixed.items[1])
	}
	if mixed.items[2].items[0].str != "set" {
		t.Fatal("the element after an unknown name is misaligned")
	}

	// Subcommands are addressable by their piped name.
	sub := mustDecodeFrame(t, runCommand(t, "COMMAND", "INFO", "config|get"))
	if sub.items[0].items[0].str != "config|get" {
		t.Fatalf("COMMAND INFO config|get returned %v", sub.items[0])
	}

	// Bare COMMAND INFO is the whole table, same as bare COMMAND.
	if !bytes.Equal(runCommand(t, "COMMAND", "INFO"), runCommand(t, "COMMAND")) {
		t.Fatal("bare COMMAND INFO must equal bare COMMAND")
	}
}

func TestCommandDocs(t *testing.T) {
	// The old handler answered an empty array here, which no real redis does.
	all := mustDecodeFrame(t, runCommand(t, "COMMAND", "DOCS"))
	if len(all.items) != 482 {
		t.Fatalf("COMMAND DOCS returned %d elements, want 482 (241 name/value pairs)", len(all.items))
	}

	named := mustDecodeFrame(t, runCommand(t, "COMMAND", "DOCS", "get", "set"))
	if len(named.items) != 4 {
		t.Fatalf("COMMAND DOCS get set returned %d elements, want 4", len(named.items))
	}
	if named.items[0].str != "get" || named.items[2].str != "set" {
		t.Fatalf("COMMAND DOCS pairs are misaligned: %v", named)
	}

	// Unknown names are omitted entirely rather than nulled, unlike INFO.
	unknown := mustDecodeFrame(t, runCommand(t, "COMMAND", "DOCS", "nosuchcmd"))
	if len(unknown.items) != 0 {
		t.Fatalf("COMMAND DOCS nosuchcmd returned %d elements, want 0", len(unknown.items))
	}
}

func TestCommandGetKeys(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"COMMAND", "GETKEYS", "GET", "foo"}, `["foo"]`},
		{[]string{"COMMAND", "GETKEYS", "SET", "k", "v"}, `["k"]`},
		{[]string{"COMMAND", "GETKEYS", "MSET", "a", "1", "b", "2"}, `["a" "b"]`},
		{[]string{"COMMAND", "GETKEYS", "ZADD", "z", "1", "m"}, `["z"]`},
		// Container commands carry the key range on the subcommand.
		{[]string{"COMMAND", "GETKEYS", "MEMORY", "USAGE", "k"}, `["k"]`},
		{[]string{"COMMAND", "GETKEYS", "OBJECT", "ENCODING", "k"}, `["k"]`},
		// Commands that locate keys through a numkeys argument answer the empty form.
		{[]string{"COMMAND", "GETKEYS", "EVAL", "return 1", "0"}, `[]`},
		// Errors.
		{[]string{"COMMAND", "GETKEYS", "PING"}, "-ERR The command has no key arguments"},
		{[]string{"COMMAND", "GETKEYS", "NOSUCH", "x"}, "-ERR Invalid command specified"},
		{[]string{"COMMAND", "GETKEYS", "GET"}, "-ERR Invalid number of arguments specified for command"},
		{[]string{"COMMAND", "GETKEYS"}, "-ERR wrong number of arguments for 'command|getkeys' command"},
	}
	for _, tc := range tests {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			got := mustDecodeFrame(t, runCommand(t, tc.args...))
			if got.String() != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCommandGetKeysAndFlags(t *testing.T) {
	got := mustDecodeFrame(t, runCommand(t, "COMMAND", "GETKEYSANDFLAGS", "GET", "foo"))
	if len(got.items) != 1 {
		t.Fatalf("expected one key, got %v", got)
	}
	pair := got.items[0]
	if len(pair.items) != 2 || pair.items[0].str != "foo" {
		t.Fatalf("expected a [key flags] pair for foo, got %v", pair)
	}
	// Key-spec flags are simple strings, replayed from the table rather than re-encoded.
	if len(pair.items[1].items) == 0 {
		t.Fatalf("expected key flags for GET, got %v", pair.items[1])
	}
	for _, f := range pair.items[1].items {
		if f.typ != '+' {
			t.Fatalf("key flag %v must be a simple string, got %q", f, f.typ)
		}
	}
}

func TestCommandListFilterBy(t *testing.T) {
	mod := mustDecodeFrame(t, runCommand(t, "COMMAND", "LIST", "FILTERBY", "MODULE", "anything"))
	if len(mod.items) != 0 {
		t.Fatalf("FILTERBY MODULE should be empty on a module-free server, got %d", len(mod.items))
	}

	pat := mustDecodeFrame(t, runCommand(t, "COMMAND", "LIST", "FILTERBY", "PATTERN", "getr*"))
	if len(pat.items) != 1 || pat.items[0].str != "getrange" {
		t.Fatalf("FILTERBY PATTERN getr* returned %v, want [getrange]", pat)
	}

	acl := mustDecodeFrame(t, runCommand(t, "COMMAND", "LIST", "FILTERBY", "ACLCAT", "read"))
	if len(acl.items) == 0 {
		t.Fatal("FILTERBY ACLCAT read returned nothing")
	}
	// The sigil belongs to the stored category, not the filter argument: a real redis
	// answers FILTERBY ACLCAT @read with an empty array.
	sigil := mustDecodeFrame(t, runCommand(t, "COMMAND", "LIST", "FILTERBY", "ACLCAT", "@read"))
	if len(sigil.items) != 0 {
		t.Fatalf("FILTERBY ACLCAT @read returned %d names, want 0", len(sigil.items))
	}

	for _, args := range [][]string{
		{"COMMAND", "LIST", "BOGUS"},
		{"COMMAND", "LIST", "FILTERBY", "BOGUS", "x"},
	} {
		got := mustDecodeFrame(t, runCommand(t, args...))
		if got.typ != '-' || got.str != "ERR syntax error" {
			t.Fatalf("%v: got %v, want -ERR syntax error", args, got)
		}
	}
}

func TestCommandHelpAndUnknownSubcommand(t *testing.T) {
	help := mustDecodeFrame(t, runCommand(t, "COMMAND", "HELP"))
	if len(help.items) != 21 {
		t.Fatalf("COMMAND HELP returned %d lines, want 21", len(help.items))
	}
	for _, line := range help.items {
		if line.typ != '+' {
			t.Fatalf("HELP line %v must be a simple string, got %q", line, line.typ)
		}
	}

	// The error echoes the caller's casing, and points at a subcommand we actually answer.
	unknown := mustDecodeFrame(t, runCommand(t, "COMMAND", "BOGUS"))
	if unknown.typ != '-' || unknown.str != "ERR unknown subcommand 'BOGUS'. Try COMMAND HELP." {
		t.Fatalf("got %v", unknown)
	}
}

// TestCommandTableResponseScope makes sure the pre-lookup intercept claims the COMMAND verb
// and nothing else: anything it swallowed by mistake would stop being admin-tunable.
func TestCommandTableResponseScope(t *testing.T) {
	for _, args := range [][]string{{"PING"}, {"INFO", "stats"}, {"KEYS", "*"}, {}} {
		var buf bytes.Buffer
		handled, err := commandTableResponse(args, &buf)
		if handled || err != nil || buf.Len() != 0 {
			t.Fatalf("%v: handled=%v err=%v wrote=%q; want false, nil, empty", args, handled, err, buf.String())
		}
	}
	// Case-insensitive on the verb, as the dispatcher is.
	var buf bytes.Buffer
	if handled, _ := commandTableResponse([]string{"command"}, &buf); !handled {
		t.Fatal("lowercase 'command' must be handled")
	}
}

// TestEveryCommandReplyIsAWellFormedFrame sweeps the whole surface and asserts each reply
// decodes completely with no trailing bytes, since these are written straight to the socket.
func TestEveryCommandReplyIsAWellFormedFrame(t *testing.T) {
	vectors := [][]string{
		{"COMMAND"},
		{"COMMAND", "COUNT"},
		{"COMMAND", "LIST"},
		{"COMMAND", "LIST", "FILTERBY", "PATTERN", "*"},
		{"COMMAND", "LIST", "FILTERBY", "ACLCAT", "dangerous"},
		{"COMMAND", "LIST", "FILTERBY", "MODULE", "x"},
		{"COMMAND", "LIST", "FILTERBY"},
		{"COMMAND", "INFO"},
		{"COMMAND", "INFO", "get"},
		{"COMMAND", "INFO", "GET", "nope", "config|get"},
		{"COMMAND", "DOCS"},
		{"COMMAND", "DOCS", "get"},
		{"COMMAND", "DOCS", "nope"},
		{"COMMAND", "GETKEYS", "MSET", "a", "1", "b", "2"},
		{"COMMAND", "GETKEYS", "PING"},
		{"COMMAND", "GETKEYSANDFLAGS", "MSET", "a", "1", "b", "2"},
		{"COMMAND", "HELP"},
		{"COMMAND", "BOGUS"},
		{"COMMAND", "docs", "GET"},
		// Adversarial argument shapes: empty strings, absurd names, a huge name.
		{"COMMAND", ""},
		{"COMMAND", "INFO", ""},
		{"COMMAND", "GETKEYS", ""},
		{"COMMAND", "DOCS", strings.Repeat("z", 5000)},
		{"COMMAND", "INFO", strings.Repeat("z", 5000)},
		{"COMMAND", "GETKEYS", "GET", strings.Repeat("k", 70000)},
	}
	for _, args := range vectors {
		name := strings.Join(args, " ")
		if len(name) > 60 {
			name = name[:60] + "..."
		}
		t.Run(name, func(t *testing.T) {
			mustDecodeFrame(t, runCommand(t, args...))
		})
	}
}

// TestCommandNeverEchoesAttackerInputIntoAName confirms the replies are assembled from the
// embedded table, not from what was sent. Only GETKEYS legitimately echoes its arguments.
func TestCommandNeverEchoesAttackerInputIntoAName(t *testing.T) {
	probe := "MARKER-\r\n*9999\r\n"
	for _, args := range [][]string{
		{"COMMAND", "INFO", probe},
		{"COMMAND", "DOCS", probe},
		{"COMMAND", "LIST", "FILTERBY", "PATTERN", probe},
	} {
		out := runCommand(t, args...)
		mustDecodeFrame(t, out)
		if bytes.Contains(out, []byte("MARKER")) {
			t.Fatalf("%v echoed attacker input into the reply: %q", args, out)
		}
	}
}
