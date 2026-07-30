package redis

import (
	_ "embed"
	"fmt"
	"io"
	"strings"
)

// The COMMAND family used to answer `:20` — a RESP integer where the protocol requires an
// array of command specs. Every client that parses the reply errors out on the type
// mismatch, which is a hard tell on the first handshake a modern client makes.
//
// A faithful reply is the full command table: 241 top-level commands for 7.2.4, each a
// ten-field array whose scalars are a specific mix of RESP types that is not guessable —
// the flags and ACL categories are SIMPLE strings, the tips are BULK strings, and the
// key_specs are nested four deep. Hand-authoring that is how you ship a malformed frame,
// and a malformed frame is worse than the wrong-but-parseable integer we started with.
//
// So the table is not hand-authored. commandtable_7.2.4.resp and commanddocs_7.2.4.resp are
// the exact bytes `COMMAND` and `COMMAND DOCS` produced on a real redis:7.2.4, captured off
// the wire and decode-verified. COUNT, LIST, INFO <name> and DOCS <name> are all sliced out
// of those same bytes, so the count can never drift from the number of entries the table
// actually contains — the specific failure this replaces.
//
// The persona these describe (7.2.4) matches redis_version in buildInfoResponse.

//go:embed commandtable_7.2.4.resp
var commandTableFrame []byte

//go:embed commanddocs_7.2.4.resp
var commandDocsFrame []byte

// commandSpec is the indexed view of one entry in the embedded table. frame is the entry's
// original bytes, replayed verbatim by COMMAND INFO; the scalars are decoded only so that
// COUNT/LIST/GETKEYS can be derived rather than restated.
type commandSpec struct {
	name     string // canonical lowercase; subcommands are "parent|sub", as redis names them
	frame    []byte // the exact ten-field RESP frame real redis emits for this command
	arity    int
	firstKey int
	lastKey  int
	step     int
	aclCats  []string
	keyFlags []byte // raw RESP array frame of the first key spec's flags, nil when none
	hasSpecs bool   // declares key specs, so it can take keys even with firstKey == 0
}

var (
	// commandTopLevel holds only the top-level commands: this is what COMMAND COUNT counts.
	commandTopLevel []*commandSpec
	// commandListNames holds top-level commands *and* subcommands, which is the larger set
	// COMMAND LIST enumerates (241 + 129 = 370 on 7.2.4).
	commandListNames  []string
	commandByName     = map[string]*commandSpec{}
	commandDocsByName = map[string][]byte{}
	// commandTableErr is non-nil only if the embedded fixtures fail to parse, which is a
	// build-time defect. TestCommandTableFixturesParse fails loudly if that ever happens.
	commandTableErr error
)

func init() {
	commandTableErr = loadCommandTable()
}

func loadCommandTable() error {
	entries, err := respElements(commandTableFrame)
	if err != nil {
		return fmt.Errorf("command table: %w", err)
	}
	for i, raw := range entries {
		spec, subs, err := parseCommandSpec(raw)
		if err != nil {
			return fmt.Errorf("command table entry %d: %w", i, err)
		}
		commandTopLevel = append(commandTopLevel, spec)
		for _, s := range append([]*commandSpec{spec}, subs...) {
			commandByName[s.name] = s
			commandListNames = append(commandListNames, s.name)
		}
	}

	docs, err := respElements(commandDocsFrame)
	if err != nil {
		return fmt.Errorf("command docs: %w", err)
	}
	if len(docs)%2 != 0 {
		return fmt.Errorf("%w: command docs has %d elements, want name/value pairs", errBadFrame, len(docs))
	}
	for i := 0; i < len(docs); i += 2 {
		name, ok := respBulkValue(docs[i])
		if !ok {
			return fmt.Errorf("%w: command docs name %d is not a bulk string", errBadFrame, i)
		}
		commandDocsByName[name] = docs[i+1]
	}
	return nil
}

// parseCommandSpec decodes one ten-field COMMAND entry, returning the entry itself and the
// specs of any subcommands nested in its tenth field.
func parseCommandSpec(raw []byte) (*commandSpec, []*commandSpec, error) {
	fields, err := respElements(raw)
	if err != nil {
		return nil, nil, err
	}
	if len(fields) != 10 {
		return nil, nil, fmt.Errorf("%w: %d fields, want 10", errBadFrame, len(fields))
	}

	name, ok := respBulkValue(fields[0])
	if !ok {
		return nil, nil, fmt.Errorf("%w: name is not a bulk string", errBadFrame)
	}
	arity, ok := respIntValue(fields[1])
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s arity is not an integer", errBadFrame, name)
	}
	firstKey, ok1 := respIntValue(fields[3])
	lastKey, ok2 := respIntValue(fields[4])
	step, ok3 := respIntValue(fields[5])
	if !ok1 || !ok2 || !ok3 {
		return nil, nil, fmt.Errorf("%w: %s key range is not integral", errBadFrame, name)
	}

	spec := &commandSpec{
		name:     name,
		frame:    raw,
		arity:    int(arity),
		firstKey: int(firstKey),
		lastKey:  int(lastKey),
		step:     int(step),
	}

	cats, err := respElements(fields[6])
	if err != nil {
		return nil, nil, fmt.Errorf("%s acl categories: %w", name, err)
	}
	for _, c := range cats {
		if v, ok := respSimpleValue(c); ok {
			spec.aclCats = append(spec.aclCats, v)
		}
	}

	keySpecs, err := respElements(fields[8])
	if err != nil {
		return nil, nil, fmt.Errorf("%s key specs: %w", name, err)
	}
	spec.hasSpecs = len(keySpecs) > 0
	if len(keySpecs) > 0 {
		spec.keyFlags = keySpecFlags(keySpecs[0])
	}

	subFrames, err := respElements(fields[9])
	if err != nil {
		return nil, nil, fmt.Errorf("%s subcommands: %w", name, err)
	}
	var subs []*commandSpec
	for _, sf := range subFrames {
		sub, nested, err := parseCommandSpec(sf)
		if err != nil {
			return nil, nil, fmt.Errorf("%s subcommand: %w", name, err)
		}
		subs = append(subs, sub)
		subs = append(subs, nested...)
	}
	return spec, subs, nil
}

// keySpecFlags pulls the raw flags array out of a key spec, which is a flat sequence of
// name/value pairs ("flags", <array>, "begin_search", <array>, ...). Returned verbatim so
// COMMAND GETKEYSANDFLAGS re-emits real redis's simple-string flag names untouched.
func keySpecFlags(spec []byte) []byte {
	pairs, err := respElements(spec)
	if err != nil {
		return nil
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		if k, ok := respBulkValue(pairs[i]); ok && k == "flags" {
			return pairs[i+1]
		}
	}
	return nil
}

// commandTableResponse answers the COMMAND verb from the compiled table, and it runs BEFORE
// the admin-authored command_responses lookup.
//
// That ordering is deliberate and is the fix for the second half of this defect. COMMAND
// COUNT must equal the number of entries bare COMMAND actually returns, and only the binary
// knows how many that is. A static row cannot know, and the seeded row did in fact disagree
// (it asserted :240 against a table of 241). Two of our own answers contradicting each other
// is detectable with two requests to us alone, whereas the exact value is only checkable
// against a real reference — so the invariant is made structural here rather than left to
// whatever a row happens to say.
func commandTableResponse(args []string, w io.Writer) (bool, error) {
	if len(args) == 0 || !strings.EqualFold(args[0], "COMMAND") {
		return false, nil
	}
	return true, writeCommandFamily(args, w)
}

func writeCommandFamily(args []string, w io.Writer) error {
	if commandTableErr != nil {
		// Embedded fixtures failed to parse (a build-time defect the tests guard against).
		// Emit a well-formed empty array: still wrong, but parseable, so the client stays
		// in sync instead of desynchronising on a half-written frame.
		return writeArray(w, nil)
	}

	if len(args) == 1 {
		return writeRawFrame(w, commandTableFrame)
	}

	switch strings.ToUpper(args[1]) {
	case "COUNT":
		return writeInteger(w, int64(len(commandTopLevel)))
	case "LIST":
		return writeCommandList(args[2:], w)
	case "INFO":
		return writeCommandInfo(args[2:], w)
	case "DOCS":
		return writeCommandDocs(args[2:], w)
	case "GETKEYS":
		return writeCommandGetKeys(args[2:], w, false)
	case "GETKEYSANDFLAGS":
		return writeCommandGetKeys(args[2:], w, true)
	case "HELP":
		return writeSimpleStringArray(w, commandHelpLines)
	default:
		// Real redis echoes the caller's casing back in this error.
		return writeError(w, fmt.Sprintf("unknown subcommand '%s'. Try COMMAND HELP.", args[1]))
	}
}

// writeCommandInfo replays the stored entry for each named command. Unknown names get a
// null element, exactly as real redis does, rather than being dropped from the array.
func writeCommandInfo(names []string, w io.Writer) error {
	if len(names) == 0 {
		// Bare COMMAND INFO is the whole table, identical to bare COMMAND.
		return writeRawFrame(w, commandTableFrame)
	}
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(names)); err != nil {
		return err
	}
	for _, name := range names {
		spec, ok := commandByName[strings.ToLower(name)]
		if !ok {
			if err := writeNullBulkString(w); err != nil {
				return err
			}
			continue
		}
		if err := writeRawFrame(w, spec.frame); err != nil {
			return err
		}
	}
	return nil
}

// writeCommandDocs emits name/doc pairs. Unlike INFO, real redis omits unknown names
// entirely instead of emitting a null, so the array length depends on how many resolved.
func writeCommandDocs(names []string, w io.Writer) error {
	if len(names) == 0 {
		return writeRawFrame(w, commandDocsFrame)
	}
	type pair struct {
		name string
		doc  []byte
	}
	found := make([]pair, 0, len(names))
	for _, name := range names {
		canonical := strings.ToLower(name)
		if doc, ok := commandDocsByName[canonical]; ok {
			found = append(found, pair{canonical, doc})
		}
	}
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(found)*2); err != nil {
		return err
	}
	for _, p := range found {
		if err := writeBulkString(w, p.name); err != nil {
			return err
		}
		if err := writeRawFrame(w, p.doc); err != nil {
			return err
		}
	}
	return nil
}

func writeCommandList(args []string, w io.Writer) error {
	if len(args) == 0 {
		return writeArray(w, commandListNames)
	}
	if len(args) != 3 || !strings.EqualFold(args[0], "FILTERBY") {
		return writeError(w, "syntax error")
	}

	switch strings.ToUpper(args[1]) {
	case "MODULE":
		// We load no modules, so no command can belong to one.
		return writeArray(w, nil)
	case "ACLCAT":
		// Stored categories carry the "@" sigil; the filter argument does not, which is
		// why a real redis answers FILTERBY ACLCAT @read with an empty array.
		want := "@" + strings.ToLower(args[2])
		var out []string
		for _, name := range commandListNames {
			for _, cat := range commandByName[name].aclCats {
				if cat == want {
					out = append(out, name)
					break
				}
			}
		}
		return writeArray(w, out)
	case "PATTERN":
		return writeArray(w, globFilter(commandListNames, args[2]))
	default:
		return writeError(w, "syntax error")
	}
}

// writeCommandGetKeys extracts the keys of a full command from the table's legacy
// first/last/step key range.
//
// Limitation, stated rather than hidden: seventeen commands (EVAL, ZUNION, LMPOP, XREAD and
// friends) declare firstkey 0 and locate their keys through a numkeys argument instead. We
// do not walk those key specs, so they get the empty-key answer — which is what a real redis
// returns for the numkeys=0 form, and wrong only for the rarer non-zero form. Nothing here
// executes or evaluates the command it is asked about.
func writeCommandGetKeys(args []string, w io.Writer, withFlags bool) error {
	verb := "command|getkeys"
	if withFlags {
		verb = "command|getkeysandflags"
	}
	if len(args) == 0 {
		return writeError(w, fmt.Sprintf("wrong number of arguments for '%s' command", verb))
	}

	spec, ok := commandByName[strings.ToLower(args[0])]
	if !ok {
		return writeError(w, "Invalid command specified")
	}
	if len(args) >= 2 {
		// Container commands (MEMORY USAGE, OBJECT ENCODING, ...) carry their key range on
		// the subcommand, indexed against the full argument vector.
		if sub, subOK := commandByName[strings.ToLower(args[0])+"|"+strings.ToLower(args[1])]; subOK {
			spec = sub
		}
	}
	if (spec.arity >= 0 && len(args) != spec.arity) || (spec.arity < 0 && len(args) < -spec.arity) {
		return writeError(w, "Invalid number of arguments specified for command")
	}
	if spec.firstKey <= 0 {
		if !spec.hasSpecs {
			return writeError(w, "The command has no key arguments")
		}
		return writeArray(w, nil)
	}

	last := spec.lastKey
	if last < 0 {
		last = len(args) + last
	}
	step := spec.step
	if step <= 0 {
		step = 1
	}
	var keys []string
	for i := spec.firstKey; i <= last && i < len(args); i += step {
		keys = append(keys, args[i])
	}

	if !withFlags {
		return writeArray(w, keys)
	}
	if _, err := fmt.Fprintf(w, "*%d\r\n", len(keys)); err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := fmt.Fprint(w, "*2\r\n"); err != nil {
			return err
		}
		if err := writeBulkString(w, key); err != nil {
			return err
		}
		flags := spec.keyFlags
		if flags == nil {
			if err := writeArray(w, nil); err != nil {
				return err
			}
			continue
		}
		if err := writeRawFrame(w, flags); err != nil {
			return err
		}
	}
	return nil
}

// commandHelpLines is the 7.2.4 COMMAND HELP text. Real redis returns it as an array of
// simple strings; the array header is computed from the slice, never written by hand.
var commandHelpLines = []string{
	"COMMAND <subcommand> [<arg> [value] [opt] ...]. Subcommands are:",
	"(no subcommand)",
	"    Return details about all Redis commands.",
	"COUNT",
	"    Return the total number of commands in this Redis server.",
	"LIST",
	"    Return a list of all commands in this Redis server.",
	"INFO [<command-name> ...]",
	"    Return details about multiple Redis commands.",
	"    If no command names are given, documentation details for all",
	"    commands are returned.",
	"DOCS [<command-name> ...]",
	"    Return documentation details about multiple Redis commands.",
	"    If no command names are given, documentation details for all",
	"    commands are returned.",
	"GETKEYS <full-command>",
	"    Return the keys from a full Redis command.",
	"GETKEYSANDFLAGS <full-command>",
	"    Return the keys and the access flags from a full Redis command.",
	"HELP",
	"    Print this help.",
}
