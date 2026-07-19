package ldap

import (
	"strings"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
)

// parseLDIF parses an admin-authored LDIF response into directory entries the honeypot can
// replay. Entries are separated by blank lines; a "dn:" line starts an entry and each
// subsequent "attr: value" line adds an attribute (repeatable for multi-valued attributes).
// Comment lines ("#..."), malformed lines, and anything before the first "dn:" are ignored.
// Returns nil when no entries are found. This lets admins author plain LDIF while the
// honeypot handles the BER wire framing (via the ldap library).
func parseLDIF(ldif string) []directoryEntry {
	var entries []directoryEntry
	var cur *directoryEntry

	for _, raw := range strings.Split(ldif, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			cur = nil // blank line ends the current entry
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if strings.EqualFold(key, "dn") {
			entries = append(entries, directoryEntry{dn: val, attributes: map[string][]string{}})
			cur = &entries[len(entries)-1]
			continue
		}
		if cur == nil { // an attribute line before any dn is ignored
			continue
		}
		cur.attributes[key] = append(cur.attributes[key], val)
	}

	return entries
}

// ldapSearchOverride consults the admin-editable command_responses (scoped to
// command_type="ldap") for a search, keyed by "baseDN filter". It returns the parsed
// entries and ok=true on a Matched row, or (nil, false) on a miss/error/oversized key so
// the caller falls back to the hardcoded fake directory.
func ldapSearchOverride(baseDN, filter string) ([]directoryEntry, bool) {
	resp, ok := cmdresp.Lookup("ldap", baseDN+" "+filter)
	if !ok {
		return nil, false
	}
	return parseLDIF(resp), true
}
