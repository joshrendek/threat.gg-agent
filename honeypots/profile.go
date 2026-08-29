package honeypots

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Profile name constants. Pass one via HONEYPOT_PROFILE, or leave it unset to
// get ProfileDefault.
const (
	ProfileDefault = "default"
	ProfileICS     = "ics"
	ProfileAll     = "all"
)

// Catalog maps a honeypot's name to its constructor.
type Catalog map[string]func() Honeypot

// profiles maps a profile name to the ordered list of honeypot names it starts.
// ProfileAll is intentionally absent here: it is computed dynamically from
// whatever Catalog is passed to Select, so it can never drift from the set of
// honeypots actually registered in main.go.
var profiles = map[string][]string{
	// ProfileDefault reproduces the exact set and order of honeypots.Register
	// calls that main.go made before profile support existed.
	ProfileDefault: {
		"kubernetes",
		"kubelet",
		"consul",
		"amqp",
		"adb",
		"postgres",
		"elasticsearch",
		"ftp",
		"sshd",
		"openclaw",
		"kafka",
		"redis",
		"mqtt",
		"mysql",
		"mssql",
		"docker",
		"etcd",
		"smb",
		"ldap",
		"telnet",
		"rdp",
		"vnc",
		"smtp",
		"jenkins",
		"mongo",
		"memcached",
		"vllm",
		"ollama",
		"ray",
		"localai",
		"lmstudio",
		"llamacpp",
		"comfyui",
		"mcp",
		"s3",
	},

	// ProfileICS is the industrial/OT honeypot profile. It is intentionally
	// empty for now (no OT protocol honeypots exist yet, e.g. Modbus, S7comm,
	// DNP3) - a follow-up change will populate it. It is defined explicitly
	// here, rather than left as a missing key, so selecting it is valid and
	// simply starts nothing.
	ProfileICS: {},
}

// Select resolves profile to an ordered list of constructed Honeypots.
//
// An empty profile means ProfileDefault. An unrecognized profile name is an
// error rather than a silent fallback to the default, so a typo in
// HONEYPOT_PROFILE fails loudly at startup instead of quietly running the
// wrong set. Similarly, a profile that names a honeypot missing from catalog
// is an error naming the missing entry.
//
// ProfileAll returns every entry in catalog, sorted alphabetically by name so
// the result is deterministic.
func Select(profile string, catalog Catalog) ([]Honeypot, error) {
	name := ResolveProfile(profile)
	names, err := ProfileNames(profile, catalog)
	if err != nil {
		return nil, err
	}

	selected := make([]Honeypot, 0, len(names))
	for _, n := range names {
		ctor, ok := catalog[n]
		if !ok {
			return nil, fmt.Errorf("honeypots: profile %q references honeypot %q, which is not in the catalog", name, n)
		}
		selected = append(selected, ctor())
	}
	return selected, nil
}

// ProfileNames resolves profile to the ordered catalog names it selects.
//
// Callers that only need to report which honeypots a profile covers should use
// this rather than constructing them and reading Name(): the catalog key is the
// identifier HONEYPOT_PROFILE actually references, it is unique by
// construction, and it does not depend on each honeypot reporting itself
// correctly -- postgres currently returns "ssh" from Name().
func ProfileNames(profile string, catalog Catalog) ([]string, error) {
	name := ResolveProfile(profile)
	if name == ProfileAll {
		return sortedCatalogNames(catalog), nil
	}
	list, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("honeypots: unknown profile %q", name)
	}
	out := make([]string, len(list))
	copy(out, list)
	return out, nil
}

func sortedCatalogNames(catalog Catalog) []string {
	names := make([]string, 0, len(catalog))
	for n := range catalog {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ProfileFromEnv reads the honeypot profile to run from HONEYPOT_PROFILE.
func ProfileFromEnv() string {
	return os.Getenv("HONEYPOT_PROFILE")
}

// ResolveProfile normalizes a raw profile string to the name Select will look
// up: surrounding whitespace trimmed, lowercased, and empty meaning
// ProfileDefault.
//
// Normalizing is deliberately narrow. An unknown profile still fails loudly in
// Select, because a node silently running the wrong honeypot set is worse than
// a node that refuses to start. But " ics" or "ICS" is not a typo -- it is the
// right answer with shell or config whitespace and casing around it, and
// fataling a node over that would take it dark for no benefit.
func ResolveProfile(profile string) string {
	name := strings.ToLower(strings.TrimSpace(profile))
	if name == "" {
		return ProfileDefault
	}
	return name
}
