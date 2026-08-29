package main

import (
	"testing"

	"github.com/joshrendek/threat.gg-agent/honeypots"
)

// The catalog and the profile definitions live in different packages and
// nothing links them at compile time: honeypots/profile.go lists NAMES, main.go
// supplies CONSTRUCTORS for those names. A typo or omission on either side is
// invisible until runtime -- and because an unresolvable profile is fatal at
// startup, that runtime is every node in the fleet, simultaneously, on the next
// auto-update. These tests are the compile-time-ish guard standing in for that.
func TestCatalogResolvesEveryDefinedProfile(t *testing.T) {
	cat := catalog()
	for _, profile := range []string{honeypots.ProfileDefault, honeypots.ProfileICS, honeypots.ProfileAll} {
		selected, err := honeypots.Select(profile, cat)
		if err != nil {
			t.Errorf("Select(%q) against the real catalog failed: %v", profile, err)
			continue
		}
		for i, h := range selected {
			if h == nil {
				t.Errorf("Select(%q): entry %d is a nil Honeypot", profile, i)
			}
		}
	}
}

// Every constructor must actually build something. A nil entry in the map, or a
// constructor returning a nil interface, would panic in StartHoneypots.
func TestCatalogConstructorsAreUsable(t *testing.T) {
	for name, ctor := range catalog() {
		if ctor == nil {
			t.Errorf("catalog[%q] has a nil constructor", name)
			continue
		}
		if h := ctor(); h == nil {
			t.Errorf("catalog[%q] constructor returned nil", name)
		}
	}
}

// The default profile is the whole catalog today. That will stop being true the
// moment an ICS-only honeypot is added, at which point this assertion should be
// changed deliberately rather than deleted -- it exists to make "I added a
// honeypot to the catalog and forgot to put it in any profile" a test failure
// instead of a honeypot that silently never starts.
func TestEveryCatalogEntryIsReachableFromSomeProfile(t *testing.T) {
	cat := catalog()
	reached := map[string]bool{}
	for _, profile := range []string{honeypots.ProfileDefault, honeypots.ProfileICS} {
		names, err := honeypots.ProfileNames(profile, cat)
		if err != nil {
			t.Fatalf("ProfileNames(%q): %v", profile, err)
		}
		for _, n := range names {
			reached[n] = true
		}
	}
	for name := range cat {
		if !reached[name] {
			t.Errorf("catalog entry %q is in no profile, so it can only ever start via HONEYPOT_PROFILE=all", name)
		}
	}
}
