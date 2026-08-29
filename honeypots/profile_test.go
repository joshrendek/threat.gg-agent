package honeypots

import (
	"reflect"
	"sort"
	"testing"
)

// fakeHoneypot is a minimal Honeypot used so profile_test.go never has to
// import real honeypot packages.
type fakeHoneypot struct {
	name string
}

func (f *fakeHoneypot) Start()       {}
func (f *fakeHoneypot) Name() string { return f.name }

// newFakeCatalog builds a Catalog whose constructors produce fakeHoneypots
// carrying the given names.
func newFakeCatalog(names ...string) Catalog {
	catalog := make(Catalog, len(names))
	for _, n := range names {
		n := n // capture for the closure
		catalog[n] = func() Honeypot { return &fakeHoneypot{name: n} }
	}
	return catalog
}

func namesOf(hs []Honeypot) []string {
	names := make([]string, len(hs))
	for i, h := range hs {
		names[i] = h.Name()
	}
	return names
}

// expectedDefaultNames pins today's 35-honeypot main.go registration order.
// This is the regression guard: if this list ever needs to change, that
// change must be deliberate, not an accidental reordering or drop.
var expectedDefaultNames = []string{
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
}

func TestSelect_DefaultReproducesTodaysBehavior(t *testing.T) {
	if len(expectedDefaultNames) != 35 {
		t.Fatalf("test setup error: expectedDefaultNames has %d entries, want 35", len(expectedDefaultNames))
	}

	catalog := newFakeCatalog(expectedDefaultNames...)

	got, err := Select(ProfileDefault, catalog)
	if err != nil {
		t.Fatalf("Select(%q, catalog) returned error: %v", ProfileDefault, err)
	}

	gotNames := namesOf(got)
	if !reflect.DeepEqual(gotNames, expectedDefaultNames) {
		t.Fatalf("Select(%q, catalog) names = %v, want %v", ProfileDefault, gotNames, expectedDefaultNames)
	}
}

func TestSelect_EmptyProfileMatchesDefault(t *testing.T) {
	catalog := newFakeCatalog(expectedDefaultNames...)

	wantHoneypots, err := Select(ProfileDefault, catalog)
	if err != nil {
		t.Fatalf("Select(%q, catalog) returned error: %v", ProfileDefault, err)
	}

	got, err := Select("", catalog)
	if err != nil {
		t.Fatalf(`Select("", catalog) returned error: %v`, err)
	}

	if !reflect.DeepEqual(namesOf(got), namesOf(wantHoneypots)) {
		t.Fatalf(`Select("", catalog) names = %v, want %v (same as %q)`, namesOf(got), namesOf(wantHoneypots), ProfileDefault)
	}
}

func TestSelect_UnknownProfileErrors(t *testing.T) {
	catalog := newFakeCatalog(expectedDefaultNames...)

	got, err := Select("nosuchprofile", catalog)
	if err == nil {
		t.Fatalf("Select(%q, catalog) = %v, %v; want a non-nil error", "nosuchprofile", got, err)
	}
}

func TestSelect_AllReturnsEveryCatalogEntrySortedAlphabetically(t *testing.T) {
	catalog := newFakeCatalog("zeta", "alpha", "mike")

	got, err := Select(ProfileAll, catalog)
	if err != nil {
		t.Fatalf("Select(%q, catalog) returned error: %v", ProfileAll, err)
	}

	want := []string{"alpha", "mike", "zeta"}
	if gotNames := namesOf(got); !reflect.DeepEqual(gotNames, want) {
		t.Fatalf("Select(%q, catalog) names = %v, want %v", ProfileAll, gotNames, want)
	}
}

func TestSelect_ICSIsEmptyAndNotAnError(t *testing.T) {
	catalog := newFakeCatalog(expectedDefaultNames...)

	got, err := Select(ProfileICS, catalog)
	if err != nil {
		t.Fatalf("Select(%q, catalog) returned error: %v", ProfileICS, err)
	}
	if len(got) != 0 {
		t.Fatalf("Select(%q, catalog) = %v, want an empty slice", ProfileICS, got)
	}
}

// TestProfilesReferenceKnownHoneypots guards against a profile definition
// drifting to reference a honeypot name that no other profile (and thus no
// catalog built from the profiles themselves) knows about. It builds a
// catalog from the union of every name used across every defined profile,
// then confirms Select succeeds for each profile against that union.
func TestProfilesReferenceKnownHoneypots(t *testing.T) {
	union := map[string]struct{}{}
	for _, names := range profiles {
		for _, n := range names {
			union[n] = struct{}{}
		}
	}

	unionNames := make([]string, 0, len(union))
	for n := range union {
		unionNames = append(unionNames, n)
	}
	sort.Strings(unionNames)

	catalog := newFakeCatalog(unionNames...)

	for profileName := range profiles {
		if _, err := Select(profileName, catalog); err != nil {
			t.Errorf("Select(%q, catalog) against the union-of-all-profiles catalog returned error: %v", profileName, err)
		}
	}
}

// ResolveProfile normalizes shell/config noise but must NOT rescue an actual
// typo -- a node running the wrong honeypot set is worse than one that refuses
// to start, so Select still errors on anything not a real profile name.
func TestResolveProfile_NormalizesWhitespaceAndCase(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ProfileDefault},
		{"   ", ProfileDefault},
		{"ics", ProfileICS},
		{"ICS", ProfileICS},
		{"  ics  ", ProfileICS},
		{"Default", ProfileDefault},
		{"ALL", ProfileAll},
		{"nosuch", "nosuch"},
	} {
		if got := ResolveProfile(tc.in); got != tc.want {
			t.Errorf("ResolveProfile(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSelect_AcceptsNormalizableProfileNames(t *testing.T) {
	cat := newFakeCatalog(expectedDefaultNames...)
	for _, in := range []string{"ICS", " ics ", "Ics"} {
		got, err := Select(in, cat)
		if err != nil {
			t.Errorf("Select(%q) unexpected error: %v", in, err)
			continue
		}
		if len(got) != 0 {
			t.Errorf("Select(%q) = %d honeypots, want 0 (ics is empty)", in, len(got))
		}
	}
	if _, err := Select("  nosuchprofile  ", cat); err == nil {
		t.Error("Select with a trimmed-but-unknown profile should still error")
	}
}
