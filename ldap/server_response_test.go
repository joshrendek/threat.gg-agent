package ldap

import (
	"testing"

	"github.com/joshrendek/threat.gg-agent/cmdresp"
	"github.com/joshrendek/threat.gg-agent/proto"
)

// TestParseLDIF: an admin authors LDAP search results as LDIF text; parseLDIF turns it into
// directory entries the honeypot replays. Entries are blank-line separated; "dn:" starts an
// entry; "attr: value" adds an attribute (repeatable for multi-valued). Junk before the
// first dn and malformed lines are ignored; empty input yields no entries.
func TestParseLDIF(t *testing.T) {
	ldif := `# a comment before any dn is ignored
dn: cn=admin,dc=corp,dc=com
objectClass: person
cn: admin
mail: admin@corp.com
mail: admin@alt.corp.com

dn: cn=svc,dc=corp,dc=com
cn: svc
`
	entries := parseLDIF(ldif)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].dn != "cn=admin,dc=corp,dc=com" {
		t.Fatalf("entry0 dn = %q", entries[0].dn)
	}
	if got := entries[0].attributes["mail"]; len(got) != 2 {
		t.Fatalf("entry0 mail = %v, want 2 values", got)
	}
	if entries[0].attributes["cn"][0] != "admin" {
		t.Fatalf("entry0 cn = %v", entries[0].attributes["cn"])
	}
	if entries[1].dn != "cn=svc,dc=corp,dc=com" {
		t.Fatalf("entry1 dn = %q", entries[1].dn)
	}

	if parseLDIF("   \n\n") != nil {
		t.Fatal("blank input should yield nil entries")
	}
}

// TestLDAPSearchOverride: the seam is scoped to command_type="ldap" and keyed by
// "baseDN filter"; a Matched row yields the parsed entries (ok=true), a miss yields
// ok=false so the caller falls back to the hardcoded fake directory.
func TestLDAPSearchOverride(t *testing.T) {
	orig := cmdresp.GetCommandResponse
	defer func() { cmdresp.GetCommandResponse = orig }()

	cmdresp.GetCommandResponse = func(in *proto.CommandRequest) (*proto.CommandResponse, error) {
		if in.CommandType != "ldap" || in.Command != "dc=corp,dc=com (objectClass=*)" {
			t.Fatalf("forwarded (%q,%q), want (ldap, baseDN+filter)", in.CommandType, in.Command)
		}
		return &proto.CommandResponse{Response: "dn: cn=x,dc=corp,dc=com\ncn: x\n", Matched: true}, nil
	}
	entries, ok := ldapSearchOverride("dc=corp,dc=com", "(objectClass=*)")
	if !ok || len(entries) != 1 || entries[0].dn != "cn=x,dc=corp,dc=com" {
		t.Fatalf("matched: ok=%v entries=%v, want one parsed entry", ok, entries)
	}

	cmdresp.GetCommandResponse = func(*proto.CommandRequest) (*proto.CommandResponse, error) {
		return &proto.CommandResponse{Matched: false}, nil
	}
	if _, ok := ldapSearchOverride("dc=corp,dc=com", "(objectClass=*)"); ok {
		t.Fatal("miss: ok=true, want false")
	}
}
