package ldap

import "strings"

type directoryEntry struct {
	dn         string
	attributes map[string][]string
}

var rootDSE = directoryEntry{
	dn: "",
	attributes: map[string][]string{
		"namingContexts":                {"dc=corp,dc=com"},
		"defaultNamingContext":          {"dc=corp,dc=com"},
		"supportedLDAPVersion":         {"3"},
		"dnsHostName":                  {"dc01.corp.com"},
		"serverName":                   {"CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,dc=corp,dc=com"},
		"supportedSASLMechanisms":      {"GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"},
		"isGlobalCatalogReady":         {"TRUE"},
		"forestFunctionality":          {"7"},
		"domainFunctionality":          {"7"},
		"domainControllerFunctionality": {"7"},
	},
}

var fakeEntries = []directoryEntry{
	{
		dn: "CN=Administrator,CN=Users,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user"},
			"cn":                 {"Administrator"},
			"sAMAccountName":     {"Administrator"},
			"userPrincipalName":  {"Administrator@corp.com"},
			"userAccountControl": {"512"},
			"memberOf":           {"CN=Domain Admins,CN=Users,dc=corp,dc=com", "CN=Enterprise Admins,CN=Users,dc=corp,dc=com"},
		},
	},
	{
		dn: "CN=Domain Admins,CN=Users,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":    {"top", "group"},
			"cn":             {"Domain Admins"},
			"sAMAccountName": {"Domain Admins"},
			"member":         {"CN=Administrator,CN=Users,dc=corp,dc=com"},
		},
	},
	{
		dn: "CN=svc-backup,OU=ServiceAccounts,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":          {"top", "person", "organizationalPerson", "user"},
			"cn":                   {"svc-backup"},
			"sAMAccountName":       {"svc-backup"},
			"userPrincipalName":    {"svc-backup@corp.com"},
			"servicePrincipalName": {"CIFS/fileserver01.corp.com", "HOST/fileserver01.corp.com"},
			"userAccountControl":   {"66048"},
		},
	},
	{
		dn: "CN=svc-sql,OU=ServiceAccounts,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":          {"top", "person", "organizationalPerson", "user"},
			"cn":                   {"svc-sql"},
			"sAMAccountName":       {"svc-sql"},
			"userPrincipalName":    {"svc-sql@corp.com"},
			"servicePrincipalName": {"MSSQLSvc/sqlserver01.corp.com:1433", "MSSQLSvc/sqlserver01.corp.com"},
			"userAccountControl":   {"66048"},
		},
	},
	{
		dn: "CN=svc-web,OU=ServiceAccounts,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":          {"top", "person", "organizationalPerson", "user"},
			"cn":                   {"svc-web"},
			"sAMAccountName":       {"svc-web"},
			"userPrincipalName":    {"svc-web@corp.com"},
			"servicePrincipalName": {"HTTP/webapp01.corp.com"},
			"userAccountControl":   {"66048"},
		},
	},
	{
		dn: "CN=john.smith,CN=Users,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user"},
			"cn":                 {"john.smith"},
			"sAMAccountName":     {"john.smith"},
			"userPrincipalName":  {"john.smith@corp.com"},
			"userAccountControl": {"512"},
			"memberOf":           {"CN=Domain Users,CN=Users,dc=corp,dc=com"},
		},
	},
	{
		dn: "CN=jane.doe,CN=Users,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user"},
			"cn":                 {"jane.doe"},
			"sAMAccountName":     {"jane.doe"},
			"userPrincipalName":  {"jane.doe@corp.com"},
			"userAccountControl": {"512"},
			"memberOf":           {"CN=Domain Users,CN=Users,dc=corp,dc=com"},
		},
	},
	{
		dn: "CN=DC01,CN=Computers,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "computer"},
			"cn":                 {"DC01"},
			"sAMAccountName":     {"DC01$"},
			"dNSHostName":        {"dc01.corp.com"},
			"userAccountControl": {"532480"},
		},
	},
	{
		dn: "CN=FILESERVER01,CN=Computers,dc=corp,dc=com",
		attributes: map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "computer"},
			"cn":                 {"FILESERVER01"},
			"sAMAccountName":     {"FILESERVER01$"},
			"dNSHostName":        {"fileserver01.corp.com"},
			"userAccountControl": {"4096"},
		},
	},
}

func getRootDSE() directoryEntry {
	return rootDSE
}

// searchEntries returns matching entries for the given search parameters.
// scope: "base" (0), "one" (1), "sub" (2)
func searchEntries(baseDN, filter, scope string) []directoryEntry {
	var results []directoryEntry
	for _, entry := range fakeEntries {
		if matchFilter(entry, filter) {
			results = append(results, entry)
		}
	}
	return results
}

// matchFilter does basic LDAP filter matching against an entry's attributes.
// Supports simple equality (attr=value), presence (attr=*), and compound filters.
func matchFilter(entry directoryEntry, filter string) bool {
	// Strip outer parens
	f := filter
	for len(f) > 0 && f[0] == '(' && f[len(f)-1] == ')' {
		f = f[1 : len(f)-1]
	}

	// Handle AND filter (&(filter1)(filter2)...)
	if len(f) > 0 && f[0] == '&' {
		return matchAndFilter(entry, f[1:])
	}

	// Handle OR filter (|(filter1)(filter2)...)
	if len(f) > 0 && f[0] == '|' {
		return matchOrFilter(entry, f[1:])
	}

	// Simple equality or presence filter: attr=value or attr=*
	parts := splitFilter(f)
	if len(parts) != 2 {
		return true // unknown filter, match everything
	}
	attr := parts[0]
	value := parts[1]

	vals, ok := entry.attributes[attr]
	if !ok {
		// Case-insensitive attribute name lookup
		for k, v := range entry.attributes {
			if strings.EqualFold(k, attr) {
				vals = v
				ok = true
				break
			}
		}
	}
	if !ok {
		return false
	}

	if value == "*" {
		return true // presence check
	}

	for _, v := range vals {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

func splitFilter(f string) []string {
	idx := strings.IndexByte(f, '=')
	if idx < 0 {
		return nil
	}
	return []string{f[:idx], f[idx+1:]}
}

func matchAndFilter(entry directoryEntry, f string) bool {
	filters := extractSubFilters(f)
	for _, sub := range filters {
		if !matchFilter(entry, sub) {
			return false
		}
	}
	return true
}

func matchOrFilter(entry directoryEntry, f string) bool {
	filters := extractSubFilters(f)
	for _, sub := range filters {
		if matchFilter(entry, sub) {
			return true
		}
	}
	return len(filters) == 0
}

func extractSubFilters(f string) []string {
	var filters []string
	depth := 0
	start := -1
	for i, c := range f {
		if c == '(' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if c == ')' {
			depth--
			if depth == 0 && start >= 0 {
				filters = append(filters, f[start:i+1])
				start = -1
			}
		}
	}
	return filters
}
