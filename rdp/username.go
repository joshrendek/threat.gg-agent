package rdp

import (
	"net"
	"strings"
)

var invalidRdpUsernames = map[string]struct{}{
	"hello": {},
}

func sanitizeRdpUsername(candidate string) string {
	normalized := strings.TrimSpace(candidate)
	if normalized == "" {
		return ""
	}

	if _, invalid := invalidRdpUsernames[strings.ToLower(normalized)]; invalid {
		return ""
	}

	if net.ParseIP(normalized) != nil {
		return ""
	}

	return normalized
}
