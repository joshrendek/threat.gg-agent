package kubernetes

import "testing"

func TestResolvePortDefault(t *testing.T) {
	if port := resolvePort(); port != defaultPort {
		t.Fatalf("expected default port %q, got %q", defaultPort, port)
	}
}

func TestResolvePortOverride(t *testing.T) {
	t.Setenv("KUBERNETES_HONEYPOT_PORT", "16443")

	if port := resolvePort(); port != "16443" {
		t.Fatalf("expected overridden port %q, got %q", "16443", port)
	}
}
