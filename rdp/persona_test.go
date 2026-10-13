package rdp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreatePersonaCreatesStableIdentity(t *testing.T) {
	dir := t.TempDir()
	first, err := loadOrCreatePersona(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.id == "" || first.domain != rdpPersonaDomain || first.createdAt.IsZero() {
		t.Fatalf("persona has incomplete identity: %#v", first)
	}
	if !validRDPHostname(first.hostname) || first.hostname != strings.ToUpper(first.hostname) {
		t.Fatalf("invalid generated hostname %q", first.hostname)
	}
	if len(first.tlsCert.Certificate) != 1 {
		t.Fatalf("certificate chain length = %d, want 1", len(first.tlsCert.Certificate))
	}

	second, err := loadOrCreatePersona(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.id != second.id || first.hostname != second.hostname || first.domain != second.domain {
		t.Fatal("persona identity changed across reload")
	}
	if string(first.certPEM) != string(second.certPEM) || string(first.keyPEM) != string(second.keyPEM) {
		t.Fatal("certificate material changed across reload")
	}
	if !first.createdAt.Equal(second.createdAt) {
		t.Fatal("persona creation time changed across reload")
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("persona directory mode = %04o, want 0700", got)
	}
	fileInfo, err := os.Stat(filepath.Join(dir, rdpPersonaFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("persona file mode = %04o, want 0600", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != rdpPersonaFile {
		t.Fatalf("persona directory contains unexpected files: %v", entries)
	}
}

func TestLoadOrCreatePersonaCertificateIdentity(t *testing.T) {
	persona, err := loadOrCreatePersona(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(persona.tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Subject.CommonName != persona.hostname {
		t.Fatalf("certificate CN = %q, want %q", certificate.Subject.CommonName, persona.hostname)
	}
	if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != persona.hostname {
		t.Fatalf("certificate DNS SANs = %v, want [%q]", certificate.DNSNames, persona.hostname)
	}
	if err := certificate.VerifyHostname(persona.hostname); err != nil {
		t.Fatalf("certificate does not verify for hostname: %v", err)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if certificate.PublicKeyAlgorithm != x509.RSA || !ok || publicKey.N.BitLen() != 2048 {
		t.Fatalf("unexpected certificate public key")
	}
}

func TestLoadOrCreatePersonaRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreatePersona(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, rdpPersonaFile)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*persistedRDPPersona){
		"version": func(p *persistedRDPPersona) { p.Version++ },
		"uuid":    func(p *persistedRDPPersona) { p.PersonaID = "not-a-uuid" },
		"hostname": func(p *persistedRDPPersona) {
			p.Hostname = "not safe"
		},
		"domain":   func(p *persistedRDPPersona) { p.Domain = strings.Repeat("X", maxRDPDomainLength+1) },
		"key pair": func(p *persistedRDPPersona) { p.KeyPEM = "not a private key" },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate persistedRDPPersona
			if err := json.Unmarshal(original, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadOrCreatePersona(dir); err == nil {
				t.Fatal("loadOrCreatePersona accepted corrupt state")
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadOrCreatePersonaUsesIndependentIdentities(t *testing.T) {
	first, err := loadOrCreatePersona(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreatePersona(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if first.id == second.id || first.hostname == second.hostname || string(first.certPEM) == string(second.certPEM) {
		t.Fatal("independent persona directories share identity material")
	}
}
