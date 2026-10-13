package rdp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

const (
	rdpPersonaVersion = 1
	rdpPersonaFile    = "persona.json"
	rdpPersonaDomain  = "WORKGROUP"

	// A persona file contains one RSA-2048 key and certificate. This bound
	// prevents a damaged file from becoming an unbounded allocation source.
	maxRDPPersonaFileSize = 128 << 10
	maxRDPHostnameLength  = 15
	maxRDPDomainLength    = 15
)

// rdpPersona is the stable server identity used by all connections from one
// deployment. certPEM and keyPEM are retained so the exact persisted material
// can be compared across restarts; tlsCert is the parsed serving certificate.
type rdpPersona struct {
	id        string
	hostname  string
	domain    string
	certPEM   []byte
	keyPEM    []byte
	tlsCert   tls.Certificate
	createdAt time.Time
}

type persistedRDPPersona struct {
	Version   int       `json:"version"`
	PersonaID string    `json:"persona_id"`
	Hostname  string    `json:"hostname"`
	Domain    string    `json:"domain"`
	CertPEM   string    `json:"cert_pem"`
	KeyPEM    string    `json:"key_pem"`
	CreatedAt time.Time `json:"created_at"`
}

// loadOrCreatePersona loads the deployment persona from dir, or creates and
// atomically stores one when the directory has no persona yet. Any existing
// but malformed persona is an error; it is never silently replaced.
func loadOrCreatePersona(dir string) (*rdpPersona, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("RDP persona directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating RDP persona directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("securing RDP persona directory: %w", err)
	}

	path := filepath.Join(dir, rdpPersonaFile)
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("RDP persona file must not be a symlink")
		}
		if info.IsDir() {
			return nil, errors.New("RDP persona file is a directory")
		}
		if info.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("RDP persona file has insecure mode %04o", info.Mode().Perm())
		}
		if info.Size() <= 0 || info.Size() > maxRDPPersonaFileSize {
			return nil, errors.New("RDP persona file has invalid size")
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("reading RDP persona: %w", readErr)
		}
		return decodeRDPPersona(data)
	case errors.Is(err, os.ErrNotExist):
		// The first invocation creates the identity below.
	default:
		return nil, fmt.Errorf("checking RDP persona: %w", err)
	}

	persona, persisted, err := newRDPPersona()
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding RDP persona: %w", err)
	}
	data = append(data, '\n')
	if err := atomicallyWriteRDPPersona(path, data); err != nil {
		return nil, err
	}
	return persona, nil
}

func newRDPPersona() (*rdpPersona, persistedRDPPersona, error) {
	id := uuid.NewV4()
	if id == uuid.Nil {
		return nil, persistedRDPPersona{}, errors.New("generating RDP persona UUID")
	}

	hostname, err := randomRDPHostname()
	if err != nil {
		return nil, persistedRDPPersona{}, err
	}
	now := time.Now().UTC()
	certPEM, keyPEM, tlsCert, err := newRDPCertificate(hostname, now)
	if err != nil {
		return nil, persistedRDPPersona{}, err
	}
	persona := &rdpPersona{
		id:        id.String(),
		hostname:  hostname,
		domain:    rdpPersonaDomain,
		certPEM:   certPEM,
		keyPEM:    keyPEM,
		tlsCert:   tlsCert,
		createdAt: now,
	}
	persisted := persistedRDPPersona{
		Version:   rdpPersonaVersion,
		PersonaID: persona.id,
		Hostname:  persona.hostname,
		Domain:    persona.domain,
		CertPEM:   string(persona.certPEM),
		KeyPEM:    string(persona.keyPEM),
		CreatedAt: persona.createdAt,
	}
	return persona, persisted, nil
}

func decodeRDPPersona(data []byte) (*rdpPersona, error) {
	var persisted persistedRDPPersona
	if err := json.Unmarshal(data, &persisted); err != nil {
		return nil, fmt.Errorf("decoding RDP persona: %w", err)
	}
	if persisted.Version != rdpPersonaVersion {
		return nil, fmt.Errorf("unsupported RDP persona version %d", persisted.Version)
	}
	parsedID, err := uuid.FromString(persisted.PersonaID)
	if err != nil || parsedID == uuid.Nil {
		return nil, errors.New("RDP persona has invalid UUID")
	}
	if !validRDPHostname(persisted.Hostname) {
		return nil, errors.New("RDP persona has invalid hostname")
	}
	if !validRDPDomain(persisted.Domain) {
		return nil, errors.New("RDP persona has invalid domain")
	}
	if persisted.CreatedAt.IsZero() || persisted.CreatedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return nil, errors.New("RDP persona has invalid creation time")
	}
	if len(persisted.CertPEM) == 0 || len(persisted.KeyPEM) == 0 {
		return nil, errors.New("RDP persona is missing certificate material")
	}

	tlsCert, err := tls.X509KeyPair([]byte(persisted.CertPEM), []byte(persisted.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing RDP persona certificate and key: %w", err)
	}
	if len(tlsCert.Certificate) != 1 {
		return nil, errors.New("RDP persona certificate chain must contain one certificate")
	}
	certificate, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing RDP persona certificate: %w", err)
	}
	if err := validateRDPCertificate(certificate, tlsCert.PrivateKey, persisted.Hostname); err != nil {
		return nil, err
	}

	return &rdpPersona{
		id:        parsedID.String(),
		hostname:  persisted.Hostname,
		domain:    persisted.Domain,
		certPEM:   []byte(persisted.CertPEM),
		keyPEM:    []byte(persisted.KeyPEM),
		tlsCert:   tlsCert,
		createdAt: persisted.CreatedAt,
	}, nil
}

func randomRDPHostname() (string, error) {
	var randomPart [6]byte
	if _, err := rand.Read(randomPart[:]); err != nil {
		return "", fmt.Errorf("generating RDP hostname: %w", err)
	}
	// WIN- plus eleven hexadecimal characters is at most 15 NetBIOS bytes.
	hostname := "WIN-" + strings.ToUpper(hex.EncodeToString(randomPart[:]))[:11]
	if !validRDPHostname(hostname) {
		return "", errors.New("generated invalid RDP hostname")
	}
	return hostname, nil
}

func newRDPCertificate(hostname string, now time.Time) ([]byte, []byte, tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("generating RDP persona RSA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("generating RDP persona certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		Issuer:                pkix.Name{CommonName: hostname},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{hostname},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("creating RDP persona certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, tls.Certificate{}, fmt.Errorf("parsing generated RDP persona certificate: %w", err)
	}
	return certPEM, keyPEM, tlsCert, nil
}

func validateRDPCertificate(certificate *x509.Certificate, privateKey any, hostname string) error {
	if certificate.Subject.CommonName != hostname || certificate.Issuer.CommonName != hostname {
		return errors.New("RDP persona certificate identity does not match hostname")
	}
	if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != hostname || len(certificate.IPAddresses) != 0 {
		return errors.New("RDP persona certificate SAN does not match hostname")
	}
	if len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 {
		return errors.New("RDP persona certificate has unexpected identities")
	}
	if certificate.IsCA || certificate.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
		return errors.New("RDP persona certificate has invalid key usage")
	}
	if time.Now().Before(certificate.NotBefore) || time.Now().After(certificate.NotAfter) {
		return errors.New("RDP persona certificate is not currently valid")
	}
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		return fmt.Errorf("RDP persona certificate signature is invalid: %w", err)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != 2048 {
		return errors.New("RDP persona certificate is not RSA-2048")
	}
	key, ok := privateKey.(*rsa.PrivateKey)
	if !ok || key.N.Cmp(publicKey.N) != 0 || key.E != publicKey.E || key.N.BitLen() != 2048 {
		return errors.New("RDP persona certificate and key do not match")
	}
	return nil
}

func validRDPHostname(hostname string) bool {
	if hostname == "" || len(hostname) > maxRDPHostnameLength || hostname != strings.ToUpper(hostname) {
		return false
	}
	if hostname[0] == '-' || hostname[len(hostname)-1] == '-' {
		return false
	}
	for i := 0; i < len(hostname); i++ {
		c := hostname[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func validRDPDomain(domain string) bool {
	if domain == "" || len(domain) > maxRDPDomainLength || domain != strings.ToUpper(domain) {
		return false
	}
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func atomicallyWriteRDPPersona(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".persona-*.tmp")
	if err != nil {
		return fmt.Errorf("creating RDP persona temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		if removeErr := os.Remove(tempPath); err == nil && removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = fmt.Errorf("cleaning RDP persona temporary file: %w", removeErr)
		}
	}()
	if err = temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("securing RDP persona temporary file: %w", err)
	}
	if _, err = temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("writing RDP persona temporary file: %w", err)
	}
	if err = temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("syncing RDP persona temporary file: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("closing RDP persona temporary file: %w", err)
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("committing RDP persona: %w", err)
	}
	return nil
}
