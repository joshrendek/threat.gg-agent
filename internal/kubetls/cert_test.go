package kubetls

import (
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateSelfSignedProducesValidServerCertificate(t *testing.T) {
	tlsCert, err := GenerateSelfSigned("worker-01", "worker-01", "localhost")
	require.NoError(t, err)
	require.Len(t, tlsCert.Certificate, 1)
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, cert.RawSubject, cert.RawIssuer)
	require.Equal(t, "worker-01", cert.Subject.CommonName)
	require.Contains(t, cert.DNSNames, "worker-01")
	require.Contains(t, cert.DNSNames, "localhost")
	require.True(t, containsIP(cert.IPAddresses, net.ParseIP("127.0.0.1")))
	require.True(t, containsIP(cert.IPAddresses, net.ParseIP("::1")))
	require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	require.NotZero(t, cert.KeyUsage&x509.KeyUsageDigitalSignature)
	require.NotZero(t, cert.KeyUsage&x509.KeyUsageKeyEncipherment)
	require.True(t, time.Now().After(cert.NotBefore))
	require.True(t, time.Now().Before(cert.NotAfter))
	require.NoError(t, cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature))
}

func containsIP(values []net.IP, want net.IP) bool {
	for _, value := range values {
		if value.Equal(want) {
			return true
		}
	}
	return false
}
