package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// newTLSConfig builds the client TLS configuration used for broker
// connections. caFile is an optional path to a PEM bundle to verify the
// broker's certificate against; when empty the host's system trust store is
// used.
//
// This is one-way (server-authenticated) TLS. The client presents no
// certificate, which matches brokers that use network scope rather than
// client certificates for authorization.
func newTLSConfig(caFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if caFile == "" {
		return cfg, nil
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("kafka: cannot read CA file %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	// AppendCertsFromPEM reports failure with a bool rather than an error, and
	// silently ignores unparsable blocks. Without this check a typo'd or
	// truncated bundle yields an empty pool and the handshake fails later with
	// an opaque "unknown authority" instead of naming the real problem.
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("kafka: no certificates found in CA file %q", caFile)
	}
	cfg.RootCAs = pool

	return cfg, nil
}
