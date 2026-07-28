package kafka

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCAPEM returns a PEM-encoded self-signed CA certificate.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// keyOnlyPEM returns a PEM block that parses as PEM but holds no certificate —
// the classic "pointed at the key instead of the cert" operator mistake.
func keyOnlyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestNewTLSConfig(t *testing.T) {
	dir := t.TempDir()
	ca := selfSignedCAPEM(t)

	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	valid := write("ca.pem", ca)
	empty := write("empty.pem", nil)
	garbage := write("garbage.pem", []byte("not a pem file at all\n"))
	keyOnly := write("key.pem", keyOnlyPEM(t))
	// A real bundle often carries human-readable text between blocks; openssl
	// and most tooling emit this, so it must not be treated as corruption.
	withPreamble := write("preamble.pem", append([]byte("Issuer: test-ca\nSubject: test-ca\n\n"), ca...))
	truncated := write("truncated.pem", ca[:len(ca)/2])
	chain := write("chain.pem", append(append([]byte{}, ca...), selfSignedCAPEM(t)...))

	tests := []struct {
		name    string
		caFile  string
		wantErr bool
		wantCAs bool // expect a non-nil RootCAs pool
	}{
		{name: "empty path uses system roots", caFile: "", wantErr: false, wantCAs: false},
		{name: "valid CA", caFile: valid, wantErr: false, wantCAs: true},
		{name: "valid chain of two", caFile: chain, wantErr: false, wantCAs: true},
		{name: "certificate with text preamble", caFile: withPreamble, wantErr: false, wantCAs: true},
		{name: "nonexistent path", caFile: filepath.Join(dir, "nope.pem"), wantErr: true},
		{name: "empty file", caFile: empty, wantErr: true},
		{name: "non-PEM garbage", caFile: garbage, wantErr: true},
		{name: "PEM but no certificate", caFile: keyOnly, wantErr: true},
		{name: "truncated certificate", caFile: truncated, wantErr: true},
		{name: "directory instead of file", caFile: dir, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := newTLSConfig(tt.caFile)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil (cfg=%v)", cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.MinVersion != tls.VersionTLS12 {
				t.Errorf("MinVersion = %#x, want %#x", cfg.MinVersion, tls.VersionTLS12)
			}
			if got := cfg.RootCAs != nil; got != tt.wantCAs {
				t.Errorf("RootCAs set = %v, want %v", got, tt.wantCAs)
			}
			// One-way TLS: the client must never present a certificate.
			if len(cfg.Certificates) != 0 {
				t.Errorf("Certificates = %d, want 0 (one-way TLS)", len(cfg.Certificates))
			}
			if cfg.InsecureSkipVerify {
				t.Error("InsecureSkipVerify must never be set")
			}
		})
	}
}
