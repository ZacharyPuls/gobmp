package kafka

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// TestNewKafkaPublisherTLSBadCA exercises NewKafkaPublisher's TLS branch.
//
// The server address is a TEST-NET-1 literal (RFC 5737, guaranteed
// unroutable), so if the CA were not validated up front the call would fall
// through to sarama and block for brockerConnectTimeout plus metadata retries.
// The elapsed-time assertion is therefore the substance of the test: it proves
// the publisher rejects an unusable CA before it opens any connection, rather
// than merely that an error is returned eventually.
func TestNewKafkaPublisherTLSBadCA(t *testing.T) {
	tests := []struct {
		name   string
		caFile func(t *testing.T) string
	}{
		{
			name:   "nonexistent CA file",
			caFile: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.pem") },
		},
		{
			name: "CA file containing no certificate",
			caFile: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "garbage.pem")
				writeFile(t, p, "this is not a certificate\n")
				return p
			},
		},
		{
			name: "empty CA file",
			caFile: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "empty.pem")
				writeFile(t, p, "")
				return p
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ServerAddress:        "192.0.2.1:9094",
				TopicRetentionTimeMs: "900000",
				TLS:                  true,
				CAFile:               tt.caFile(t),
			}

			start := time.Now()
			pub, err := NewKafkaPublisher(cfg)
			elapsed := time.Since(start)

			if err == nil {
				if pub != nil {
					pub.Stop()
				}
				t.Fatal("expected an error for an unusable CA file, got nil")
			}
			if pub != nil {
				t.Error("publisher is non-nil alongside an error")
			}
			if !strings.Contains(err.Error(), "kafka:") {
				t.Errorf("error = %q, want the CA-file error from newTLSConfig", err)
			}
			// Generous bound: the real path is microseconds, whereas reaching
			// sarama would take brockerConnectTimeout (120s) or longer.
			if elapsed > 10*time.Second {
				t.Errorf("took %s: the CA was validated after a connection attempt, not before", elapsed)
			}
		})
	}
}

// TestNewKafkaPublisherTLSMockBroker is the TLS success path: NewKafkaPublisher
// completes a real handshake against a broker whose certificate is verified
// against the configured CA file, and returns a working publisher.
//
// sarama's MockBroker speaks plaintext only, so it is fronted with a
// TLS-terminating proxy. That is enough to exercise the whole chain the flags
// exist for: --kafka-ca is read from disk, the pool it builds is what verifies
// the peer, and config.Net.TLS is what carries it into sarama.
func TestNewKafkaPublisherTLSMockBroker(t *testing.T) {
	serverCert, caPEM := newSelfSignedCert(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, caFile, string(caPEM))

	mb := sarama.NewMockBroker(t, 1)
	defer mb.Close()

	proxy := startTLSProxy(t, mb.Addr(), serverCert)
	defer proxy.Close()

	// Metadata has to advertise the proxy rather than mb.Addr(). sarama dials
	// the advertised address for the producer's own connection, so advertising
	// the plaintext mock would send the producer around the TLS listener and
	// the test would pass without a handshake ever happening.
	mb.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t),
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(proxy.addr(), mb.BrokerID()),
		"ProduceRequest": sarama.NewMockProduceResponse(t),
	})

	cfg := &Config{
		ServerAddress:        proxy.addr(),
		TopicRetentionTimeMs: "900000",
		// Topic creation is out of scope here and needs its own API-version
		// handling; the TLS branch is upstream of it either way.
		SkipTopicCreation: true,
		TLS:               true,
		CAFile:            caFile,
	}

	// Bounded rather than called directly. If the TLS branch regresses, the
	// client speaks Kafka at a TLS listener, the handshake never completes and
	// sarama retries metadata 300 times with a 10s backoff — so a plain call
	// would hang until the whole package's test timeout fired, reported as an
	// unrelated panic. The success path returns in milliseconds.
	type result struct {
		p   pub.Publisher
		err error
	}
	ch := make(chan result, 1)
	go func() {
		p, err := NewKafkaPublisher(cfg)
		ch <- result{p: p, err: err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("NewKafkaPublisher over TLS: %v", r.err)
		}
		if r.p == nil {
			t.Fatal("NewKafkaPublisher returned a nil publisher without an error")
		}
		if proxy.handshakes() == 0 {
			t.Error("publisher connected without completing a TLS handshake")
		}
		r.p.Stop()
	case <-time.After(20 * time.Second):
		t.Fatal("NewKafkaPublisher did not return: no TLS handshake completed with the broker")
	}
}

// TestNewKafkaPublisherTLSTopicCreation is the same success path with topic
// creation left on, which is what a TLS deployment actually gets:
// SkipTopicCreation defaults to false, so the first thing a TLS user reaches is
// ClusterAdmin, and after it the controller-broker connection. Both are opened
// from the same sarama config the TLS branch populated, so both have to come up
// over TLS before any producer exists. The skip=true case above never touches
// either of them.
func TestNewKafkaPublisherTLSTopicCreation(t *testing.T) {
	serverCert, caPEM := newSelfSignedCert(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, caFile, string(caPEM))

	mb := sarama.NewMockBroker(t, 1)
	defer mb.Close()

	proxy := startTLSProxy(t, mb.Addr(), serverCert)
	defer proxy.Close()

	// Cap CreateTopics (API key 19) at V4 so MockCreateTopicsResponse applies;
	// V5+ expects TopicResults, which the mock does not populate. Same reason as
	// TestNewKafkaPublisher_WithTopicCreation_Success.
	apiVersions := sarama.NewMockApiVersionsResponse(t).SetApiKeys([]sarama.ApiVersionsResponseKey{
		{ApiKey: 0, MinVersion: 5, MaxVersion: 8},  // Produce
		{ApiKey: 1, MinVersion: 7, MaxVersion: 11}, // Fetch
		{ApiKey: 3, MinVersion: 0, MaxVersion: 9},  // Metadata
		{ApiKey: 19, MinVersion: 0, MaxVersion: 4}, // CreateTopics
	})
	mb.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": apiVersions,
		// SetController is what makes waitForControllerBrokerConnection resolve,
		// and it resolves to the advertised address, so the controller
		// connection is a second TLS handshake through the proxy.
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(proxy.addr(), mb.BrokerID()).
			SetController(mb.BrokerID()),
		"CreateTopicsRequest": sarama.NewMockCreateTopicsResponse(t),
		"ProduceRequest":      sarama.NewMockProduceResponse(t),
	})

	cfg := &Config{
		ServerAddress:        proxy.addr(),
		TopicRetentionTimeMs: "900000",
		SkipTopicCreation:    false,
		TLS:                  true,
		CAFile:               caFile,
	}

	type result struct {
		p   pub.Publisher
		err error
	}
	ch := make(chan result, 1)
	go func() {
		p, err := NewKafkaPublisher(cfg)
		ch <- result{p: p, err: err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("NewKafkaPublisher over TLS with topic creation: %v", r.err)
		}
		if r.p == nil {
			t.Fatal("NewKafkaPublisher returned a nil publisher without an error")
		}
		// ClusterAdmin, the controller broker and the producer each connect, so
		// more than the single handshake of the skip=true case is expected.
		if got := proxy.handshakes(); got < 2 {
			t.Errorf("completed %d TLS handshakes, want at least 2 (cluster admin, controller broker, producer)", got)
		}
		r.p.Stop()
	case <-time.After(30 * time.Second):
		t.Fatal("NewKafkaPublisher did not return: the admin or controller connection never completed a TLS handshake")
	}
}

// TestNewTLSConfigVerifiesPeer pins the property that makes --kafka-ca mean
// anything: the config newTLSConfig returns actually validates the broker's
// certificate chain. The negative case is the one that matters — it fails if
// InsecureSkipVerify is ever set, or if an unusable CA file were allowed to
// yield an empty pool that silently falls back to trusting anything.
func TestNewTLSConfigVerifiesPeer(t *testing.T) {
	serverCert, serverCAPEM := newSelfSignedCert(t)
	_, unrelatedCAPEM := newSelfSignedCert(t)

	tests := []struct {
		name    string
		caPEM   []byte
		wantErr bool
	}{
		{name: "certificate chains to the configured CA", caPEM: serverCAPEM, wantErr: false},
		{name: "certificate does not chain to the configured CA", caPEM: unrelatedCAPEM, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			writeFile(t, caFile, string(tt.caPEM))

			cfg, err := newTLSConfig(caFile)
			if err != nil {
				t.Fatalf("newTLSConfig: %v", err)
			}

			addr, stop := startTLSHandshakeServer(t, serverCert)
			defer stop()

			conn, err := tls.Dial("tcp", addr, cfg)
			if err == nil {
				_ = conn.Close()
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("handshake succeeded against a certificate that does not chain to the configured CA")
				}
				var unknown x509.UnknownAuthorityError
				if !errors.As(err, &unknown) {
					t.Errorf("error = %v, want an unknown-authority verification failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake against the configured CA: %v", err)
			}
		})
	}
}

// newSelfSignedCert returns a server certificate for 127.0.0.1 and the PEM
// bytes to trust it with. The certificate is its own issuer, so the same PEM
// serves as the CA bundle.
func newSelfSignedCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "gobmp-test-broker"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build key pair: %v", err)
	}

	return pair, certPEM
}

// tlsProxy terminates TLS on 127.0.0.1 and forwards the plaintext stream to a
// target address, which lets a plaintext sarama MockBroker stand in for a
// TLS-only broker.
type tlsProxy struct {
	ln     net.Listener
	target string
	wg     sync.WaitGroup

	mu   sync.Mutex
	seen int
}

func startTLSProxy(t *testing.T, target string, cert tls.Certificate) *tlsProxy {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	p := &tlsProxy{ln: ln, target: target}
	p.wg.Add(1)
	go p.serve()

	return p
}

func (p *tlsProxy) addr() string { return p.ln.Addr().String() }

func (p *tlsProxy) handshakes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}

func (p *tlsProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return // listener closed
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(conn)
		}()
	}
}

func (p *tlsProxy) handle(client net.Conn) {
	// Handshake explicitly so a failure is not mistaken for the target being
	// unreachable, and so the counter only advances on a verified connection.
	if tc, ok := client.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			_ = client.Close()
			return
		}
		p.mu.Lock()
		p.seen++
		p.mu.Unlock()
	}

	server, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = client.Close()
		return
	}

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(server, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, server); done <- struct{}{} }()
	<-done
	// Closing both ends unblocks whichever copy is still reading, so neither
	// goroutine outlives the test.
	_ = client.Close()
	_ = server.Close()
	<-done
}

func (p *tlsProxy) Close() {
	_ = p.ln.Close()
	p.wg.Wait()
}

// startTLSHandshakeServer accepts TLS connections and does nothing but the
// handshake. Used where the assertion is about certificate verification, so
// piping to a broker would only add a way for the test to fail for the wrong
// reason.
func startTLSHandshakeServer(t *testing.T, cert tls.Certificate) (string, func()) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			// A handshake error is an expected outcome here, not a failure.
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		wg.Wait()
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
