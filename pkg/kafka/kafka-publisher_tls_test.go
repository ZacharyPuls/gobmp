package kafka

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
