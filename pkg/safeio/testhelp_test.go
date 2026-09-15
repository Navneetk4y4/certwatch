package safeio

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	rand2 "math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// seededReader is a deterministic CSPRNG stream. ChaCha8 rather than a hand-rolled
// LCG: key generation searches for primes, and a poor-quality stream makes that
// search take unbounded time. Deterministic so a planted key is byte-identical
// across runs, which is what the security canary needs.
func seededReader(seed byte) io.Reader {
	var s [32]byte
	for i := range s {
		s[i] = seed ^ byte(i*31+7)
	}
	return rand2.NewChaCha8(s)
}

var (
	rsaOnce sync.Once
	rsaKey  *rsa.PrivateKey
)

// testRSAKey returns a deterministic RSA-2048 key, generated once per process.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaOnce.Do(func() {
		k, err := rsa.GenerateKey(seededReader(7), 2048)
		if err != nil {
			t.Fatalf("generate rsa key: %v", err)
		}
		rsaKey = k
	})
	if rsaKey == nil {
		t.Fatal("rsa key generation failed")
	}
	return rsaKey
}

func testCertDER(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), seededReader(byte(len(cn)+3)))
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(cn)) + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(seededReader(byte(len(cn)+11)), tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// mustPolicy builds a policy rooted at dir with generous but finite limits.
func mustPolicy(t *testing.T, dir string, opt PolicyOptions) *Policy {
	t.Helper()
	p, err := NewPolicy([]string{dir}, opt)
	if err != nil {
		t.Fatalf("NewPolicy(%q): %v", dir, err)
	}
	return p
}
