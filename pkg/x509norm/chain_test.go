package x509norm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/x509norm"
)

// buildChain returns (rootDER, intermediateDER, leafDER).
func buildChain(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root CA"},
		NotBefore: now, NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		SubjectKeyId: []byte{1, 1, 1, 1},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore: now, NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		SubjectKeyId: []byte{2, 2, 2, 2}, AuthorityKeyId: []byte{1, 1, 1, 1},
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(interDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "api.internal.example"},
		NotBefore: now, NotAfter: now.AddDate(0, 6, 0),
		DNSNames: []string{"api.internal.example"}, AuthorityKeyId: []byte{2, 2, 2, 2},
		SubjectKeyId: []byte{3, 3, 3, 3},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	return rootDER, interDER, leafDER
}

// X509-002: the leaf must be identified structurally, in any presented order.
//
// Servers get chain order wrong often enough that trusting the presented order
// produces wrong answers in production — and "wrong certificate reported" is the
// one failure this product cannot afford.
func TestIdentifyLeafInAnyOrder(t *testing.T) {
	root, inter, leaf := buildChain(t)

	orders := []struct {
		name string
		ders [][]byte
	}{
		{"canonical leaf-first", [][]byte{leaf, inter, root}},
		{"reversed root-first", [][]byte{root, inter, leaf}},
		{"leaf in the middle", [][]byte{inter, leaf, root}},
		{"leaf last", [][]byte{root, inter, leaf}},
		{"without the root", [][]byte{inter, leaf}},
		{"leaf alone", [][]byte{leaf}},
		{"with a duplicate intermediate", [][]byte{inter, leaf, inter, root}},
	}

	wantLeaf := x509norm.Fingerprint(leaf)
	for _, o := range orders {
		t.Run(o.name, func(t *testing.T) {
			ch, err := x509norm.ParseChain(o.ders)
			if err != nil {
				t.Fatal(err)
			}
			if ch.Leaf.Fingerprint != wantLeaf {
				t.Fatalf("identified %q as the leaf, want api.internal.example", ch.Leaf.SubjectCN)
			}
		})
	}
}

// An extra, unrelated certificate in the presented set must not confuse leaf
// identification. Some servers send their whole trust store.
func TestIdentifyLeafWithUnrelatedCertificate(t *testing.T) {
	_, inter, leaf := buildChain(t)
	_, _, unrelated := buildChain(t)

	ch, err := x509norm.ParseChain([][]byte{inter, unrelated, leaf})
	if err != nil {
		t.Fatal(err)
	}
	// Two end-entity certificates are present, so the answer is ambiguous by
	// construction. What must NOT happen is picking the intermediate.
	if ch.Leaf.IsCA {
		t.Fatalf("picked a CA certificate as the leaf: %q", ch.Leaf.SubjectCN)
	}
}

func TestParsePEMSkipsPrivateKeyBlocks(t *testing.T) {
	_, _, leaf := buildChain(t)
	doc := "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0\n-----END PRIVATE KEY-----\n" +
		string(pemEncode("CERTIFICATE", leaf))

	certs, err := x509norm.ParsePEM([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
	if certs[0].Fingerprint != x509norm.Fingerprint(leaf) {
		t.Fatal("wrong certificate returned")
	}
}

func TestParseChainRejectsEmpty(t *testing.T) {
	if _, err := x509norm.ParseChain(nil); err == nil {
		t.Fatal("empty chain accepted")
	}
}
