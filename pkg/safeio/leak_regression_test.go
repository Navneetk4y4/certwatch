package safeio

import (
	"bytes"
	"crypto/x509"
	"path/filepath"
	"testing"
)

// REGRESSION: cert || key must never be returned as "a certificate".
//
// Found by adversarial review, NOT by the canary — the canary's planted DER
// form was a pure PKCS#8 key, so this leak class was outside what it planted.
// The canary has since been extended with this form (test/canary), and this
// test pins the underlying behaviour at the unit level.
//
// Mechanism: looksLikeCertificateDER checked only that the outer TLV described
// a Certificate, and permitted trailing bytes. readSniffed then returned the
// WHOLE file body. A file of `certificate || private-key` therefore returned
// 1544 bytes for a 326-byte certificate, private key included. INV-1 violated.
func TestCertificateWithAppendedKeyIsRefused(t *testing.T) {
	key := testRSAKey(t)
	cert := testCertDER(t, "trailing.example")
	pkcs8 := mustPKCS8(t, key)

	combined := append(append([]byte{}, cert...), pkcs8...)

	// Unit level: the structural check must reject trailing bytes outright.
	if looksLikeCertificateDER(combined) {
		t.Fatal("looksLikeCertificateDER accepts a certificate with trailing bytes appended")
	}
	if cls, _ := classifyDER(combined); cls == ClassCertificateDER {
		t.Fatal("classifyDER returns ClassCertificateDER for cert||key")
	}

	// End to end: nothing containing key bytes may be returned.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "combined.der"), combined)
	res, _ := walkDir(t, dir, PolicyOptions{})
	keyPrefix := key.N.Bytes()[:32]
	for _, r := range res {
		for _, der := range r.CertificateDER {
			if bytes.Contains(der, keyPrefix) {
				t.Fatalf("LEAK: %d bytes returned for a %d-byte certificate", len(der), len(cert))
			}
		}
	}
}

// A clean certificate with NO trailing bytes must still be accepted, or the fix
// above would have closed the leak by breaking the product.
func TestCleanCertificateStillAccepted(t *testing.T) {
	dir := t.TempDir()
	cert := testCertDER(t, "clean.example")
	writeFile(t, filepath.Join(dir, "clean.der"), cert)
	_, c := walkDir(t, dir, PolicyOptions{})
	if c.CertificatesReturned != 1 {
		t.Fatalf("a clean DER certificate was rejected: %v", c.Dispositions)
	}
}

// Trailing bytes of any kind are refused, not just key material: unaccounted-for
// bytes are never returned, whatever they are.
func TestAnyTrailingBytesRefused(t *testing.T) {
	cert := testCertDER(t, "t.example")
	for _, trailer := range [][]byte{
		{0x00},
		{0x0A},
		bytes.Repeat([]byte{0x41}, 100),
		x509.MarshalPKCS1PrivateKey(testRSAKey(t)),
	} {
		combined := append(append([]byte{}, cert...), trailer...)
		if looksLikeCertificateDER(combined) {
			t.Errorf("accepted a certificate with %d trailing bytes", len(trailer))
		}
	}
}

// The returned slice must not alias a buffer that also held unclassified bytes.
func TestReturnedDERIsACopy(t *testing.T) {
	dir := t.TempDir()
	cert := testCertDER(t, "copy.example")
	writeFile(t, filepath.Join(dir, "c.der"), cert)
	res, _ := walkDir(t, dir, PolicyOptions{})
	for _, r := range res {
		for _, der := range r.CertificateDER {
			if len(der) != len(cert) {
				t.Fatalf("returned %d bytes for a %d-byte certificate", len(der), len(cert))
			}
			if !bytes.Equal(der, cert) {
				t.Fatal("returned DER differs from the file content")
			}
		}
	}
}
