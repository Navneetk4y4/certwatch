package safeio

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SAFEIO-005: a mixed bundle must yield its certificates AND count the key block,
// with no key byte anywhere in the returned data.
func TestPEMMixedBundle(t *testing.T) {
	dir := t.TempDir()
	key := testRSAKey(t)
	certA := testCertDER(t, "a.example")
	certB := testCertDER(t, "b.example")

	var buf bytes.Buffer
	buf.Write(pemBlock("CERTIFICATE", certA))
	buf.Write(pemBlock("PRIVATE KEY", mustPKCS8(t, key)))
	buf.Write(pemBlock("CERTIFICATE", certB))
	writeFile(t, filepath.Join(dir, "bundle.pem"), buf.Bytes())

	res, c := walkDir(t, dir, PolicyOptions{})
	if c.CertificatesReturned != 2 {
		t.Fatalf("CertificatesReturned = %d, want 2", c.CertificatesReturned)
	}
	if c.PrivateKeyBlocksSkipped != 1 {
		t.Fatalf("PrivateKeyBlocksSkipped = %d, want 1", c.PrivateKeyBlocksSkipped)
	}
	keyPrefix := key.N.Bytes()[:32]
	for _, r := range res {
		for _, der := range r.CertificateDER {
			if bytes.Contains(der, keyPrefix) {
				t.Fatal("key material returned from a mixed bundle")
			}
		}
	}
}

// Every private-key PEM label must be caught, including ones we have not seen:
// the check is suffix-based so an unknown "FOO PRIVATE KEY" fails closed.
func TestPEMPrivateKeyLabels(t *testing.T) {
	labels := []string{
		"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK",
		"FUTURE FORMAT PRIVATE KEY",
	}
	for _, l := range labels {
		if !isPrivateKeyBlockType(l) {
			t.Errorf("isPrivateKeyBlockType(%q) = false; must fail closed", l)
		}
	}
	for _, l := range []string{"CERTIFICATE", "PUBLIC KEY", "CERTIFICATE REQUEST", "DH PARAMETERS"} {
		if isPrivateKeyBlockType(l) {
			t.Errorf("isPrivateKeyBlockType(%q) = true; false positive", l)
		}
	}
}

// A truncated block (BEGIN with no END) must terminate at EOF, not hang.
func TestPEMTruncatedBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "trunc.pem"),
		[]byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\nMIIEvQIBADANBgkq\n"))
	writeFile(t, filepath.Join(dir, "good.pem"), pemBlock("CERTIFICATE", testCertDER(t, "g.example")))

	_, c := walkDir(t, dir, PolicyOptions{})
	if c.PrivateKeyBlocksSkipped != 1 {
		t.Fatalf("truncated key block not counted: %+v", c.Dispositions)
	}
	if c.CertificatesReturned != 1 {
		t.Fatalf("the good certificate was not read: %d", c.CertificatesReturned)
	}
}

// A file of garbage with no PEM markers must not allocate unboundedly, and must
// be reported as containing no certificate rather than silently ignored.
func TestPEMGarbageNoAllocation(t *testing.T) {
	dir := t.TempDir()
	garbage := bytes.Repeat([]byte("not a certificate at all, just noise. "), 20000) // ~760 KB
	writeFile(t, filepath.Join(dir, "noise.pem"), garbage)

	_, c := walkDir(t, dir, PolicyOptions{})
	if countClass(c, SkippedNoCertificates) != 1 {
		t.Fatalf("garbage not classified as no-certificates: %v", c.Dispositions)
	}
}

// A single enormous line must not exhaust memory: the scanner buffer is bounded.
func TestPEMEnormousLine(t *testing.T) {
	dir := t.TempDir()
	line := append([]byte("-----BEGIN CERTIFICATE-----\n"), bytes.Repeat([]byte("A"), 300<<10)...)
	writeFile(t, filepath.Join(dir, "long.pem"), line)
	_, c := walkDir(t, dir, PolicyOptions{MaxFileBytes: 1 << 20})
	if c.CertificatesReturned != 0 {
		t.Fatalf("a 300 KB base64 line was accepted as a certificate")
	}
	if ok, why := c.Conserved(); !ok {
		t.Fatal(why)
	}
}

// An unknown block type is skipped and counted — never silently dropped.
func TestPEMUnknownBlockCounted(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	buf.Write(pemBlock("DH PARAMETERS", []byte{1, 2, 3, 4}))
	buf.Write(pemBlock("CERTIFICATE", testCertDER(t, "u.example")))
	writeFile(t, filepath.Join(dir, "mixed.pem"), buf.Bytes())

	_, c := walkDir(t, dir, PolicyOptions{})
	if c.UnknownPEMBlocksSkipped != 1 {
		t.Fatalf("UnknownPEMBlocksSkipped = %d, want 1", c.UnknownPEMBlocksSkipped)
	}
	if c.CertificatesReturned != 1 {
		t.Fatalf("CertificatesReturned = %d, want 1", c.CertificatesReturned)
	}
}

// SAFEIO-006: the DER classifier, including the fail-closed case.
func TestClassifyDER(t *testing.T) {
	key := testRSAKey(t)
	cases := []struct {
		name string
		data []byte
		want Classification
	}{
		{"certificate", testCertDER(t, "d.example"), ClassCertificateDER},
		{"pkcs8 rsa key", mustPKCS8(t, key), SkippedPrivateKeyBlock},
		{"pkcs1 rsa key", x509.MarshalPKCS1PrivateKey(key), SkippedPrivateKeyBlock},
		{"random bytes", bytes.Repeat([]byte{0xAB}, 512), SkippedAmbiguousDER},
		{"too short", []byte{0x30, 0x02}, SkippedAmbiguousDER},
		{"sequence of nothing", []byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06}, SkippedAmbiguousDER},
		{"indefinite length", []byte{0x30, 0x80, 0x30, 0x02, 0x01, 0x00, 0x00, 0x00}, SkippedAmbiguousDER},
		{"leading whitespace before cert", append([]byte{0x20, 0x20}, testCertDER(t, "w.example")...), SkippedAmbiguousDER},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason := classifyDER(c.data)
			if got != c.want {
				t.Fatalf("classifyDER = %v (%s), want %v", got, reason, c.want)
			}
		})
	}
}

// An EC (SEC1) private key in DER must be refused. Marshalled by crypto/x509
// rather than hand-built, so the fixture is a real SEC1 encoding.
func TestClassifyDERSEC1(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), seededReader(21))
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := classifyDER(sec1); got != SkippedPrivateKeyBlock {
		t.Fatalf("SEC1 EC key classified as %v", got)
	}
}

// A .crt holding PEM and a .crt holding DER must both work: both occur in the wild.
func TestSniffedExtensions(t *testing.T) {
	dir := t.TempDir()
	der := testCertDER(t, "sniff.example")
	writeFile(t, filepath.Join(dir, "pem-in-crt.crt"), pemBlock("CERTIFICATE", der))
	writeFile(t, filepath.Join(dir, "der-in-crt.crt"), der)
	writeFile(t, filepath.Join(dir, "der-in-cer.cer"), der)
	writeFile(t, filepath.Join(dir, "plain.der"), der)

	_, c := walkDir(t, dir, PolicyOptions{})
	if c.CertificatesReturned != 4 {
		t.Fatalf("CertificatesReturned = %d, want 4: %v", c.CertificatesReturned, c.Dispositions)
	}
}

// The returned Result type must never carry DER for a skip class. This is the
// invariant expressed at the type level; assert it holds in practice.
func TestSkipsNeverCarryDER(t *testing.T) {
	dir := t.TempDir()
	key := testRSAKey(t)
	writeFile(t, filepath.Join(dir, "k.key"), pemBlock("PRIVATE KEY", mustPKCS8(t, key)))
	writeFile(t, filepath.Join(dir, "raw.der"), mustPKCS8(t, key))
	writeFile(t, filepath.Join(dir, "noise.der"), bytes.Repeat([]byte{0x42}, 256))
	_ = os.Symlink(filepath.Join(dir, "k.key"), filepath.Join(dir, "l.pem"))

	res, _ := walkDir(t, dir, PolicyOptions{})
	for _, r := range res {
		if !r.Class.IsCertificate() && len(r.CertificateDER) != 0 {
			t.Fatalf("%s: skip class %v carried %d DER blocks", r.Path, r.Class, len(r.CertificateDER))
		}
		if !r.Class.IsCertificate() && strings.TrimSpace(r.Reason) == "" {
			t.Fatalf("%s: skip class %v has an empty reason", r.Path, r.Class)
		}
	}
}

// Regression for the coverage gap found by TestPEMGarbageNoAllocation:
// a line too long to be PEM must not hide a certificate that follows it.
// Before the fix, bufio.Scanner returned ErrTooLong and abandoned the file.
func TestPEMOverlongLineDoesNotHideFollowingCertificate(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte("X"), 200<<10)) // one 200 KB line, no newline
	buf.WriteByte('\n')
	buf.Write(pemBlock("CERTIFICATE", testCertDER(t, "after.example")))
	writeFile(t, filepath.Join(dir, "mixed.pem"), buf.Bytes())

	_, c := walkDir(t, dir, PolicyOptions{MaxFileBytes: 1 << 20})
	if c.CertificatesReturned != 1 {
		t.Fatalf("CertificatesReturned = %d, want 1: a certificate after an overlong line was lost", c.CertificatesReturned)
	}
}

// And the key-hiding variant: an overlong line must not cause a private key
// after it to be read either.
func TestPEMOverlongLineStillSkipsFollowingKey(t *testing.T) {
	dir := t.TempDir()
	key := testRSAKey(t)
	var buf bytes.Buffer
	buf.Write(bytes.Repeat([]byte("X"), 200<<10))
	buf.WriteByte('\n')
	buf.Write(pemBlock("PRIVATE KEY", mustPKCS8(t, key)))
	buf.Write(pemBlock("CERTIFICATE", testCertDER(t, "after2.example")))
	writeFile(t, filepath.Join(dir, "mixed2.pem"), buf.Bytes())

	res, c := walkDir(t, dir, PolicyOptions{MaxFileBytes: 1 << 20})
	if c.PrivateKeyBlocksSkipped != 1 {
		t.Fatalf("PrivateKeyBlocksSkipped = %d, want 1", c.PrivateKeyBlocksSkipped)
	}
	keyPrefix := key.N.Bytes()[:32]
	for _, r := range res {
		for _, der := range r.CertificateDER {
			if bytes.Contains(der, keyPrefix) {
				t.Fatal("key material returned after an overlong line")
			}
		}
	}
}
