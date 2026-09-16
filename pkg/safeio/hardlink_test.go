package safeio

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// KNOWN LIMITATION, pinned by test: a HARDLINK is not a symlink, and
// O_NOFOLLOW does not stop one.
//
// A hardlink placed inside a declared root, pointing at a file outside it, IS
// read. The scope boundary is therefore enforced against symlinks but not
// against hardlinks.
//
// Why this is documented rather than blocked:
//
//   - Detecting it means refusing any file with st_nlink > 1, which also
//     refuses legitimate hardlinked certificate bundles. That is a real cost
//     for a narrow gain.
//   - Creating a hardlink requires write access inside the scanned directory
//     AND read access to the target, so the attacker already has the file.
//   - Most importantly, INV-1 still holds: the content classifiers refuse key
//     material whatever path it arrived by. The test below pins exactly that.
//
// If a customer's threat model includes an attacker with write access to a
// scanned certificate directory, the correct answer is to not declare a
// writable directory in scope.yaml — which the documentation should say.
func TestHardlinkedCertificateIsRead(t *testing.T) {
	base := t.TempDir()
	scan := filepath.Join(base, "scan")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{scan, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(outside, "external.pem")
	writeFile(t, target, pemBlock("CERTIFICATE", testCertDER(t, "external.example")))

	link := filepath.Join(scan, "innocent.pem")
	if err := os.Link(target, link); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}

	_, c := walkDir(t, scan, PolicyOptions{})
	if c.CertificatesReturned != 1 {
		t.Fatalf("expected the hardlinked certificate to be read (documented limitation), got %d",
			c.CertificatesReturned)
	}
}

// INV-1 holds regardless of how the bytes arrived. A hardlink to a private key
// is still refused, by content, in every form.
func TestHardlinkedPrivateKeyNeverEscapes(t *testing.T) {
	base := t.TempDir()
	scan := filepath.Join(base, "scan")
	secret := filepath.Join(base, "secret")
	for _, d := range []string{scan, secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	key := testRSAKey(t)
	pkcs8 := mustPKCS8(t, key)

	// Four shapes, each hardlinked into the scanned directory under an
	// innocent-looking certificate extension.
	files := map[string][]byte{
		"keyonly.pem": pemBlock("PRIVATE KEY", pkcs8),
		"combo.pem": append(pemBlock("CERTIFICATE", testCertDER(t, "a.example")),
			pemBlock("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))...),
		"keyfirst.pem": append(pemBlock("PRIVATE KEY", pkcs8),
			pemBlock("CERTIFICATE", testCertDER(t, "b.example"))...),
		"derkey.der": pkcs8,
	}
	for name, content := range files {
		src := filepath.Join(secret, name)
		writeFile(t, src, content)
		if err := os.Link(src, filepath.Join(scan, name)); err != nil {
			t.Skipf("hardlinks unavailable: %v", err)
		}
	}

	res, c := walkDir(t, scan, PolicyOptions{})
	keyPrefix := key.N.Bytes()[:32]
	for _, r := range res {
		for _, der := range r.CertificateDER {
			if bytes.Contains(der, keyPrefix) {
				t.Fatalf("key material escaped via a hardlink at %s", r.Path)
			}
		}
	}
	// The certificates in the mixed bundles must still be found: refusing
	// everything would pass this test while breaking the product.
	if c.CertificatesReturned != 2 {
		t.Fatalf("CertificatesReturned = %d, want 2 (one from each mixed bundle)", c.CertificatesReturned)
	}
	if c.PrivateKeyBlocksSkipped < 2 {
		t.Fatalf("PrivateKeyBlocksSkipped = %d, want at least 2", c.PrivateKeyBlocksSkipped)
	}
}
