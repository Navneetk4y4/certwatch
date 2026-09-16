package safeio

import (
	"bytes"
	"testing"
)

// FuzzClassifyDER: the fail-closed guarantee.
//
// The critical property is NOT that classification is accurate — it is that
// nothing which is, or might be, a private key is ever returned as a
// certificate. Ambiguity must always resolve toward skipping.
func FuzzClassifyDER(f *testing.F) {
	f.Add([]byte{0x30, 0x82, 0x01, 0x22, 0x30, 0x0d})
	f.Add([]byte{0x30, 0x1a, 0x02, 0x01, 0x00}) // PKCS#8 prefix
	f.Add([]byte{0x30, 0x1a, 0x02, 0x01, 0x01}) // SEC1 prefix
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})       // indefinite length
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		class, reason := classifyDER(b)
		switch class {
		case ClassCertificateDER:
			// If it is returned as a certificate it must NOT look like a key.
			if isPrivateKeyDER(b) {
				t.Fatalf("classifyDER returned ClassCertificateDER for input that isPrivateKeyDER accepts")
			}
			if !looksLikeCertificateDER(b) {
				t.Fatalf("classifyDER returned ClassCertificateDER for input that fails the structural check")
			}
		case SkippedPrivateKeyBlock, SkippedAmbiguousDER:
			if reason == "" {
				t.Fatal("a skip with no reason; skips must never be silent")
			}
		default:
			t.Fatalf("classifyDER returned unexpected class %v", class)
		}
	})
}

// FuzzReadPEM: the PEM path must never panic, never hang, and never return a
// certificate that is actually key material.
func FuzzReadPEM(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n"))        // unterminated
	f.Add([]byte("-----BEGIN X-----\n-----END Y-----\n")) // mismatched labels
	f.Add([]byte(""))
	f.Add(bytes.Repeat([]byte("A"), 100000)) // one enormous line

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		dir := t.TempDir()
		path := dir + "/fuzz.pem"
		writeFileRaw(t, path, body)

		p, err := NewPolicy([]string{dir}, PolicyOptions{})
		if err != nil {
			t.Skip()
		}
		res, c, err := ReadCertificatesOnly(t.Context(), p.Roots()[0], p)
		if err != nil {
			return
		}
		if ok, why := c.Conserved(); !ok {
			t.Fatalf("counter conservation violated: %s", why)
		}
		for _, r := range res {
			if !r.Class.IsCertificate() && len(r.CertificateDER) != 0 {
				t.Fatalf("skip class %v returned %d DER blocks", r.Class, len(r.CertificateDER))
			}
			for _, der := range r.CertificateDER {
				// Anything returned as a certificate must not be a private key.
				if isPrivateKeyDER(der) {
					t.Fatal("a DER-encoded private key was returned as a certificate")
				}
			}
		}
	})
}
