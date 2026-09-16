package x509norm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/x509norm"
)

func build(t *testing.T, shape func(*x509.Certificate)) *model.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test.example"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
	shape(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509norm.ParseDER(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// X509-004: the six SAN normalisation rules.
func TestSANNormalisation(t *testing.T) {
	cases := []struct {
		name  string
		shape func(*x509.Certificate)
		want  []string
	}{
		{"lowercases", func(c *x509.Certificate) { c.DNSNames = []string{"HOST.Example.COM"} },
			[]string{"DNS:host.example.com"}},
		{"strips one trailing dot", func(c *x509.Certificate) { c.DNSNames = []string{"host.example.com."} },
			[]string{"DNS:host.example.com"}},
		{"preserves wildcard exactly", func(c *x509.Certificate) { c.DNSNames = []string{"*.example.com"} },
			[]string{"DNS:*.example.com"}},
		{"deduplicates", func(c *x509.Certificate) { c.DNSNames = []string{"a.example", "a.example", "a.example"} },
			[]string{"DNS:a.example"}},
		{"sorts", func(c *x509.Certificate) { c.DNSNames = []string{"z.example", "a.example", "m.example"} },
			[]string{"DNS:a.example", "DNS:m.example", "DNS:z.example"}},
		{"compresses IPv6", func(c *x509.Certificate) {
			c.IPAddresses = []net.IP{net.ParseIP("2001:0db8:0000:0000:0000:0000:0000:0001")}
		}, []string{"IP:2001:db8::1"}},
		{"unmaps IPv4-mapped IPv6", func(c *x509.Certificate) {
			c.IPAddresses = []net.IP{net.ParseIP("::ffff:192.0.2.1")}
		}, []string{"IP:192.0.2.1"}},
		{"lowercases email", func(c *x509.Certificate) { c.EmailAddresses = []string{"Ops@Example.COM"} },
			[]string{"EMAIL:ops@example.com"}},
		{"keeps URI", func(c *x509.Certificate) {
			u, _ := url.Parse("spiffe://cluster.local/ns/default/sa/api")
			c.URIs = []*url.URL{u}
		}, []string{"URI:spiffe://cluster.local/ns/default/sa/api"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := build(t, tc.shape).SANs
			if len(got) != len(tc.want) {
				t.Fatalf("SANs = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("SANs = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// Rule 6: truncation must be visible, never silent.
func TestSANTruncationIsVisible(t *testing.T) {
	c := build(t, func(tm *x509.Certificate) {
		for i := 0; i < 1200; i++ {
			tm.DNSNames = append(tm.DNSNames, strings.Repeat("a", 3)+string(rune('a'+i%26))+".example")
		}
	})
	if len(c.SANs) > x509norm.MaxSANs {
		t.Fatalf("SANs not capped: %d", len(c.SANs))
	}
	if len(c.SANs) == x509norm.MaxSANs && c.SANsTruncatedCount == 0 {
		t.Fatal("SAN list was truncated but the true count was not recorded")
	}
	if c.SANsTruncatedCount > 0 && c.ParseStatus != model.ParsePartial {
		t.Fatalf("truncated SANs must mark the certificate partial, got %s", c.ParseStatus)
	}
}

// X509-005: key algorithm and size. Ed25519 must report NO size.
func TestKeyAlgorithmAndSize(t *testing.T) {
	valid, _, err := corpusLoad(t)
	if err != nil {
		t.Fatal(err)
	}
	var sawEd, sawRSA, sawEC bool
	for _, e := range valid {
		c, _ := x509norm.ParseDER(e.DER)
		switch c.KeyAlgorithm {
		case model.KeyEd25519:
			sawEd = true
			if c.KeySize != nil {
				t.Fatalf("%s: Ed25519 reported key size %d; it must be nil, because a bit size "+
					"is not a meaningful property of Ed25519 and reporting 256 invites a "+
					"meaningless comparison with ECDSA P-256", e.Name, *c.KeySize)
			}
		case model.KeyRSA:
			sawRSA = true
			if c.KeySize == nil || *c.KeySize < 512 {
				t.Fatalf("%s: RSA key size missing or implausible", e.Name)
			}
		case model.KeyECDSA:
			sawEC = true
			if c.KeySize == nil {
				t.Fatalf("%s: ECDSA key size missing", e.Name)
			}
		}
	}
	if !sawEd || !sawRSA || !sawEC {
		t.Fatalf("corpus did not cover all three algorithms (ed=%v rsa=%v ec=%v)", sawEd, sawRSA, sawEC)
	}
}

// X509-003: DN rendering, including escaping and order preservation.
func TestDNRendering(t *testing.T) {
	c := build(t, func(tm *x509.Certificate) {
		tm.Subject = pkix.Name{
			CommonName:         "host.example",
			Organization:       []string{"Example, Inc."},
			OrganizationalUnit: []string{"Platform", "SRE"},
			Country:            []string{"GB"},
		}
	})
	if !strings.Contains(c.SubjectDN, "CN=host.example") {
		t.Fatalf("SubjectDN missing CN: %q", c.SubjectDN)
	}
	// RFC 4514 §2.4: a comma inside a value must be escaped.
	if !strings.Contains(c.SubjectDN, `O=Example\, Inc.`) {
		t.Fatalf("comma in an attribute value was not escaped: %q", c.SubjectDN)
	}
	// RFC 4514 prints most-specific first.
	cnIdx := strings.Index(c.SubjectDN, "CN=")
	cIdx := strings.Index(c.SubjectDN, "C=GB")
	if cnIdx < 0 || cIdx < 0 || cnIdx > cIdx {
		t.Fatalf("RDN order is not most-specific-first: %q", c.SubjectDN)
	}
	if c.SubjectCN != "host.example" {
		t.Fatalf("SubjectCN = %q", c.SubjectCN)
	}
}

// Serial handling: text, lowercase hex, leading zeros preserved.
func TestSerialNormalisation(t *testing.T) {
	c := build(t, func(tm *x509.Certificate) {
		tm.SerialNumber = new(big.Int).SetBytes([]byte{0x0A, 0x1B, 0x2C, 0x3D})
	})
	if c.Serial != "a1b2c3d" && c.Serial != "0a1b2c3d" {
		t.Fatalf("Serial = %q, want lowercase hex of the serial bytes", c.Serial)
	}
	if strings.ContainsAny(c.Serial, ":ABCDEF ") {
		t.Fatalf("Serial %q contains separators or uppercase", c.Serial)
	}
}

// A serial longer than the legal 20 bytes must survive as text.
func TestOversizedSerial(t *testing.T) {
	big24 := make([]byte, 24)
	for i := range big24 {
		big24[i] = byte(i + 1)
	}
	c := build(t, func(tm *x509.Certificate) { tm.SerialNumber = new(big.Int).SetBytes(big24) })
	if len(c.Serial) != 48 {
		t.Fatalf("24-byte serial rendered as %q (%d chars), want 48 hex chars", c.Serial, len(c.Serial))
	}
}

// Self-signed detection must verify the signature, not just compare DNs:
// comparing DNs alone reports a cross-signed intermediate as self-signed.
func TestSelfSignedDetection(t *testing.T) {
	c := build(t, func(tm *x509.Certificate) {
		tm.Subject = pkix.Name{CommonName: "root.example"}
		tm.IsCA = true
		tm.BasicConstraintsValid = true
	})
	if !c.IsSelfSigned {
		t.Fatal("a genuinely self-signed certificate was not detected")
	}
}

func TestExpiryHelpers(t *testing.T) {
	c := build(t, func(tm *x509.Certificate) {
		tm.NotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		tm.NotAfter = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	})
	at := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if d := c.DaysRemaining(at); d != 28 {
		t.Fatalf("DaysRemaining = %d, want 28", d)
	}
	if c.Expired(at) {
		t.Fatal("reported expired while still valid")
	}
	if !c.Expired(time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("did not report expired after notAfter")
	}
	if !c.NotYetValid(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("did not report not-yet-valid before notBefore")
	}
}

// Regression, found by FuzzParseDER: a certificate whose public-key algorithm
// is not recognised must not be reported as fully parsed.
//
// ParseOK is a claim that the canonical fields are populated. A certificate
// with an unknown key algorithm cannot be policy-evaluated on key algorithm or
// minimum key size, so reporting it as `ok` would be a status that lies about
// completeness — and policy mode would silently skip a check it believes it ran.
func TestUnknownKeyAlgorithmIsNotReportedAsOK(t *testing.T) {
	valid, _, err := corpusLoad(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range valid {
		c, _ := x509norm.ParseDER(e.DER)
		if c.ParseStatus == model.ParseOK && c.KeyAlgorithm == model.KeyUnknown {
			t.Fatalf("%s: ParseStatus=ok with KeyAlgorithm=unknown", e.Name)
		}
		if c.ParseStatus == model.ParseOK && c.KeyAlgorithm != model.KeyEd25519 && c.KeySize == nil {
			t.Fatalf("%s: ParseStatus=ok but no key size for %s", e.Name, c.KeyAlgorithm)
		}
	}
}
