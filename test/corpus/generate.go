// Package corpus generates the certificate test corpus.
//
// Generated rather than collected, for one reason: no customer certificate ever
// enters this repository. A generated corpus can also cover cases that are rare
// in the wild but catastrophic when mishandled — a notAfter beyond 2038, a
// serial over 20 bytes, a 1000-entry SAN list.
//
// Determinism matters: the same seed produces the same corpus, so a parse-rate
// regression is attributable to a code change and not to a different sample.
package corpus

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	rand2 "math/rand/v2"
	"net"
	"net/url"
	"time"
)

// Entry is one corpus certificate with what it is meant to exercise.
type Entry struct {
	Name string
	DER  []byte
	// ExpectParseable is false for entries deliberately malformed beyond
	// recovery. The corpus assertion allows a small budget of these.
	ExpectParseable bool
	Exercises       string
}

func reader(seed uint64) io.Reader {
	var s [32]byte
	for i := range s {
		s[i] = byte(seed>>(uint(i%8)*8)) ^ byte(i*13+5)
	}
	return rand2.NewChaCha8(s)
}

var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Generate builds the corpus. n is the number of routine certificates added on
// top of the hand-written edge cases; the total must be at least 500.
func Generate(n int) ([]Entry, error) {
	var out []Entry

	// add takes the (der, err) pair directly so each call site stays one line.
	add := func(name, exercises string, parseable bool, made func() ([]byte, error)) {
		der, err := made()
		if err != nil {
			return
		}
		out = append(out, Entry{Name: name, DER: der, ExpectParseable: parseable, Exercises: exercises})
	}

	// ---- Key algorithms and sizes ----
	add("rsa-2048", "RSA 2048, the common case", true, func() ([]byte, error) { return mk(1, func(t *x509.Certificate) {}, keyRSA(2048)) })
	add("rsa-4096", "large RSA modulus", true, func() ([]byte, error) { return mk(2, func(t *x509.Certificate) {}, keyRSA(4096)) })
	add("rsa-1024", "weak key, must still parse and be reported", true, func() ([]byte, error) { return mk(3, func(t *x509.Certificate) {}, keyRSA(1024)) })
	add("ecdsa-p256", "ECDSA P-256", true, func() ([]byte, error) { return mk(4, func(t *x509.Certificate) {}, keyEC(elliptic.P256())) })
	add("ecdsa-p384", "ECDSA P-384", true, func() ([]byte, error) { return mk(5, func(t *x509.Certificate) {}, keyEC(elliptic.P384())) })
	add("ecdsa-p521", "ECDSA P-521", true, func() ([]byte, error) { return mk(6, func(t *x509.Certificate) {}, keyEC(elliptic.P521())) })
	add("ed25519", "Ed25519: key size must be NULL, not 256", true, func() ([]byte, error) { return mk(7, func(t *x509.Certificate) {}, keyEd()) })

	// ---- Validity windows ----
	add("expired", "expired certificate", true, func() ([]byte, error) {
		return mk(10, func(t *x509.Certificate) {
			t.NotBefore = base.AddDate(-3, 0, 0)
			t.NotAfter = base.AddDate(-1, 0, 0)
		}, keyEC(elliptic.P256()))
	})
	add("not-yet-valid", "notBefore in the future", true, func() ([]byte, error) {
		return mk(11, func(t *x509.Certificate) {
			t.NotBefore = base.AddDate(5, 0, 0)
			t.NotAfter = base.AddDate(6, 0, 0)
		}, keyEC(elliptic.P256()))
	})
	add("beyond-2038", "notAfter past the 32-bit epoch; must not wrap", true, func() ([]byte, error) {
		return mk(12, func(t *x509.Certificate) {
			t.NotAfter = time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC)
		}, keyEC(elliptic.P256()))
	})
	add("very-short-life", "47-day lifetime, the 2029 regime", true, func() ([]byte, error) {
		return mk(13, func(t *x509.Certificate) {
			t.NotAfter = base.AddDate(0, 0, 47)
		}, keyEC(elliptic.P256()))
	})

	// ---- SAN shapes ----
	add("wildcard", "wildcard SAN; must NOT cover the bare domain", true, func() ([]byte, error) {
		return mk(20, func(t *x509.Certificate) {
			t.DNSNames = []string{"*.example.com"}
		}, keyEC(elliptic.P256()))
	})
	add("wildcard-plus-apex", "both wildcard and apex present", true, func() ([]byte, error) {
		return mk(21, func(t *x509.Certificate) {
			t.DNSNames = []string{"*.example.com", "example.com"}
		}, keyEC(elliptic.P256()))
	})
	add("idn-punycode", "already-punycode SAN", true, func() ([]byte, error) {
		return mk(22, func(t *x509.Certificate) {
			t.DNSNames = []string{"xn--bcher-kva.example"}
		}, keyEC(elliptic.P256()))
	})
	add("trailing-dot", "fully-qualified name with a trailing dot", true, func() ([]byte, error) {
		return mk(23, func(t *x509.Certificate) {
			t.DNSNames = []string{"host.example.com."}
		}, keyEC(elliptic.P256()))
	})
	add("mixed-case-san", "uppercase SAN must normalise to lowercase", true, func() ([]byte, error) {
		return mk(24, func(t *x509.Certificate) {
			t.DNSNames = []string{"Host.EXAMPLE.Com"}
		}, keyEC(elliptic.P256()))
	})
	add("ipv4-san", "iPAddress SAN, v4", true, func() ([]byte, error) {
		return mk(25, func(t *x509.Certificate) {
			t.IPAddresses = []net.IP{net.ParseIP("10.20.30.40")}
		}, keyEC(elliptic.P256()))
	})
	add("ipv6-san", "iPAddress SAN, v6; must compress and lowercase", true, func() ([]byte, error) {
		return mk(26, func(t *x509.Certificate) {
			t.IPAddresses = []net.IP{net.ParseIP("2001:0DB8:0000:0000:0000:0000:0000:0001")}
		}, keyEC(elliptic.P256()))
	})
	add("ipv4-mapped-v6", "IPv4-mapped IPv6 must normalise to IPv4", true, func() ([]byte, error) {
		return mk(27, func(t *x509.Certificate) {
			t.IPAddresses = []net.IP{net.ParseIP("::ffff:192.0.2.1")}
		}, keyEC(elliptic.P256()))
	})
	add("uri-san", "URI SAN (SPIFFE-style)", true, func() ([]byte, error) {
		return mk(28, func(t *x509.Certificate) {
			u, _ := url.Parse("spiffe://cluster.local/ns/default/sa/api")
			t.URIs = []*url.URL{u}
		}, keyEC(elliptic.P256()))
	})
	add("email-san", "rfc822Name SAN", true, func() ([]byte, error) {
		return mk(29, func(t *x509.Certificate) {
			t.EmailAddresses = []string{"Ops@Example.COM"}
		}, keyEC(elliptic.P256()))
	})
	add("many-sans-250", "250 SANs, a CDN-shaped certificate", true, func() ([]byte, error) {
		return mk(30, func(t *x509.Certificate) {
			for i := 0; i < 250; i++ {
				t.DNSNames = append(t.DNSNames, fmt.Sprintf("h%03d.cdn.example", i))
			}
		}, keyEC(elliptic.P256()))
	})
	add("many-sans-1200", "1200 SANs; must truncate at 1000 and record the true count", true, func() ([]byte, error) {
		return mk(31, func(t *x509.Certificate) {
			for i := 0; i < 1200; i++ {
				t.DNSNames = append(t.DNSNames, fmt.Sprintf("h%04d.big.example", i))
			}
		}, keyEC(elliptic.P256()))
	})
	add("no-sans", "no SAN extension at all; CN only", true, func() ([]byte, error) {
		return mk(32, func(t *x509.Certificate) {
			t.DNSNames = nil
		}, keyEC(elliptic.P256()))
	})

	// ---- Serial shapes ----
	add("serial-20-bytes", "maximum legal serial length", true, func() ([]byte, error) {
		return mk(40, func(t *x509.Certificate) {
			t.SerialNumber = new(big.Int).SetBytes(bytesOf(20, 0xA7))
		}, keyEC(elliptic.P256()))
	})
	add("serial-24-bytes", "serial OVER the legal limit; occurs in the wild", true, func() ([]byte, error) {
		return mk(41, func(t *x509.Certificate) {
			t.SerialNumber = new(big.Int).SetBytes(bytesOf(24, 0x5C))
		}, keyEC(elliptic.P256()))
	})
	add("serial-one", "minimal serial", true, func() ([]byte, error) {
		return mk(42, func(t *x509.Certificate) {
			t.SerialNumber = big.NewInt(1)
		}, keyEC(elliptic.P256()))
	})
	add("serial-leading-zero", "serial whose first byte is zero", true, func() ([]byte, error) {
		return mk(43, func(t *x509.Certificate) {
			t.SerialNumber = new(big.Int).SetBytes([]byte{0x00, 0x01, 0x02, 0x03})
		}, keyEC(elliptic.P256()))
	})

	// ---- Subject / issuer shapes ----
	add("empty-subject", "no subject attributes; legal and increasingly common", true, func() ([]byte, error) {
		return mk(50, func(t *x509.Certificate) {
			t.Subject = pkix.Name{}
			t.DNSNames = []string{"nosubject.example"}
		}, keyEC(elliptic.P256()))
	})
	add("utf8-subject", "non-ASCII subject", true, func() ([]byte, error) {
		return mk(51, func(t *x509.Certificate) {
			t.Subject = pkix.Name{CommonName: "Ünïcödé Ltd", Organization: []string{"Ünïcödé"}}
		}, keyEC(elliptic.P256()))
	})
	add("comma-in-dn", "attribute value containing a comma; must be escaped", true, func() ([]byte, error) {
		return mk(52, func(t *x509.Certificate) {
			t.Subject = pkix.Name{CommonName: "host", Organization: []string{"Example, Inc."}}
		}, keyEC(elliptic.P256()))
	})
	add("multi-ou", "several OU attributes; order must be preserved", true, func() ([]byte, error) {
		return mk(53, func(t *x509.Certificate) {
			t.Subject = pkix.Name{CommonName: "h", OrganizationalUnit: []string{"Platform", "Infrastructure", "SRE"}}
		}, keyEC(elliptic.P256()))
	})
	add("long-dn", "very long subject", true, func() ([]byte, error) {
		return mk(54, func(t *x509.Certificate) {
			t.Subject = pkix.Name{CommonName: repeat("a", 200), Organization: []string{repeat("b", 200)}}
		}, keyEC(elliptic.P256()))
	})

	// ---- CA and usage shapes ----
	add("ca-root", "self-signed CA", true, func() ([]byte, error) {
		return mk(60, func(t *x509.Certificate) {
			t.IsCA = true
			t.BasicConstraintsValid = true
			t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}, keyEC(elliptic.P256()))
	})
	add("client-auth-only", "clientAuth EKU only; partner mTLS", true, func() ([]byte, error) {
		return mk(61, func(t *x509.Certificate) {
			t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}, keyEC(elliptic.P256()))
	})
	add("no-eku", "no extended key usage", true, func() ([]byte, error) {
		return mk(62, func(t *x509.Certificate) {
			t.ExtKeyUsage = nil
		}, keyEC(elliptic.P256()))
	})
	add("unknown-eku", "unrecognised EKU OID", true, func() ([]byte, error) {
		return mk(63, func(t *x509.Certificate) {
			t.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}
		}, keyEC(elliptic.P256()))
	})
	add("critical-unknown-ext", "critical extension we do not recognise", true, func() ([]byte, error) {
		return mk(64, func(t *x509.Certificate) {
			t.ExtraExtensions = []pkix.Extension{{
				Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 7}, Critical: true, Value: []byte{0x04, 0x02, 0x01, 0x02},
			}}
		}, keyEC(elliptic.P256()))
	})

	// ---- Signature algorithms ----
	add("sha1-rsa", "SHA-1 signature; deprecated and still deployed", true,
		func() ([]byte, error) { return mkSig(70, x509.SHA1WithRSA, keyRSA(2048)) })
	add("sha384-ecdsa", "ECDSA SHA-384", true, func() ([]byte, error) { return mkSig(71, x509.ECDSAWithSHA384, keyEC(elliptic.P384())) })
	add("sha512-rsa", "RSA SHA-512", true, func() ([]byte, error) { return mkSig(72, x509.SHA512WithRSA, keyRSA(2048)) })

	// ---- Routine fill, to reach the corpus size target ----
	for i := 0; i < n; i++ {
		seed := uint64(1000 + i)
		idx := i
		add(fmt.Sprintf("routine-%04d", i), "routine certificate", true, func() ([]byte, error) {
			return mk(seed, func(t *x509.Certificate) {
				t.Subject = pkix.Name{CommonName: fmt.Sprintf("svc%04d.internal.example", idx)}
				t.DNSNames = []string{
					fmt.Sprintf("svc%04d.internal.example", idx),
					fmt.Sprintf("svc%04d.prod.internal.example", idx),
				}
				t.NotAfter = base.AddDate(0, 0, 200-(idx%200))
			}, keyEC(elliptic.P256()))
		})
	}

	return out, nil
}

// Malformed returns deliberately broken inputs. These must never panic and must
// be recorded as partial or unparseable — never dropped.
//
// Note what is NOT here: a bit flip in the signature bytes. That produces a
// perfectly parseable certificate with a different fingerprint, because
// x509.ParseCertificate does not verify signatures. Asserting that such input
// "must not parse" would be testing the wrong thing. See
// Corrupted() for inputs that must still parse cleanly.
func Malformed() []Entry {
	good, _ := Generate(0)
	valid := good[0].DER

	return []Entry{
		{Name: "empty", DER: nil, Exercises: "empty input"},
		{Name: "one-byte", DER: []byte{0x30}, Exercises: "single byte"},
		{Name: "truncated-header", DER: valid[:4], Exercises: "truncated DER header"},
		{Name: "truncated-half", DER: valid[:len(valid)/2], Exercises: "truncated mid-certificate"},
		{Name: "truncated-last-byte", DER: valid[:len(valid)-1], Exercises: "off-by-one truncation"},
		{Name: "all-zeros", DER: make([]byte, 512), Exercises: "zero bytes"},
		{Name: "all-ff", DER: bytesOf(512, 0xFF), Exercises: "0xFF bytes"},
		// A flip in the LENGTH HEADER is structurally fatal.
		{Name: "bit-flipped-length", DER: flip(valid, 3), Exercises: "bit flip in the DER length header"},
		{Name: "bit-flipped-tag", DER: flip(valid, 0), Exercises: "bit flip in the outer tag"},
		{Name: "length-overflow", DER: []byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
			Exercises: "declared length far beyond the buffer"},
		{Name: "indefinite-length", DER: []byte{0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00},
			Exercises: "indefinite length, illegal in DER"},
		{Name: "deep-nesting", DER: nest(200), Exercises: "deeply nested SEQUENCEs"},
		{Name: "prepended-garbage", DER: append([]byte{0xAA, 0xBB, 0xCC}, valid...),
			Exercises: "valid certificate with a prefix"},
	}
}

// Corrupted returns inputs that are altered but MUST still parse cleanly.
//
// These exist to stop a future "reject anything suspicious" change from
// silently dropping valid certificates: a signature this parser cannot verify
// is not the parser's business, and an inventory that omits such certificates
// is wrong in the direction that matters.
func Corrupted() []Entry {
	good, _ := Generate(0)
	valid := good[0].DER
	return []Entry{
		{Name: "signature-bit-flip", DER: flip(valid, len(valid)-10), ExpectParseable: true,
			Exercises: "bit flip in the signature; must still parse, with a different fingerprint"},
	}
}

// ---- builders ----

type keyMaker func(seed uint64) (pub any, priv any, err error)

func keyRSA(bits int) keyMaker {
	return func(seed uint64) (any, any, error) {
		k, err := rsa.GenerateKey(reader(seed), bits)
		if err != nil {
			return nil, nil, err
		}
		return &k.PublicKey, k, nil
	}
}

func keyEC(c elliptic.Curve) keyMaker {
	return func(seed uint64) (any, any, error) {
		k, err := ecdsa.GenerateKey(c, reader(seed))
		if err != nil {
			return nil, nil, err
		}
		return &k.PublicKey, k, nil
	}
}

func keyEd() keyMaker {
	return func(seed uint64) (any, any, error) {
		pub, priv, err := ed25519.GenerateKey(reader(seed))
		return pub, priv, err
	}
}

func mk(seed uint64, shape func(*x509.Certificate), km keyMaker) ([]byte, error) {
	return mkSig(seed, x509.UnknownSignatureAlgorithm, km, shape)
}

func mkSig(seed uint64, sig x509.SignatureAlgorithm, km keyMaker, shapes ...func(*x509.Certificate)) ([]byte, error) {
	pub, priv, err := km(seed)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(seed) + 1),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("corpus-%d.example", seed)},
		NotBefore:             base,
		NotAfter:              base.AddDate(0, 0, 200),
		DNSNames:              []string{fmt.Sprintf("corpus-%d.example", seed)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sig,
	}
	for _, s := range shapes {
		s(tmpl)
	}
	return x509.CreateCertificate(reader(seed+7), tmpl, tmpl, pub, priv)
}

func bytesOf(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b ^ byte(i)
	}
	return out
}

func flip(b []byte, at int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	if at < len(out) {
		out[at] ^= 0x40
	}
	return out
}

func nest(depth int) []byte {
	out := []byte{}
	for i := 0; i < depth; i++ {
		out = append([]byte{0x30, byte(len(out))}, out...)
		if len(out) > 250 {
			break
		}
	}
	return out
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
