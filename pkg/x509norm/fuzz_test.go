package x509norm_test

import (
	"testing"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/x509norm"
	"github.com/certwatch/certwatch/test/corpus"
)

// X509-007. These entry points consume bytes from hostile endpoints and hostile
// files. A panic is a denial of service on a whole scan task; a hang is worse,
// because it blocks every remaining target behind it.
//
// Crashers found here are committed to testdata/fuzz/ and become permanent
// regression tests, not one-off fixes.

func FuzzParseDER(f *testing.F) {
	valid, malformed, err := corpus.Load()
	if err != nil {
		f.Fatal(err)
	}
	for i, e := range valid {
		if i > 60 {
			break
		}
		f.Add(e.DER)
	}
	for _, e := range malformed {
		f.Add(e.DER)
	}

	f.Fuzz(func(t *testing.T, der []byte) {
		c, _ := x509norm.ParseDER(der)
		if c == nil {
			t.Fatal("ParseDER returned nil; it must always return a row")
		}
		// Every non-empty input must be identifiable, or it can be dropped
		// silently from an inventory — the failure this package exists to avoid.
		if len(der) > 0 && c.Fingerprint == "" {
			t.Fatal("no fingerprint for non-empty input")
		}
		// A status of ok must mean the core fields are actually populated.
		if c.ParseStatus == model.ParseOK {
			if c.NotAfter.IsZero() || c.NotBefore.IsZero() {
				t.Fatal("ParseOK but validity window is zero")
			}
			if c.KeyAlgorithm == model.KeyUnknown {
				t.Fatal("ParseOK but key algorithm is unknown")
			}
		}
		// SANs must be capped regardless of input.
		if len(c.SANs) > x509norm.MaxSANs {
			t.Fatalf("SAN list exceeded the cap: %d", len(c.SANs))
		}
	})
}

func FuzzParsePEM(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----"))
	f.Add([]byte(""))
	f.Add([]byte("not pem at all"))

	f.Fuzz(func(t *testing.T, b []byte) {
		certs, err := x509norm.ParsePEM(b)
		if err != nil {
			return
		}
		if len(certs) > x509norm.MaxChainLength {
			t.Fatalf("returned %d certificates, over the chain cap", len(certs))
		}
		for _, c := range certs {
			if c == nil {
				t.Fatal("nil certificate in the returned slice")
			}
		}
	})
}

func FuzzParseChain(f *testing.F) {
	valid, _, err := corpus.Load()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid[0].DER, valid[1].DER)
	f.Add([]byte{}, []byte{})
	f.Add(valid[0].DER, []byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, a, b []byte) {
		ch, err := x509norm.ParseChain([][]byte{a, b})
		if err != nil {
			return
		}
		if ch.Leaf == nil {
			t.Fatal("chain returned with a nil leaf")
		}
		// The leaf must never also appear among the intermediates, or downstream
		// code would count one certificate twice.
		for _, i := range ch.Intermediates {
			if i == ch.Leaf {
				t.Fatal("leaf also present in intermediates")
			}
		}
	})
}
