package x509norm_test

import (
	"testing"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/x509norm"
	"github.com/certwatch/certwatch/test/corpus"
)

// X509-008: the corpus gate. <1% unparseable, zero panics.
//
// This is a blocking gate for MVP v0. If the pass rate cannot reach 99%, the
// ParseStatus semantics are wrong — not the certificates.
func TestCorpusPassRate(t *testing.T) {
	valid, _, err := corpus.Load()
	if err != nil {
		t.Fatal(err)
	}

	var ok, partial, unparseable int
	for _, e := range valid {
		c, _ := x509norm.ParseDER(e.DER)
		if c == nil {
			t.Fatalf("%s: ParseDER returned nil; it must always return a certificate", e.Name)
		}
		if c.Fingerprint == "" {
			t.Fatalf("%s: no fingerprint; every input must yield a stable identity", e.Name)
		}
		switch c.ParseStatus {
		case model.ParseOK:
			ok++
		case model.ParsePartial:
			partial++
		case model.ParseUnparseable:
			unparseable++
			t.Logf("unparseable: %s (%s) notes=%v", e.Name, e.Exercises, c.ParseNotes)
		}
	}

	total := len(valid)
	rate := float64(unparseable) / float64(total) * 100
	t.Logf("corpus: %d total, %d ok, %d partial, %d unparseable (%.2f%%)", total, ok, partial, unparseable, rate)
	if rate >= 1.0 {
		t.Fatalf("unparseable rate %.2f%% >= 1%% gate", rate)
	}
}

// Malformed input must never panic and must always yield a row.
//
// A certificate that cannot be parsed is MORE interesting to an inventory, not
// less: it is disproportionately likely to be the ancient appliance certificate
// nobody manages. Dropping it is how an inventory quietly becomes wrong.
func TestMalformedNeverPanicsAndNeverDrops(t *testing.T) {
	_, malformed, err := corpus.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range malformed {
		t.Run(e.Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on malformed input %q (%s): %v", e.Name, e.Exercises, r)
				}
			}()
			c, _ := x509norm.ParseDER(e.DER)
			if c == nil {
				t.Fatalf("%s: returned nil instead of a row", e.Name)
			}
			if len(e.DER) > 0 && c.Fingerprint == "" {
				t.Fatalf("%s: no fingerprint recorded; the row must still be identifiable", e.Name)
			}
			if c.ParseStatus == model.ParseOK {
				t.Fatalf("%s: malformed input reported as fully parsed", e.Name)
			}
			if len(c.ParseNotes) == 0 {
				t.Fatalf("%s: no parse note explaining why it is not ok", e.Name)
			}
		})
	}
}

// P-6: the fingerprint is stable and is SHA-256 of the FULL DER.
func TestFingerprintStability(t *testing.T) {
	valid, _, err := corpus.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range valid[:20] {
		a, _ := x509norm.ParseDER(e.DER)
		b, _ := x509norm.ParseDER(e.DER)
		if a.Fingerprint != b.Fingerprint {
			t.Fatalf("%s: fingerprint not stable", e.Name)
		}
		if a.Fingerprint != x509norm.Fingerprint(e.DER) {
			t.Fatalf("%s: fingerprint disagrees with Fingerprint()", e.Name)
		}
		if len(a.Fingerprint) != 64 {
			t.Fatalf("%s: fingerprint is %d chars, want 64 (SHA-256 hex)", e.Name, len(a.Fingerprint))
		}
	}
}

// P-5: normalisation is idempotent. Two observations of the same certificate
// must produce equivalent canonical data, or dedup and expected-state
// comparison both break.
func TestNormalisationIdempotent(t *testing.T) {
	valid, _, err := corpus.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range valid {
		a, _ := x509norm.ParseDER(e.DER)
		b, _ := x509norm.ParseDER(e.DER)
		if a.SubjectDN != b.SubjectDN || a.IssuerDN != b.IssuerDN || a.Serial != b.Serial {
			t.Fatalf("%s: DN or serial not idempotent", e.Name)
		}
		if len(a.SANs) != len(b.SANs) {
			t.Fatalf("%s: SAN count not idempotent", e.Name)
		}
		for i := range a.SANs {
			if a.SANs[i] != b.SANs[i] {
				t.Fatalf("%s: SAN %d not idempotent: %q vs %q", e.Name, i, a.SANs[i], b.SANs[i])
			}
		}
	}
}

// A certificate whose signature bytes were altered must STILL parse cleanly.
//
// x509.ParseCertificate does not verify signatures, and it should not: an
// inventory that silently omits certificates it considers suspicious is wrong
// in the direction that matters most. The fingerprint must change, because the
// DER changed.
func TestCorruptedSignatureStillParses(t *testing.T) {
	for _, e := range corpus.Corrupted() {
		t.Run(e.Name, func(t *testing.T) {
			c, err := x509norm.ParseDER(e.DER)
			if err != nil {
				t.Fatalf("%s: %v", e.Name, err)
			}
			if c.ParseStatus != model.ParseOK {
				t.Fatalf("%s: status %s, want ok (%v)", e.Name, c.ParseStatus, c.ParseNotes)
			}
			valid, _, _ := corpus.Load()
			if c.Fingerprint == x509norm.Fingerprint(valid[0].DER) {
				t.Fatal("fingerprint did not change despite altered DER")
			}
		})
	}
}
