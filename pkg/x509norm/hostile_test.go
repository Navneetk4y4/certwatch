package x509norm

import (
	"encoding/asn1"
	"strings"
	"testing"
)

// decodeRawString handles ASN.1 string types that crypto/x509 leaves as raw
// bytes: BMPString, UniversalString and TeletexString. They appear in older
// enterprise and appliance certificates — exactly the population this product
// exists to find — and they carry ATTACKER-CONTROLLED bytes.
//
// The requirement is not perfect decoding. It is: never panic, always return
// something renderable, and never produce invalid UTF-8 that would corrupt a
// JSON report downstream.
func TestDecodeRawStringOnHostileInput(t *testing.T) {
	cases := []struct {
		name string
		rv   asn1.RawValue
	}{
		{"BMPString, valid", asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0x00, 0x41, 0x00, 0x42}}},
		{"BMPString, ODD length", asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0x00, 0x41, 0x00}}},
		{"BMPString, empty", asn1.RawValue{Tag: asn1.TagBMPString, Bytes: nil}},
		{"BMPString, unpaired surrogate", asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0xD8, 0x00, 0x00, 0x41}}},
		{"BMPString, all 0xFF", asn1.RawValue{Tag: asn1.TagBMPString, Bytes: []byte{0xFF, 0xFF, 0xFF, 0xFF}}},
		{"UniversalString, valid", asn1.RawValue{Tag: 28, Bytes: []byte{0, 0, 0, 0x41, 0, 0, 0, 0x42}}},
		{"UniversalString, misaligned", asn1.RawValue{Tag: 28, Bytes: []byte{0, 0, 0, 0x41, 0, 0}}},
		{"UniversalString, out of range rune", asn1.RawValue{Tag: 28, Bytes: []byte{0xFF, 0xFF, 0xFF, 0xFF}}},
		{"TeletexString", asn1.RawValue{Tag: asn1.TagT61String, Bytes: []byte{0x41, 0xE9, 0x42}}},
		{"TeletexString, all high bytes", asn1.RawValue{Tag: asn1.TagT61String, Bytes: []byte{0xFF, 0xFE, 0xFD}}},
		{"unknown tag, invalid UTF-8", asn1.RawValue{Tag: 99, Bytes: []byte{0xFF, 0xFE, 0x41}}},
		{"unknown tag, empty", asn1.RawValue{Tag: 99, Bytes: nil}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on hostile input: %v", r)
				}
			}()
			got := decodeRawString(tc.rv)
			// The result is embedded in a JSON report, so invalid UTF-8 here
			// would corrupt the output for every downstream consumer.
			if !isValidUTF8(got) {
				t.Fatalf("produced invalid UTF-8 from %s: %q", tc.name, got)
			}
		})
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			continue // an explicit replacement char is a deliberate, valid marker
		}
	}
	return strings.ToValidUTF8(s, "") == strings.ReplaceAll(s, "\x00", "\x00") || len(s) == 0 || strings.ToValidUTF8(s, "�") == s
}

// decodeDNValue must accept every shape crypto/x509 can hand it, and never
// render a Go struct dump into a customer-facing DN.
func TestDecodeDNValueShapes(t *testing.T) {
	cases := []struct {
		name string
		in   any
	}{
		{"string", "plain"},
		{"bytes", []byte("bytes")},
		{"raw value", asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("raw")}},
		{"nil", nil},
		{"int", 42},
		{"oid", asn1.ObjectIdentifier{1, 2, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decodeDNValue(tc.in)
			if strings.Contains(got, "%!") {
				t.Fatalf("a formatting verb leaked into the DN value: %q", got)
			}
		})
	}
}

// RFC 4514 escaping. An unescaped comma in a DN value would shift every
// subsequent attribute, which silently changes what the DN means.
func TestEscapeDNValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{`Example, Inc.`, `Example\, Inc.`},
		{`a+b`, `a\+b`},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{`a;b`, `a\;b`},
		{`a<b>c`, `a\<b\>c`},
		{` leading`, `\ leading`},   // RFC 4514 §2.4: a leading space is escaped
		{`trailing `, `trailing\ `}, // and a trailing one
		{`#hash`, `\#hash`},
		{"tab\there", `tab\09here`},
		{"nul\x00here", `nul\00here`},
		{"plain", "plain"},
		{"", ""},
	}
	for _, c := range cases {
		if got := escapeDNValue(c.in); got != c.want {
			t.Errorf("escapeDNValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// normaliseDNSName consumes SAN values from hostile certificates.
//
// The idempotence property (P-5) matters most: two observations of the same
// certificate must normalise identically, or deduplication and expected-state
// comparison both break.
func TestNormaliseDNSNameHostileAndIdempotent(t *testing.T) {
	inputs := []string{
		"", ".", "..", "...",
		"a", "A", "example.com", "EXAMPLE.COM.", "  example.com  ",
		"*.example.com", "*.EXAMPLE.com.", "*", "*.",
		"xn--bcher-kva.example", "bücher.example", "BÜCHER.example",
		strings.Repeat("a", 63) + ".example",
		strings.Repeat("a", 300) + ".example",
		strings.Repeat("a.", 200) + "example",
		"exam\x00ple.com", "tab\there.example", "\x7fdel.example",
		"exam ple.com",
		"-leading-hyphen.example",
		"..double..dots..",
		"\xff\xfe invalid utf8",
		"café.example", "CAFÉ.EXAMPLE",
	}

	for _, in := range inputs {
		t.Run(shortName(in), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on %q: %v", in, r)
				}
			}()
			first, _ := normaliseDNSName(in)
			second, _ := normaliseDNSName(first)
			if first != second {
				t.Fatalf("NOT IDEMPOTENT: %q -> %q -> %q. Two observations of the same "+
					"certificate would not deduplicate", in, first, second)
			}
		})
	}
}

// Wildcards must survive normalisation EXACTLY. "*.example.com" does not cover
// "example.com", and a normaliser that expanded or stripped the wildcard would
// make a SAN-coverage check report PASS on an endpoint browsers reject.
func TestWildcardsSurviveNormalisationExactly(t *testing.T) {
	cases := map[string]string{
		"*.example.com":       "*.example.com",
		"*.EXAMPLE.COM":       "*.example.com",
		"*.example.com.":      "*.example.com",
		"*.a.b.c.example.com": "*.a.b.c.example.com",
	}
	for in, want := range cases {
		got, _ := normaliseDNSName(in)
		if got != want {
			t.Errorf("normaliseDNSName(%q) = %q, want %q", in, got, want)
		}
		if !strings.HasPrefix(got, "*.") {
			t.Errorf("the wildcard label was lost normalising %q -> %q", in, got)
		}
	}
}

// A name that cannot be IDN-normalised is kept VERBATIM and the certificate is
// marked partial — never silently dropped, and never silently mangled.
func TestUnnormalisableNameIsKeptWithANote(t *testing.T) {
	// A leading hyphen is rejected by the IDNA Lookup profile. (A very long
	// label is NOT — idna.Lookup converts it happily — so an earlier version of
	// this test used a fixture that never exercised the failure path at all.)
	bad := "-leading-hyphen.ünïcödé.example"
	got, note := normaliseDNSName(bad)
	if got == "" {
		t.Fatal("an un-normalisable name was dropped rather than kept verbatim")
	}
	if note == "" {
		t.Fatal("an un-normalisable name produced no parse note; the degradation would be invisible")
	}
	if !strings.Contains(note, "verbatim") {
		t.Errorf("the note does not explain what happened: %q", note)
	}
}

// splitTopLevel must not split on an ESCAPED comma, or a DN containing
// "O=Example\, Inc." would be read as two attributes.
func TestSplitTopLevelRespectsEscaping(t *testing.T) {
	got := splitTopLevel(`CN=host,O=Example\, Inc.,C=GB`)
	if len(got) != 3 {
		t.Fatalf("split into %d parts (%v), want 3: an escaped comma was treated as a separator", len(got), got)
	}
	if got[1] != `O=Example\, Inc.` {
		t.Fatalf("part 1 = %q", got[1])
	}
}

func TestNormaliseSerialEdgeCases(t *testing.T) {
	if got := normaliseSerial(nil); got != "" {
		t.Errorf("normaliseSerial(nil) = %q, want empty", got)
	}
}

func shortName(s string) string {
	if s == "" {
		return "empty"
	}
	if len(s) > 24 {
		return s[:24] + "..."
	}
	return s
}
