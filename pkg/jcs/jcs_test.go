package jcs

import (
	"errors"
	"math"
	"testing"
)

// RFC 8785 §3.2.4, the worked example, byte for byte.
func TestRFC8785Example(t *testing.T) {
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// RFC 8785 §3.2.3: keys sort by UTF-16 code unit. U+1F600 (surrogates D83D
// DE00) sorts BEFORE U+FB33 in UTF-16 but AFTER it by code point — the case
// that catches a rune-order or byte-order implementation.
func TestRFC8785KeySorting(t *testing.T) {
	in := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

// RFC 8785 Appendix B number vectors (IEEE-754 bit patterns).
func TestRFC8785Numbers(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"}, // negative zero
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
	}
	for _, c := range cases {
		if got := FormatFloat(math.Float64frombits(c.bits)); got != c.want {
			t.Errorf("%016x: got %s want %s", c.bits, got, c.want)
		}
	}
}

// Re-serialisation by a proxy must not change the canonical form.
func TestEquivalentBodiesCanonicaliseIdentically(t *testing.T) {
	a := `{"b":1,"a":[1,2,{"y":"\u0041","x":true}]}`
	b := "{ \"a\" : [ 1 , 2.0 , { \"x\" : true , \"y\" : \"A\" } ] ,\n\"b\":1e0}"
	ca, err := Canonicalize([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Canonicalize([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("%s != %s", ca, cb)
	}
}

// Each of these would let two raw bodies with different meanings share one
// signature.
func TestAmbiguousInputsAreRefused(t *testing.T) {
	cases := map[string]struct {
		in   string
		want error
	}{
		"duplicate key":        {`{"tenant_id":"a","tenant_id":"b"}`, ErrDuplicateKey},
		"nested duplicate key": {`{"x":[{"k":1,"k":2}]}`, ErrDuplicateKey},
		"integer beyond 2^53":  {`{"n":9007199254740993}`, ErrUnsafeNumber},
		"negative beyond 2^53": {`{"n":-9007199254740993}`, ErrUnsafeNumber},
		"overflowing exponent": {`{"n":1e400}`, ErrUnsafeNumber},
		"lone high surrogate":  {`{"s":"\ud800"}`, ErrInvalid},
		"lone low surrogate":   {`{"s":"\udc00x"}`, ErrInvalid},
		"invalid UTF-8":        {"{\"s\":\"\xff\"}", ErrInvalid},
		"trailing value":       {`{"a":1}{"a":2}`, ErrInvalid},
		"trailing garbage":     {`{"a":1} x`, ErrInvalid},
		"empty":                {``, ErrInvalid},
		"truncated":            {`{"a":`, ErrInvalid},
		"non-string key":       {`{1:2}`, ErrInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Canonicalize([]byte(c.in))
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestDeepNestingIsRefused(t *testing.T) {
	deep := ""
	for i := 0; i <= MaxDepth+1; i++ {
		deep += "["
	}
	for i := 0; i <= MaxDepth+1; i++ {
		deep += "]"
	}
	if _, err := Canonicalize([]byte(deep)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

// 2^53 itself is exact and must be accepted; it is the boundary.
func TestSafeIntegerBoundary(t *testing.T) {
	got, err := Canonicalize([]byte(`[9007199254740992,-9007199254740992]`))
	if err != nil || string(got) != `[9007199254740992,-9007199254740992]` {
		t.Fatalf("%s %v", got, err)
	}
}
