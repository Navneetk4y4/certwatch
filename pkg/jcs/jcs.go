// Package jcs is RFC 8785 JSON Canonicalization Scheme.
//
// PROTO-007, build item 118. Mode 2 signs the CANONICAL form of a request body
// so that a TLS-inspecting proxy which re-serialises JSON (reorders keys,
// changes whitespace, re-escapes strings) does not break the signature, while
// any change to the MEANING of the body does.
//
// # Stricter than the RFC, deliberately
//
// The signature covers the canonical form; the server then acts on the raw
// body. Anything that lets two raw bodies with different meanings share one
// canonical form is a signature bypass, so the parser refuses:
//
//   - duplicate object keys. encoding/json keeps the LAST value; a signer that
//     canonicalised a different parse would sign the FIRST. Refused outright.
//   - integers beyond ±2^53. JCS maps every number to an IEEE double, so
//     9007199254740993 and 9007199254740992 canonicalise identically while
//     Go's int decoder would read them as different values.
//   - invalid UTF-8 and lone surrogate escapes.
//   - trailing content after the value.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth bounds nesting. A deeply nested body is a stack-exhaustion attempt,
// not a collector payload.
const MaxDepth = 64

var (
	ErrDuplicateKey = errors.New("jcs: duplicate object key")
	ErrUnsafeNumber = errors.New("jcs: number cannot be represented exactly")
	ErrInvalid      = errors.New("jcs: invalid JSON")
)

// maxSafeInt is 2^53: the largest magnitude at which every integer is an
// exactly representable double.
const maxSafeInt = 1 << 53

// Canonicalize returns the RFC 8785 form of one JSON value.
func Canonicalize(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out bytes.Buffer
	if err := value(dec, &out, 0); err != nil {
		return nil, err
	}
	// Anything after the value but whitespace is refused. Asking the decoder
	// for another token is not enough: invalid trailing bytes make it return
	// an error, which would read as "nothing more".
	if len(bytes.TrimLeft(raw[dec.InputOffset():], " \t\r\n")) != 0 {
		return nil, fmt.Errorf("%w: trailing content after the value", ErrInvalid)
	}
	return out.Bytes(), nil
}

func value(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: nesting deeper than %d", ErrInvalid, MaxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return object(dec, out, depth)
		case '[':
			return array(dec, out, depth)
		}
		return fmt.Errorf("%w: unexpected %q", ErrInvalid, t)
	case string:
		return writeString(out, t)
	case json.Number:
		s, err := Number(string(t))
		if err != nil {
			return err
		}
		out.WriteString(s)
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("%w: unexpected token", ErrInvalid)
	}
	return nil
}

type member struct {
	key   string
	units []uint16
	val   []byte
}

func object(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	var ms []member
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		k, ok := tok.(string)
		if !ok {
			return fmt.Errorf("%w: object key is not a string", ErrInvalid)
		}
		if seen[k] {
			return fmt.Errorf("%w: %q", ErrDuplicateKey, k)
		}
		seen[k] = true
		var v bytes.Buffer
		if err := value(dec, &v, depth+1); err != nil {
			return err
		}
		ms = append(ms, member{key: k, units: utf16.Encode([]rune(k)), val: v.Bytes()})
	}
	if _, err := dec.Token(); err != nil { // '}'
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// RFC 8785 §3.2.3: sort by UTF-16 code units, not by UTF-8 bytes or runes.
	// They differ for characters above U+FFFF versus U+E000..U+FFFF.
	sort.Slice(ms, func(i, j int) bool { return lessUTF16(ms[i].units, ms[j].units) })
	out.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := writeString(out, m.key); err != nil {
			return err
		}
		out.WriteByte(':')
		out.Write(m.val)
	}
	out.WriteByte('}')
	return nil
}

func array(dec *json.Decoder, out *bytes.Buffer, depth int) error {
	out.WriteByte('[')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := value(dec, out, depth+1); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // ']'
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	out.WriteByte(']')
	return nil
}

func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// writeString emits the RFC 8785 §3.2.2.2 form: only '"', '\\' and the C0
// controls are escaped; everything else, including '/', U+2028 and non-ASCII,
// is written as literal UTF-8.
func writeString(out *bytes.Buffer, s string) error {
	// encoding/json replaces a lone surrogate escape with U+FFFD rather than
	// failing. Two different raw strings would then canonicalise identically,
	// so a replacement character here is refused unless the input really
	// contained one — which we cannot tell apart, so it is refused outright.
	if strings.ContainsRune(s, utf8.RuneError) {
		return fmt.Errorf("%w: string contains U+FFFD (lone surrogate or replacement)", ErrInvalid)
	}
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

// Number returns the ECMAScript Number.prototype.toString form of a JSON
// number literal (RFC 8785 §3.2.2.3).
func Number(lit string) (string, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("%w: %q", ErrUnsafeNumber, lit)
	}
	// Compared on the LITERAL, not on f: 2^53+1 has already rounded to 2^53
	// by the time it is a float64, which is exactly the collision refused.
	if !strings.ContainsAny(lit, ".eE") {
		n, err := strconv.ParseInt(lit, 10, 64)
		if err != nil || n > maxSafeInt || n < -maxSafeInt {
			return "", fmt.Errorf("%w: integer %s exceeds 2^53", ErrUnsafeNumber, lit)
		}
	}
	return FormatFloat(f), nil
}

// FormatFloat is ECMAScript Number::toString for a finite double.
//
// encoding/json already implements exactly the ES6 rule for float64 (decimal
// notation for 1e-6 <= |x| < 1e21, otherwise exponent with a sign and no
// leading zeros). The one difference is negative zero, which ES renders "0".
func FormatFloat(f float64) string {
	if f == 0 {
		return "0"
	}
	b, _ := json.Marshal(f)
	return string(b)
}
