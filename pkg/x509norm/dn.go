package x509norm

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Attribute type short names per RFC 4514 §3. Types not listed are rendered as
// a dotted OID, which RFC 4514 permits and which is unambiguous.
var attrShortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "STREET",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
	"2.5.4.5":                    "SERIALNUMBER",
	"1.2.840.113549.1.9.1":       "emailAddress",
}

// normaliseDN renders a distinguished name in RFC 4514 string form.
//
// Attribute ORDER IS PRESERVED AS ENCODED and not sorted. Two DNs differing
// only in attribute order are different DNs, and normalising the order would
// silently merge two distinct issuers.
//
// RFC 4514 prints RDNs in reverse order (most specific first), which is what
// every tool a customer will compare against does.
func normaliseDN(n pkix.Name) string {
	rdns := n.ToRDNSequence()
	parts := make([]string, 0, len(rdns))
	for i := len(rdns) - 1; i >= 0; i-- {
		set := rdns[i]
		atvs := make([]string, 0, len(set))
		for _, atv := range set {
			atvs = append(atvs, formatATV(atv))
		}
		// Multi-valued RDNs join with '+', per RFC 4514.
		parts = append(parts, strings.Join(atvs, "+"))
	}
	return strings.Join(parts, ",")
}

func formatATV(atv pkix.AttributeTypeAndValue) string {
	oid := atv.Type.String()
	name, known := attrShortNames[oid]
	if !known {
		name = oid
	}
	return name + "=" + escapeDNValue(decodeDNValue(atv.Value))
}

// decodeDNValue renders an attribute value as a Go string.
//
// crypto/x509 decodes PrintableString, UTF8String and IA5String for us, but
// leaves BMPString, UniversalString and TeletexString as raw asn1.RawValue.
// Those appear in older enterprise and appliance certificates — exactly the
// population this product exists to find — so they must be handled rather than
// rendered as Go struct dumps.
func decodeDNValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case asn1.RawValue:
		return decodeRawString(t)
	case fmt.Stringer:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func decodeRawString(rv asn1.RawValue) string {
	switch rv.Tag {
	case asn1.TagBMPString: // UCS-2, big-endian
		if len(rv.Bytes)%2 != 0 {
			return strings.ToValidUTF8(string(rv.Bytes), "�")
		}
		u := make([]uint16, 0, len(rv.Bytes)/2)
		for i := 0; i+1 < len(rv.Bytes); i += 2 {
			u = append(u, uint16(rv.Bytes[i])<<8|uint16(rv.Bytes[i+1]))
		}
		return string(utf16.Decode(u))

	case 28: // UniversalString: UCS-4, big-endian
		if len(rv.Bytes)%4 != 0 {
			return strings.ToValidUTF8(string(rv.Bytes), "�")
		}
		var sb strings.Builder
		for i := 0; i+3 < len(rv.Bytes); i += 4 {
			r := rune(uint32(rv.Bytes[i])<<24 | uint32(rv.Bytes[i+1])<<16 |
				uint32(rv.Bytes[i+2])<<8 | uint32(rv.Bytes[i+3]))
			sb.WriteRune(r)
		}
		return sb.String()

	case asn1.TagT61String: // TeletexString. Treated as Latin-1, which is what
		// virtually every real-world encoder actually meant.
		var sb strings.Builder
		for _, b := range rv.Bytes {
			sb.WriteRune(rune(b))
		}
		return sb.String()

	default:
		return strings.ToValidUTF8(string(rv.Bytes), "�")
	}
}

// escapeDNValue applies RFC 4514 §2.4 escaping.
func escapeDNValue(s string) string {
	if s == "" {
		return ""
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c == ' ' && (i == 0 || i == len(s)-1):
			sb.WriteString("\\ ")
		case c == '#' && i == 0:
			sb.WriteString("\\#")
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&sb, "\\%02X", c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}
