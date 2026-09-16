package x509norm

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
)

// lenientParse recovers what it can from a certificate that crypto/x509
// rejected.
//
// Go's parser is materially stricter than OpenSSL and rejects certificates that
// are serving production traffic today: negative serials, unusual string
// encodings, malformed extensions. Those certificates are disproportionately
// likely to be the ancient appliance certificate nobody manages — which makes
// them MORE interesting to an inventory, not less.
//
// So: recover serial, subject, issuer and the validity window by walking the
// TBSCertificate structurally. If five core fields come back, the status is
// `partial`; otherwise `unparseable`. Either way the row exists, with its
// fingerprint, and the inventory does not quietly become wrong.
//
// This path handles hostile input and is in the fuzz corpus.
func lenientParse(der []byte, out *model.Certificate, cause error) *model.Certificate {
	out.ParseNotes = append(out.ParseNotes, "crypto/x509 rejected this certificate: "+cause.Error())

	recovered := 0
	defer func() {
		// The lenient walker touches attacker-controlled structure. A panic here
		// would take down a whole scan task for one bad certificate on one host,
		// so it is contained and reported rather than propagated.
		if r := recover(); r != nil {
			out.ParseNotes = append(out.ParseNotes, fmt.Sprintf("lenient recovery aborted: %v", r))
			out.ParseStatus = model.ParseUnparseable
		}
	}()

	var top asn1.RawValue
	if _, err := asn1.Unmarshal(der, &top); err != nil || top.Tag != asn1.TagSequence {
		out.ParseNotes = append(out.ParseNotes, "not a DER SEQUENCE")
		return out
	}
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(top.Bytes, &tbs); err != nil || tbs.Tag != asn1.TagSequence {
		out.ParseNotes = append(out.ParseNotes, "no TBSCertificate SEQUENCE")
		return out
	}

	rest := tbs.Bytes

	// [0] EXPLICIT version, optional.
	var probe asn1.RawValue
	if r, err := asn1.Unmarshal(rest, &probe); err == nil {
		if probe.Class == asn1.ClassContextSpecific && probe.Tag == 0 {
			rest = r
		}
	}

	// serialNumber INTEGER
	var serial *big.Int
	if r, err := asn1.Unmarshal(rest, &serial); err == nil && serial != nil {
		out.Serial = normaliseSerial(serial)
		recovered++
		rest = r
	} else {
		// A serial Go refuses (negative, or over 20 bytes) still has bytes.
		var raw asn1.RawValue
		if r2, err2 := asn1.Unmarshal(rest, &raw); err2 == nil && raw.Tag == asn1.TagInteger {
			out.Serial = normaliseSerial(new(big.Int).SetBytes(raw.Bytes))
			out.ParseNotes = append(out.ParseNotes, "serial recovered from raw bytes")
			recovered++
			rest = r2
		}
	}

	// signature AlgorithmIdentifier
	if r, ok := skipElement(rest); ok {
		rest = r
	}

	// issuer Name
	if dn, r, ok := recoverName(rest); ok {
		out.IssuerDN = dn
		recovered++
		rest = r
	}

	// validity SEQUENCE { notBefore, notAfter }
	if nb, na, r, ok := recoverValidity(rest); ok {
		out.NotBefore, out.NotAfter = nb, na
		recovered += 2
		rest = r
	}

	// subject Name
	if dn, _, ok := recoverName(rest); ok {
		out.SubjectDN = dn
		out.SubjectCN = firstCN(dn)
		recovered++
	}

	if recovered >= 5 {
		out.ParseStatus = model.ParsePartial
		out.ParseNotes = append(out.ParseNotes,
			fmt.Sprintf("recovered %d core fields via lenient parsing", recovered))
	} else {
		out.ParseStatus = model.ParseUnparseable
		out.ParseNotes = append(out.ParseNotes,
			fmt.Sprintf("only %d core fields recoverable; recorded by fingerprint only", recovered))
	}
	return out
}

func skipElement(b []byte) ([]byte, bool) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	if err != nil {
		return b, false
	}
	return rest, true
}

// recoverName renders a Name without going through pkix, which is where the
// strict decoding lives.
func recoverName(b []byte) (string, []byte, bool) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(b, &seq)
	if err != nil || seq.Tag != asn1.TagSequence {
		return "", b, false
	}
	var rdns []string
	cur := seq.Bytes
	for len(cur) > 0 {
		var set asn1.RawValue
		next, err := asn1.Unmarshal(cur, &set)
		if err != nil {
			break
		}
		inner := set.Bytes
		for len(inner) > 0 {
			var atvSeq asn1.RawValue
			n2, err := asn1.Unmarshal(inner, &atvSeq)
			if err != nil {
				break
			}
			var oid asn1.ObjectIdentifier
			after, err := asn1.Unmarshal(atvSeq.Bytes, &oid)
			if err == nil {
				var val asn1.RawValue
				if _, err := asn1.Unmarshal(after, &val); err == nil {
					name, known := attrShortNames[oid.String()]
					if !known {
						name = oid.String()
					}
					rdns = append(rdns, name+"="+escapeDNValue(decodeRawString(val)))
				}
			}
			inner = n2
		}
		cur = next
	}
	if len(rdns) == 0 {
		return "", rest, false
	}
	// Reverse for RFC 4514 order.
	for i, j := 0, len(rdns)-1; i < j; i, j = i+1, j-1 {
		rdns[i], rdns[j] = rdns[j], rdns[i]
	}
	return joinComma(rdns), rest, true
}

func recoverValidity(b []byte) (time.Time, time.Time, []byte, bool) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(b, &seq)
	if err != nil || seq.Tag != asn1.TagSequence {
		return time.Time{}, time.Time{}, b, false
	}
	nb, after, ok := recoverTime(seq.Bytes)
	if !ok {
		return time.Time{}, time.Time{}, rest, false
	}
	na, _, ok := recoverTime(after)
	if !ok {
		return time.Time{}, time.Time{}, rest, false
	}
	return nb, na, rest, true
}

// recoverTime handles UTCTime and GeneralizedTime. A notAfter beyond 2038 is
// encoded as GeneralizedTime and must not wrap.
func recoverTime(b []byte) (time.Time, []byte, bool) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	if err != nil {
		return time.Time{}, b, false
	}
	s := string(rv.Bytes)
	layouts := []string{
		"060102150405Z0700", "0601021504Z0700",
		"20060102150405Z0700", "200601021504Z0700",
		"20060102150405.999999999Z0700",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), rest, true
		}
	}
	return time.Time{}, rest, false
}

func firstCN(dn string) string {
	for _, part := range splitTopLevel(dn) {
		if len(part) > 3 && part[:3] == "CN=" {
			return part[3:]
		}
	}
	return ""
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// splitTopLevel splits on unescaped commas.
func splitTopLevel(s string) []string {
	var out []string
	start, esc := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case esc:
			esc = false
		case s[i] == '\\':
			esc = true
		case s[i] == ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
