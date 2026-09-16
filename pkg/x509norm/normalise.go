// Package x509norm parses and normalises X.509 certificates into the canonical
// model.Certificate form.
//
// Two properties matter more than anything else here:
//
//  1. It never panics. It consumes bytes from hostile endpoints and hostile
//     files; a panic is a denial of service on a whole scan task. Every entry
//     point is fuzzed.
//
//  2. It never silently drops a certificate. Go's crypto/x509 is materially
//     stricter than OpenSSL and rejects certificates that are serving
//     production traffic today — negative serials, unusual string encodings,
//     malformed extensions. Such a certificate is recorded as `partial` or
//     `unparseable` with whatever was recoverable, because it is
//     disproportionately likely to be the one nobody manages.
//
// Normalisation must be idempotent: two observations of the same certificate
// must produce equivalent canonical data, or deduplication and expected-state
// comparison both break.
package x509norm

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/idna"

	"github.com/certwatch/certwatch/pkg/model"
)

// MaxSANs caps the SAN list. CDN certificates with thousands of names exist;
// beyond this the list is truncated, the true count is recorded, and the
// certificate is marked partial — visible, not silent.
const MaxSANs = 1000

// MaxDERBytes bounds a single certificate before any parse is attempted.
const MaxDERBytes = 64 << 10

// Fingerprint is SHA-256 of the full certificate DER, lowercase hex.
//
// It is computed without parsing, so an unparseable certificate still has a
// stable identity and still appears in the inventory.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ParseDER normalises one DER-encoded certificate.
//
// It always returns a non-nil *model.Certificate with a valid Fingerprint, even
// when parsing fails completely. The error return is advisory: callers record
// the certificate regardless and use ParseStatus to decide what it means.
func ParseDER(der []byte) (*model.Certificate, error) {
	out := &model.Certificate{
		ParseStatus:  model.ParseUnparseable,
		RawDERLength: len(der),
		KeyAlgorithm: model.KeyUnknown,
		SANs:         []string{},
		KeyUsage:     []string{},
		ExtKeyUsage:  []string{},
	}
	if len(der) == 0 {
		out.ParseNotes = append(out.ParseNotes, "empty input")
		return out, fmt.Errorf("x509norm: empty DER")
	}
	if len(der) > MaxDERBytes {
		out.Fingerprint = Fingerprint(der)
		out.ParseNotes = append(out.ParseNotes,
			fmt.Sprintf("input is %d bytes, over the %d byte certificate limit", len(der), MaxDERBytes))
		return out, fmt.Errorf("x509norm: input too large")
	}
	out.Fingerprint = Fingerprint(der)

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// The lenient path: recover what we can rather than losing the row.
		return lenientParse(der, out, err), nil
	}
	return normalise(cert, out), nil
}

func normalise(c *x509.Certificate, out *model.Certificate) *model.Certificate {
	out.ParseStatus = model.ParseOK

	out.Serial = normaliseSerial(c.SerialNumber)
	out.SubjectDN = normaliseDN(c.Subject)
	out.SubjectCN = c.Subject.CommonName
	out.IssuerDN = normaliseDN(c.Issuer)
	out.NotBefore = c.NotBefore.UTC()
	out.NotAfter = c.NotAfter.UTC()
	out.SignatureAlgorithm = c.SignatureAlgorithm.String()
	out.IsCA = c.IsCA

	if len(c.AuthorityKeyId) > 0 {
		out.IssuerKeyID = hex.EncodeToString(c.AuthorityKeyId)
	}
	if len(c.SubjectKeyId) > 0 {
		out.SubjectKeyID = hex.EncodeToString(c.SubjectKeyId)
	}

	sans, truncated, notes := NormaliseSANs(c)
	out.SANs = sans
	out.SANsTruncatedCount = truncated
	out.ParseNotes = append(out.ParseNotes, notes...)

	out.KeyAlgorithm, out.KeySize = keyAlgorithmAndSize(c)
	if out.KeyAlgorithm == model.KeyUnknown {
		// crypto/x509 accepted the structure but we cannot name the public-key
		// algorithm — a DSA key, or an OID Go does not model. The certificate is
		// real and belongs in the inventory, but calling this `ok` would be a
		// status that lies about completeness, and downstream policy evaluation
		// (key algorithm, minimum key size) cannot be performed on it.
		out.ParseNotes = append(out.ParseNotes,
			"public key algorithm is not recognised; key algorithm and size are unavailable")
	}
	out.KeyUsage = keyUsageNames(c.KeyUsage)
	out.ExtKeyUsage = extKeyUsageNames(c)

	// Self-signed means subject equals issuer AND the signature verifies against
	// the certificate's own public key. Comparing DNs alone reports a
	// cross-signed intermediate as self-signed, which is wrong and misleading.
	out.IsSelfSigned = isSelfSigned(c)

	if len(out.ParseNotes) > 0 {
		out.ParseStatus = model.ParsePartial
	}
	return out
}

// normaliseSerial renders a serial as lowercase hex with no separators and
// leading zeros preserved.
//
// Negative serials occur in the wild (they are illegal, and they exist anyway).
// Two's-complement bytes are rendered with a leading minus so the value is
// unambiguous and never collides with a positive serial of the same magnitude.
func normaliseSerial(n *big.Int) string {
	if n == nil {
		return ""
	}
	neg := n.Sign() < 0
	b := new(big.Int).Abs(n).Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	s := hex.EncodeToString(b)
	if neg {
		return "-" + s
	}
	return s
}

// keyAlgorithmAndSize returns the algorithm and its size in bits.
// Ed25519 returns nil: a size is not a meaningful property of it, and reporting
// 256 invites a comparison with ECDSA P-256 that means nothing.
func keyAlgorithmAndSize(c *x509.Certificate) (model.KeyAlgorithm, *int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		n := pub.N.BitLen()
		return model.KeyRSA, &n
	case *ecdsa.PublicKey:
		if pub.Curve == nil || pub.Curve.Params() == nil {
			return model.KeyECDSA, nil
		}
		n := pub.Curve.Params().BitSize
		return model.KeyECDSA, &n
	case ed25519.PublicKey:
		return model.KeyEd25519, nil
	default:
		return model.KeyUnknown, nil
	}
}

func isSelfSigned(c *x509.Certificate) bool {
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func keyUsageNames(u x509.KeyUsage) []string {
	out := []string{}
	for _, k := range keyUsageBits {
		if u&k.bit != 0 {
			out = append(out, k.name)
		}
	}
	return out
}

var extKeyUsageNames_ = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "any",
	x509.ExtKeyUsageServerAuth:                 "serverAuth",
	x509.ExtKeyUsageClientAuth:                 "clientAuth",
	x509.ExtKeyUsageCodeSigning:                "codeSigning",
	x509.ExtKeyUsageEmailProtection:            "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:             "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                  "ipsecUser",
	x509.ExtKeyUsageTimeStamping:               "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                "ocspSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "microsoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "netscapeServerGatedCrypto",
}

func extKeyUsageNames(c *x509.Certificate) []string {
	out := []string{}
	for _, e := range c.ExtKeyUsage {
		if n, ok := extKeyUsageNames_[e]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("unknown(%d)", int(e)))
		}
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	sort.Strings(out)
	return out
}

// NormaliseSANs implements the six rules.
//
//  1. Collect dNSName, iPAddress, URI and emailAddress entries.
//  2. dNSName: lowercase; strip ONE trailing dot; IDN -> punycode. A name that
//     fails IDN conversion is kept VERBATIM and the certificate is marked partial.
//  3. iPAddress: canonical netip form; IPv6 lowercased and compressed;
//     IPv4-mapped IPv6 normalised to IPv4.
//  4. Wildcards kept exactly as encoded. "*.example.com" is NOT expanded and
//     NOT treated as covering "example.com" -- because it does not.
//  5. Sort lexicographically, deduplicate.
//  6. Cap at MaxSANs; beyond that truncate, mark partial, record the true count.
func NormaliseSANs(c *x509.Certificate) (sans []string, truncated int, notes []string) {
	seen := make(map[string]bool)
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			sans = append(sans, s)
		}
	}

	total := len(c.DNSNames) + len(c.IPAddresses) + len(c.URIs) + len(c.EmailAddresses)

	for _, d := range c.DNSNames {
		n, note := normaliseDNSName(d)
		if note != "" {
			notes = append(notes, note)
		}
		add("DNS:" + n)
	}
	for _, ip := range c.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			add("IP:" + a.Unmap().String())
		} else {
			notes = append(notes, "unparseable iPAddress SAN")
		}
	}
	for _, u := range c.URIs {
		if u != nil {
			add("URI:" + u.String())
		}
	}
	for _, e := range c.EmailAddresses {
		add("EMAIL:" + strings.ToLower(e))
	}

	sort.Strings(sans)
	if len(sans) > MaxSANs {
		truncated = total
		notes = append(notes, fmt.Sprintf("SAN list truncated to %d of %d entries", MaxSANs, total))
		sans = sans[:MaxSANs]
	}
	if sans == nil {
		sans = []string{}
	}
	return sans, truncated, notes
}

// normaliseDNSName applies rule 2, preserving wildcards per rule 4.
func normaliseDNSName(d string) (string, string) {
	s := strings.TrimSpace(d)
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".") // exactly one trailing dot

	if s == "" {
		return "", "empty dNSName SAN"
	}
	// ASCII-only names need no IDN work, which is the overwhelming majority and
	// avoids putting hostile bytes through a larger code path unnecessarily.
	if isASCII(s) {
		return s, ""
	}
	// A wildcard label must be preserved exactly; IDN-convert only the rest.
	if strings.HasPrefix(s, "*.") {
		rest, err := idna.Lookup.ToASCII(s[2:])
		if err != nil {
			return s, fmt.Sprintf("dNSName %q could not be IDN-normalised, kept verbatim", d)
		}
		return "*." + rest, ""
	}
	a, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return s, fmt.Sprintf("dNSName %q could not be IDN-normalised, kept verbatim", d)
	}
	return a, ""
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
