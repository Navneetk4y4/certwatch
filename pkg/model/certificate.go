// Package model holds the canonical wire types.
//
// These types are shared verbatim between the collector and the control plane's
// API contract, so a divergence between what the collector sends and what the
// server expects becomes a compile error rather than a runtime rejection.
//
// They are deliberately plain: no methods that reach out, no interfaces, no
// embedded behaviour. A type here should be obvious to a reviewer reading it
// cold.
package model

import "time"

// ParseStatus records how completely a certificate could be read.
//
// A certificate that Go's crypto/x509 rejects is MORE interesting to an
// inventory, not less — it is disproportionately likely to be the ancient
// appliance certificate nobody has touched in six years. So a rejected
// certificate is recorded as partial or unparseable with whatever was
// recoverable, and never silently dropped. Silently dropping is how an
// inventory quietly becomes wrong.
type ParseStatus string

const (
	ParseOK          ParseStatus = "ok"
	ParsePartial     ParseStatus = "partial"
	ParseUnparseable ParseStatus = "unparseable"
)

// KeyAlgorithm is the public-key algorithm of the certificate's subject key.
type KeyAlgorithm string

const (
	KeyRSA     KeyAlgorithm = "RSA"
	KeyECDSA   KeyAlgorithm = "ECDSA"
	KeyEd25519 KeyAlgorithm = "Ed25519"
	KeyUnknown KeyAlgorithm = "unknown"
)

// Certificate is the canonical normalised form of one X.509 certificate.
//
// Identity is Fingerprint: SHA-256 of the FULL certificate DER. Not of the
// public key, not of the TBS — of the whole DER, because that is what "the same
// certificate" means to a customer looking at two endpoints.
type Certificate struct {
	// Fingerprint is SHA-256 of the full DER, lowercase hex. This is identity.
	Fingerprint string `json:"sha256"`

	// Serial is hex, lowercase, no separators, leading zeros preserved.
	// Text, never numeric: serials exceed 20 bytes in the wild and may be
	// negative, and both break an integer column.
	Serial string `json:"serial"`

	SubjectDN string `json:"subject_dn"`
	// SubjectCN is the first CN attribute, or empty. Modern certificates often
	// have no CN at all, which is not an error.
	SubjectCN string `json:"subject_cn"`

	// SANs are normalised and sorted. See x509norm for the six rules.
	SANs []string `json:"sans"`
	// SANsTruncatedCount is the true count when SANs was capped. Zero otherwise.
	SANsTruncatedCount int `json:"sans_truncated_count,omitempty"`

	IssuerDN string `json:"issuer_dn"`
	// IssuerKeyID is the Authority Key Identifier when present, lowercase hex.
	// Used to link a leaf to an observed issuer without relying on DN string
	// equality, which is fragile across encodings.
	IssuerKeyID string `json:"issuer_key_id,omitempty"`
	// SubjectKeyID is the Subject Key Identifier when present, lowercase hex.
	SubjectKeyID string `json:"subject_key_id,omitempty"`

	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`

	KeyAlgorithm KeyAlgorithm `json:"key_algorithm"`
	// KeySize is modulus bits for RSA, curve bits for ECDSA, and nil for
	// Ed25519 — where a size is not a meaningful property.
	KeySize            *int   `json:"key_size"`
	SignatureAlgorithm string `json:"signature_algorithm"`

	IsCA         bool `json:"is_ca"`
	IsSelfSigned bool `json:"is_self_signed"`

	KeyUsage    []string `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`

	ParseStatus ParseStatus `json:"parse_status"`
	// ParseNotes explain a partial or unparseable status in plain English.
	ParseNotes []string `json:"parse_notes,omitempty"`

	// RawDERLength is recorded even when nothing else could be parsed, so an
	// unparseable certificate is still a countable row in the inventory.
	RawDERLength int `json:"raw_der_length"`
}

// DaysRemaining is the whole days from now until NotAfter. Negative when expired.
func (c *Certificate) DaysRemaining(now time.Time) int {
	return int(c.NotAfter.Sub(now).Hours() / 24)
}

// Expired reports whether now is after NotAfter.
func (c *Certificate) Expired(now time.Time) bool { return now.After(c.NotAfter) }

// NotYetValid reports whether now is before NotBefore.
func (c *Certificate) NotYetValid(now time.Time) bool { return now.Before(c.NotBefore) }

// Chain is a certificate chain as presented by a server or found in a bundle.
//
// Leaf is identified structurally, not by position: servers get the order wrong
// often enough that trusting presented order produces wrong answers in
// production. See x509norm.IdentifyLeaf.
type Chain struct {
	Leaf          *Certificate   `json:"leaf"`
	Intermediates []*Certificate `json:"intermediates,omitempty"`
	// Complete reports whether a path from leaf to a trusted root could be
	// constructed from the presented intermediates plus the trust bundle.
	Complete bool `json:"chain_complete"`
	// Validation is one of valid, incomplete, untrusted, expired.
	Validation string `json:"chain_validation"`
	// PresentedOutOfOrder records that the server sent the chain in a
	// non-canonical order. Informational; common in the wild.
	PresentedOutOfOrder bool `json:"presented_out_of_order,omitempty"`
}

const (
	ChainValid      = "valid"
	ChainIncomplete = "incomplete"
	ChainUntrusted  = "untrusted"
	ChainExpired    = "expired"
)
