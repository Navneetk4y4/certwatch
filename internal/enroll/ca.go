// Package enroll issues and manages collector identities.
//
// ENROL-001..004, build items 103-106.
//
// # The rule that shapes this package
//
// THE COLLECTOR'S PRIVATE KEY NEVER LEAVES THE CUSTOMER.
//
// The collector generates its own key, keeps it, and sends a CSR. The server
// receives a public key and a proof of possession, issues a certificate, and
// stores the certificate. There is no code path here that accepts a private
// key, and no column in the schema that could hold one.
//
// That is why "we hold no customer key material" is a property of the
// architecture rather than a promise: to break it somebody would have to add
// both an API that accepts a key and a column to put it in, and a reviewer
// would see both.
//
// # On ACM Private CA
//
// The specification names ACM Private CA for item 103. The CA interface below
// is deliberately narrow — Sign(csr) and Bundle() — so an ACM PCA
// implementation drops in beside the local one. Only the local CA is built
// and tested here; see docs for what remains externally blocked.
package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Issuance limits. Short-lived on purpose: a collector certificate that lives
// a year is a credential an attacker can use for a year.
const (
	// ClientCertLifetime is 30 days. With rotation at 50% life (item 106) a
	// collector renews every 15 days, so a stolen certificate is useful for
	// at most 30 and usually far less.
	ClientCertLifetime = 30 * 24 * time.Hour
	// RotateAfterFraction is when a collector should renew. Half-life leaves
	// a full half-life of slack if renewal starts failing, which is the
	// margin that stops a transient outage becoming an expiry outage.
	RotateAfterFraction = 0.5

	// MinRSABits and the ECDSA curve allowlist. A CSR below these is refused
	// with 422 rather than issued — issuing a weak identity is worse than
	// refusing to issue one.
	MinRSABits = 3072
)

// Errors map directly onto the status codes the specification requires.
var (
	ErrWeakKey      = errors.New("enroll: key does not meet the minimum strength")       // 422
	ErrBadCSR       = errors.New("enroll: certificate signing request is not usable")    // 422
	ErrCNMismatch   = errors.New("enroll: CSR common name does not match the enrolment") // 422
	ErrTokenUnknown = errors.New("enroll: unknown or expired enrolment token")           // 401
	ErrTokenUsed    = errors.New("enroll: enrolment token has already been used")        // 409
	ErrRevoked      = errors.New("enroll: certificate is revoked")
)

// CA issues client certificates. Narrow on purpose so an ACM Private CA
// implementation can replace the local one without touching callers.
type CA interface {
	// Sign issues a client certificate for a validated CSR.
	Sign(csr *x509.CertificateRequest, cn string, notBefore time.Time,
		lifetime time.Duration) (derBytes []byte, err error)
	// Bundle is the CA chain a collector pins and a server trusts.
	Bundle() []*x509.Certificate
}

// LocalCA is an in-process CA for development, test and self-hosted
// deployment. Its private key lives wherever the operator puts it; this
// package never writes it anywhere.
type LocalCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	// serial is monotonic within a process. A real CA needs a persistent
	// counter or random serials; this is noted rather than pretended away.
	serialSeed int64
}

// NewLocalCA creates a CA from an existing certificate and signer.
func NewLocalCA(cert *x509.Certificate, key crypto.Signer) (*LocalCA, error) {
	if cert == nil || key == nil {
		return nil, errors.New("enroll: a CA needs both a certificate and a signer")
	}
	if !cert.IsCA {
		return nil, errors.New("enroll: the supplied certificate is not a CA")
	}
	return &LocalCA{cert: cert, key: key, serialSeed: time.Now().UnixNano()}, nil
}

// GenerateLocalCA mints a fresh CA. For development and tests.
func GenerateLocalCA(cn string, now time.Time) (*LocalCA, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	ca, err := NewLocalCA(cert, key)
	return ca, key, err
}

// Bundle returns the CA chain.
func (c *LocalCA) Bundle() []*x509.Certificate { return []*x509.Certificate{c.cert} }

// BundlePEM renders the bundle for distribution to collectors.
func (c *LocalCA) BundlePEM() []byte {
	var out []byte
	for _, cert := range c.Bundle() {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

// Sign issues a client certificate.
//
// The issued certificate is CLIENT auth only. A collector identity that also
// carries server auth could be used to impersonate the control plane to
// another collector, which is a privilege nobody needs it to have.
func (c *LocalCA) Sign(csr *x509.CertificateRequest, cn string,
	notBefore time.Time, lifetime time.Duration) ([]byte, error) {
	if csr == nil {
		return nil, ErrBadCSR
	}
	if lifetime <= 0 {
		lifetime = ClientCertLifetime
	}
	c.serialSeed++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(c.serialSeed),
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{"certwatch-collector"}},
		NotBefore:    notBefore.Add(-2 * time.Minute), // small backdate for clock skew
		NotAfter:     notBefore.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// CLIENT auth only. Never ExtKeyUsageServerAuth.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.key)
}

// ValidateCSR checks a CSR before anything is issued for it.
//
// The signature check is the one that matters most: it is proof the requester
// holds the private key for the public key they are asking us to certify.
// Without it, anyone could have a certificate issued for somebody else's key.
func ValidateCSR(der []byte, expectCN string) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCSR, err)
	}
	// Proof of possession.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature does not verify, so the requester "+
			"has not shown they hold the private key: %v", ErrBadCSR, err)
	}
	if expectCN != "" && csr.Subject.CommonName != expectCN {
		return nil, fmt.Errorf("%w: CSR asks for %q", ErrCNMismatch, csr.Subject.CommonName)
	}
	if err := checkKeyStrength(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr, nil
}

// checkKeyStrength refuses to certify a key that is too weak to be worth
// certifying.
func checkKeyStrength(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			return fmt.Errorf("%w: unsupported elliptic curve", ErrWeakKey)
		}
	case interface{ Size() int }: // *rsa.PublicKey
		if bits := k.Size() * 8; bits < MinRSABits {
			return fmt.Errorf("%w: RSA %d bits, minimum is %d", ErrWeakKey, bits, MinRSABits)
		}
		return nil
	default:
		// Ed25519 and anything else: refuse rather than guess. An unknown key
		// type we cannot assess is not a key type we should certify.
		return fmt.Errorf("%w: unsupported key type %T", ErrWeakKey, pub)
	}
}

// Fingerprint is SHA-256 of the DER, lowercase hex — the same identity
// convention the rest of the product uses.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ShouldRotate reports whether a certificate has passed its rotation point.
//
// Item 106: rotate at 50% of life. Leaving it to expiry means a transient
// renewal failure becomes an outage; renewing at half-life leaves a full
// half-life of slack to notice and fix it.
func ShouldRotate(notBefore, notAfter, now time.Time) bool {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return true
	}
	return !now.Before(notBefore.Add(time.Duration(float64(life) * RotateAfterFraction)))
}
