// Package mode2 is the signed-request transport for collectors behind a
// TLS-inspecting proxy.
//
// PROTO-007, build item 118. A proxy that terminates TLS strips the client
// certificate, so mTLS cannot carry the collector's identity. Mode 2 moves the
// identity into the request: every request carries a detached JWS, made with
// the collector's ENROLLED private key, over
//
//	JCS(body) + method + path + collector + tenant + nonce + iat + exp
//
// The key signs; it is never sent. The server verifies with the public key
// from the certificate it issued at enrolment.
//
// # What the signature binds, and why each one
//
//	alg      pinned to the enrolled key's type; never chosen by the request
//	kid      the enrolled certificate's fingerprint — the KEY identity
//	cw_cid   the collector — checked against what kid resolves to
//	cw_tid   the tenant — checked against what kid resolves to, never used
//	cw_mth   the method   } a signature for GET /v1/tasks cannot be replayed
//	cw_path  the path     } as POST /v1/ingest/observations
//	cw_nonce single use, enforced by the server's replay store
//	iat/exp  freshness; a captured request is useless after five minutes
//	payload  JCS of the body, so a proxy may re-serialise but not change it
//
// The tenant a request acts in comes from kid -> enrolled certificate, never
// from cw_tid. cw_tid exists so that a mismatch is DETECTED and refused rather
// than silently corrected.
package mode2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/certwatch/certwatch/pkg/jcs"
)

// Header carries the detached JWS.
const Header = "X-Certwatch-Signature"

const (
	// MaxSkew is how far iat may be from the server's clock either way.
	MaxSkew = 300 * time.Second
	// MaxLifetime bounds exp - iat. The replay store must remember a nonce at
	// least this long plus MaxSkew, or a replay inside the window succeeds.
	MaxLifetime = 300 * time.Second
	// NonceTTL is how long the server must remember a nonce.
	NonceTTL = MaxLifetime + 2*MaxSkew
	// MaxSignatureLen bounds the header before any parsing.
	MaxSignatureLen = 4096
)

var (
	ErrMalformed = errors.New("mode2: malformed signature")
	ErrAlgorithm = errors.New("mode2: algorithm not permitted for this key")
	ErrSignature = errors.New("mode2: signature does not verify")
	ErrExpired   = errors.New("mode2: signature expired")
	ErrSkew      = errors.New("mode2: timestamp outside the permitted clock skew")
	ErrBinding   = errors.New("mode2: signature is for a different request")
	ErrKey       = errors.New("mode2: unsupported key")
	ErrReplay    = errors.New("mode2: nonce already used")
)

// Claims is the protected header. Every field is required.
type Claims struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Cid   string `json:"cw_cid"`
	Tid   string `json:"cw_tid"`
	Mth   string `json:"cw_mth"`
	Path  string `json:"cw_path"`
	Nonce string `json:"cw_nonce"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

var (
	nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{22,86}$`) // >= 128 bits
	kidRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var b64 = base64.RawURLEncoding.Strict()

// AlgFor is the ONE algorithm a key may use. The request never chooses: a
// header naming anything else is refused before the signature is looked at,
// which is what makes "none", HS256-with-the-public-key and RS/ES confusion
// impossible rather than merely checked for.
func AlgFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return "ES256", nil
		}
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return "RS256", nil
		}
	}
	return "", ErrKey
}

// NewNonce returns 192 random bits, base64url.
func NewNonce() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// CanonicalBody is what the signature covers. An empty body (a GET) is the
// empty string, not "null".
func CanonicalBody(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	return jcs.Canonicalize(body)
}

// Sign produces the compact detached JWS for one request. c.Alg is set from
// the key; whatever the caller put there is ignored.
func Sign(key crypto.Signer, c Claims, body []byte) (string, error) {
	alg, err := AlgFor(key.Public())
	if err != nil {
		return "", err
	}
	c.Alg = alg
	canon, err := CanonicalBody(body)
	if err != nil {
		return "", err
	}
	hj, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if hj, err = jcs.Canonicalize(hj); err != nil {
		return "", err
	}
	hdr := b64.EncodeToString(hj)
	digest := sha256.Sum256([]byte(hdr + "." + b64.EncodeToString(canon)))
	var sig []byte
	switch k := key.Public().(type) {
	case *ecdsa.PublicKey:
		der, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return "", err
		}
		if sig, err = derToRaw(der, k); err != nil {
			return "", err
		}
	case *rsa.PublicKey:
		if sig, err = key.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			return "", err
		}
	}
	return hdr + ".." + b64.EncodeToString(sig), nil
}

// Parsed is a signature that has been structurally decoded but NOT verified.
// Nothing in Claims may be trusted until Verify has returned nil.
type Parsed struct {
	Claims Claims
	header string
	sig    []byte
}

// Parse decodes the header without trusting it. The only claim a caller may
// use before Verify is Kid, to find the key to verify with.
func Parse(s string) (Parsed, error) {
	var p Parsed
	if len(s) == 0 || len(s) > MaxSignatureLen {
		return p, fmt.Errorf("%w: length", ErrMalformed)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[1] != "" {
		// Detached only. An attached payload would be a second copy of the
		// body that could disagree with the first.
		return p, fmt.Errorf("%w: not a detached compact JWS", ErrMalformed)
	}
	hj, err := b64.DecodeString(parts[0])
	if err != nil {
		return p, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	if p.sig, err = b64.DecodeString(parts[2]); err != nil || len(p.sig) == 0 {
		return p, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	// Strict: duplicate members, unknown members and trailing data are all
	// refused. A "crit", "jku", "x5u" or "jwk" header is an unknown member
	// and so cannot redirect key selection.
	if _, err := jcs.Canonicalize(hj); err != nil {
		return p, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(hj)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p.Claims); err != nil {
		return p, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	c := p.Claims
	if !kidRE.MatchString(c.Kid) || c.Cid == "" || c.Tid == "" || c.Mth == "" ||
		c.Path == "" || !nonceRE.MatchString(c.Nonce) || c.Iat == 0 || c.Exp == 0 {
		return p, fmt.Errorf("%w: a required claim is missing or malformed", ErrMalformed)
	}
	p.header = parts[0]
	return p, nil
}

// Expect is the request the signature must be for.
type Expect struct {
	Method string
	Path   string
	Now    time.Time
}

// Verify checks the signature, the algorithm, freshness and the request
// binding. It does NOT check cw_cid/cw_tid against the key's owner or the
// nonce against the replay store — the caller holds that state and must.
func (p Parsed) Verify(pub crypto.PublicKey, body []byte, want Expect) error {
	alg, err := AlgFor(pub)
	if err != nil {
		return err
	}
	if p.Claims.Alg != alg {
		return fmt.Errorf("%w: header says %q, key requires %q", ErrAlgorithm, p.Claims.Alg, alg)
	}
	canon, err := CanonicalBody(body)
	if err != nil {
		return fmt.Errorf("%w: body: %v", ErrMalformed, err)
	}
	digest := sha256.Sum256([]byte(p.header + "." + b64.EncodeToString(canon)))
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if len(p.sig) != 64 {
			return ErrSignature
		}
		r := new(big.Int).SetBytes(p.sig[:32])
		s := new(big.Int).SetBytes(p.sig[32:])
		if !ecdsa.Verify(k, digest[:], r, s) {
			return ErrSignature
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], p.sig) != nil {
			return ErrSignature
		}
	}
	// Only now are the claims authentic.
	c := p.Claims
	if c.Mth != want.Method || c.Path != want.Path {
		return ErrBinding
	}
	now := want.Now.Unix()
	if c.Exp <= c.Iat || time.Duration(c.Exp-c.Iat)*time.Second > MaxLifetime {
		return fmt.Errorf("%w: lifetime", ErrMalformed)
	}
	if d := now - c.Iat; d > int64(MaxSkew/time.Second) || -d > int64(MaxSkew/time.Second) {
		return ErrSkew
	}
	if now >= c.Exp {
		return ErrExpired
	}
	return nil
}

// derToRaw converts an ASN.1 ECDSA signature to the fixed-width R||S form
// JWS requires.
func derToRaw(der []byte, k *ecdsa.PublicKey) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, err
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}
