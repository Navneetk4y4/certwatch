// Package canary builds the planted-key fixture tree and the leak detector used
// by the security canary (INV-1).
//
// It is a library rather than test-only code so that CANARY-B can reuse exactly
// the same planting and detection logic against additional surfaces (outbound
// payloads, telemetry, spool, crash output) without reimplementing it. One
// detector, one definition of "a leak".
package canary

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	rand2 "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Window sizes for detection. A 32-byte contiguous window rather than an exact
// match is the point: it catches truncated, re-encoded and partially-leaked
// material, which is what a real bug produces. An exact-match test would pass
// against a bug that leaked half a key.
const (
	RawWindow    = 32
	Base64Window = 48
)

// PlantedKey is the synthetic private key and everything derived from it that a
// leak would reveal.
type PlantedKey struct {
	Key        *rsa.PrivateKey
	PKCS8DER   []byte
	PKCS1DER   []byte
	ModulusRaw []byte
	PEMBodies  []string // base64 body lines of each PEM encoding
}

// SeedReader returns a deterministic CSPRNG stream from a 32-byte seed file.
// Deterministic so the planted key is byte-identical across runs; ChaCha8 rather
// than a hand-rolled stream because key generation searches for primes and a
// low-quality stream makes that search take unbounded time.
func SeedReader(seedPath string, tweak byte) (io.Reader, error) {
	b, err := os.ReadFile(seedPath) //nolint:gosec // test fixture, not collector code
	if err != nil {
		return nil, fmt.Errorf("canary: reading seed %s: %w", seedPath, err)
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("canary: seed %s is %d bytes, want at least 32", seedPath, len(b))
	}
	var s [32]byte
	copy(s[:], b)
	s[31] ^= tweak
	return rand2.NewChaCha8(s), nil
}

// GenerateKey builds the synthetic private key from the seed file.
func GenerateKey(seedPath string) (*PlantedKey, error) {
	r, err := SeedReader(seedPath, 0)
	if err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		return nil, fmt.Errorf("canary: generating planted key: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)

	pk := &PlantedKey{
		Key:        key,
		PKCS8DER:   pkcs8,
		PKCS1DER:   pkcs1,
		ModulusRaw: key.N.Bytes(),
	}
	for _, enc := range [][2]any{{"PRIVATE KEY", pkcs8}, {"RSA PRIVATE KEY", pkcs1}} {
		blk := pem.EncodeToMemory(&pem.Block{Type: enc[0].(string), Bytes: enc[1].([]byte)})
		for _, line := range strings.Split(string(blk), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "-----") {
				pk.PEMBodies = append(pk.PEMBodies, line)
			}
		}
	}
	return pk, nil
}

// PlantedForm records one planted artefact so the test can assert on it.
type PlantedForm struct {
	Path        string
	Description string
}

// Tree is the fixture tree: five forms of the planted key and three valid
// certificates, so the canary proves the scanner works as well as that it does
// not leak.
type Tree struct {
	Root         string
	ScanDir      string
	Key          *PlantedKey
	Forms        []PlantedForm
	Certificates [][]byte
}

// Plant writes the fixture tree under root.
//
// Five forms, each exercising a different protection path:
//
//	a) certs/server.key              forbidden extension  -> SkippedForbiddenExtension
//	b) certs/bundle.pem              mixed CERT + KEY     -> certificates returned, key block skipped
//	c) certs/nested/deep/id_rsa      no extension         -> SkippedForbiddenExtension
//	d) certs/link.pem -> ../secret/  symlink escape       -> SkippedSymlinkEscape
//	e) certs/raw.der                 PKCS#8 DER           -> SkippedPrivateKeyBlock
//	f) certs/appended.der            cert || PKCS#8 key   -> SkippedAmbiguousDER
//
// Form (f) exists because adversarial review found a real leak that forms
// (a)-(e) did not plant: a DER file whose outer structure describes a valid
// certificate but which has key bytes appended. The classifier accepted it and
// returned the whole file. Planting only a PURE key meant the canary could not
// see that class at all — which is the lesson: a canary tests the leak shapes
// it plants, and nothing else.
func Plant(root, seedPath string) (*Tree, error) {
	key, err := GenerateKey(seedPath)
	if err != nil {
		return nil, err
	}
	scan := filepath.Join(root, "certs")
	secret := filepath.Join(root, "secret")
	for _, d := range []string{scan, secret, filepath.Join(scan, "nested", "deep")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}

	t := &Tree{Root: root, ScanDir: scan, Key: key}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key.PKCS8DER})
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: key.PKCS1DER})

	// Three valid certificates, in three encodings.
	for i, cn := range []string{"alpha.canary.test", "beta.canary.test", "gamma.canary.test"} {
		der, err := makeCert(seedPath, cn, byte(i+1))
		if err != nil {
			return nil, err
		}
		t.Certificates = append(t.Certificates, der)
	}
	if err := write(filepath.Join(scan, "alpha.pem"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: t.Certificates[0]})); err != nil {
		return nil, err
	}
	if err := write(filepath.Join(scan, "beta.crt"), t.Certificates[1]); err != nil {
		return nil, err
	}
	if err := write(filepath.Join(scan, "gamma.der"), t.Certificates[2]); err != nil {
		return nil, err
	}

	// (a) forbidden extension
	if err := write(filepath.Join(scan, "server.key"), keyPEM); err != nil {
		return nil, err
	}
	t.Forms = append(t.Forms, PlantedForm{filepath.Join(scan, "server.key"), "PEM private key with a .key extension"})

	// (b) mixed bundle: a real certificate and a private key in one file
	var bundle bytes.Buffer
	bundle.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: t.Certificates[0]}))
	bundle.Write(rsaPEM)
	if err := write(filepath.Join(scan, "bundle.pem"), bundle.Bytes()); err != nil {
		return nil, err
	}
	t.Forms = append(t.Forms, PlantedForm{filepath.Join(scan, "bundle.pem"), "PEM bundle mixing a certificate and a private key"})

	// (c) no extension
	hidden := filepath.Join(scan, "nested", "deep", "id_rsa")
	if err := write(hidden, rsaPEM); err != nil {
		return nil, err
	}
	t.Forms = append(t.Forms, PlantedForm{hidden, "extensionless private key nested three levels down"})

	// (d) symlink escape: the classic world-writable certs/ pointing at /etc/ssl/private
	if err := write(filepath.Join(secret, "server.key"), keyPEM); err != nil {
		return nil, err
	}
	link := filepath.Join(scan, "link.pem")
	if err := os.Symlink(filepath.Join(secret, "server.key"), link); err != nil {
		return nil, fmt.Errorf("canary: planting symlink: %w", err)
	}
	t.Forms = append(t.Forms, PlantedForm{link, "symlink from the scan directory to a private key outside it"})

	// (e) raw PKCS#8 DER with a certificate-looking extension
	if err := write(filepath.Join(scan, "raw.der"), key.PKCS8DER); err != nil {
		return nil, err
	}
	t.Forms = append(t.Forms, PlantedForm{filepath.Join(scan, "raw.der"), "raw PKCS#8 DER private key named .der"})

	// (f) a valid certificate with a private key appended -- the leak class the
	// original five forms could not see.
	appended := append(append([]byte{}, t.Certificates[1]...), key.PKCS8DER...)
	if err := write(filepath.Join(scan, "appended.der"), appended); err != nil {
		return nil, err
	}
	t.Forms = append(t.Forms, PlantedForm{filepath.Join(scan, "appended.der"),
		"valid certificate DER with a PKCS#8 private key appended"})

	return t, nil
}

// Artefact is one captured surface to be searched for leaked material.
type Artefact struct {
	Name string
	Data []byte
}

// Leak describes a detection.
type Leak struct {
	Artefact string
	Kind     string
	Offset   int
	Detail   string
}

func (l Leak) String() string {
	return fmt.Sprintf("%s: %s at offset %d (%s)", l.Artefact, l.Kind, l.Offset, l.Detail)
}

// Detect searches every artefact for any trace of the planted key.
//
// Five detections, deliberately overlapping:
//
//  1. any RawWindow-byte contiguous window of the modulus or of either DER encoding
//  2. the STANDARD base64 of any Base64Window-byte window of the same — catches a
//     []byte accidentally marshalled into JSON, the single most likely leak
//  3. the URL-SAFE base64 of the same — a different alphabet is still a leak, and
//     JWT/JWS-adjacent code paths use it by default
//  4. the HEX encoding of the same — fingerprint-formatting helpers and %x verbs
//     produce hex, and an earlier version of this detector would have missed it
//  5. any PEM body line of the key, verbatim
//
// Detections 3 and 4 were added after adversarial review observed that the
// original three would miss a leak in either encoding.
func Detect(pk *PlantedKey, artefacts []Artefact) []Leak {
	var leaks []Leak
	raws := [][2]any{
		{"modulus", pk.ModulusRaw},
		{"pkcs8-der", pk.PKCS8DER},
		{"pkcs1-der", pk.PKCS1DER},
	}

	for _, a := range artefacts {
		if len(a.Data) == 0 {
			continue
		}
		for _, r := range raws {
			name, data := r[0].(string), r[1].([]byte)
			if off := findWindow(a.Data, data, RawWindow); off >= 0 {
				leaks = append(leaks, Leak{a.Name, "raw-" + name, off,
					fmt.Sprintf("%d-byte contiguous window of the planted key's %s", RawWindow, name)})
			}
			if off := findEncodedWindow(a.Data, data, Base64Window, base64.StdEncoding.EncodeToString); off >= 0 {
				leaks = append(leaks, Leak{a.Name, "base64-" + name, off,
					fmt.Sprintf("standard base64 of a %d-byte window of the planted key's %s", Base64Window, name)})
			}
			if off := findEncodedWindow(a.Data, data, Base64Window, base64.RawURLEncoding.EncodeToString); off >= 0 {
				leaks = append(leaks, Leak{a.Name, "base64url-" + name, off,
					fmt.Sprintf("URL-safe base64 of a %d-byte window of the planted key's %s", Base64Window, name)})
			}
			if off := findEncodedWindow(a.Data, data, RawWindow, hex.EncodeToString); off >= 0 {
				leaks = append(leaks, Leak{a.Name, "hex-" + name, off,
					fmt.Sprintf("hex encoding of a %d-byte window of the planted key's %s", RawWindow, name)})
			}
		}
		for _, line := range pk.PEMBodies {
			if len(line) < 16 {
				continue
			}
			if off := bytes.Index(a.Data, []byte(line)); off >= 0 {
				leaks = append(leaks, Leak{a.Name, "pem-body-line", off, "a PEM body line of the planted key, verbatim"})
			}
		}
	}
	return leaks
}

// findWindow reports the offset of the first occurrence in hay of any
// window-sized contiguous slice of needle.
func findWindow(hay, needle []byte, window int) int {
	if len(needle) < window {
		return -1
	}
	for i := 0; i+window <= len(needle); i++ {
		if off := bytes.Index(hay, needle[i:i+window]); off >= 0 {
			return off
		}
	}
	return -1
}

// findEncodedWindow searches for an encoded window of the needle under the
// given encoder.
//
// It checks three phase alignments because a byte slice embedded in a larger
// encoded payload will not start on a 3-byte boundary, and it trims the
// alignment-sensitive edges of each encoded window so the stable interior is
// what gets matched. Hex is alignment-insensitive but goes through the same
// path for uniformity; the trim costs a few characters of sensitivity and
// removes a class of false negative.
func findEncodedWindow(hay, needle []byte, window int, encode func([]byte) string) int {
	if len(needle) < window {
		return -1
	}
	for phase := 0; phase < 3; phase++ {
		for i := phase; i+window <= len(needle); i += 3 {
			enc := encode(needle[i : i+window])
			if len(enc) > 8 {
				enc = enc[4 : len(enc)-4]
			}
			if len(enc) < 8 {
				continue
			}
			if off := bytes.Index(hay, []byte(enc)); off >= 0 {
				return off
			}
		}
	}
	return -1
}

func makeCert(seedPath, cn string, tweak byte) ([]byte, error) {
	r, err := SeedReader(seedPath, tweak)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(tweak) + 100),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
		DNSNames:     []string{cn},
	}
	r2, err := SeedReader(seedPath, tweak+64)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(r2, tmpl, tmpl, &key.PublicKey, key)
}

func write(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600) //nolint:gosec // fixture planting, not collector code
}
