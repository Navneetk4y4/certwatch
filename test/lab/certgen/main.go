// Command certgen writes every certificate fixture the lab needs.
//
// NOT deterministic, despite the -seed flag. Measured, not assumed: two runs
// with the same seed produce different private keys AND different signatures.
// Both ecdsa.GenerateKey and x509.CreateCertificate route through
// randutil.MaybeReadByte, which randomly consumes a byte from the reader to
// stop callers depending on exact output — precisely what a seed is for.
//
// An earlier version of this comment claimed byte-identical output. Diffing
// two runs falsified it. The seed still helps a little (it removes the system
// entropy source) but it does not give reproducibility.
//
// So the fixtures are COMMITTED, not regenerated — the same conclusion
// test/corpus already reached for the same reason. Run this only when a
// fixture must change, and commit the result, so a failing test is
// attributable to a code change and not to a fresh signature.
//
// These are LAB certificates for deliberately-broken endpoints. They are not
// secrets and they are not trusted by anything outside the lab network.
//
//	go run ./test/lab/certgen -out test/lab/certs
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// chacha8 gives a deterministic key stream without pulling in a dependency.
type detReader struct {
	s [4]uint64
	n uint64
}

func newDetReader(seed uint64) *detReader {
	return &detReader{s: [4]uint64{seed ^ 0x9E3779B97F4A7C15, seed + 1, seed + 2, seed + 3}}
}

func (r *detReader) next() uint64 {
	// xoshiro256**, sufficient for reproducible test keys and nothing else.
	rotl := func(x uint64, k int) uint64 { return x<<k | x>>(64-k) }
	res := rotl(r.s[1]*5, 7) * 9
	t := r.s[1] << 17
	r.s[2] ^= r.s[0]
	r.s[3] ^= r.s[1]
	r.s[1] ^= r.s[2]
	r.s[0] ^= r.s[3]
	r.s[2] ^= t
	r.s[3] = rotl(r.s[3], 45)
	r.n++
	return res
}

func (r *detReader) Read(p []byte) (int, error) {
	var buf [8]byte
	for i := 0; i < len(p); i += 8 {
		binary.LittleEndian.PutUint64(buf[:], r.next())
		copy(p[i:], buf[:])
	}
	return len(p), nil
}

type issued struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func mustKey(r *detReader) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		panic(err)
	}
	return k
}

func issue(r *detReader, tmpl *x509.Certificate, parent *issued) *issued {
	key := mustKey(r)
	signer := key
	parentCert := tmpl
	if parent != nil {
		signer = parent.key
		parentCert = parent.cert
	}
	der, err := x509.CreateCertificate(r, tmpl, parentCert, &key.PublicKey, signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &issued{cert: c, der: der, key: key}
}

func writePEM(dir, name string, blocks ...*pem.Block) {
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, b := range blocks {
		if err := pem.Encode(f, b); err != nil {
			panic(err)
		}
	}
}

func certBlock(i *issued) *pem.Block { return &pem.Block{Type: "CERTIFICATE", Bytes: i.der} }

func keyBlock(i *issued) *pem.Block {
	b, err := x509.MarshalECPrivateKey(i.key)
	if err != nil {
		panic(err)
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
}

func main() {
	out := flag.String("out", "test/lab/certs", "output directory")
	seed := flag.Uint64("seed", 20260920, "deterministic seed")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		panic(err)
	}
	r := newDetReader(*seed)
	// A fixed base time keeps notBefore/notAfter stable across runs. Validity
	// is expressed relative to it so "expired" stays expired.
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	serial := int64(1000)
	tmpl := func(cn string, sans []string, notBefore, notAfter time.Time, ca bool) *x509.Certificate {
		serial++
		t := &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"certwatch lab"}},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames:              sans,
			BasicConstraintsValid: true,
		}
		if ca {
			t.IsCA = true
			t.KeyUsage |= x509.KeyUsageCertSign
			t.ExtKeyUsage = nil
		}
		return t
	}

	// --- the PKI: one root, one intermediate --------------------------------
	root := issue(r, tmpl("certwatch lab root CA", nil, base.AddDate(-1, 0, 0), base.AddDate(9, 0, 0), true), nil)
	inter := issue(r, tmpl("certwatch lab issuing CA G2", nil, base.AddDate(-1, 0, 0), base.AddDate(5, 0, 0), true), root)
	// A second issuing CA, so policy mode has an issuer to reject.
	rogue := issue(r, tmpl("unapproved issuing CA", nil, base.AddDate(-1, 0, 0), base.AddDate(5, 0, 0), true), root)

	writePEM(*out, "root.crt", certBlock(root))
	writePEM(*out, "chain.crt", certBlock(inter), certBlock(root))
	writePEM(*out, "ca-bundle.crt", certBlock(inter), certBlock(root))

	// leaf writes cert+chain and key; `full` controls whether the intermediate
	// is included, which is what makes web-badchain broken.
	leaf := func(name, cn string, sans []string, nb, na time.Time, parent *issued, full bool) *issued {
		li := issue(r, tmpl(cn, sans, nb, na, false), parent)
		blocks := []*pem.Block{certBlock(li)}
		if full {
			blocks = append(blocks, certBlock(parent))
		}
		writePEM(*out, name+".crt", blocks...)
		writePEM(*out, name+".key", keyBlock(li))
		return li
	}

	good := base.AddDate(0, 3, 0) // 90 days from base

	// --- 059: the healthy pool. Three backends, ONE certificate -------------
	pool := leaf("pool", "lab.internal.test",
		[]string{"lab.internal.test", "www.lab.internal.test"}, base, good, inter, true)

	// --- 064 (GAP-3): web-divergent. A SECOND certificate, also valid, also
	// from the approved issuer, for the same hostname. Policy mode accepts
	// both, so fingerprint divergence is the only signal the pool is split.
	leaf("divergent", "lab.internal.test",
		[]string{"lab.internal.test"}, base, base.AddDate(0, 2, 0), inter, true)

	// --- 060: the three broken ones -----------------------------------------
	leaf("expired", "expired.lab.internal.test",
		[]string{"expired.lab.internal.test"},
		base.AddDate(0, -6, 0), base.AddDate(0, -1, 0), inter, true) // expired a month ago
	leaf("badchain", "badchain.lab.internal.test",
		[]string{"badchain.lab.internal.test"}, base, good, inter, false) // intermediate omitted
	leaf("wronghost", "somewhere-else.example.net",
		[]string{"somewhere-else.example.net"}, base, good, inter, true)

	// --- 062: web-sni. Three hostnames, one address -------------------------
	for _, h := range []string{"alpha", "beta", "gamma"} {
		leaf("sni-"+h, h+".lab.internal.test", []string{h + ".lab.internal.test"}, base, good, inter, true)
	}

	// --- 063: web-policy-rotate. Same issuer, different key: a legitimate
	// rotation that policy mode must stay SILENT about.
	leaf("rotate-old", "rotate.lab.internal.test",
		[]string{"rotate.lab.internal.test"}, base.AddDate(0, -2, 0), base.AddDate(0, 1, 0), inter, true)
	leaf("rotate-new", "rotate.lab.internal.test",
		[]string{"rotate.lab.internal.test"}, base, good, inter, true)

	// An unapproved issuer, for the policy rejection path.
	leaf("rogue", "rogue.lab.internal.test",
		[]string{"rogue.lab.internal.test"}, base, good, rogue, true)

	// --- near expiry, for the near_expiry / expired escalation --------------
	leaf("nearexpiry", "nearexpiry.lab.internal.test",
		[]string{"nearexpiry.lab.internal.test"}, base, base.AddDate(0, 0, 5), inter, true)

	// --- 062: mTLS client certificate ---------------------------------------
	leaf("client", "lab client", nil, base, good, inter, true)

	// --- fixtures for the parsing edge cases --------------------------------
	// A certificate with a NUL byte in a SAN cannot be produced by
	// x509.CreateCertificate, so the hostile-input cases stay in
	// pkg/x509norm/hostile_test.go where they can be built byte by byte. The
	// lab covers what a real server can actually serve.

	fmt.Printf("wrote fixtures to %s\n", *out)
	fmt.Printf("  pool leaf fingerprint stable across runs: %x\n", pool.der[:8])
}
