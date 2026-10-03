package mode2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

const fp = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func claims(t *testing.T) Claims {
	n, err := NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	return Claims{Kid: fp, Cid: "c-1", Tid: "t-1", Mth: "POST",
		Path: "/v1/ingest/observations", Nonce: n,
		Iat: t0.Unix(), Exp: t0.Add(MaxLifetime).Unix()}
}

var body = []byte(`{"batch_id":"01JBQ8AAAA","observations":[{"sha256":"ab","port":443}]}`)

func expect() Expect {
	return Expect{Method: "POST", Path: "/v1/ingest/observations", Now: t0.Add(10 * time.Second)}
}

func sign(t *testing.T, k crypto.Signer, c Claims, b []byte) string {
	t.Helper()
	s, err := Sign(k, c, b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verify(sig string, pub crypto.PublicKey, b []byte, e Expect) error {
	p, err := Parse(sig)
	if err != nil {
		return err
	}
	return p.Verify(pub, b, e)
}

func TestValidSignatureVerifies(t *testing.T) {
	k := ecKey(t)
	if err := verify(sign(t, k, claims(t), body), &k.PublicKey, body, expect()); err != nil {
		t.Fatal(err)
	}
}

func TestRSAKeyVerifies(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(sign(t, k, claims(t), body), &k.PublicKey, body, expect()); err != nil {
		t.Fatal(err)
	}
}

// The reason JCS exists: a proxy that re-serialises the body must not break
// the signature, as long as it does not change what the body means.
func TestReserialisedBodyStillVerifies(t *testing.T) {
	k := ecKey(t)
	sig := sign(t, k, claims(t), body)
	reformatted := []byte("{\n  \"observations\" : [ { \"port\" : 443.0, \"sha256\" : \"\\u0061b\" } ],\n  \"batch_id\" : \"01JBQ8AAAA\"\n}")
	if err := verify(sig, &k.PublicKey, reformatted, expect()); err != nil {
		t.Fatal(err)
	}
}

func TestForgedAndAlteredRequestsAreRefused(t *testing.T) {
	k := ecKey(t)
	other := ecKey(t)
	good := sign(t, k, claims(t), body)

	t.Run("signed by another key", func(t *testing.T) {
		if err := verify(sign(t, other, claims(t), body), &k.PublicKey, body, expect()); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("verified with the wrong key", func(t *testing.T) {
		if err := verify(good, &other.PublicKey, body, expect()); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("body altered", func(t *testing.T) {
		alt := []byte(strings.Replace(string(body), "443", "444", 1))
		if err := verify(good, &k.PublicKey, alt, expect()); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("body removed", func(t *testing.T) {
		if err := verify(good, &k.PublicKey, nil, expect()); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
	// Re-encode the header with one claim changed, keep the old signature.
	for _, mut := range []struct {
		name string
		f    func(*Claims)
	}{
		{"tenant claim altered", func(c *Claims) { c.Tid = "t-2" }},
		{"collector claim altered", func(c *Claims) { c.Cid = "c-2" }},
		{"nonce altered", func(c *Claims) { c.Nonce = strings.Repeat("A", 32) }},
		{"expiry extended", func(c *Claims) { c.Exp += 3600 }},
		{"path altered", func(c *Claims) { c.Path = "/v1/tasks" }},
	} {
		t.Run(mut.name, func(t *testing.T) {
			p, _ := Parse(good)
			c := p.Claims
			mut.f(&c)
			hj, _ := json.Marshal(c)
			forged := b64.EncodeToString(hj) + ".." + strings.Split(good, ".")[2]
			if err := verify(forged, &k.PublicKey, body, expect()); !errors.Is(err, ErrSignature) {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("signature truncated", func(t *testing.T) {
		if err := verify(good[:len(good)-4], &k.PublicKey, body, expect()); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("signature bit flipped", func(t *testing.T) {
		parts := strings.Split(good, ".")
		raw, _ := b64.DecodeString(parts[2])
		raw[10] ^= 1
		if err := verify(parts[0]+".."+b64.EncodeToString(raw), &k.PublicKey, body, expect()); !errors.Is(err, ErrSignature) {
			t.Fatalf("got %v", err)
		}
	})
}

// The request never picks the algorithm. Each of these is a known JWS attack.
func TestAlgorithmSubstitutionIsImpossible(t *testing.T) {
	k := ecKey(t)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	headerWith := func(alg string) string {
		c := claims(t)
		c.Alg = alg
		hj, _ := json.Marshal(c)
		return b64.EncodeToString(hj)
	}
	t.Run("none", func(t *testing.T) {
		sig := headerWith("none") + ".." + b64.EncodeToString([]byte{0})
		if err := verify(sig, &k.PublicKey, body, expect()); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("HS256 keyed with the public key", func(t *testing.T) {
		h := headerWith("HS256")
		pubBytes := elliptic.MarshalCompressed(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
		canon, _ := CanonicalBody(body)
		mac := hmac.New(sha256.New, pubBytes)
		mac.Write([]byte(h + "." + b64.EncodeToString(canon)))
		sig := h + ".." + b64.EncodeToString(mac.Sum(nil))
		if err := verify(sig, &k.PublicKey, body, expect()); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("RS256 header against an EC key", func(t *testing.T) {
		// A genuine RS256 signature by an RSA key, presented for the EC key.
		sig := sign(t, rk, claims(t), body)
		if err := verify(sig, &k.PublicKey, body, expect()); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("ES256 header against an RSA key", func(t *testing.T) {
		sig := sign(t, k, claims(t), body)
		if err := verify(sig, &rk.PublicKey, body, expect()); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("lowercase alg", func(t *testing.T) {
		sig := headerWith("es256") + ".." + b64.EncodeToString(make([]byte, 64))
		if err := verify(sig, &k.PublicKey, body, expect()); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("weak or unsupported keys are refused", func(t *testing.T) {
		p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		small, _ := rsa.GenerateKey(rand.Reader, 1024)
		for _, pub := range []crypto.PublicKey{&p384.PublicKey, &small.PublicKey, "not a key"} {
			if _, err := AlgFor(pub); !errors.Is(err, ErrKey) {
				t.Fatalf("%T accepted", pub)
			}
		}
	})
}

func TestFreshnessIsEnforced(t *testing.T) {
	k := ecKey(t)
	cases := []struct {
		name string
		mut  func(*Claims)
		now  time.Time
		want error
	}{
		{"expired", func(c *Claims) { c.Exp = c.Iat + 60 }, t0.Add(61 * time.Second), ErrExpired},
		{"exactly at exp", func(c *Claims) { c.Exp = c.Iat + 60 }, t0.Add(60 * time.Second), ErrExpired},
		{"past full lifetime", nil, t0.Add(MaxLifetime + time.Second), ErrSkew},
		{"issued too far in the future", func(c *Claims) {
			c.Iat = t0.Add(MaxSkew + time.Minute).Unix()
			c.Exp = c.Iat + 60
		}, t0, ErrSkew},
		{"issued too far in the past", func(c *Claims) {
			c.Iat = t0.Add(-MaxSkew - time.Minute).Unix()
			c.Exp = c.Iat + 60
		}, t0, ErrSkew},
		{"lifetime longer than allowed", func(c *Claims) { c.Exp = c.Iat + 3600 }, t0, ErrMalformed},
		{"exp before iat", func(c *Claims) { c.Exp = c.Iat - 1 }, t0, ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl := claims(t)
			if c.mut != nil {
				c.mut(&cl)
			}
			e := expect()
			e.Now = c.now
			if err := verify(sign(t, k, cl, body), &k.PublicKey, body, e); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
	t.Run("collector clock 4 minutes behind is tolerated", func(t *testing.T) {
		cl := claims(t)
		e := expect()
		e.Now = t0.Add(4 * time.Minute)
		if err := verify(sign(t, k, cl, body), &k.PublicKey, body, e); err != nil {
			t.Fatal(err)
		}
	})
}

// A valid signature for one request is not valid for another.
func TestSignatureIsBoundToTheRequest(t *testing.T) {
	k := ecKey(t)
	sig := sign(t, k, claims(t), body)
	for _, e := range []Expect{
		{Method: "GET", Path: "/v1/ingest/observations", Now: t0},
		{Method: "POST", Path: "/v1/collectors/heartbeat", Now: t0},
		{Method: "POST", Path: "/v1/ingest/observations?x=1", Now: t0},
	} {
		if err := verify(sig, &k.PublicKey, body, e); !errors.Is(err, ErrBinding) {
			t.Fatalf("%s %s: got %v", e.Method, e.Path, err)
		}
	}
}

func TestMalformedSignaturesAreRefusedBeforeAnyKeyLookup(t *testing.T) {
	k := ecKey(t)
	good := sign(t, k, claims(t), body)
	parts := strings.Split(good, ".")
	hdr := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return b64.EncodeToString(b)
	}
	base := func() map[string]any {
		c := claims(t)
		c.Alg = "ES256"
		b, _ := json.Marshal(c)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	withField := func(k string, v any) string { m := base(); m[k] = v; return hdr(m) + ".." + parts[2] }
	without := func(k string) string { m := base(); delete(m, k); return hdr(m) + ".." + parts[2] }

	cases := map[string]string{
		"empty":                    "",
		"oversized":                strings.Repeat("A", MaxSignatureLen+1),
		"two parts":                parts[0] + "." + parts[2],
		"attached payload":         parts[0] + "." + b64.EncodeToString(body) + "." + parts[2],
		"four parts":               good + ".x",
		"padded base64":            parts[0] + "=.." + parts[2],
		"standard base64 alphabet": strings.ReplaceAll(parts[0], "-", "+") + "+.." + parts[2],
		"header not JSON":          b64.EncodeToString([]byte("nope")) + ".." + parts[2],
		"empty signature":          parts[0] + "..",
		"embedded jwk":             withField("jwk", map[string]string{"kty": "EC"}),
		"jku redirect":             withField("jku", "https://evil.example/keys"),
		"crit header":              withField("crit", []string{"b64"}),
		"missing nonce":            without("cw_nonce"),
		"missing tenant":           without("cw_tid"),
		"missing kid":              without("kid"),
		"short nonce":              withField("cw_nonce", "abc"),
		"kid not a fingerprint":    withField("kid", "../../etc/passwd"),
		"duplicate header member": b64.EncodeToString([]byte(strings.Replace(
			string(mustDecode(parts[0])), `{`, `{"cw_tid":"t-other",`, 1))) + ".." + parts[2],
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(sig); !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func mustDecode(s string) []byte {
	b, err := b64.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// A body the canonicaliser refuses cannot be verified, so a duplicate-key
// body — which encoding/json would read differently from what was signed —
// never reaches the decoder.
func TestAmbiguousBodyIsRefused(t *testing.T) {
	k := ecKey(t)
	sig := sign(t, k, claims(t), body)
	dup := []byte(`{"batch_id":"01JBQ8AAAA","batch_id":"other","observations":[]}`)
	if err := verify(sig, &k.PublicKey, dup, expect()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v", err)
	}
}

// Sign ignores a caller-supplied alg: the key decides.
func TestSignIgnoresCallerAlgorithm(t *testing.T) {
	k := ecKey(t)
	c := claims(t)
	c.Alg = "none"
	p, err := Parse(sign(t, k, c, body))
	if err != nil {
		t.Fatal(err)
	}
	if p.Claims.Alg != "ES256" {
		t.Fatalf("alg %q", p.Claims.Alg)
	}
}

func TestEmptyBodyIsSignable(t *testing.T) {
	k := ecKey(t)
	c := claims(t)
	c.Mth, c.Path = "GET", "/v1/tasks?wait=30"
	sig := sign(t, k, c, nil)
	e := Expect{Method: "GET", Path: "/v1/tasks?wait=30", Now: t0}
	if err := verify(sig, &k.PublicKey, nil, e); err != nil {
		t.Fatal(err)
	}
	if err := verify(sig, &k.PublicKey, []byte(`{}`), e); !errors.Is(err, ErrSignature) {
		t.Fatalf("a body added to a signed GET: %v", err)
	}
}
