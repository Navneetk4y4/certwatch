package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// A REAL OpenID provider, locally.
//
// It serves a real discovery document, a real JWKS, and mints real RS256 ID
// tokens with a real signature. go-oidc does real verification against it.
// Nothing about the token path is stubbed, because the thing being tested IS
// the token path — a mocked verifier would pass every test below while the
// product accepted forged tokens.
//
// It is also deliberately controllable: each field an attack needs to corrupt
// (issuer, audience, nonce, signing key, email_verified) is a knob.

type fakeIDP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	keyID  string
	issuer string

	// Knobs the attack tests turn.
	overrideIssuer   string          // mint tokens claiming a different issuer
	overrideAudience string          // mint for a different client
	overrideNonce    string          // ignore the requested nonce
	emailVerified    bool            // claim an unverified email
	email            string          // the email claim
	subject          string          //
	signWithOtherKey *rsa.PrivateKey // forge with a key not in the JWKS
	skewTokenExpiry  time.Duration

	// Issued codes -> the PKCE challenge and nonce that were requested.
	codes map[string]codeRecord
	// requirePKCE, when true, refuses an exchange whose verifier does not
	// hash to the challenge. A real provider does this; turning it off proves
	// our side sends a correct verifier rather than relying on the provider.
	requirePKCE  bool
	lastVerifier string
}

type codeRecord struct {
	challenge string
	nonce     string
	used      bool
}

func newFakeIDP(t *testing.T, clientID string) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{
		key: key, keyID: "test-key-1", emailVerified: true,
		email: "user@tenant-a.test", subject: "sub-123",
		codes: map[string]codeRecord{}, requirePKCE: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSONRaw(w, map[string]any{
			"issuer":                                f.issuer,
			"authorization_endpoint":                f.issuer + "/authorize",
			"token_endpoint":                        f.issuer + "/token",
			"jwks_uri":                              f.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &f.key.PublicKey, KeyID: f.keyID, Algorithm: "RS256", Use: "sig",
		}}}
		writeJSONRaw(w, jwks)
	})
	// The authorization endpoint records the challenge and hands back a code.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + randHex()
		f.codes[code] = codeRecord{
			challenge: q.Get("code_challenge"),
			nonce:     q.Get("nonce"),
		}
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"),
			http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.Form.Get("code")
		rec, ok := f.codes[code]
		if !ok || rec.used {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		f.lastVerifier = r.Form.Get("code_verifier")
		if f.requirePKCE {
			sum := sha256.Sum256([]byte(f.lastVerifier))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != rec.challenge {
				http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`,
					http.StatusBadRequest)
				return
			}
		}
		rec.used = true
		f.codes[code] = rec

		nonce := rec.nonce
		if f.overrideNonce != "" {
			nonce = f.overrideNonce
		}
		// aud is the client that made THIS request, as a real IdP does.
		aud := clientID
		if u, _, ok := r.BasicAuth(); ok && u != "" {
			aud = u
		} else if c := r.Form.Get("client_id"); c != "" {
			aud = c
		}
		writeJSONRaw(w, map[string]any{
			"access_token": "at-" + randHex(),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.mintIDToken(t, aud, nonce),
		})
	})
	f.srv = httptest.NewServer(mux)
	f.issuer = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) mintIDToken(t *testing.T, aud, nonce string) string {
	t.Helper()
	iss := f.issuer
	if f.overrideIssuer != "" {
		iss = f.overrideIssuer
	}
	if f.overrideAudience != "" {
		aud = f.overrideAudience
	}
	signKey := f.key
	if f.signWithOtherKey != nil {
		signKey = f.signWithOtherKey
	}
	exp := time.Now().Add(time.Hour)
	if f.skewTokenExpiry != 0 {
		exp = time.Now().Add(f.skewTokenExpiry)
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: signKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", f.keyID))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss": iss, "sub": f.subject, "aud": aud,
		"exp": exp.Unix(), "iat": time.Now().Unix(),
		"nonce": nonce, "email": f.email, "email_verified": f.emailVerified,
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeJSONRaw(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randHex() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return n.Text(16)
}
