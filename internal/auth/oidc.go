package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// AUTH-001 and AUTH-003, build items 098 and 100.
//
// # Where the tenant comes from
//
// project_1_architecture.md is explicit: derive tenant_id from the verified
// identity claim, NEVER from the request body, path or header. So the tenant
// is resolved from the EMAIL DOMAIN inside a signed, verified ID token, and
// from nowhere else. A caller cannot name the tenant they would like to be.
//
// # What is actually checked, and why each one matters
//
//	state          binds the callback to a browser that started a login.
//	               Without it, an attacker completes a login in the victim's
//	               browser using their own code: login CSRF.
//	PKCE verifier  binds the code to the client that requested it. Without it,
//	               a code intercepted at the redirect is redeemable by anyone.
//	nonce          binds the ID TOKEN to this login. Without it, a token
//	               replayed from another session is accepted.
//	issuer + aud   checked by go-oidc against discovery; a token minted by a
//	               different provider, or for a different client, is refused.
//	signature      checked against the provider's JWKS.
//	single use     the flow row is deleted on use, so a replayed callback
//	               finds nothing.
//
// Token verification is delegated to go-oidc rather than hand-rolled. A
// hand-written JWT verifier is the single most reliable way to introduce an
// authentication bypass — alg=none, HMAC-vs-RSA confusion, unchecked aud.

// Errors are deliberately coarse at the edge; see LoginFailure.
var (
	ErrUnknownDomain   = errors.New("auth: no tenant for that email domain")
	ErrStateUnknown    = errors.New("auth: unknown or expired login state")
	ErrStateReplayed   = errors.New("auth: login state already used")
	ErrNonceMismatch   = errors.New("auth: id token nonce does not match this login")
	ErrEmailUnverified = errors.New("auth: the provider did not verify this email address")
	ErrRedirectURI     = errors.New("auth: redirect_uri is not registered")
)

// FlowTTL bounds how long a login may sit half-finished.
const FlowTTL = 10 * time.Minute

// Provider is one configured identity provider for one tenant.
type Provider struct {
	TenantID     tenancy.Tenant
	Issuer       string
	ClientID     string
	ClientSecret string
	EmailDomain  string
}

// OIDC runs the Authorization Code + PKCE flow.
type OIDC struct {
	st  *store.Store
	log *safelog.Logger
	now func() time.Time

	// RedirectURIs is the allowlist. A redirect_uri arriving in a request is
	// never trusted: an open redirect here turns into a stolen authorization
	// code, because the code is delivered TO that URI.
	RedirectURIs []string

	// providerFor is injectable so tests can stand up a real local IdP with
	// real keys instead of reaching the internet.
	providerFor func(ctx context.Context, issuer string) (*oidc.Provider, error)
}

// NewOIDC builds the flow handler.
func NewOIDC(st *store.Store, log *safelog.Logger, now func() time.Time, redirects []string) *OIDC {
	if now == nil {
		now = time.Now
	}
	return &OIDC{
		st: st, log: log, now: now, RedirectURIs: redirects,
		providerFor: func(ctx context.Context, issuer string) (*oidc.Provider, error) {
			// Discovery. go-oidc checks that the document's own `issuer`
			// matches the URL it was fetched from, which stops a provider
			// claiming to be somebody else.
			return oidc.NewProvider(ctx, issuer)
		},
	}
}

// SetProviderResolver replaces discovery. Test-only seam.
func (o *OIDC) SetProviderResolver(f func(ctx context.Context, issuer string) (*oidc.Provider, error)) {
	o.providerFor = f
}

func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge is S256. The plain method is not offered: it provides no
// binding at all if the request is observable, which is the threat PKCE
// exists for.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (o *OIDC) redirectAllowed(uri string) bool {
	for _, r := range o.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}

// ProviderForDomain resolves an email domain to its tenant's provider.
//
// Pre-tenancy by necessity: the domain is what decides the tenant. It reads
// identity_providers, which IS tenant-policied, so the lookup goes through a
// narrow privileged query — and returns the same error for "no such domain"
// as for "disabled", so a caller cannot enumerate which companies are
// customers.
func (o *OIDC) ProviderForDomain(ctx context.Context, domain string) (Provider, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return Provider{}, ErrUnknownDomain
	}
	var p Provider
	var tid string
	err := o.st.Privileged(ctx,
		"resolve an email domain to its tenant's identity provider; the domain IS the tenant selector",
		func(ctx context.Context, pool *pgxpool.Pool) error {
			return pool.QueryRow(ctx, `
				SELECT tenant_id::text, issuer, client_id, email_domain::text
				  FROM provider_domain_index
				 WHERE email_domain = $1 AND enabled`, domain).
				Scan(&tid, &p.Issuer, &p.ClientID, &p.EmailDomain)
		})
	if err != nil {
		// One error for every failure. "Unknown domain" and "disabled
		// provider" must be indistinguishable: the difference tells an
		// outsider whether a company is a customer.
		return Provider{}, ErrUnknownDomain
	}
	p.TenantID = tenancy.Tenant(tid)
	if !p.TenantID.Valid() {
		return Provider{}, ErrUnknownDomain
	}
	return p, nil
}

// AuthRequest is what Start returns: where to send the browser.
type AuthRequest struct {
	AuthorizationURL string
	State            string
}

// Start begins a login for an email domain.
func (o *OIDC) Start(ctx context.Context, emailDomain, redirectURI string) (AuthRequest, error) {
	if !o.redirectAllowed(redirectURI) {
		// Never reflect an unregistered redirect_uri. The authorization code
		// is delivered to this URI; accepting an arbitrary one hands the code
		// to the attacker.
		return AuthRequest{}, ErrRedirectURI
	}
	prov, err := o.ProviderForDomain(ctx, emailDomain)
	if err != nil {
		return AuthRequest{}, err
	}
	p, err := o.providerFor(ctx, prov.Issuer)
	if err != nil {
		return AuthRequest{}, fmt.Errorf("auth: provider discovery failed: %w", err)
	}

	state, err := randB64(32)
	if err != nil {
		return AuthRequest{}, err
	}
	nonce, err := randB64(32)
	if err != nil {
		return AuthRequest{}, err
	}
	verifier, err := randB64(48) // 64 chars, inside RFC 7636's 43..128
	if err != nil {
		return AuthRequest{}, err
	}

	if err := o.st.Privileged(ctx, "record an in-flight login; no tenant is decided yet",
		func(ctx context.Context, pool *pgxpool.Pool) error {
			_, e := pool.Exec(ctx, `
				INSERT INTO oidc_flows (state, nonce, code_verifier, redirect_uri, issuer, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6)`,
				state, nonce, verifier, redirectURI, prov.Issuer, o.now().UTC().Add(FlowTTL))
			return e
		}); err != nil {
		return AuthRequest{}, fmt.Errorf("auth: recording login state: %w", err)
	}

	cfg := oauth2.Config{
		ClientID:     prov.ClientID,
		ClientSecret: prov.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	u := cfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	return AuthRequest{AuthorizationURL: u, State: state}, nil
}

// Identity is a verified end-user identity.
type Identity struct {
	Subject  string
	Email    string
	Issuer   string
	TenantID tenancy.Tenant
	Domain   string
}

// Complete finishes a login from the provider's callback.
func (o *OIDC) Complete(ctx context.Context, state, code string) (Identity, error) {
	if state == "" || code == "" {
		return Identity{}, ErrStateUnknown
	}

	// Consume the flow row ATOMICALLY. The UPDATE ... WHERE consumed_at IS
	// NULL RETURNING pattern means two concurrent callbacks with the same
	// state cannot both succeed: exactly one gets a row. That is code-replay
	// protection that does not depend on timing.
	var nonce, verifier, redirectURI, issuer string
	var expires time.Time
	err := o.st.Privileged(ctx, "consume an in-flight login state exactly once",
		func(ctx context.Context, pool *pgxpool.Pool) error {
			return pool.QueryRow(ctx, `
				UPDATE oidc_flows SET consumed_at = now()
				 WHERE state = $1 AND consumed_at IS NULL
				RETURNING nonce, code_verifier, redirect_uri, issuer, expires_at`, state).
				Scan(&nonce, &verifier, &redirectURI, &issuer, &expires)
		})
	if err != nil {
		// Either unknown or already used. Same answer for both.
		return Identity{}, ErrStateUnknown
	}
	if o.now().UTC().After(expires) {
		return Identity{}, ErrStateUnknown
	}

	p, err := o.providerFor(ctx, issuer)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: provider discovery failed: %w", err)
	}
	prov, err := o.providerForIssuer(ctx, issuer)
	if err != nil {
		return Identity{}, ErrUnknownDomain
	}

	cfg := oauth2.Config{
		ClientID:     prov.ClientID,
		ClientSecret: prov.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	tok, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("auth: code exchange failed: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, errors.New("auth: provider returned no id_token")
	}

	// Signature, issuer and audience, all checked against discovery + JWKS.
	verifier2 := p.Verifier(&oidc.Config{ClientID: prov.ClientID})
	idt, err := verifier2.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: id token rejected: %w", err)
	}
	if idt.Nonce != nonce {
		// A token minted for a different login. Without this check a token
		// captured elsewhere is accepted here.
		return Identity{}, ErrNonceMismatch
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("auth: reading claims: %w", err)
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" || !strings.Contains(email, "@") {
		return Identity{}, errors.New("auth: id token carries no usable email claim")
	}
	// An unverified email is an unproven domain, and the domain is what picks
	// the tenant. Accepting it would let anyone who can set a profile field
	// choose which company to join.
	if claims.EmailVerified == nil || !*claims.EmailVerified {
		return Identity{}, ErrEmailUnverified
	}
	domain := email[strings.LastIndex(email, "@")+1:]

	// The tenant comes from the VERIFIED domain, and the provider that minted
	// the token must be the one registered for that domain. Without this
	// second check, a tenant's own provider could mint a token with somebody
	// else's domain in the email claim and cross into their account.
	bound, err := o.ProviderForDomain(ctx, domain)
	if err != nil {
		return Identity{}, ErrUnknownDomain
	}
	if bound.Issuer != issuer {
		return Identity{}, ErrUnknownDomain
	}
	return Identity{
		Subject: idt.Subject, Email: email, Issuer: issuer,
		TenantID: bound.TenantID, Domain: domain,
	}, nil
}

// providerForIssuer finds the registered client for an issuer.
func (o *OIDC) providerForIssuer(ctx context.Context, issuer string) (Provider, error) {
	var p Provider
	var tid string
	err := o.st.Privileged(ctx, "resolve an issuer to its registered client id",
		func(ctx context.Context, pool *pgxpool.Pool) error {
			return pool.QueryRow(ctx, `
				SELECT tenant_id::text, issuer, client_id, email_domain::text
				  FROM provider_domain_index WHERE issuer = $1 AND enabled LIMIT 1`, issuer).
				Scan(&tid, &p.Issuer, &p.ClientID, &p.EmailDomain)
		})
	if err != nil {
		return Provider{}, ErrUnknownDomain
	}
	p.TenantID = tenancy.Tenant(tid)
	return p, nil
}

// ProvisionUser is AUTH-003, item 100: just-in-time provisioning.
//
// A user who authenticates for a domain we know, and does not yet exist, is
// created as a VIEWER. Viewer is the floor on purpose — JIT provisioning
// creates accounts without anyone approving them, so the account it creates
// must be able to read and nothing else. Elevation is a deliberate act by an
// admin.
func (o *OIDC) ProvisionUser(ctx context.Context, id Identity) (userID string, role tenancy.Role, err error) {
	ctx = tenancy.WithTenant(ctx, id.TenantID)
	err = o.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		// Existing user by subject, or by email within this tenant.
		e := tx.Conn().QueryRow(ctx, `
			SELECT id::text, role::text FROM users
			 WHERE tenant_id = $1::uuid AND (sso_subject = $2 OR email = $3)
			 ORDER BY (sso_subject = $2) DESC LIMIT 1`,
			id.TenantID.String(), id.Subject, id.Email).Scan(&userID, (*string)(&role))
		if e == nil {
			// Bind the subject on first SSO login for a pre-created user, and
			// refresh last_seen_at.
			_, e2 := tx.Conn().Exec(ctx, `
				UPDATE users SET sso_subject = $2, sso_issuer = $3, last_seen_at = now()
				 WHERE id = $1::uuid`, userID, id.Subject, id.Issuer)
			return e2
		}
		return tx.Conn().QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, sso_subject, sso_issuer, role, last_seen_at)
			VALUES ($1::uuid, $2, $3, $4, 'viewer', now())
			RETURNING id::text, role::text`,
			id.TenantID.String(), id.Email, id.Subject, id.Issuer).
			Scan(&userID, (*string)(&role))
	})
	if err != nil {
		return "", "", fmt.Errorf("auth: provisioning user: %w", err)
	}
	return userID, role, nil
}

// LoginFailure writes the single response every login failure gets.
//
// The same body for unknown domain, expired state, replayed state, bad nonce
// and a provider error. Each distinction is information about somebody else's
// account or about which companies are customers.
func LoginFailure(w http.ResponseWriter, log *safelog.Logger, reason string) {
	if log != nil {
		log.Info("login refused", safelog.Str("reason", reason))
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error": "sign-in could not be completed",
	})
}

// SafeRedirect rejects anything that is not one of the registered URIs.
func (o *OIDC) SafeRedirect(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !o.redirectAllowed(raw) {
		return "", ErrRedirectURI
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return "", ErrRedirectURI
	}
	return raw, nil
}
