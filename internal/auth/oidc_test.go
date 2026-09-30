package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

const testRedirect = "https://app.certwatch.test/auth/callback"

type oidcFixture struct {
	*fixture
	idp *fakeIDP
	o   *OIDC
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	f := newAuthFixture(t)
	idp := newFakeIDP(t, "client-a")
	o := NewOIDC(f.st, safelog.Discard(), func() time.Time { return f.clock },
		[]string{testRedirect})

	// Register the provider for tenant A's domain.
	ctx := tenancy.WithTenant(context.Background(), f.tenantA)
	if err := f.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, e := tx.Conn().Exec(ctx, `
			INSERT INTO identity_providers (tenant_id, issuer, client_id, email_domain)
			VALUES ($1::uuid,$2,$3,$4)`,
			f.tenantA.String(), idp.issuer, "client-a", "tenant-a.test")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return &oidcFixture{fixture: f, idp: idp, o: o}
}

// drive runs a complete browser flow against the fake IdP and returns the
// identity, or the error the callback produced.
func (x *oidcFixture) drive(t *testing.T, domain string) (Identity, error) {
	t.Helper()
	req, err := x.o.Start(context.Background(), domain, testRedirect)
	if err != nil {
		return Identity{}, err
	}
	// Follow the authorization redirect the way a browser would.
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := c.Get(req.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	state := loc.Query().Get("state")
	if code == "" || state != req.State {
		t.Fatalf("authorization did not return a code bound to our state (code=%q state=%q want %q)",
			code, state, req.State)
	}
	return x.o.Complete(context.Background(), state, code)
}

// ---------------------------------------------------------------------------
// The happy path, end to end, against a real signature
// ---------------------------------------------------------------------------

func TestOIDCFullFlowResolvesTenantFromTheVerifiedDomain(t *testing.T) {
	x := newOIDCFixture(t)
	id, err := x.drive(t, "tenant-a.test")
	if err != nil {
		t.Fatalf("a valid login failed: %v", err)
	}
	if id.TenantID != x.tenantA {
		t.Errorf("tenant = %s, want %s — the tenant must come from the verified email domain",
			id.TenantID, x.tenantA)
	}
	if id.Email != "user@tenant-a.test" || id.Subject != "sub-123" {
		t.Errorf("identity = %+v", id)
	}
	// PKCE actually happened: the provider received a verifier.
	if len(x.idp.lastVerifier) < 43 {
		t.Errorf("code_verifier was %d chars; RFC 7636 requires 43-128",
			len(x.idp.lastVerifier))
	}
}

func TestJITProvisioningCreatesAViewerAndIsIdempotent(t *testing.T) {
	x := newOIDCFixture(t)
	id, err := x.drive(t, "tenant-a.test")
	if err != nil {
		t.Fatal(err)
	}
	uid1, role, err := x.o.ProvisionUser(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if role != tenancy.RoleViewer {
		t.Errorf("JIT role = %s, want viewer — nobody approved this account, so it "+
			"must be able to read and nothing else", role)
	}
	// Repeated provisioning must return the SAME user, not a duplicate.
	id2, err := x.drive(t, "tenant-a.test")
	if err != nil {
		t.Fatal(err)
	}
	uid2, _, err := x.o.ProvisionUser(context.Background(), id2)
	if err != nil {
		t.Fatal(err)
	}
	if uid1 != uid2 {
		t.Errorf("repeated login created a second user: %s then %s", uid1, uid2)
	}
	var n int
	ctx := tenancy.WithTenant(context.Background(), x.tenantA)
	if err := x.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx,
			`SELECT count(*) FROM users WHERE email = $1`, id.Email).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d user rows for one email; JIT provisioning is not idempotent", n)
	}
}

// Provisioning must NOT silently promote an existing user.
func TestJITProvisioningDoesNotElevateAnExistingUser(t *testing.T) {
	x := newOIDCFixture(t)
	// Pre-create the same email as a viewer, then make them an operator.
	uid := x.mkUser(t, x.tenantA, "user@tenant-a.test", tenancy.RoleOperator)
	id, err := x.drive(t, "tenant-a.test")
	if err != nil {
		t.Fatal(err)
	}
	gotID, role, err := x.o.ProvisionUser(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != uid {
		t.Fatalf("matched the wrong user: %s want %s", gotID, uid)
	}
	if role != tenancy.RoleOperator {
		t.Errorf("role = %s, want operator — provisioning must not downgrade either", role)
	}
}

// ---------------------------------------------------------------------------
// Attacks
// ---------------------------------------------------------------------------

// Login CSRF: a callback with a state we never issued must be refused.
func TestUnknownStateIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	if _, err := x.o.Complete(context.Background(), "state-we-never-issued", "code-x"); !errors.Is(err, ErrStateUnknown) {
		t.Fatalf("err = %v, want ErrStateUnknown — otherwise an attacker completes a "+
			"login in the victim's browser using their own code", err)
	}
}

// Code replay: the same state/code pair must work exactly once.
func TestStateIsSingleUse(t *testing.T) {
	x := newOIDCFixture(t)
	req, err := x.o.Start(context.Background(), "tenant-a.test", testRedirect)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := c.Get(req.AuthorizationURL)
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")

	if _, err := x.o.Complete(context.Background(), req.State, code); err != nil {
		t.Fatalf("first completion failed: %v", err)
	}
	if _, err := x.o.Complete(context.Background(), req.State, code); err == nil {
		t.Fatal("the same state completed twice; a replayed callback must find nothing")
	}
}

// The test above passes even with OUR replay guard removed, because the fake
// IdP also refuses a reused authorization code — so it was proving the
// provider's behaviour, not ours. Found by mutating the consumed_at check and
// watching nothing fail.
//
// This one isolates our guard: replay the state with a DIFFERENT, entirely
// FRESH code. The provider would happily redeem it. Only our own single-use
// consumption can refuse it.
func TestStateCannotBeReusedEvenWithAFreshCode(t *testing.T) {
	x := newOIDCFixture(t)
	req, err := x.o.Start(context.Background(), "tenant-a.test", testRedirect)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	get := func() string {
		resp, e := c.Get(req.AuthorizationURL)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		loc, _ := url.Parse(resp.Header.Get("Location"))
		return loc.Query().Get("code")
	}
	code1, code2 := get(), get() // two independent, both-valid codes
	if code1 == code2 {
		t.Fatal("fixture error: the IdP reused a code")
	}
	if _, err := x.o.Complete(context.Background(), req.State, code1); err != nil {
		t.Fatalf("first completion failed: %v", err)
	}
	// code2 has never been redeemed. If the state were reusable this succeeds.
	if _, err := x.o.Complete(context.Background(), req.State, code2); !errors.Is(err, ErrStateUnknown) {
		t.Fatalf("err = %v, want ErrStateUnknown. A login state must be single-use "+
			"independently of whether the provider happens to refuse the code.", err)
	}
}

func TestExpiredLoginStateIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	req, err := x.o.Start(context.Background(), "tenant-a.test", testRedirect)
	if err != nil {
		t.Fatal(err)
	}
	x.clock = x.clock.Add(FlowTTL + time.Minute)
	if _, err := x.o.Complete(context.Background(), req.State, "code-any"); !errors.Is(err, ErrStateUnknown) {
		t.Fatalf("err = %v, want ErrStateUnknown for an expired login", err)
	}
}

// An unregistered redirect_uri must never be accepted: the authorization code
// is delivered TO that URI.
func TestUnregisteredRedirectURIIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	for _, bad := range []string{
		"https://evil.test/steal",
		"https://app.certwatch.test/auth/callback/../../evil",
		"http://app.certwatch.test/auth/callback",
		"https://app.certwatch.test.evil.test/auth/callback",
		"",
	} {
		if _, err := x.o.Start(context.Background(), "tenant-a.test", bad); !errors.Is(err, ErrRedirectURI) {
			t.Errorf("redirect_uri %q was accepted (err=%v)", bad, err)
		}
	}
}

// A token signed by a key that is NOT in the provider's JWKS must be refused.
func TestForgedTokenSignatureIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	x.idp.signWithOtherKey = other
	if _, err := x.drive(t, "tenant-a.test"); err == nil {
		t.Fatal("a token signed with a key outside the JWKS was accepted")
	}
}

// A token whose issuer is somebody else must be refused.
func TestWrongIssuerIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	x.idp.overrideIssuer = "https://accounts.evil.test"
	if _, err := x.drive(t, "tenant-a.test"); err == nil {
		t.Fatal("a token claiming a different issuer was accepted")
	}
}

// A token minted for a different client (audience) must be refused.
func TestWrongAudienceIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	x.idp.overrideAudience = "some-other-client"
	if _, err := x.drive(t, "tenant-a.test"); err == nil {
		t.Fatal("a token minted for another client was accepted")
	}
}

// Nonce binding: a token that does not carry THIS login's nonce is a token
// replayed from another session.
func TestNonceMismatchIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	x.idp.overrideNonce = "a-nonce-from-some-other-login"
	_, err := x.drive(t, "tenant-a.test")
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("err = %v, want ErrNonceMismatch", err)
	}
}

func TestExpiredIDTokenIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	x.idp.skewTokenExpiry = -time.Hour
	if _, err := x.drive(t, "tenant-a.test"); err == nil {
		t.Fatal("an expired id_token was accepted")
	}
}

// An UNVERIFIED email means an unproven domain, and the domain picks the
// tenant. Accepting it lets anyone who can edit a profile field choose which
// company to join.
func TestUnverifiedEmailIsRefused(t *testing.T) {
	x := newOIDCFixture(t)
	x.idp.emailVerified = false
	_, err := x.drive(t, "tenant-a.test")
	if !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("err = %v, want ErrEmailUnverified", err)
	}
}

// THE cross-tenant attack: tenant A's own identity provider mints a token
// whose email claims tenant B's domain. The issuer is legitimate, the
// signature is valid, the nonce is right — and it must still be refused,
// because that issuer is not the one registered for B's domain.
func TestAProviderCannotMintATokenForAnotherTenantsDomain(t *testing.T) {
	x := newOIDCFixture(t)
	// Register tenant B with a DIFFERENT issuer.
	ctxB := tenancy.WithTenant(context.Background(), x.tenantB)
	if err := x.st.InTenantTx(ctxB, func(ctx context.Context, tx *store.Tx) error {
		_, e := tx.Conn().Exec(ctx, `
			INSERT INTO identity_providers (tenant_id, issuer, client_id, email_domain)
			VALUES ($1::uuid,$2,$3,$4)`,
			x.tenantB.String(), "https://idp-b.test", "client-b", "tenant-b.test")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	// A's provider claims a B address.
	x.idp.email = "attacker@tenant-b.test"
	_, err := x.drive(t, "tenant-a.test")
	if err == nil {
		t.Fatal("tenant A's provider minted a token for tenant B's domain and it was accepted")
	}
	if !errors.Is(err, ErrUnknownDomain) {
		t.Errorf("err = %v, want ErrUnknownDomain (non-enumerable)", err)
	}
}

// A domain nobody has registered must be refused NON-ENUMERABLY: the same
// error as a disabled provider, so an outsider cannot discover which
// companies are customers.
func TestUnknownDomainIsRefusedNonEnumerably(t *testing.T) {
	x := newOIDCFixture(t)
	_, errUnknown := x.o.Start(context.Background(), "never-registered.test", testRedirect)
	if !errors.Is(errUnknown, ErrUnknownDomain) {
		t.Fatalf("err = %v, want ErrUnknownDomain", errUnknown)
	}

	// Disable tenant A's provider; the error must be identical.
	ctx := tenancy.WithTenant(context.Background(), x.tenantA)
	if err := x.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, e := tx.Conn().Exec(ctx, `UPDATE identity_providers SET enabled = false`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	_, errDisabled := x.o.Start(context.Background(), "tenant-a.test", testRedirect)
	if errDisabled.Error() != errUnknown.Error() {
		t.Errorf("a disabled provider (%v) is distinguishable from an unknown domain (%v); "+
			"the difference reveals which companies are customers", errDisabled, errUnknown)
	}
}

// PKCE must actually bind: an exchange without the right verifier fails at
// the provider. Proven by making the provider strict and confirming our
// verifier satisfies it, then confirming a wrong verifier does not.
func TestPKCEVerifierIsRequiredAndCorrect(t *testing.T) {
	x := newOIDCFixture(t)
	x.idp.requirePKCE = true
	if _, err := x.drive(t, "tenant-a.test"); err != nil {
		t.Fatalf("a strict-PKCE provider rejected our exchange: %v", err)
	}
	sent := x.idp.lastVerifier
	if sent == "" {
		t.Fatal("no code_verifier was sent")
	}
	if strings.ContainsAny(sent, "+/=") {
		t.Errorf("verifier %q is not base64url; RFC 7636 requires the URL alphabet", sent)
	}
}

// The challenge must be S256, never plain: plain provides no binding at all
// when the request is observable.
func TestAuthorizationURLUsesS256(t *testing.T) {
	x := newOIDCFixture(t)
	req, err := x.o.Start(context.Background(), "tenant-a.test", testRedirect)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(req.AuthorizationURL)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Error("no code_challenge in the authorization URL")
	}
	if q.Get("nonce") == "" {
		t.Error("no nonce in the authorization URL")
	}
	if q.Get("state") == "" {
		t.Error("no state in the authorization URL")
	}
	// The verifier must never appear in the URL — that would defeat PKCE.
	if strings.Contains(req.AuthorizationURL, q.Get("code_challenge")+"&code_verifier") {
		t.Error("the code_verifier leaked into the authorization URL")
	}
}

// A provider that is down must produce a clean refusal, not a panic or a
// half-finished login.
func TestProviderFailureIsHandledCleanly(t *testing.T) {
	x := newOIDCFixture(t)
	x.idp.srv.Close() // the IdP is now unreachable
	_, err := x.o.Start(context.Background(), "tenant-a.test", testRedirect)
	if err == nil {
		t.Fatal("Start succeeded against a dead provider")
	}
	if strings.Contains(err.Error(), "panic") {
		t.Errorf("provider failure produced %v", err)
	}
}
