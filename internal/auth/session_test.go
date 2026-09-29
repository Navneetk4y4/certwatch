package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
)

// AUTH-002 / AUTH-004. Adversarial by design: every test below is an attempt
// to get in, or to get further than the role allows.

func TestSessionLifecycle(t *testing.T) {
	h := newAuthFixture(t)
	tok, s, err := h.login(h.tenantA, h.userA, tenancy.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.mgr.Lookup(context.Background(), tok)
	if err != nil {
		t.Fatalf("a freshly-issued session did not validate: %v", err)
	}
	if got.UserID != s.UserID || got.TenantID != h.tenantA {
		t.Errorf("session resolved to the wrong principal: %+v", got)
	}
	if got.Role != tenancy.RoleOperator {
		t.Errorf("Role = %s, want operator", got.Role)
	}
}

func TestMissingAndMalformedTokensAreRefused(t *testing.T) {
	h := newAuthFixture(t)
	for _, tok := range []string{
		"", "not-a-token", strings.Repeat("A", 43), "../../etc/passwd",
		"\x00\x01\x02", strings.Repeat("x", 100000),
	} {
		if _, err := h.mgr.Lookup(context.Background(), tok); err == nil {
			t.Errorf("a malformed token was accepted: %.30q", tok)
		}
	}
}

// An ALTERED token must not authenticate. One flipped character is a
// different SHA-256 and therefore a different row, or no row.
func TestAlteredTokenIsRefused(t *testing.T) {
	h := newAuthFixture(t)
	tok, _, err := h.login(h.tenantA, h.userA, tenancy.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	altered := []byte(tok)
	if altered[0] == 'A' {
		altered[0] = 'B'
	} else {
		altered[0] = 'A'
	}
	if _, err := h.mgr.Lookup(context.Background(), string(altered)); err == nil {
		t.Fatal("a token with one character changed still authenticated")
	}
}

func TestExpiredSessionIsRefused(t *testing.T) {
	h := newAuthFixture(t)
	tok, _, err := h.login(h.tenantA, h.userA, tenancy.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	// Absolute expiry: move past it even though the session is being used.
	h.clock = h.clock.Add(AbsoluteLifetime + time.Minute)
	_, err = h.mgr.Lookup(context.Background(), tok)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired", err)
	}
}

func TestIdleSessionIsRefusedEvenBeforeAbsoluteExpiry(t *testing.T) {
	h := newAuthFixture(t)
	tok, _, err := h.login(h.tenantA, h.userA, tenancy.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(IdleLifetime + time.Minute) // still inside AbsoluteLifetime
	if _, err := h.mgr.Lookup(context.Background(), tok); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("err = %v, want ErrSessionExpired from the idle window", err)
	}
}

func TestRevokedSessionIsRefusedImmediately(t *testing.T) {
	h := newAuthFixture(t)
	tok, s, err := h.login(h.tenantA, h.userA, tenancy.RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.mgr.Revoke(tenancy.WithTenant(context.Background(), h.tenantA), s); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mgr.Lookup(context.Background(), tok); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("err = %v, want ErrSessionRevoked", err)
	}
}

// A disabled user's EXISTING sessions must stop working at once. Checking only
// at login leaves a fired employee signed in until their session happens to
// expire, which can be hours.
func TestDisablingAUserKillsTheirLiveSessions(t *testing.T) {
	h := newAuthFixture(t)
	tok, _, err := h.login(h.tenantA, h.userA, tenancy.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.mgr.Lookup(context.Background(), tok); err != nil {
		t.Fatalf("precondition: %v", err)
	}
	ctx := tenancy.WithTenant(context.Background(), h.tenantA)
	if err := h.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, e := tx.Conn().Exec(ctx,
			`UPDATE users SET disabled_at = now() WHERE id = $1::uuid`, h.userA)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mgr.Lookup(context.Background(), tok); err == nil {
		t.Fatal("a disabled user's live session still authenticates")
	}
}

// Rotation: the new token works, the OLD one is a detectable replay, and the
// absolute expiry is NOT extended by rotating.
func TestRotationInvalidatesTheOldTokenAndDoesNotExtendAbsoluteExpiry(t *testing.T) {
	h := newAuthFixture(t)
	oldTok, s, err := h.login(h.tenantA, h.userA, tenancy.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	origAbsolute := s.ExpiresAt

	h.clock = h.clock.Add(5 * time.Minute)
	newTok, next, err := h.mgr.Rotate(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if newTok == oldTok {
		t.Fatal("rotation returned the same token")
	}
	if !next.ExpiresAt.Equal(origAbsolute) {
		t.Errorf("rotation extended the absolute expiry from %s to %s; "+
			"a stolen token could then be refreshed forever", origAbsolute, next.ExpiresAt)
	}
	if _, err := h.mgr.Lookup(context.Background(), newTok); err != nil {
		t.Errorf("the rotated-to token does not work: %v", err)
	}
	if _, err := h.mgr.Lookup(context.Background(), oldTok); !errors.Is(err, ErrReplay) {
		t.Errorf("err = %v, want ErrReplay — a replayed old cookie must be identifiable", err)
	}
}

// Cross-tenant: a valid session for tenant A must never resolve to tenant B.
func TestSessionNeverResolvesToAnotherTenant(t *testing.T) {
	h := newAuthFixture(t)
	tokA, _, err := h.login(h.tenantA, h.userA, tenancy.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	tokB, _, err := h.login(h.tenantB, h.userB, tenancy.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	gotA, err := h.mgr.Lookup(context.Background(), tokA)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := h.mgr.Lookup(context.Background(), tokB)
	if err != nil {
		t.Fatal(err)
	}
	if gotA.TenantID != h.tenantA || gotB.TenantID != h.tenantB {
		t.Fatalf("sessions crossed tenants: A->%s B->%s", gotA.TenantID, gotB.TenantID)
	}
	if gotA.TenantID == gotB.TenantID {
		t.Fatal("two tenants resolved to the same id")
	}
}

// ---------------------------------------------------------------------------
// Middleware: authentication failures are indistinguishable from one another
// ---------------------------------------------------------------------------

func TestEveryAuthenticationFailureLooksIdentical(t *testing.T) {
	h := newAuthFixture(t)
	mw := &Middleware{Sessions: h.mgr, Secure: false}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw.Authenticate(next)

	// Build one of each failure class.
	revokedTok, revokedS, _ := h.login(h.tenantA, h.userA, tenancy.RoleViewer)
	_ = h.mgr.Revoke(tenancy.WithTenant(context.Background(), h.tenantA), revokedS)

	expiredTok, _, _ := h.login(h.tenantA, h.userA, tenancy.RoleViewer)
	rotatedTok, rotatedS, _ := h.login(h.tenantA, h.userA, tenancy.RoleViewer)
	_, _, _ = h.mgr.Rotate(context.Background(), rotatedS)
	h.clock = h.clock.Add(AbsoluteLifetime + time.Minute) // expires expiredTok

	var bodies []string
	var codes []int
	for _, tok := range []string{"", "garbage", revokedTok, expiredTok, rotatedTok} {
		r := httptest.NewRequest("GET", "/api/v1/me", nil)
		if tok != "" {
			r.AddCookie(&http.Cookie{Name: "certwatch_session_insecure_dev", Value: tok})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		codes = append(codes, w.Code)
		bodies = append(bodies, w.Body.String())
	}
	for i := range codes {
		if codes[i] != http.StatusUnauthorized {
			t.Errorf("case %d: status %d, want 401", i, codes[i])
		}
		if bodies[i] != bodies[0] {
			t.Errorf("case %d body differs from case 0:\n %q\n %q\n"+
				"Distinguishable failures tell an attacker whether an account exists.",
				i, bodies[i], bodies[0])
		}
	}
}

// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

func TestRoleHierarchy(t *testing.T) {
	cases := []struct {
		have, want tenancy.Role
		ok         bool
	}{
		{tenancy.RoleAdmin, tenancy.RoleAdmin, true},
		{tenancy.RoleAdmin, tenancy.RoleOperator, true},
		{tenancy.RoleAdmin, tenancy.RoleViewer, true},
		{tenancy.RoleOperator, tenancy.RoleAdmin, false},
		{tenancy.RoleOperator, tenancy.RoleOperator, true},
		{tenancy.RoleViewer, tenancy.RoleOperator, false},
		{tenancy.RoleViewer, tenancy.RoleViewer, true},
		// An unknown role must satisfy NOTHING. A typo in a role string has to
		// deny rather than grant.
		{tenancy.Role("superadmin"), tenancy.RoleViewer, false},
		{tenancy.Role(""), tenancy.RoleViewer, false},
		{tenancy.Role("ADMIN"), tenancy.RoleAdmin, false},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.want); got != c.ok {
			t.Errorf("Role(%q).AtLeast(%q) = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
}

func TestRequireDeniesInsufficientRoleWith403(t *testing.T) {
	mw := &Middleware{Secure: false}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := mw.Require(tenancy.RoleAdmin, next)

	r := httptest.NewRequest("POST", "/api/v1/users", nil)
	ctx := tenancy.WithActor(r.Context(), tenancy.Actor{Role: tenancy.RoleViewer})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r.WithContext(ctx))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a too-low role inside your own tenant", w.Code)
	}
}

// Require without Authenticate in front of it is a wiring bug. It must fail
// closed, turning the mistake into a broken endpoint rather than an open one.
func TestRequireWithoutAuthenticateFailsClosed(t *testing.T) {
	mw := &Middleware{Secure: false}
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	h := mw.Require(tenancy.RoleViewer, next)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/me", nil))
	if reached {
		t.Fatal("the handler ran with no actor in context")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// Item 102: the matrix must be total and must not silently default.
func TestAuthorizationMatrixIsCompleteAndSane(t *testing.T) {
	if len(Matrix) < 15 {
		t.Fatalf("the matrix has only %d entries; it is meant to be the complete route list", len(Matrix))
	}
	seen := map[string]bool{}
	for _, p := range Matrix {
		k := p.Method + " " + p.Path
		if seen[k] {
			t.Errorf("duplicate matrix entry for %s", k)
		}
		seen[k] = true
		if !p.MinRole.AtLeast(tenancy.RoleViewer) {
			t.Errorf("%s has role %q, which grants nothing", k, p.MinRole)
		}
		// Every mutating route must need at least operator. A viewer that can
		// POST is the classic privilege mistake.
		if p.Method != "GET" && !p.MinRole.AtLeast(tenancy.RoleOperator) {
			t.Errorf("%s is mutating but only needs %q", k, p.MinRole)
		}
	}
	// Spot-check the two that matter most.
	if r, _ := RequiredRole("POST", "/api/v1/collectors/enrollment-tokens"); r != tenancy.RoleAdmin {
		t.Errorf("minting an enrolment token needs %q, want admin — it creates a credential "+
			"that can ingest data", r)
	}
	if r, _ := RequiredRole("GET", "/api/v1/audit"); r != tenancy.RoleAdmin {
		t.Errorf("reading the audit log needs %q, want admin", r)
	}
	if _, ok := RequiredRole("GET", "/api/v1/not-registered"); ok {
		t.Error("an unregistered route returned a role")
	}
}

func TestCookieFlags(t *testing.T) {
	w := httptest.NewRecorder()
	SetCookie(w, "tok", time.Now().Add(time.Hour), true)
	c := w.Result().Cookies()[0]
	if !c.HttpOnly {
		t.Error("cookie is readable by JavaScript; XSS could exfiltrate the session")
	}
	if !c.Secure {
		t.Error("cookie is not Secure")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Errorf("name = %q, want the __Host- prefix so a compromised subdomain "+
			"cannot set our session cookie", c.Name)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q; __Host- requires no Domain attribute", c.Domain)
	}
}
