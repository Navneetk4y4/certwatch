package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certwatch/certwatch/internal/tenancy"
)

// Behaviour of the unified pre-tenancy accessors, against real PostgreSQL as
// the real application role — which has no direct privilege on the table, so
// every call below genuinely goes through a ptl_* function.

func registerProvider(t *testing.T, s *Store, tn string, issuer, client, domain string) error {
	t.Helper()
	ctx := ctxFor(tenantOf(tn))
	return s.InTenantTx(ctx, func(ctx context.Context, tx *Tx) error {
		_, err := tx.Conn().Exec(ctx, `
			INSERT INTO identity_providers (tenant_id, issuer, client_id, email_domain)
			VALUES ($1::uuid,$2,$3,$4)`, tn, issuer, client, domain)
		return err
	})
}

func TestEmailDomainRouteResolvesAndIsCaseInsensitive(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	if err := registerProvider(t, s, a.String(), "https://idp", "client-a", "Example.Test"); err != nil {
		t.Fatal(err)
	}
	r, err := s.LookupEmailDomain(context.Background(), "EXAMPLE.test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Tenant != a || r.ClientID != "client-a" || r.Issuer != "https://idp" {
		t.Errorf("route = %+v", r)
	}
}

func TestMissingRouteIsErrNoRoute(t *testing.T) {
	s, _ := newTestDB(t)
	ctx := context.Background()
	if _, err := s.LookupEmailDomain(ctx, "nobody.test"); !errors.Is(err, ErrNoRoute) {
		t.Errorf("domain: err = %v", err)
	}
	h := sha256.Sum256([]byte("nope"))
	if _, err := s.LookupSession(ctx, h[:]); !errors.Is(err, ErrNoRoute) {
		t.Errorf("session: err = %v", err)
	}
	if _, err := s.LookupEnrollmentToken(ctx, h[:]); !errors.Is(err, ErrNoRoute) {
		t.Errorf("token: err = %v", err)
	}
	if _, err := s.LookupCollectorCert(ctx, strings.Repeat("0", 64)); !errors.Is(err, ErrNoRoute) {
		t.Errorf("cert: err = %v", err)
	}
	if _, err := s.ConsumeOIDCFlow(ctx, strings.Repeat("s", 40)); !errors.Is(err, ErrNoRoute) {
		t.Errorf("flow: err = %v", err)
	}
}

// A disabled provider is indistinguishable from an unknown domain.
func TestDisabledDomainLooksExactlyLikeAnUnknownOne(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	if err := registerProvider(t, s, a.String(), "https://idp", "c", "off.test"); err != nil {
		t.Fatal(err)
	}
	if err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		_, e := tx.Conn().Exec(ctx, `UPDATE identity_providers SET enabled = false`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	_, errOff := s.LookupEmailDomain(context.Background(), "off.test")
	_, errNone := s.LookupEmailDomain(context.Background(), "never.test")
	if !errors.Is(errOff, ErrNoRoute) || !errors.Is(errNone, ErrNoRoute) {
		t.Fatalf("disabled=%v unknown=%v; both must be ErrNoRoute", errOff, errNone)
	}
}

// CROSS-TENANT ROUTING ATTEMPT 1: claim a domain another tenant owns.
func TestADomainCannotBeClaimedFromAnotherTenant(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	b := makeTenant(t, mig, "b")
	if err := registerProvider(t, s, a.String(), "https://idp-a", "client-a", "owned.test"); err != nil {
		t.Fatal(err)
	}
	if err := registerProvider(t, s, b.String(), "https://idp-b", "client-b", "owned.test"); err == nil {
		t.Fatal("tenant B claimed a domain routed to tenant A")
	}
	r, err := s.LookupEmailDomain(context.Background(), "owned.test")
	if err != nil || r.Tenant != a {
		t.Fatalf("after the attempt the route is %+v (err %v); it must still be A", r, err)
	}
}

// ...including while the owner's provider is merely DISABLED. Disabling is not
// releasing. Only deleting the provider frees the domain.
func TestADisabledDomainIsStillOwned(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	b := makeTenant(t, mig, "b")
	if err := registerProvider(t, s, a.String(), "https://idp-a", "client-a", "owned.test"); err != nil {
		t.Fatal(err)
	}
	if err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		_, e := tx.Conn().Exec(ctx, `UPDATE identity_providers SET enabled = false`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := registerProvider(t, s, b.String(), "https://idp-b", "client-b", "owned.test"); err == nil {
		t.Fatal("tenant B took over a domain whose owner had only DISABLED its provider")
	}
	// Deleting releases it.
	if err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		_, e := tx.Conn().Exec(ctx, `DELETE FROM identity_providers`)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := registerProvider(t, s, b.String(), "https://idp-b", "client-b", "owned.test"); err != nil {
		t.Fatalf("a deleted domain could not be claimed: %v", err)
	}
}

// CROSS-TENANT ROUTING ATTEMPT 2: register ANOTHER tenant's OAuth client for
// your own domain. Client IDs are public, so this must be refused.
func TestAClientRegistrationBelongsToOneTenant(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	b := makeTenant(t, mig, "b")
	if err := registerProvider(t, s, a.String(), "https://idp", "client-a", "a.test"); err != nil {
		t.Fatal(err)
	}
	if err := registerProvider(t, s, b.String(), "https://idp", "client-a", "b.test"); err == nil {
		t.Fatal("tenant B registered tenant A's OAuth client for its own domain")
	}
	// The same tenant may use one client for several domains.
	if err := registerProvider(t, s, a.String(), "https://idp", "client-a", "a2.test"); err != nil {
		t.Errorf("one tenant could not reuse its own client for a second domain: %v", err)
	}
}

// Two tenants racing to register the same client: exactly one wins.
func TestConcurrentClientRegistrationHasOneWinner(t *testing.T) {
	s, mig := newTestDB(t)
	tenants := make([]string, 6)
	for i := range tenants {
		tenants[i] = makeTenant(t, mig, "race").String()
	}
	var wg sync.WaitGroup
	ok := make([]bool, len(tenants))
	for i, tn := range tenants {
		wg.Add(1)
		go func(i int, tn string) {
			defer wg.Done()
			ok[i] = registerProvider(t, s, tn, "https://idp", "contested",
				"d"+tn[:8]+".test") == nil
		}(i, tn)
	}
	wg.Wait()
	won := 0
	for _, v := range ok {
		if v {
			won++
		}
	}
	if won != 1 {
		t.Errorf("%d tenants registered the same client concurrently; want exactly 1", won)
	}
}

// An OIDC flow is single-use, under real concurrency.
func TestOIDCFlowIsConsumedExactlyOnceUnderConcurrency(t *testing.T) {
	s, _ := newTestDB(t)
	ctx := context.Background()
	state := strings.Repeat("q", 43)
	if err := s.CreateOIDCFlow(ctx, OIDCFlow{
		State: state, Nonce: "n", CodeVerifier: "v", RedirectURI: "https://r",
		Issuer: "https://idp", ClientID: "c", EmailDomain: "x.test",
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, err := s.ConsumeOIDCFlow(ctx, state); err == nil && f.ClientID == "c" {
				mu.Lock()
				got++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if got != 1 {
		t.Errorf("%d of 10 concurrent consumers received the flow; want exactly 1", got)
	}
}

// A duplicate flow state is refused rather than silently overwriting the
// first login's verifier.
func TestDuplicateOIDCStateIsRefused(t *testing.T) {
	s, _ := newTestDB(t)
	ctx := context.Background()
	f := OIDCFlow{State: strings.Repeat("d", 43), Nonce: "n", CodeVerifier: "v",
		RedirectURI: "https://r", Issuer: "i", ClientID: "c", EmailDomain: "x.test",
		ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.CreateOIDCFlow(ctx, f); err != nil {
		t.Fatal(err)
	}
	f.CodeVerifier = "attacker-chosen"
	if err := s.CreateOIDCFlow(ctx, f); err == nil {
		t.Fatal("a second flow with the same state was accepted")
	}
}

// Routes are written by triggers on RLS-protected tables, so a tenant can
// only ever route to itself. Creating an organization registers it.
func TestActiveTenantsFollowsOrganizations(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "a")
	b := makeTenant(t, mig, "b")
	ids, err := s.ActiveTenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id.String()] = true
	}
	if !seen[a.String()] || !seen[b.String()] {
		t.Errorf("ActiveTenants = %v, missing a or b", ids)
	}
}

// Only internal/store/pretenancy.go may issue SQL against the routing table or
// its functions. Anywhere else would be a second, unreviewed path around the
// accessors.
//
// It inspects Go STRING LITERALS via go/ast rather than grepping source text.
// A comment explaining the design may name the table; a SQL string may not. A
// substring match flagged a comment in oidc.go, and the fix was to make the
// check precise rather than to reword the comment.
func TestOnlyPreTenancyAccessorsTouchTheLookup(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") ||
			strings.HasSuffix(path, filepath.Join("internal", "store", "pretenancy.go")) {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v := lit.Value
			if strings.Contains(v, "pre_tenancy_lookup") || strings.Contains(v, "ptl_") {
				// migrate.go legitimately names the table in a constant.
				if !(strings.HasSuffix(path, filepath.Join("internal", "store", "migrate.go")) &&
					v == `"pre_tenancy_lookup"`) {
					offenders = append(offenders, path+": "+v)
				}
			}
			return true
		})
		return nil
	})
	if len(offenders) != 0 {
		t.Errorf("SQL reaches pre-tenancy routing outside pretenancy.go:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// The guard above must be shown to fire. Feed it a synthetic file that issues
// SQL against the table and require it to be caught.
func TestTheAccessorGuardActuallyFires(t *testing.T) {
	src := `package x
var q = "SELECT * FROM pre_tenancy_lookup"`
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	caught := false
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING &&
			strings.Contains(lit.Value, "pre_tenancy_lookup") {
			caught = true
		}
		return true
	})
	if !caught {
		t.Fatal("the string-literal inspection did not see SQL naming the table")
	}
}

func tenantOf(s string) tenancy.Tenant { return tenancy.Tenant(s) }
