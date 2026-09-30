package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"

	"github.com/certwatch/certwatch/internal/tenancy"
)

// TENANT-004, build item 097: the cross-tenant isolation suite.
//
// These tests are adversarial on purpose. Each one is tenant A deliberately
// trying to reach tenant B's rows by a different route, and each one expects
// to fail. A suite that only proves "A can read A" proves nothing — it passes
// identically on a database with no policies at all.
//
// Every test here runs against real PostgreSQL as the real application role.

// seed inserts one endpoint and one certificate for a tenant, returning ids.
func seed(t *testing.T, s *Store, tn tenancy.Tenant, host string) (endpointID, credID string) {
	t.Helper()
	ctx := ctxFor(tn)
	err := s.InTenantTx(ctx, func(ctx context.Context, tx *Tx) error {
		if err := tx.Conn().QueryRow(ctx,
			`INSERT INTO endpoints (tenant_id, hostname, port, sni)
			 VALUES ($1::uuid, $2, 443, '') RETURNING id::text`,
			tn.String(), host).Scan(&endpointID); err != nil {
			return err
		}
		fp := strings.Repeat("a", 63) + string(host[0])
		return tx.Conn().QueryRow(ctx,
			`INSERT INTO credentials (tenant_id, kind, fingerprint)
			 VALUES ($1::uuid,'x509',$2) RETURNING id::text`,
			tn.String(), fp).Scan(&credID)
	})
	if err != nil {
		t.Fatalf("seed %s: %v", host, err)
	}
	return endpointID, credID
}

func TestTenantCanReadItsOwnRows(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	epA, _ := seed(t, s, a, "a.example.com")

	var got string
	err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		return tx.Conn().QueryRow(ctx,
			`SELECT hostname FROM endpoints WHERE id = $1::uuid`, epA).Scan(&got)
	})
	if err != nil {
		t.Fatalf("A could not read its own endpoint: %v", err)
	}
	if got != "a.example.com" {
		t.Errorf("hostname = %q", got)
	}
}

// The core assertion. A holds B's real primary key — the IDOR case — and must
// still get nothing.
func TestCrossTenantReadByDirectIDReturnsNothing(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	b := makeTenant(t, mig, "tenant-b")
	seed(t, s, a, "a.example.com")
	epB, credB := seed(t, s, b, "b.example.com")

	for _, tc := range []struct{ name, query, arg string }{
		{"endpoint", `SELECT hostname FROM endpoints WHERE id = $1::uuid`, epB},
		{"credential", `SELECT fingerprint FROM credentials WHERE id = $1::uuid`, credB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v string
			err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
				return tx.Conn().QueryRow(ctx, tc.query, tc.arg).Scan(&v)
			})
			if err == nil {
				t.Fatalf("IDOR: tenant A read tenant B's %s by id and got %q", tc.name, v)
			}
			if !strings.Contains(err.Error(), "no rows") {
				t.Fatalf("unexpected error (want no-rows): %v", err)
			}
		})
	}
}

// Every tenant-owned table, swept generically. A per-table test only covers
// the tables somebody remembered; this covers the table added next year.
func TestNoTenantOwnedTableLeaksAcrossTenants(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	b := makeTenant(t, mig, "tenant-b")
	seed(t, s, a, "a.example.com")
	seed(t, s, b, "b.example.com")

	rows, err := mig.Query(context.Background(), `
		SELECT c.relname FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_attribute att ON att.attrelid = c.oid
		 WHERE n.nspname='public' AND c.relkind='r'
		   AND att.attname='tenant_id' AND att.attnum>0 AND NOT att.attisdropped
		 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	if len(tables) < 10 {
		t.Fatalf("only %d tenant-owned tables found; the sweep is not covering the schema", len(tables))
	}

	for _, tbl := range tables {
		t.Run(tbl, func(t *testing.T) {
			var n int
			err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
				return tx.Conn().QueryRow(ctx,
					"SELECT count(*) FROM "+tbl+" WHERE tenant_id = $1::uuid", b.String()).Scan(&n)
			})
			if err != nil {
				t.Fatalf("query %s: %v", tbl, err)
			}
			if n != 0 {
				t.Errorf("tenant A saw %d of tenant B's rows in %s", n, tbl)
			}
		})
	}
}

// A WRITE stamped with another tenant's id must be refused by WITH CHECK, not
// silently accepted. Without WITH CHECK, A can plant rows in B's account.
func TestCrossTenantWriteIsRefused(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	b := makeTenant(t, mig, "tenant-b")

	err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		_, e := tx.Conn().Exec(ctx,
			`INSERT INTO endpoints (tenant_id, hostname, port, sni)
			 VALUES ($1::uuid, 'planted.example.com', 443, '')`, b.String())
		return e
	})
	if err == nil {
		t.Fatal("tenant A inserted a row into tenant B's account")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "row-level security") &&
		!strings.Contains(strings.ToLower(err.Error()), "violates") {
		t.Errorf("refused, but not by RLS — check the reason: %v", err)
	}
}

// UPDATE must not be able to move a row from A to B, which would be a
// cross-tenant write dressed as an edit.
func TestTenantCannotReassignARowToAnotherTenant(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	b := makeTenant(t, mig, "tenant-b")
	epA, _ := seed(t, s, a, "a.example.com")

	err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		_, e := tx.Conn().Exec(ctx,
			`UPDATE endpoints SET tenant_id = $1::uuid WHERE id = $2::uuid`, b.String(), epA)
		return e
	})
	if err == nil {
		t.Fatal("tenant A moved one of its rows into tenant B")
	}
}

// DELETE must not reach across.
func TestCrossTenantDeleteAffectsNothing(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	b := makeTenant(t, mig, "tenant-b")
	epB, _ := seed(t, s, b, "b.example.com")

	err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		tag, e := tx.Conn().Exec(ctx, `DELETE FROM endpoints WHERE id = $1::uuid`, epB)
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 0 {
			t.Errorf("tenant A deleted %d of tenant B's rows", tag.RowsAffected())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// And B's row is still there.
	var n int
	if err := s.InTenantTx(ctxFor(b), func(ctx context.Context, tx *Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT count(*) FROM endpoints`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("tenant B has %d endpoints, want 1", n)
	}
}

// No tenant in the context means no database handle. This is the structural
// half of the guarantee: forgetting to scope is a broken request, never a
// cross-tenant read.
func TestBeginWithoutATenantIsRefused(t *testing.T) {
	s, _ := newTestDB(t)
	if _, err := s.Begin(context.Background()); err == nil {
		t.Fatal("Begin succeeded with no tenant in context")
	}
	bad := tenancy.WithTenant(context.Background(), tenancy.Tenant("not-a-uuid"))
	if _, err := s.Begin(bad); err == nil {
		t.Fatal("Begin accepted a malformed tenant id")
	}
}

// The tenant binding must be TRANSACTION-local. If it were session-level it
// would survive on the pooled connection and the next tenant to borrow that
// connection would inherit it — a cross-tenant read with the database's full
// blessing.
func TestTenantBindingDoesNotSurviveTheTransaction(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	seed(t, s, a, "a.example.com")

	// Force a single connection, so the next query provably reuses it.
	s.pool.Config().MaxConns = 1

	if err := s.InTenantTx(ctxFor(a), func(ctx context.Context, tx *Tx) error {
		var n int
		return tx.Conn().QueryRow(ctx, `SELECT count(*) FROM endpoints`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}

	// Now read the GUC outside any transaction on that same pool. If the
	// setting leaked, app.tenant_id is still set.
	err := s.Privileged(context.Background(), "test: prove the tenant GUC did not leak",
		func(ctx context.Context, p *pgxpool.Pool) error {
			var v string
			e := p.QueryRow(ctx, `SELECT current_setting('app.tenant_id', true)`).Scan(&v)
			if e != nil {
				return e
			}
			if v != "" {
				t.Errorf("app.tenant_id survived the transaction as %q — "+
					"a session-level SET would leak this onto the next tenant", v)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}

// An unscoped read of a policied table must ERROR rather than quietly return
// zero rows. current_setting(..., false) is what makes the mistake loud.
func TestUnscopedReadOfAPoliciedTableErrors(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	seed(t, s, a, "a.example.com")

	err := s.Privileged(context.Background(), "test: unscoped read must fail loudly",
		func(ctx context.Context, p *pgxpool.Pool) error {
			var n int
			return p.QueryRow(ctx, `SELECT count(*) FROM endpoints`).Scan(&n)
		})
	if err == nil {
		t.Fatal("an unscoped read of endpoints succeeded; it must error, " +
			"because silently returning zero rows hides the bug")
	}
}

// The sweep: every tenant-owned table must have RLS enabled AND forced AND a
// policy. This is what catches a table added later by someone who never read
// migration 001.
func TestEveryTenantTableIsPoliciedAndForced(t *testing.T) {
	_, mig := newTestDB(t)
	bad, err := UnpoliciedTenantTables(context.Background(), mig)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Errorf("these tenant-owned tables are not protected by a forced RLS policy: %v\n"+
			"Add SELECT tenant_rls('<table>') to the migration that creates them.", bad)
	}
}

// Vacuity guard. The sweep above is only worth trusting if it has been shown
// to reject something: create a deliberately-unpoliced table and require that
// it is found.
func TestTheSweepActuallyDetectsAnUnpoliciedTable(t *testing.T) {
	_, mig := newTestDB(t)
	ctx := context.Background()
	if _, err := mig.Exec(ctx, `CREATE TABLE leaky (
		id uuid PRIMARY KEY DEFAULT uuid_v7(),
		tenant_id uuid NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	bad, err := UnpoliciedTenantTables(ctx, mig)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, b := range bad {
		if b == "leaky" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the sweep did not flag a table with no policy at all; it proves nothing. got %v", bad)
	}

	// And a table with ENABLE but not FORCE must also be flagged — that is the
	// line people actually miss, and the owner bypasses the policy without it.
	if _, err := mig.Exec(ctx, `
		ALTER TABLE leaky ENABLE ROW LEVEL SECURITY;
		CREATE POLICY p ON leaky USING (tenant_id = current_setting('app.tenant_id', false)::uuid);`); err != nil {
		t.Fatal(err)
	}
	bad, _ = UnpoliciedTenantTables(ctx, mig)
	found = false
	for _, b := range bad {
		if b == "leaky" {
			found = true
		}
	}
	if !found {
		t.Error("a table with ENABLE but not FORCE was treated as protected; " +
			"without FORCE the table owner bypasses the policy entirely")
	}
}

// FORCE ROW LEVEL SECURITY, tested directly.
//
// The app-role tests above cannot detect a missing FORCE, because the app role
// does not own the tables — ENABLE alone already constrains it. FORCE exists
// for the OWNER, which is the migration role, which is exactly the connection
// someone uses during an incident. Without FORCE that connection silently sees
// and writes every tenant's rows.
//
// Mutation-checked: removing FORCE from tenant_rls() makes this test fail.
func TestTableOwnerIsAlsoSubjectToThePolicy(t *testing.T) {
	s, mig := newTestDB(t)
	a := makeTenant(t, mig, "tenant-a")
	b := makeTenant(t, mig, "tenant-b")
	seed(t, s, a, "a.example.com")
	seed(t, s, b, "b.example.com")

	ctx := context.Background()
	// The migrator OWNS endpoints. Bind it to tenant A and confirm it cannot
	// see B — that is only true when the policy is FORCEd.
	tx, err := mig.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // test cleanup
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.tenant_id', $1, true)`, a.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM endpoints`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("the table OWNER, bound to tenant A, saw %d endpoints; want 1.\n"+
			"Seeing 2 means FORCE ROW LEVEL SECURITY is missing and the owner "+
			"bypasses every tenant policy.", n)
	}
}

// The pre-tenancy exemption is bounded by this test. If somebody adds a third
// un-policied table, this fails and they have to justify it in a diff rather
// than add it quietly.
func TestPreTenancyExemptionListStaysSmall(t *testing.T) {
	want := []string{"session_index", "oidc_flows", "provider_domain_index"}
	if len(PreTenancyTables) != len(want) {
		t.Fatalf("PreTenancyTables has %d entries, want exactly %d (%v).\n"+
			"Every entry is a table with a tenant_id and NO row-level security. "+
			"Adding one needs an argument, not a commit.",
			len(PreTenancyTables), len(want), want)
	}
	for i := range want {
		if PreTenancyTables[i] != want[i] {
			t.Errorf("PreTenancyTables[%d] = %q, want %q", i, PreTenancyTables[i], want[i])
		}
	}
}

// And the exemption must not become a hole: an exempt table may hold ONLY the
// mapping it exists for. If session_index ever grows a column carrying real
// tenant data, it stops being a lookup index and becomes an un-policied copy
// of customer records.
func TestExemptTablesHoldOnlyTheirMapping(t *testing.T) {
	_, mig := newTestDB(t)
	allowed := map[string]map[string]bool{
		"session_index": {"token_hash": true, "session_id": true, "tenant_id": true},
		"oidc_flows": {"state": true, "nonce": true, "code_verifier": true,
			"redirect_uri": true, "issuer": true, "created_at": true,
			"expires_at": true, "consumed_at": true},
		// Routing only. If a secret column ever appears here, this fails.
		"provider_domain_index": {"email_domain": true, "tenant_id": true,
			"issuer": true, "client_id": true, "enabled": true},
	}
	for tbl, cols := range allowed {
		rows, err := mig.Query(context.Background(), `
			SELECT a.attname FROM pg_attribute a
			  JOIN pg_class c ON c.oid = a.attrelid
			 WHERE c.relname = $1 AND a.attnum > 0 AND NOT a.attisdropped`, tbl)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var col string
			if err := rows.Scan(&col); err != nil {
				t.Fatal(err)
			}
			if !cols[col] {
				t.Errorf("%s.%s is not in the permitted column set. An un-policied "+
					"table may hold only the mapping it exists for.", tbl, col)
			}
		}
		rows.Close()
	}
}
