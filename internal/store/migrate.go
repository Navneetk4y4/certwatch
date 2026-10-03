package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migration is one forward-only step.
type Migration struct {
	Version int
	Name    string
	SQL     string
	// Checksum detects a migration edited after it was applied — the class of
	// mistake where two environments disagree about what "001" means.
	Checksum string
}

// LoadMigrations reads the embedded migrations in version order.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		num, rest, ok := strings.Cut(e.Name(), "_")
		if !ok {
			return nil, fmt.Errorf("store: migration %q is not NNN_name.sql", e.Name())
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("store: migration %q has a non-numeric version", e.Name())
		}
		body, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		out = append(out, Migration{
			Version:  v,
			Name:     strings.TrimSuffix(rest, ".sql"),
			SQL:      string(body),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("store: migrations must be numbered without gaps; "+
				"expected %03d, found %03d", i+1, m.Version)
		}
	}
	return out, nil
}

const migrationTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    int PRIMARY KEY,
    name       text NOT NULL,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// Migrate applies every unapplied migration, in order, each in its own
// transaction.
//
// Run as the OWNER role, not the application role: the application role has
// no DDL rights, which is deliberate — an application that can DROP TABLE has
// an availability problem one SQL injection away.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (applied []int, err error) {
	ms, err := LoadMigrations()
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, migrationTable); err != nil {
		return nil, fmt.Errorf("store: creating schema_migrations: %w", err)
	}

	rows, err := pool.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	have := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			rows.Close()
			return nil, err
		}
		have[v] = sum
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, m := range ms {
		if sum, ok := have[m.Version]; ok {
			if sum != m.Checksum {
				// Forward-only means applied migrations are immutable. If this
				// fires, two environments have different ideas of what the
				// schema is, and guessing which is right is how data is lost.
				return applied, fmt.Errorf(
					"store: migration %03d_%s was edited after it was applied "+
						"(recorded %s, on disk %s). Migrations are forward-only: "+
						"add %03d instead of changing this one",
					m.Version, m.Name, sum[:12], m.Checksum[:12], len(ms)+1)
			}
			continue
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("store: migration %03d_%s: %w", m.Version, m.Name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1,$2,$3)`,
			m.Version, m.Name, m.Checksum); err != nil {
			_ = tx.Rollback(ctx)
			return applied, err
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, err
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}

// PreTenancyTable is the ONE table allowed to exist without row-level
// security.
//
// It answers the questions that precede tenancy — which tenant a session
// cookie, an email domain, a client certificate or an enrolment token belongs
// to; which login a provider callback is for; which tenants a worker should
// serve. Those cannot be scoped to a tenant, because the tenant is what is
// being determined.
//
// Migration 009 consolidated six narrow tables into this one, and in doing so
// took away the application role's direct access entirely: every read and
// write goes through a ptl_* SECURITY DEFINER function that takes one key and
// returns one kind's fields. See internal/store/pretenancy.go.
//
// The architectural invariant, asserted by TestExactlyOnePreTenancyTable: the
// set of public tables without FORCED row-level security is exactly
// {schema_migrations, pre_tenancy_lookup}. A seventh routing table — or any
// table someone forgets to policy — fails the build.
const PreTenancyTable = "pre_tenancy_lookup"

// PreTenancyTables is kept as a slice so the sweep below can exclude it.
var PreTenancyTables = []string{PreTenancyTable}

// UnpoliciedTenantTables is TENANT-004, build item 097 — the sweep.
//
// It asks Postgres itself which tables carry a tenant_id but are not protected
// by an enabled, FORCED row-level security policy. A per-table test can only
// check the tables somebody remembered to write a test for; this catches the
// table added next year by someone who never read this file.
//
// rowsecurity alone is not enough: without relforcerowsecurity the table OWNER
// bypasses the policy, and the owner is the migration role.
func UnpoliciedTenantTables(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	const q = `
SELECT c.relname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public'
   AND c.relkind = 'r'
   AND EXISTS (
        SELECT 1 FROM pg_attribute a
         WHERE a.attrelid = c.oid AND a.attname IN ('tenant_id','id')
           AND a.attnum > 0 AND NOT a.attisdropped
           AND (a.attname = 'tenant_id' OR c.relname = 'organizations'))
   AND c.relname <> 'schema_migrations'
   AND c.relname <> ALL($1::text[])
   AND (
        NOT c.relrowsecurity
     OR NOT c.relforcerowsecurity
     OR NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
   )
 ORDER BY c.relname`
	rows, err := pool.Query(ctx, q, PreTenancyTables)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
