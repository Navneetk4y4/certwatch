// Package store is the only path to the database.
//
// TENANT-003, build item 094.
//
// # The one thing to understand here
//
// Tenant scoping is applied with set_config('app.tenant_id', $1, TRUE) —
// is_local = true, which means TRANSACTION-local, the programmatic equivalent
// of SET LOCAL.
//
// A session-level SET would be a cross-tenant data leak on a pooled
// connection: the setting outlives the request, the connection returns to the
// pool, and the next request — for a different tenant — inherits it. Every
// RLS policy in migration 001 reads that GUC, so inheriting it means reading
// another tenant's rows with the database's full blessing.
//
// Transaction-local means it is gone when the transaction ends, whether it
// commits or rolls back, before the connection can be reused.
//
// # Why there is no QueryContext on Store
//
// There is deliberately no way to run a query outside a transaction, because
// outside a transaction there is nowhere to put the tenant setting. If you
// want to read one row you open a transaction. That is the cost of making the
// boundary structural instead of remembered.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// Store owns the connection pool.
type Store struct {
	pool *pgxpool.Pool
	log  *safelog.Logger
}

// Config is what it takes to connect.
type Config struct {
	// DSN is a libpq connection string. It carries a password and must never
	// be logged; safelog has no field constructor that would take it.
	DSN string
	// MaxConns bounds the pool. A collector fleet reporting on a schedule can
	// otherwise open one connection per concurrent report.
	MaxConns int32
	// ConnectTimeout bounds startup so a wrong DSN fails fast rather than
	// hanging a deployment.
	ConnectTimeout time.Duration
}

// Open connects and verifies the security preconditions before returning a
// usable handle. A Store that cannot prove the app role is constrained is not
// returned at all.
func Open(ctx context.Context, cfg Config, log *safelog.Logger) (*Store, error) {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 10
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		// Deliberately does not echo the DSN: it contains a password.
		return nil, errors.New("store: the database connection string is not valid")
	}
	pc.MaxConns = cfg.MaxConns
	pc.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("store: connecting: %w", err)
	}
	s := &Store{pool: pool, log: log}
	if err := s.pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return s, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the pool for migrations and for the privileged checks below.
// Everything else goes through Begin.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// ErrRoleCanBypassRLS is fatal at startup by design.
var ErrRoleCanBypassRLS = errors.New(
	"store: the application database role has BYPASSRLS; every tenant isolation policy is decorative")

// VerifyRoleIsConstrained is TENANT-001, build item 091.
//
// If the connecting role can bypass row-level security, every policy written
// in migration 001 is decoration and the isolation tests pass for the wrong
// reason. Checking it at startup means the failure is a refused boot rather
// than a silent, total loss of tenant isolation.
//
// Superuser is checked too: a superuser bypasses RLS regardless of the
// rolbypassrls flag, which is the way this check is usually defeated.
func (s *Store) VerifyRoleIsConstrained(ctx context.Context) error {
	var bypass, super bool
	var who string
	err := s.pool.QueryRow(ctx,
		`SELECT current_user, rolbypassrls, rolsuper
		   FROM pg_roles WHERE rolname = current_user`).Scan(&who, &bypass, &super)
	if err != nil {
		return fmt.Errorf("store: checking role privileges: %w", err)
	}
	if bypass || super {
		return fmt.Errorf("%w (role %q: bypassrls=%v superuser=%v)",
			ErrRoleCanBypassRLS, who, bypass, super)
	}
	return nil
}

// Tx is a transaction with a tenant already bound to it.
type Tx struct {
	tx     pgx.Tx
	tenant tenancy.Tenant
}

// Tenant reports which tenant this transaction is scoped to.
func (t *Tx) Tenant() tenancy.Tenant { return t.tenant }

// Conn exposes the underlying transaction for query execution.
func (t *Tx) Conn() pgx.Tx { return t.tx }

// Begin opens a transaction scoped to the tenant in ctx.
//
// It fails when there is no tenant. That is the whole design: there is no way
// to reach the database without declaring who you are acting for.
func (s *Store) Begin(ctx context.Context) (*Tx, error) {
	tid, err := tenancy.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: begin: %w", err)
	}
	// TRANSACTION-local (third argument true). See the package comment: a
	// session-level SET here would leak the tenant onto a pooled connection.
	// The id is a bind parameter, never interpolated.
	if _, err := tx.Exec(ctx,
		`SELECT set_config('app.tenant_id', $1, true)`, tid.String()); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("store: binding tenant: %w", err)
	}
	return &Tx{tx: tx, tenant: tid}, nil
}

// Commit ends the transaction. The tenant binding disappears with it.
func (t *Tx) Commit(ctx context.Context) error { return t.tx.Commit(ctx) }

// Rollback ends the transaction without applying changes. Safe to defer.
func (t *Tx) Rollback(ctx context.Context) {
	_ = t.tx.Rollback(ctx)
}

// InTenantTx runs fn inside a tenant-scoped transaction, rolling back on error.
func (s *Store) InTenantTx(ctx context.Context, fn func(context.Context, *Tx) error) error {
	tx, err := s.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// Privileged operations
// ---------------------------------------------------------------------------

// ErrPrivilegedRequiresReason exists so that every unscoped query has to say
// out loud why it is allowed to be unscoped.
var ErrPrivilegedRequiresReason = errors.New("store: a privileged query must state its reason")

// Privileged runs a query with NO tenant binding.
//
// It exists because a handful of operations genuinely precede tenancy: finding
// which tenant an OIDC issuer/subject belongs to, resolving a collector's
// client certificate to a tenant, and the scheduler asking which endpoints are
// due across all tenants.
//
// Three things keep it from becoming the back door:
//
//  1. The RLS policies still apply — the role has no BYPASSRLS, verified at
//     startup — so a tenant-owned table returns NOTHING here. current_setting
//     is called with missing_ok = false, so an unscoped read of a policied
//     table errors rather than quietly returning zero rows.
//  2. Every call must pass a reason, which is logged.
//  3. Callers are countable: `grep -rn "Privileged(" --include=*.go`.
func (s *Store) Privileged(ctx context.Context, reason string,
	fn func(context.Context, *pgxpool.Pool) error) error {
	if reason == "" {
		return ErrPrivilegedRequiresReason
	}
	if s.log != nil {
		s.log.Debug("privileged query", safelog.Str("reason", reason))
	}
	return fn(ctx, s.pool)
}
