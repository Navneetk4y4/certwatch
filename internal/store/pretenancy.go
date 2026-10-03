package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/certwatch/certwatch/internal/tenancy"
)

// Pre-tenancy routing.
//
// A handful of questions have to be answered BEFORE a tenant is known,
// because their answer is what decides the tenant: which tenant does this
// session cookie belong to, which tenant owns this email domain, which tenant
// does this client certificate belong to. They are answered from one table,
// pre_tenancy_lookup — the only table in the schema without row-level
// security — and ONLY through the accessors in this file.
//
// The application role has no privilege on that table. Each accessor below
// calls a SECURITY DEFINER function that takes one key and returns one kind's
// fields, so the database itself enforces that, for example, a session lookup
// cannot return a code_verifier. Nothing here can list domains, sessions,
// certificates or tokens; the only enumeration is ActiveTenants, which returns
// opaque ids.
//
// TestOnlyPreTenancyAccessorsTouchTheLookup asserts no other Go file in the
// module names pre_tenancy_lookup or a ptl_ function.

// ErrNoRoute is returned when a key resolves to nothing. Callers must collapse
// it into whatever indistinguishable error their edge returns.
var ErrNoRoute = errors.New("store: no pre-tenancy route for that key")

// SessionRoute is what a session cookie resolves to.
type SessionRoute struct {
	Tenant    tenancy.Tenant
	SessionID string
}

// LookupSession resolves a session token hash.
func (s *Store) LookupSession(ctx context.Context, tokenHash []byte) (SessionRoute, error) {
	var r SessionRoute
	var tid, sid string
	err := s.pool.QueryRow(ctx,
		`SELECT o_tenant::text, o_session::text FROM ptl_session($1)`, tokenHash).
		Scan(&tid, &sid)
	if err != nil {
		return r, routeErr(err)
	}
	r.Tenant, r.SessionID = tenancy.Tenant(tid), sid
	if !r.Tenant.Valid() {
		return SessionRoute{}, ErrNoRoute
	}
	return r, nil
}

// DomainRoute is what an email domain resolves to. Disabled domains are not
// returned at all: "unknown" and "disabled" must be indistinguishable.
type DomainRoute struct {
	Tenant   tenancy.Tenant
	Issuer   string
	ClientID string
}

// LookupEmailDomain resolves an email domain to its tenant's identity provider.
func (s *Store) LookupEmailDomain(ctx context.Context, domain string) (DomainRoute, error) {
	var r DomainRoute
	var tid string
	err := s.pool.QueryRow(ctx,
		`SELECT o_tenant::text, o_issuer, o_client FROM ptl_email_domain($1)`, domain).
		Scan(&tid, &r.Issuer, &r.ClientID)
	if err != nil {
		return DomainRoute{}, routeErr(err)
	}
	r.Tenant = tenancy.Tenant(tid)
	if !r.Tenant.Valid() {
		return DomainRoute{}, ErrNoRoute
	}
	return r, nil
}

// CollectorRoute is what a client certificate fingerprint resolves to.
type CollectorRoute struct {
	Tenant      tenancy.Tenant
	CollectorID string
	ExpiresAt   time.Time
	Revoked     bool
}

// LookupCollectorCert resolves an mTLS client certificate fingerprint.
func (s *Store) LookupCollectorCert(ctx context.Context, fingerprint string) (CollectorRoute, error) {
	var r CollectorRoute
	var tid string
	err := s.pool.QueryRow(ctx,
		`SELECT o_tenant::text, o_collector::text, o_expires, o_revoked
		   FROM ptl_collector_cert($1)`, fingerprint).
		Scan(&tid, &r.CollectorID, &r.ExpiresAt, &r.Revoked)
	if err != nil {
		return CollectorRoute{}, routeErr(err)
	}
	r.Tenant = tenancy.Tenant(tid)
	if !r.Tenant.Valid() {
		return CollectorRoute{}, ErrNoRoute
	}
	return r, nil
}

// TokenRoute is what an enrolment token hash resolves to.
type TokenRoute struct {
	Tenant    tenancy.Tenant
	ExpiresAt time.Time
	Used      bool
}

// LookupEnrollmentToken resolves an enrolment token hash.
func (s *Store) LookupEnrollmentToken(ctx context.Context, tokenHash []byte) (TokenRoute, error) {
	var r TokenRoute
	var tid string
	err := s.pool.QueryRow(ctx,
		`SELECT o_tenant::text, o_expires, o_used FROM ptl_enrollment_token($1)`, tokenHash).
		Scan(&tid, &r.ExpiresAt, &r.Used)
	if err != nil {
		return TokenRoute{}, routeErr(err)
	}
	r.Tenant = tenancy.Tenant(tid)
	if !r.Tenant.Valid() {
		return TokenRoute{}, ErrNoRoute
	}
	return r, nil
}

// ActiveTenants lists opaque tenant ids, for a worker that serves every
// tenant. It is the only enumeration the pre-tenancy layer offers.
func (s *Store) ActiveTenants(ctx context.Context) ([]tenancy.Tenant, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text FROM ptl_active_tenants() AS id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tenancy.Tenant
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, tenancy.Tenant(id))
	}
	return out, rows.Err()
}

// OIDCFlow is an in-flight login.
//
// It records the client_id and the email domain it was started for, not just
// the issuer. Completion used to look the client up again by issuer with
// LIMIT 1, and two tenants sharing an identity provider share an issuer — so
// a token audienced to tenant B's client could be accepted into tenant A.
type OIDCFlow struct {
	State        string
	Nonce        string
	CodeVerifier string
	RedirectURI  string
	Issuer       string
	ClientID     string
	EmailDomain  string
	ExpiresAt    time.Time
}

// CreateOIDCFlow records a login in flight.
func (s *Store) CreateOIDCFlow(ctx context.Context, f OIDCFlow) error {
	_, err := s.pool.Exec(ctx,
		`SELECT ptl_create_oidc_flow($1,$2,$3,$4,$5,$6,$7,$8)`,
		f.State, f.Nonce, f.CodeVerifier, f.RedirectURI, f.Issuer, f.ClientID,
		f.EmailDomain, f.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("store: recording login state: %w", err)
	}
	return nil
}

// ConsumeOIDCFlow returns a flow and marks it spent, atomically. A second call
// for the same state returns ErrNoRoute whether or not the first has
// committed, so a replayed callback cannot complete.
func (s *Store) ConsumeOIDCFlow(ctx context.Context, state string) (OIDCFlow, error) {
	f := OIDCFlow{State: state}
	err := s.pool.QueryRow(ctx, `
		SELECT o_nonce, o_verifier, o_redirect, o_issuer, o_client, o_domain, o_expires
		  FROM ptl_consume_oidc_flow($1)`, state).
		Scan(&f.Nonce, &f.CodeVerifier, &f.RedirectURI, &f.Issuer, &f.ClientID,
			&f.EmailDomain, &f.ExpiresAt)
	if err != nil {
		return OIDCFlow{}, routeErr(err)
	}
	return f, nil
}

func routeErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRoute
	}
	return err
}
