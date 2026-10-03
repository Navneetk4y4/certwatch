package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/certwatch/certwatch/internal/store/db"

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
	row, err := db.New(s.pool).PtlSession(ctx, tokenHash)
	if err != nil {
		return r, routeErr(err)
	}
	tid, sid = row.Tenant, row.SessionID
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
	row, err := db.New(s.pool).PtlEmailDomain(ctx, domain)
	if err != nil {
		return DomainRoute{}, routeErr(err)
	}
	tid, r.Issuer, r.ClientID = row.Tenant, row.Issuer, row.ClientID
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
	row, err := db.New(s.pool).PtlCollectorCert(ctx, fingerprint)
	if err != nil {
		return CollectorRoute{}, routeErr(err)
	}
	tid, r.CollectorID, r.Revoked = row.Tenant, row.CollectorID, row.Revoked
	r.ExpiresAt = row.ExpiresAt.Time
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
	row, err := db.New(s.pool).PtlEnrollmentToken(ctx, tokenHash)
	if err != nil {
		return TokenRoute{}, routeErr(err)
	}
	tid, r.Used = row.Tenant, row.Used
	r.ExpiresAt = row.ExpiresAt.Time
	r.Tenant = tenancy.Tenant(tid)
	if !r.Tenant.Valid() {
		return TokenRoute{}, ErrNoRoute
	}
	return r, nil
}

// ActiveTenants lists opaque tenant ids, for a worker that serves every
// tenant. It is the only enumeration the pre-tenancy layer offers.
func (s *Store) ActiveTenants(ctx context.Context) ([]tenancy.Tenant, error) {
	ids, err := db.New(s.pool).PtlActiveTenants(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]tenancy.Tenant, 0, len(ids))
	for _, id := range ids {
		out = append(out, tenancy.Tenant(id))
	}
	return out, nil
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
	err := db.New(s.pool).PtlCreateOIDCFlow(ctx, db.PtlCreateOIDCFlowParams{
		State: f.State, Nonce: f.Nonce, CodeVerifier: f.CodeVerifier,
		RedirectUri: f.RedirectURI, Issuer: f.Issuer, ClientID: f.ClientID,
		EmailDomain: f.EmailDomain,
		ExpiresAt:   pgtype.Timestamptz{Time: f.ExpiresAt.UTC(), Valid: true},
	})
	if err != nil {
		return fmt.Errorf("store: recording login state: %w", err)
	}
	return nil
}

// ConsumeOIDCFlow returns a flow and marks it spent, atomically. A second call
// for the same state returns ErrNoRoute whether or not the first has
// committed, so a replayed callback cannot complete.
func (s *Store) ConsumeOIDCFlow(ctx context.Context, state string) (OIDCFlow, error) {
	row, err := db.New(s.pool).PtlConsumeOIDCFlow(ctx, state)
	if err != nil {
		return OIDCFlow{}, routeErr(err)
	}
	return OIDCFlow{
		State: state, Nonce: row.Nonce, CodeVerifier: row.CodeVerifier,
		RedirectURI: row.RedirectUri, Issuer: row.Issuer, ClientID: row.ClientID,
		EmailDomain: row.EmailDomain, ExpiresAt: row.ExpiresAt.Time,
	}, nil
}

func routeErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoRoute
	}
	return err
}
