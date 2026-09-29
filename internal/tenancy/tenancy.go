// Package tenancy carries the acting tenant through a request.
//
// TENANT-002, build item 093. There is one rule and it is structural: you
// cannot obtain a database handle without a tenant in the context. Not "you
// should not" — `store.Begin` returns an error, so the failure mode of
// forgetting is a broken request, not a cross-tenant read.
//
// The tenant id is NOT a parameter anyone passes to a query. It is set as a
// transaction-local Postgres setting and read by the RLS policy. Application
// code never writes `WHERE tenant_id = $1`, because a filter that a developer
// can forget is not a security boundary.
package tenancy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// ErrNoTenant is returned wherever a tenant is required and absent.
var ErrNoTenant = errors.New("tenancy: no tenant in context")

type ctxKey struct{}

type actorKey struct{}

// uuidRe validates the id BEFORE it reaches set_config. The value is passed as
// a bind parameter so this is defence in depth rather than the only guard, but
// an id that is not a UUID is a bug worth failing loudly on either way.
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Tenant is an organization id.
type Tenant string

// Valid reports whether t is a well-formed UUID.
func (t Tenant) Valid() bool { return uuidRe.MatchString(string(t)) }

func (t Tenant) String() string { return string(t) }

// Role is the acting user's role within the tenant.
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// rank orders roles for the "at least" check. Higher is more privileged.
func (r Role) rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	}
	return 0
}

// AtLeast reports whether r is at least as privileged as want. An unknown role
// ranks 0 and therefore satisfies nothing — a typo in a role string denies
// rather than grants.
func (r Role) AtLeast(want Role) bool { return r.rank() >= want.rank() && r.rank() > 0 }

// Actor is who is acting, within a tenant.
type Actor struct {
	UserID string
	Email  string
	Role   Role
	// Kind distinguishes a human from a collector or an internal worker, for
	// the audit log. A collector has no user id.
	Kind string
}

// WithTenant returns a context carrying t.
func WithTenant(ctx context.Context, t Tenant) context.Context {
	return context.WithValue(ctx, ctxKey{}, t)
}

// FromContext returns the tenant, or an error if absent or malformed.
func FromContext(ctx context.Context) (Tenant, error) {
	v, ok := ctx.Value(ctxKey{}).(Tenant)
	if !ok || v == "" {
		return "", ErrNoTenant
	}
	if !v.Valid() {
		return "", fmt.Errorf("tenancy: tenant id %q is not a uuid", string(v))
	}
	return v, nil
}

// WithActor returns a context carrying the acting principal.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFromContext returns the acting principal, if any.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok
}

// MustTenant is for call sites that have already checked. It panics rather
// than defaulting, because a default tenant is a cross-tenant read waiting to
// happen.
func MustTenant(ctx context.Context) Tenant {
	t, err := FromContext(ctx)
	if err != nil {
		panic("tenancy: " + err.Error())
	}
	return t
}
