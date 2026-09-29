package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// AUTH-004 and AUTH-005, build items 101 and 102.
//
// # Why the order is the control
//
// Middleware runs: authenticate -> bind tenant -> authorize.
//
// Authorizing before binding the tenant means an operator of tenant A asks
// about an object in tenant B, passes the role check (they ARE an operator),
// and the query is the only thing standing between them and the row. Binding
// the tenant first means the row does not exist as far as the database is
// concerned, and the role check is then a second, independent gate.
//
// # Why 404 and not 403
//
// Scenario S23. 403 says "this exists and you may not have it", which turns
// any id-shaped URL into an existence oracle: an attacker enumerates ids and
// learns which ones are real in other tenants. 404 says nothing. The rule is
// that a cross-tenant request is indistinguishable from a request for
// something that was never there.
//
// 403 IS used for one case: a request inside your OWN tenant for which your
// role is too low. There the object's existence is not a secret — you are a
// member of that tenant — and telling someone "you need an operator role"
// is useful rather than leaky.

type sessionKey struct{}

// Middleware authenticates a request and binds tenant + actor to its context.
type Middleware struct {
	Sessions *Manager
	Log      *safelog.Logger
	// Secure selects the __Host- cookie. False only for local HTTP dev.
	Secure bool
}

// Authenticate is the outermost gate. On success the downstream handler's
// context carries both the tenant (so the database can be reached at all) and
// the actor (so authorization has something to check).
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := TokenFromRequest(r, m.Secure)
		s, err := m.Sessions.Lookup(r.Context(), tok)
		if err != nil {
			// Every authentication failure gets the SAME response. A caller
			// must not learn whether the session was unknown, expired,
			// revoked or replayed — each distinction is information about
			// somebody else's account.
			if m.Log != nil {
				m.Log.Info("authentication refused",
					safelog.Str("reason", classify(err)),
					safelog.Str("path", r.URL.Path))
			}
			ClearCookie(w, m.Secure)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authentication required",
			})
			return
		}
		ctx := tenancy.WithTenant(r.Context(), s.TenantID)
		ctx = tenancy.WithActor(ctx, s.Actor())
		ctx = context.WithValue(ctx, sessionKey{}, s)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// classify maps an error to a short label for the LOG only. It never reaches
// the response.
func classify(err error) string {
	switch {
	case err == nil:
		return "ok"
	case strings.Contains(err.Error(), "replay"):
		return "rotated_token_replayed"
	case strings.Contains(err.Error(), "expired"):
		return "expired"
	case strings.Contains(err.Error(), "revoked"):
		return "revoked"
	default:
		return "unknown_session"
	}
}

// SessionFromContext returns the authenticated session.
func SessionFromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(Session)
	return s, ok
}

// Require enforces a minimum role. It runs AFTER Authenticate, so the tenant
// is already bound and the database is already refusing other tenants' rows.
func (m *Middleware) Require(min tenancy.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := tenancy.ActorFromContext(r.Context())
		if !ok {
			// Require without Authenticate in front of it is a wiring bug.
			// Failing closed turns it into a broken endpoint rather than an
			// open one.
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "authentication required",
			})
			return
		}
		if !a.Role.AtLeast(min) {
			// 403, not 404: this is inside the caller's own tenant, so the
			// object's existence is not a secret and naming the required role
			// is useful.
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":         "insufficient privilege",
				"required_role": string(min),
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NotFound is the response for anything the caller may not see, INCLUDING
// things that exist in another tenant. Use it wherever a lookup returns no
// rows: with RLS bound, "no rows" and "not yours" are the same query result,
// which is exactly the property that makes the API non-enumerable.
func NotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// No caching of authenticated responses: a shared proxy must not serve
	// one tenant's data to another.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteJSON is the exported form for handlers.
func WriteJSON(w http.ResponseWriter, code int, v any) { writeJSON(w, code, v) }

// Permission is one row of the authorization matrix (item 102).
type Permission struct {
	Method  string
	Path    string
	MinRole tenancy.Role
}

// Matrix is the COMPLETE list of API routes and the role each requires.
//
// Complete is the operative word: a test asserts every registered route
// appears here. A route that is added without a matrix entry fails the build
// rather than defaulting to some permission, because the default a hurried
// developer picks is usually "authenticated" and that is how a viewer ends up
// able to delete an endpoint.
var Matrix = []Permission{
	{"GET", "/api/v1/endpoints", tenancy.RoleViewer},
	{"GET", "/api/v1/endpoints/{id}", tenancy.RoleViewer},
	{"POST", "/api/v1/endpoints", tenancy.RoleOperator},
	{"DELETE", "/api/v1/endpoints/{id}", tenancy.RoleOperator},
	{"GET", "/api/v1/endpoints/{id}/history", tenancy.RoleViewer},
	{"GET", "/api/v1/certificates", tenancy.RoleViewer},
	{"GET", "/api/v1/certificates/{id}", tenancy.RoleViewer},
	{"GET", "/api/v1/expectations", tenancy.RoleViewer},
	{"POST", "/api/v1/expectations", tenancy.RoleOperator},
	// Confirming an expected state is what makes it able to ALERT (D14).
	// Operator, not viewer: it is the act that turns observation into paging.
	{"POST", "/api/v1/expectations/{id}/confirm", tenancy.RoleOperator},
	{"GET", "/api/v1/alerts", tenancy.RoleViewer},
	{"POST", "/api/v1/alerts/{id}/acknowledge", tenancy.RoleOperator},
	{"GET", "/api/v1/collectors", tenancy.RoleViewer},
	// Minting an enrolment token creates a credential that can ingest data.
	// Admin only.
	{"POST", "/api/v1/collectors/enrollment-tokens", tenancy.RoleAdmin},
	{"DELETE", "/api/v1/collectors/{id}", tenancy.RoleAdmin},
	{"GET", "/api/v1/audit", tenancy.RoleAdmin},
	{"GET", "/api/v1/users", tenancy.RoleAdmin},
	{"POST", "/api/v1/users", tenancy.RoleAdmin},
	{"GET", "/api/v1/me", tenancy.RoleViewer},
	{"GET", "/api/v1/summary", tenancy.RoleViewer},
}

// RequiredRole returns the role a route needs, and whether it is in the matrix.
func RequiredRole(method, path string) (tenancy.Role, bool) {
	for _, p := range Matrix {
		if p.Method == method && p.Path == path {
			return p.MinRole, true
		}
	}
	return "", false
}
