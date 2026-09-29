// Package auth is authentication and authorization for the control plane.
//
// AUTH-002 and AUTH-004, build items 099 and 101.
//
// # Two rules that shape everything here
//
//  1. The session token is never stored. Only its SHA-256. A database dump is
//     then a list of useless hashes instead of a set of working logins.
//
//  2. Authorization happens AFTER tenant scoping, never before. Checking the
//     role first and the tenant second means a correctly-roled user of tenant
//     A gets a considered, authorized answer about tenant B's object. The
//     order is the control.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
)

// Errors. Deliberately few and deliberately vague at the edge: see Handler,
// which collapses all of them to one response so that a caller cannot tell
// "no such session" from "expired" from "revoked".
var (
	ErrNoSession      = errors.New("auth: no session")
	ErrSessionExpired = errors.New("auth: session expired")
	ErrSessionRevoked = errors.New("auth: session revoked")
	ErrReplay         = errors.New("auth: rotated session token replayed")
	ErrForbidden      = errors.New("auth: insufficient privilege")
)

// Lifetimes.
const (
	// AbsoluteLifetime bounds a stolen token no matter how actively it is
	// used. Without it, a token refreshed by traffic lives forever.
	AbsoluteLifetime = 12 * time.Hour
	// IdleLifetime bounds an abandoned session on a shared machine.
	IdleLifetime = 60 * time.Minute
	// TokenBytes is the entropy in a session token. 32 bytes is 256 bits.
	TokenBytes = 32
	// CookieName is prefixed __Host- which the browser enforces: HTTPS only,
	// no Domain attribute, Path=/. It cannot be set by a subdomain, which
	// removes session fixation from a compromised sibling host.
	CookieName = "__Host-certwatch_session"
)

// Session is an authenticated session as the server sees it.
type Session struct {
	ID            string
	TenantID      tenancy.Tenant
	UserID        string
	Email         string
	Role          tenancy.Role
	ExpiresAt     time.Time
	IdleExpiresAt time.Time
}

// Actor converts a session to the acting principal.
func (s Session) Actor() tenancy.Actor {
	return tenancy.Actor{UserID: s.UserID, Email: s.Email, Role: s.Role, Kind: "user"}
}

// hashToken is the one place a token becomes a stored value.
func hashToken(tok string) []byte {
	sum := sha256.Sum256([]byte(tok))
	return sum[:]
}

// NewToken mints a session token. It is returned ONCE, to be set as a cookie,
// and never stored in that form.
func NewToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generating session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Manager issues and validates sessions.
type Manager struct {
	st  *store.Store
	now func() time.Time
}

// NewManager builds a Manager. now is injectable so expiry can be tested
// against a five-day sequence without sleeping.
func NewManager(st *store.Store, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{st: st, now: now}
}

// Create issues a session for a user who has just authenticated.
func (m *Manager) Create(ctx context.Context, userID, email string,
	role tenancy.Role, userAgent, sourceIP string) (token string, s Session, err error) {
	tid, err := tenancy.FromContext(ctx)
	if err != nil {
		return "", Session{}, err
	}
	token, err = NewToken()
	if err != nil {
		return "", Session{}, err
	}
	now := m.now().UTC()
	s = Session{
		TenantID: tid, UserID: userID, Email: email, Role: role,
		ExpiresAt:     now.Add(AbsoluteLifetime),
		IdleExpiresAt: now.Add(IdleLifetime),
	}
	th := hashToken(token)
	err = m.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := tx.Conn().QueryRow(ctx, `
			INSERT INTO sessions
			    (tenant_id, user_id, token_hash, expires_at, idle_expires_at, user_agent, source_ip)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, NULLIF($7,'')::inet)
			RETURNING id::text`,
			tid.String(), userID, th,
			s.ExpiresAt, s.IdleExpiresAt, userAgent, sourceIP).Scan(&s.ID); err != nil {
			return err
		}
		// Same transaction: an index row without a session, or a session
		// without an index row, would be an un-loggable-in account.
		_, err := tx.Conn().Exec(ctx,
			`INSERT INTO session_index (token_hash, session_id, tenant_id)
			 VALUES ($1, $2::uuid, $3::uuid)`, th, s.ID, tid.String())
		return err
	})
	if err != nil {
		return "", Session{}, fmt.Errorf("auth: creating session: %w", err)
	}
	return token, s, nil
}

// Lookup validates a token and returns the session.
//
// This is the one query in the system that runs BEFORE a tenant is known — a
// cookie does not say which tenant it belongs to. It is a Privileged read for
// that reason, and it is narrow: it selects only by token hash, and the hash
// is compared in constant time after retrieval.
func (m *Manager) Lookup(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrNoSession
	}
	want := hashToken(token)

	// Step one, pre-tenancy: which tenant is this cookie for? Only
	// session_index can answer, and it holds nothing else.
	var tenantID string
	if err := m.st.Privileged(ctx,
		"resolve a session cookie to its tenant; a cookie carries no tenant of its own",
		func(ctx context.Context, p *pgxpool.Pool) error {
			return p.QueryRow(ctx,
				`SELECT tenant_id::text FROM session_index WHERE token_hash = $1`, want).
				Scan(&tenantID)
		}); err != nil {
		return Session{}, ErrNoSession
	}
	tn := tenancy.Tenant(tenantID)
	if !tn.Valid() {
		return Session{}, ErrNoSession
	}

	// Step two: everything else is read under that tenant's own RLS policy,
	// exactly like any other query in the system.
	var (
		s          Session
		revoked    *time.Time
		rotatedTo  *string
		storedHash []byte
		disabled   *time.Time
	)
	err := m.st.InTenantTx(tenancy.WithTenant(ctx, tn),
		func(ctx context.Context, tx *store.Tx) error {
			return tx.Conn().QueryRow(ctx, `
				SELECT s.id::text, s.user_id::text, u.email::text, u.role::text,
				       s.expires_at, s.idle_expires_at, s.revoked_at,
				       s.rotated_to::text, s.token_hash, u.disabled_at
				  FROM sessions s
				  JOIN users u ON u.id = s.user_id
				 WHERE s.token_hash = $1`, want).
				Scan(&s.ID, &s.UserID, &s.Email, (*string)(&s.Role),
					&s.ExpiresAt, &s.IdleExpiresAt, &revoked, &rotatedTo,
					&storedHash, &disabled)
		})
	if err != nil {
		return Session{}, ErrNoSession
	}
	if subtle.ConstantTimeCompare(storedHash, want) != 1 {
		return Session{}, ErrNoSession
	}
	if rotatedTo != nil {
		// This token was rotated away. Presenting it now is a replay, which
		// usually means the old cookie was captured.
		return Session{}, ErrReplay
	}
	if revoked != nil {
		return Session{}, ErrSessionRevoked
	}
	// A disabled user's existing sessions must stop working immediately.
	// Checking only at login would leave a fired employee signed in until
	// their session happened to expire.
	if disabled != nil {
		return Session{}, ErrSessionRevoked
	}
	now := m.now().UTC()
	if !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpiresAt) {
		return Session{}, ErrSessionExpired
	}
	s.TenantID = tn
	return s, nil
}

// Touch extends the idle window. The absolute expiry is never extended.
func (m *Manager) Touch(ctx context.Context, s Session) error {
	ctx = tenancy.WithTenant(ctx, s.TenantID)
	return m.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.Conn().Exec(ctx, `
			UPDATE sessions SET last_used_at = now(), idle_expires_at = $2
			 WHERE id = $1::uuid AND revoked_at IS NULL`,
			s.ID, m.now().UTC().Add(IdleLifetime))
		return err
	})
}

// Rotate issues a new token for the same session and marks the old one
// rotated. Call it on every privilege change — that is what stops a token
// captured before an elevation from still carrying the elevation after.
func (m *Manager) Rotate(ctx context.Context, s Session) (string, Session, error) {
	ctx = tenancy.WithTenant(ctx, s.TenantID)
	newTok, err := NewToken()
	if err != nil {
		return "", Session{}, err
	}
	var newID string
	now := m.now().UTC()
	next := s
	next.ExpiresAt = s.ExpiresAt // absolute expiry is NOT extended by rotation
	next.IdleExpiresAt = now.Add(IdleLifetime)

	err = m.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		if err := tx.Conn().QueryRow(ctx, `
			INSERT INTO sessions (tenant_id, user_id, token_hash, expires_at, idle_expires_at)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5) RETURNING id::text`,
			s.TenantID.String(), s.UserID, hashToken(newTok),
			next.ExpiresAt, next.IdleExpiresAt).Scan(&newID); err != nil {
			return err
		}
		if _, err := tx.Conn().Exec(ctx,
			`INSERT INTO session_index (token_hash, session_id, tenant_id)
			 VALUES ($1, $2::uuid, $3::uuid)`,
			hashToken(newTok), newID, s.TenantID.String()); err != nil {
			return err
		}
		_, err := tx.Conn().Exec(ctx,
			`UPDATE sessions SET rotated_to = $2::uuid WHERE id = $1::uuid`, s.ID, newID)
		return err
	})
	if err != nil {
		return "", Session{}, err
	}
	next.ID = newID
	return newTok, next, nil
}

// Revoke ends one session.
func (m *Manager) Revoke(ctx context.Context, s Session) error {
	ctx = tenancy.WithTenant(ctx, s.TenantID)
	return m.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.Conn().Exec(ctx,
			`UPDATE sessions SET revoked_at = now() WHERE id = $1::uuid`, s.ID)
		return err
	})
}

// RevokeAllForUser is "sign out everywhere", and is what a password reset or a
// suspected compromise calls.
func (m *Manager) RevokeAllForUser(ctx context.Context, userID string) error {
	return m.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.Conn().Exec(ctx,
			`UPDATE sessions SET revoked_at = now()
			  WHERE user_id = $1::uuid AND revoked_at IS NULL`, userID)
		return err
	})
}

// SetCookie writes the session cookie with the flags that matter.
//
// __Host- prefix: the browser refuses the cookie unless Secure is set, Path is
// "/" and there is NO Domain attribute. That last part is the valuable one —
// it means a compromised subdomain cannot set a session cookie for us.
//
// SameSite=Lax rather than Strict: Strict breaks the OIDC redirect back from
// the identity provider, and Lax still blocks cross-site POST.
func SetCookie(w http.ResponseWriter, token string, expires time.Time, secure bool) {
	name := CookieName
	if !secure {
		// __Host- REQUIRES Secure. On plain-HTTP local development the browser
		// would silently drop the cookie, so the prefix is dropped instead —
		// visibly, and only when Secure is off.
		name = "certwatch_session_insecure_dev"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true, // JavaScript cannot read it, so XSS cannot exfiltrate it
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie removes the session cookie.
func ClearCookie(w http.ResponseWriter, secure bool) {
	name := CookieName
	if !secure {
		name = "certwatch_session_insecure_dev"
	}
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// TokenFromRequest reads the session token from the request.
func TokenFromRequest(r *http.Request, secure bool) string {
	name := CookieName
	if !secure {
		name = "certwatch_session_insecure_dev"
	}
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}
