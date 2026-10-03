package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// ENROL-002, build item 104: the enrolment token.
//
// Mint, hash, single-use, 24 hours, audited. Replay gives 409, expiry gives
// 401 — different codes because they are different situations: an expired
// token means "start again", a replayed one means "somebody may have your
// token".

// TokenTTL is how long an enrolment token is usable.
const TokenTTL = 24 * time.Hour

// Service issues collector identities.
type Service struct {
	st  *store.Store
	ca  CA
	log *safelog.Logger
	now func() time.Time
}

// NewService builds the enrolment service.
func NewService(st *store.Store, ca CA, log *safelog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{st: st, ca: ca, log: log, now: now}
}

func hashToken(tok string) []byte {
	sum := sha256.Sum256([]byte(tok))
	return sum[:]
}

// MintToken creates a single-use enrolment token.
//
// The token is returned ONCE and never stored in that form — only its
// SHA-256. A database dump is then a list of useless hashes rather than a bag
// of working enrolment credentials.
func (s *Service) MintToken(ctx context.Context, createdBy string) (string, time.Time, error) {
	tid, err := tenancy.FromContext(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	expires := s.now().UTC().Add(TokenTTL)

	err = s.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := tx.Conn().Exec(ctx, `
			INSERT INTO enrollment_tokens (tenant_id, token_hash, created_by, expires_at)
			VALUES ($1::uuid, $2, NULLIF($3::text,'')::uuid, $4)`,
			tid.String(), hashToken(tok), createdBy, expires); err != nil {
			return err
		}
		// Audited: minting a credential that can ingest data is a privileged
		// act and must leave a trace naming who did it.
		return audit(ctx, tx, tid.String(), createdBy, "enrollment_token.mint",
			"enrollment_token", "")
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("enroll: minting token: %w", err)
	}
	return tok, expires, nil
}

// Result is a completed enrolment.
type Result struct {
	CollectorID    string
	CertificatePEM []byte
	CABundlePEM    []byte
	Fingerprint    string
	NotAfter       time.Time
}

// Enroll redeems a token and issues a client certificate for a CSR.
//
// Pre-tenancy: the token is what identifies the tenant, so the redemption is
// a narrow privileged read of enrollment_tokens. Everything after that runs
// inside the resolved tenant's own scope.
func (s *Service) Enroll(ctx context.Context, token string, csrDER []byte,
	collectorName string) (Result, error) {
	if token == "" || len(csrDER) == 0 {
		return Result{}, ErrTokenUnknown
	}
	th := hashToken(token)

	// Resolve the token to its tenant, and consume it ATOMICALLY. The
	// UPDATE ... WHERE used_at IS NULL RETURNING pattern means two concurrent
	// redemptions cannot both succeed: exactly one gets a row.
	route, err := s.st.LookupEnrollmentToken(ctx, th)
	if err != nil {
		if errors.Is(err, store.ErrNoRoute) {
			return Result{}, ErrTokenUnknown
		}
		return Result{}, fmt.Errorf("enroll: reading token: %w", err)
	}
	if route.Used {
		return Result{}, ErrTokenUsed
	}
	if s.now().UTC().After(route.ExpiresAt) {
		return Result{}, ErrTokenUnknown
	}
	tenant := route.Tenant

	// The CN is derived by US, from the tenant, never taken from the CSR.
	// Letting a requester choose their own CN would let one collector ask for
	// another's identity.
	cn := fmt.Sprintf("collector.%s", tenant)
	csr, err := ValidateCSR(csrDER, "")
	if err != nil {
		return Result{}, err
	}

	now := s.now().UTC()
	der, err := s.ca.Sign(csr, cn, now, ClientCertLifetime)
	if err != nil {
		return Result{}, fmt.Errorf("enroll: issuing: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Result{}, err
	}
	fp := Fingerprint(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	var res Result
	tctx := tenancy.WithTenant(ctx, tenant)
	err = s.st.InTenantTx(tctx, func(ctx context.Context, tx *store.Tx) error {
		// Consume the token inside the same transaction that creates the
		// collector. A crash between them would burn a token without issuing
		// anything, or issue without burning it.
		tag, err := tx.Conn().Exec(ctx, `
			UPDATE enrollment_tokens SET used_at = $2
			 WHERE token_hash = $1 AND used_at IS NULL`, th, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			// Lost the race to a concurrent redemption.
			return ErrTokenUsed
		}
		if err := tx.Conn().QueryRow(ctx, `
			INSERT INTO collectors (tenant_id, name, client_cert_fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'active') RETURNING id::text`,
			tenant.String(), collectorName, fp).Scan(&res.CollectorID); err != nil {
			return err
		}
		if _, err := tx.Conn().Exec(ctx, `
			UPDATE enrollment_tokens SET used_by_collector = $2::uuid
			 WHERE token_hash = $1`, th, res.CollectorID); err != nil {
			return err
		}
		if _, err := tx.Conn().Exec(ctx, `
			INSERT INTO collector_certificates
			  (tenant_id, collector_id, fingerprint, serial, subject_cn,
			   not_before, not_after, certificate_pem)
			VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)`,
			tenant.String(), res.CollectorID, fp, cert.SerialNumber.String(),
			cn, cert.NotBefore, cert.NotAfter, string(certPEM)); err != nil {
			return err
		}
		return audit(ctx, tx, tenant.String(), "", "collector.enrolled",
			"collector", res.CollectorID)
	})
	if err != nil {
		return Result{}, err
	}
	res.CertificatePEM = certPEM
	res.Fingerprint = fp
	res.NotAfter = cert.NotAfter
	if lc, ok := s.ca.(*LocalCA); ok {
		res.CABundlePEM = lc.BundlePEM()
	}
	return res, nil
}

// Identity is a resolved mTLS client.
type Identity struct {
	TenantID    tenancy.Tenant
	CollectorID string
	Fingerprint string
}

// ResolveClient maps a presented client certificate to its collector.
//
// Pre-tenancy: the certificate IS the tenant selector. The index carries the
// two facts needed to refuse early — revoked and not_after — so an expired or
// revoked client never reaches tenant-scoped code at all.
func (s *Service) ResolveClient(ctx context.Context, der []byte) (Identity, error) {
	fp := Fingerprint(der)
	route, err := s.st.LookupCollectorCert(ctx, fp)
	if err != nil {
		return Identity{}, ErrTokenUnknown
	}
	if route.Revoked {
		return Identity{}, ErrRevoked
	}
	if s.now().UTC().After(route.ExpiresAt) {
		return Identity{}, fmt.Errorf("enroll: client certificate expired at %s", route.ExpiresAt)
	}
	id := Identity{TenantID: route.Tenant, CollectorID: route.CollectorID, Fingerprint: fp}
	return id, nil
}

// Revoke marks a collector certificate unusable, immediately.
func (s *Service) Revoke(ctx context.Context, fingerprint, reason string) error {
	return s.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		tag, err := tx.Conn().Exec(ctx, `
			UPDATE collector_certificates
			   SET revoked_at = $2, revoked_reason = $3
			 WHERE fingerprint = $1 AND revoked_at IS NULL`,
			fingerprint, s.now().UTC(), reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errors.New("enroll: no such active certificate in this tenant")
		}
		return audit(ctx, tx, tx.Tenant().String(), "", "collector_certificate.revoked",
			"collector_certificate", "")
	})
}

// Rotate issues a replacement certificate for an existing collector.
//
// Reuses the collector row and chains the old certificate to the new one, so
// a superseded identity is identifiable as superseded rather than unknown.
func (s *Service) Rotate(ctx context.Context, collectorID string, csrDER []byte) (Result, error) {
	tid, err := tenancy.FromContext(ctx)
	if err != nil {
		return Result{}, err
	}
	cn := fmt.Sprintf("collector.%s", tid)
	csr, err := ValidateCSR(csrDER, "")
	if err != nil {
		return Result{}, err
	}
	now := s.now().UTC()
	der, err := s.ca.Sign(csr, cn, now, ClientCertLifetime)
	if err != nil {
		return Result{}, err
	}
	cert, _ := x509.ParseCertificate(der)
	fp := Fingerprint(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	var res Result
	err = s.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var newID string
		if err := tx.Conn().QueryRow(ctx, `
			INSERT INTO collector_certificates
			  (tenant_id, collector_id, fingerprint, serial, subject_cn,
			   not_before, not_after, certificate_pem)
			VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8) RETURNING id::text`,
			tid.String(), collectorID, fp, cert.SerialNumber.String(), cn,
			cert.NotBefore, cert.NotAfter, string(certPEM)).Scan(&newID); err != nil {
			return err
		}
		// Chain the previous active certificate to this one.
		if _, err := tx.Conn().Exec(ctx, `
			UPDATE collector_certificates SET replaced_by = $2::uuid
			 WHERE collector_id = $1::uuid AND id <> $2::uuid
			   AND revoked_at IS NULL AND replaced_by IS NULL`,
			collectorID, newID); err != nil {
			return err
		}
		if _, err := tx.Conn().Exec(ctx,
			`UPDATE collectors SET client_cert_fingerprint = $2 WHERE id = $1::uuid`,
			collectorID, fp); err != nil {
			return err
		}
		return audit(ctx, tx, tid.String(), "", "collector_certificate.rotated",
			"collector", collectorID)
	})
	if err != nil {
		return Result{}, err
	}
	res = Result{CollectorID: collectorID, CertificatePEM: certPEM,
		Fingerprint: fp, NotAfter: cert.NotAfter}
	return res, nil
}

func audit(ctx context.Context, tx *store.Tx, tid, actor, action, kind, objID string) error {
	_, err := tx.Conn().Exec(ctx, `
		INSERT INTO audit_events (tenant_id, actor_id, actor_kind, action, object_kind, object_id)
		VALUES ($1::uuid, NULLIF($2::text,'')::uuid, $3, $4, $5, NULLIF($6::text,'')::uuid)`,
		tid, actor, actorKind(actor), action, kind, objID)
	return err
}

func actorKind(actor string) string {
	if actor == "" {
		return "system"
	}
	return "user"
}
