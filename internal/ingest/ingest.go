// Package ingest accepts collector reports over mTLS.
//
// INGEST-001..006 and PROTO-002, build items 107-114.
//
// # The server does not trust the collector
//
// INV-5. A collector is software running inside a customer's network, and the
// most likely way a private key reaches this service is a bug in that
// software, not malice. So the server scans every payload for private-key
// patterns and REJECTS the batch rather than storing it. The collector's own
// pkg/safeio boundary is the first line; this is the second, and it exists
// precisely because the first one can have a bug.
//
// # Schema-closed decoding
//
// An unknown field is an ERROR, not something to ignore. Loosening later is
// easy; tightening after collectors are in the field is not — a deployed
// fleet would start failing on a field they already send.
package ingest

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/certwatch/certwatch/internal/enroll"
	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// INGEST-006, item 114: payload caps. Each bounds a specific failure.
const (
	// MaxObservations bounds one batch. A collector with a million endpoints
	// sends many batches rather than one enormous one.
	MaxObservations = 1000
	// MaxCompressedBytes bounds what we read off the wire.
	MaxCompressedBytes = 5 << 20 // 5 MB
	// MaxDecompressedBytes bounds what a gzip bomb can expand to. Without
	// this, 5 MB on the wire becomes gigabytes in memory.
	MaxDecompressedBytes = 20 << 20 // 20 MB
	// MaxBatchIDLen bounds the idempotency key.
	MaxBatchIDLen = 128
)

// Protocol version. PROTO-008: an unknown version is refused with an upgrade
// hint rather than guessed at.
const (
	ProtocolVersion       = "1"
	ProtocolVersionHeader = "X-Certwatch-Protocol"
)

var (
	ErrUnknownField   = errors.New("ingest: payload contains an unknown field")
	ErrTooLarge       = errors.New("ingest: payload exceeds the size cap")
	ErrKeyMaterial    = errors.New("ingest: payload contains private-key material")
	ErrTenantMismatch = errors.New("ingest: payload tenant does not match the client certificate")
	ErrBadVersion     = errors.New("ingest: unsupported protocol version")
)

// Batch is the wire payload. Every field is explicit; the decoder is closed.
type Batch struct {
	BatchID      string        `json:"batch_id"`
	TenantID     string        `json:"tenant_id"`
	CollectorID  string        `json:"collector_id"`
	StartedAt    time.Time     `json:"started_at"`
	FinishedAt   time.Time     `json:"finished_at"`
	ScopeDigest  string        `json:"scope_digest,omitempty"`
	Observations []Observation `json:"observations"`
}

// Observation is one certificate seen at one address.
type Observation struct {
	Hostname     string    `json:"hostname,omitempty"`
	Address      string    `json:"address"`
	Port         int       `json:"port"`
	SNI          string    `json:"sni,omitempty"`
	Fingerprint  string    `json:"sha256"`
	SubjectCN    string    `json:"subject_cn,omitempty"`
	SubjectDN    string    `json:"subject_dn,omitempty"`
	IssuerDN     string    `json:"issuer_dn,omitempty"`
	SANs         []string  `json:"sans,omitempty"`
	Serial       string    `json:"serial,omitempty"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	KeyAlgorithm string    `json:"key_algorithm,omitempty"`
	KeySize      *int      `json:"key_size,omitempty"`
	ParseStatus  string    `json:"parse_status,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// keyPatterns are the shapes private-key material takes in a payload.
//
// INV-5. Deliberately broad: a false positive costs a collector one rejected
// batch and a loud error; a false negative means key material in our database.
// The asymmetry is the entire argument for erring wide.
var keyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)-----BEGIN[ A-Z]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)-----BEGIN[ A-Z]*ENCRYPTED PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)\bPuTTY-User-Key-File\b`),
	regexp.MustCompile(`(?i)\bprivateKeyPem\b|\bprivate_key_pem\b|\bprivateKey\b`),
	// PKCS#8 and PKCS#1 DER headers, base64-encoded. These are what a buggy
	// collector that base64s a whole file would actually send.
	regexp.MustCompile(`MII[A-Za-z0-9+/]{6,}(?:BAD|AgEAAo|EvAIBA|EvQIBA)`),
	regexp.MustCompile(`(?i)\bBEGIN RSA PRIVATE\b|\bBEGIN EC PRIVATE\b|\bBEGIN DSA PRIVATE\b`),
}

// ScanForKeyMaterial returns the pattern that matched, or empty.
//
// Runs over the RAW decompressed bytes, before JSON decoding. Scanning the
// decoded struct would miss key material hidden in a field the schema does not
// model — and the schema is closed, so such a field would be rejected anyway,
// but the scan must not depend on that ordering.
func ScanForKeyMaterial(raw []byte) string {
	for _, re := range keyPatterns {
		if loc := re.FindIndex(raw); loc != nil {
			return re.String()
		}
	}
	return ""
}

// Decoder limits and closes the payload.
type Decoder struct{ log *safelog.Logger }

// Decode reads a batch from r, enforcing every cap and the closed schema.
//
// Order matters and is deliberate:
//
//  1. bound the compressed read      (a huge body never reaches memory)
//  2. bound the decompressed read    (a gzip bomb never reaches memory)
//  3. scan for key material          (BEFORE anything is parsed or stored)
//  4. decode with unknown fields disallowed
//  5. bound the observation count
func (d *Decoder) Decode(r io.Reader, gzipped bool) (Batch, error) {
	var b Batch
	limited := io.LimitReader(r, MaxCompressedBytes+1)
	var src io.Reader = limited
	if gzipped {
		zr, err := gzip.NewReader(limited)
		if err != nil {
			return b, fmt.Errorf("ingest: gzip: %w", err)
		}
		defer zr.Close()
		src = io.LimitReader(zr, MaxDecompressedBytes+1)
	}
	raw, err := io.ReadAll(src)
	if err != nil {
		return b, fmt.Errorf("ingest: reading payload: %w", err)
	}
	if gzipped && len(raw) > MaxDecompressedBytes {
		return b, fmt.Errorf("%w: decompressed payload exceeds %d bytes",
			ErrTooLarge, MaxDecompressedBytes)
	}
	if !gzipped && len(raw) > MaxCompressedBytes {
		return b, fmt.Errorf("%w: payload exceeds %d bytes", ErrTooLarge, MaxCompressedBytes)
	}

	// INV-5, before parsing. Nothing is stored, logged or decoded until this
	// has passed.
	if pat := ScanForKeyMaterial(raw); pat != "" {
		if d.log != nil {
			// The pattern name, never the match. Logging the match would put
			// the key material in the log, which is the thing being prevented.
			d.log.Error("ingest rejected: private-key material in payload",
				safelog.Str("pattern", pat))
		}
		return b, ErrKeyMaterial
	}

	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return b, fmt.Errorf("%w: %v", ErrUnknownField, err)
		}
		return b, fmt.Errorf("ingest: decoding: %w", err)
	}
	// Exactly one JSON value. Trailing content is a smuggling attempt or a
	// broken encoder; either way it is not something to silently ignore.
	if dec.More() {
		return b, errors.New("ingest: payload contains more than one JSON value")
	}
	if len(b.Observations) > MaxObservations {
		return b, fmt.Errorf("%w: %d observations, maximum is %d",
			ErrTooLarge, len(b.Observations), MaxObservations)
	}
	if len(b.BatchID) < 8 || len(b.BatchID) > MaxBatchIDLen {
		return b, errors.New("ingest: batch_id must be 8-128 characters")
	}
	return b, nil
}

// Service stores accepted batches.
type Service struct {
	st  *store.Store
	log *safelog.Logger
	now func() time.Time
	dec *Decoder

	// RejectedKeyMaterial counts INV-5 rejections. Exposed so the canary and
	// the metrics endpoint can both assert on it.
	RejectedKeyMaterial int64
}

// NewService builds the ingest service.
func NewService(st *store.Store, log *safelog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{st: st, log: log, now: now, dec: &Decoder{log: log}}
}

// Accept stores a batch for an authenticated collector.
//
// id comes from the mTLS client certificate and is the ONLY source of tenancy.
// The tenant_id in the payload is checked AGAINST it and never used instead —
// item 109. A collector that names another tenant gets 403 and an audit event.
func (s *Service) Accept(ctx context.Context, id enroll.Identity, b Batch) (accepted int, duplicate bool, err error) {
	if b.TenantID != "" && b.TenantID != id.TenantID.String() {
		// Audited, because a collector claiming another tenant is either a
		// serious bug or an attack and somebody must be able to see it later.
		_ = s.auditMismatch(ctx, id, b.TenantID)
		return 0, false, ErrTenantMismatch
	}
	tctx := tenancy.WithTenant(ctx, id.TenantID)

	err = s.st.InTenantTx(tctx, func(ctx context.Context, tx *store.Tx) error {
		tid := id.TenantID.String()
		// INGEST-004: idempotency by batch_id. A retry after a network
		// timeout must change no row (P-8).
		tag, err := tx.Conn().Exec(ctx, `
			INSERT INTO ingest_batches (tenant_id, batch_id, collector_id, observations)
			VALUES ($1::uuid, $2, $3::uuid, $4)
			ON CONFLICT (tenant_id, batch_id) DO NOTHING`,
			tid, b.BatchID, id.CollectorID, len(b.Observations))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			duplicate = true
			return nil
		}

		for _, o := range b.Observations {
			if o.Fingerprint == "" {
				continue
			}
			// Natural-key upsert: the same certificate seen again updates
			// last_seen rather than creating a second row.
			var credID string
			if err := tx.Conn().QueryRow(ctx, `
				INSERT INTO credentials (tenant_id, kind, fingerprint, last_seen)
				VALUES ($1::uuid,'x509',$2,$3)
				ON CONFLICT (tenant_id, fingerprint)
				  DO UPDATE SET last_seen = EXCLUDED.last_seen
				RETURNING id::text`,
				tid, o.Fingerprint, s.now().UTC()).Scan(&credID); err != nil {
				return err
			}
			if _, err := tx.Conn().Exec(ctx, `
				INSERT INTO certificates
				  (credential_id, tenant_id, serial, subject_dn, subject_cn, sans,
				   issuer_dn, not_before, not_after, key_algorithm, key_size, parse_status)
				VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,
				        COALESCE(NULLIF($12,''),'ok'))
				ON CONFLICT (credential_id) DO NOTHING`,
				credID, tid, o.Serial, o.SubjectDN, o.SubjectCN, strs(o.SANs),
				o.IssuerDN, nullTime(o.NotBefore), nullTime(o.NotAfter),
				o.KeyAlgorithm, o.KeySize, o.ParseStatus); err != nil {
				return err
			}
			// Endpoint, if the observation names one.
			var epID *string
			if o.Hostname != "" {
				var e string
				if err := tx.Conn().QueryRow(ctx, `
					INSERT INTO endpoints (tenant_id, hostname, port, sni, last_seen)
					VALUES ($1::uuid,$2,$3,$4,$5)
					ON CONFLICT (tenant_id, hostname, port, sni)
					  DO UPDATE SET last_seen = EXCLUDED.last_seen
					RETURNING id::text`,
					tid, o.Hostname, o.Port, o.SNI, s.now().UTC()).Scan(&e); err != nil {
					return err
				}
				epID = &e
			}
			if _, err := tx.Conn().Exec(ctx, `
				INSERT INTO observations
				  (tenant_id, credential_id, endpoint_id, collector_id, address, port, observed_at)
				VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,NULLIF($5,'')::inet,$6,$7)`,
				tid, credID, epID, id.CollectorID, o.Address, o.Port,
				nullTimeOr(o.ObservedAt, s.now().UTC())); err != nil {
				return err
			}
			accepted++
		}
		_, err = tx.Conn().Exec(ctx,
			`UPDATE collectors SET last_seen_at = $2, scope_digest = COALESCE(NULLIF($3,''), scope_digest)
			  WHERE id = $1::uuid`, id.CollectorID, s.now().UTC(), b.ScopeDigest)
		return err
	})
	return accepted, duplicate, err
}

func (s *Service) auditMismatch(ctx context.Context, id enroll.Identity, claimed string) error {
	tctx := tenancy.WithTenant(ctx, id.TenantID)
	return s.st.InTenantTx(tctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := tx.Conn().Exec(ctx, `
			INSERT INTO audit_events (tenant_id, actor_kind, action, object_kind, object_id, detail)
			VALUES ($1::uuid,'collector','ingest.tenant_mismatch','collector',$2::uuid,$3::jsonb)`,
			id.TenantID.String(), id.CollectorID,
			fmt.Sprintf(`{"claimed_tenant":%q}`, claimed))
		return err
	})
}

// strs normalises a possibly-nil string slice to an empty slice.
//
// A nil slice means "none", not "unknown". Passing nil sends SQL NULL, which
// overrides a NOT NULL DEFAULT '{}' column and fails the insert. This is the
// third time this exact shape has bitten (ips_matching in internal/history
// was the second), which is why it is a named helper rather than an inline
// fix at one call site.
func strs(a []string) []string {
	if a == nil {
		return []string{}
	}
	return a
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
func nullTimeOr(t, fallback time.Time) time.Time {
	if t.IsZero() {
		return fallback
	}
	return t.UTC()
}

// Handler is the HTTP surface. It expects mTLS to have already happened: the
// client certificate on the TLS connection is the identity.
type Handler struct {
	Svc    *Service
	Enroll *enroll.Service
	Log    *safelog.Logger
}

// ServeHTTP handles POST /ingest/v1/batch.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if v := r.Header.Get(ProtocolVersionHeader); v != "" && v != ProtocolVersion {
		// PROTO-008: name the supported version rather than guessing.
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "unsupported protocol version", "supported": ProtocolVersion,
			"upgrade": "https://certwatch.example/docs/collector-upgrade",
		})
		return
	}
	// mTLS identity. No certificate means no identity: there is no fallback
	// to a header or a bearer token, because a fallback is the thing an
	// attacker would use.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeErr(w, http.StatusUnauthorized, "client certificate required")
		return
	}
	id, err := h.Enroll.ResolveClient(r.Context(), r.TLS.PeerCertificates[0].Raw)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "client certificate not accepted")
		return
	}

	b, err := h.Svc.dec.Decode(r.Body, r.Header.Get("Content-Encoding") == "gzip")
	switch {
	case errors.Is(err, ErrKeyMaterial):
		h.Svc.RejectedKeyMaterial++
		// 400 and a named reason: the collector operator must be able to find
		// and fix the bug that sent us a key.
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "payload contained private-key material and was rejected",
			"reason": "ingest.rejected_key_material",
		})
		return
	case errors.Is(err, ErrTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	case errors.Is(err, ErrUnknownField):
		writeErr(w, http.StatusBadRequest, "payload contains an unknown field")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, "payload could not be decoded")
		return
	}

	accepted, dup, err := h.Svc.Accept(r.Context(), id, b)
	switch {
	case errors.Is(err, ErrTenantMismatch):
		writeErr(w, http.StatusForbidden, "payload tenant does not match the client certificate")
		return
	case err != nil:
		if h.Log != nil {
			h.Log.Error("ingest failed", safelog.Err(err))
		}
		// Never echo the database error: it can carry schema and data.
		writeErr(w, http.StatusInternalServerError, "could not store the batch")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"accepted": accepted, "duplicate": dup, "batch_id": b.BatchID,
	})
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
