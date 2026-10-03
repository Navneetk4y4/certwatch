package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/certwatch/certwatch/internal/enroll"
	"github.com/certwatch/certwatch/internal/mode2"
	"github.com/certwatch/certwatch/internal/sched"
	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// The collector-facing protocol surface. PROTO-003, PROTO-007, PROTO-008;
// build items 115, 118, 119.
//
//	POST /v1/ingest/observations   batched results, idempotent by batch_id
//	GET  /v1/tasks?wait=&max=      long-poll for work
//	POST /v1/collectors/heartbeat  liveness, spool pressure, deprecation
//
// Every request passes the same gate, in this order:
//
//  1. protocol version            — refused before anything else is read
//  2. body: bounded, decompressed, INV-5 scanned
//  3. authentication              — mTLS certificate, or Mode 2 signature
//  4. the handler, with an Identity whose tenant came from step 3 only
//
// There is one Authenticator per listener. The mTLS listener never consults a
// signature header and the Mode 2 listener never consults a certificate, so
// neither can be used to bypass the other.

// ProtocolVersionHeader names the request's protocol version. It is echoed on
// every response.
const ProtocolVersionHeader = "X-Certwatch-Protocol"

// CurrentProtocol is the newest protocol this server speaks.
const CurrentProtocol = 1

// VersionPolicy is the skew rule: the current version is served; an older one
// is served with a deprecation notice until its supported_until; anything
// else — unknown, newer, retired, missing, malformed — is refused with an
// upgrade URL. The server never guesses forward.
type VersionPolicy struct {
	Current    int
	Deprecated map[int]time.Time
	UpgradeURL string
}

// DefaultVersionPolicy serves protocol 1 only.
func DefaultVersionPolicy() VersionPolicy {
	return VersionPolicy{Current: CurrentProtocol,
		UpgradeURL: "https://certwatch.example/docs/collector-upgrade"}
}

// Deprecation is the notice an old collector receives.
type Deprecation struct {
	Version        int    `json:"protocol_version"`
	SupportedUntil string `json:"supported_until"`
	Message        string `json:"message"`
	UpgradeURL     string `json:"upgrade_url"`
}

var versionRE = regexp.MustCompile(`^[1-9][0-9]{0,3}$`)

// Check resolves a request's version header.
func (p VersionPolicy) Check(h []string, now time.Time) (int, *Deprecation, bool) {
	if len(h) != 1 || !versionRE.MatchString(h[0]) {
		return 0, nil, false
	}
	v, _ := strconv.Atoi(h[0])
	if v == p.Current {
		return v, nil, true
	}
	if until, ok := p.Deprecated[v]; ok && now.Before(until) {
		return v, &Deprecation{Version: v, SupportedUntil: until.UTC().Format("2006-01-02"),
			Message: fmt.Sprintf("protocol %d is deprecated; upgrade this collector before %s",
				v, until.UTC().Format("2006-01-02")),
			UpgradeURL: p.UpgradeURL}, true
	}
	return v, nil, false
}

func (p VersionPolicy) supported(now time.Time) []int {
	out := []int{p.Current}
	for v, until := range p.Deprecated {
		if now.Before(until) {
			out = append(out, v)
		}
	}
	return out
}

// Authenticator turns a request into a collector identity.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request, body []byte) (enroll.Identity, error)
}

// MTLSAuth: the verified client certificate on the connection is the identity.
type MTLSAuth struct{ Enroll *enroll.Service }

// Authenticate implements Authenticator.
func (a MTLSAuth) Authenticate(ctx context.Context, r *http.Request, _ []byte) (enroll.Identity, error) {
	// No certificate means no identity: there is no fallback to a header or a
	// bearer token, because a fallback is the thing an attacker would use.
	//
	// MEASURED EQUIVALENCE: dropping the VerifiedChains condition fails no
	// test, because ServerTLSConfig's RequireAndVerifyClientCert already
	// refuses an unverified chain in the handshake. It stays so that a future
	// change to RequestClientCert cannot silently accept any certificate.
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return enroll.Identity{}, ErrNoClientCert
	}
	return a.Enroll.ResolveClient(ctx, r.TLS.PeerCertificates[0].Raw)
}

// Mode2Auth: the detached JWS in X-Certwatch-Signature is the identity.
type Mode2Auth struct {
	Enroll *enroll.Service
	Store  *store.Store
	Now    func() time.Time
}

// Authenticate implements Authenticator. Order is the security argument:
//
//  1. parse — structure only, nothing trusted
//  2. kid -> enrolled certificate route; revoked or expired stops here
//  3. that certificate's public key, from the database, never the request
//  4. verify: pinned alg, signature over JCS(body), method, path, freshness
//  5. cw_cid / cw_tid must equal what kid resolved to — the collector's
//     identity decides the tenant; the claim is only checked against it
//  6. consume the nonce — after verification, so unauthenticated requests
//     cannot fill the replay store
func (a Mode2Auth) Authenticate(ctx context.Context, r *http.Request, body []byte) (enroll.Identity, error) {
	h := r.Header.Values(mode2.Header)
	if len(h) != 1 {
		return enroll.Identity{}, mode2.ErrMalformed
	}
	p, err := mode2.Parse(h[0])
	if err != nil {
		return enroll.Identity{}, err
	}
	id, err := a.Enroll.ResolveFingerprint(ctx, p.Claims.Kid)
	if err != nil {
		return enroll.Identity{}, err
	}
	pub, err := a.Enroll.PublicKey(ctx, id)
	if err != nil {
		return enroll.Identity{}, err
	}
	now := a.Now().UTC()
	if err := p.Verify(pub, body, mode2.Expect{Method: r.Method, Path: r.URL.RequestURI(), Now: now}); err != nil {
		return enroll.Identity{}, err
	}
	if p.Claims.Cid != id.CollectorID || p.Claims.Tid != id.TenantID.String() {
		// A genuine signature by this collector's key, naming someone else.
		// That is a bug or an attack; either way the key's owner should see it.
		_ = auditIn(ctx, a.Store, id, "ingest.mode2_identity_mismatch",
			map[string]string{"claimed_tenant": p.Claims.Tid, "claimed_collector": p.Claims.Cid})
		return enroll.Identity{}, ErrTenantMismatch
	}
	tctx := tenancy.WithTenant(ctx, id.TenantID)
	err = a.Store.InTenantTx(tctx, func(ctx context.Context, tx *store.Tx) error {
		// Housekeeping first, bounded to this collector, so the store cannot
		// grow without limit however long a collector runs.
		if _, err := tx.Conn().Exec(ctx, `
			DELETE FROM mode2_nonces WHERE collector_id = $1::uuid AND expires_at < $2`,
			id.CollectorID, now); err != nil {
			return err
		}
		tag, err := tx.Conn().Exec(ctx, `
			INSERT INTO mode2_nonces (tenant_id, collector_id, nonce, expires_at)
			VALUES ($1::uuid, $2::uuid, $3, $4)
			ON CONFLICT DO NOTHING`,
			id.TenantID.String(), id.CollectorID, p.Claims.Nonce, now.Add(mode2.NonceTTL))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return mode2.ErrReplay
		}
		return nil
	})
	if err != nil {
		return enroll.Identity{}, err
	}
	return id, nil
}

// API serves the collector protocol.
type API struct {
	Svc      *Service
	Queue    *sched.Queue
	Auth     Authenticator
	Versions VersionPolicy
	Log      *safelog.Logger
	Now      func() time.Time

	// MaxWait caps ?wait=. PollInterval is how often a waiting request
	// re-checks the queue when nothing wakes it sooner.
	MaxWait      time.Duration
	PollInterval time.Duration
	// TaskLease is how long a collector holds a task before it is handed out
	// again.
	TaskLease time.Duration
	// MaxWaiting bounds concurrent long-polls server-wide; MaxPerCollector
	// bounds them per collector. Both answer 429 rather than queueing,
	// because a parked request costs a goroutine and a connection.
	MaxWaiting      int
	MaxPerCollector int

	mu       sync.Mutex
	waiting  int
	perColl  map[string]int
	wake     chan struct{}
	stopping chan struct{}
	stopOnce sync.Once
}

// NewAPI builds the protocol API with production defaults.
func NewAPI(svc *Service, q *sched.Queue, auth Authenticator, log *safelog.Logger) *API {
	return &API{Svc: svc, Queue: q, Auth: auth, Versions: DefaultVersionPolicy(), Log: log,
		Now: svc.now, MaxWait: 30 * time.Second, PollInterval: time.Second,
		TaskLease: 10 * time.Minute, MaxWaiting: 4096, MaxPerCollector: 2}
}

// Notify wakes every waiting long-poll to re-check the queue now. The
// scheduler calls it after enqueueing; PollInterval covers other processes.
func (a *API) Notify() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.wake != nil {
		close(a.wake)
	}
	a.wake = make(chan struct{})
}

// Stop releases every waiting long-poll with an empty answer, so a graceful
// shutdown does not wait out 30-second polls.
func (a *API) Stop() {
	a.mu.Lock()
	if a.stopping == nil {
		a.stopping = make(chan struct{})
	}
	ch := a.stopping
	a.mu.Unlock()
	a.stopOnce.Do(func() { close(ch) })
}

func (a *API) signals() (wake, stop chan struct{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.wake == nil {
		a.wake = make(chan struct{})
	}
	if a.stopping == nil {
		a.stopping = make(chan struct{})
	}
	return a.wake, a.stopping
}

type route struct {
	method string
	h      func(w http.ResponseWriter, r *http.Request, id enroll.Identity, body []byte, dep *Deprecation)
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(ProtocolVersionHeader, strconv.Itoa(a.Versions.Current))
	routes := map[string]route{
		"/v1/ingest/observations":  {http.MethodPost, a.observations},
		"/v1/tasks":                {http.MethodGet, a.tasks},
		"/v1/collectors/heartbeat": {http.MethodPost, a.heartbeat},
	}
	rt, ok := routes[r.URL.Path]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != rt.method {
		w.Header().Set("Allow", rt.method)
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	now := a.Now().UTC()
	_, dep, ok := a.Versions.Check(r.Header.Values(ProtocolVersionHeader), now)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "unsupported protocol version", "reason": "protocol.unsupported_version",
			"supported": a.Versions.supported(now), "upgrade_url": a.Versions.UpgradeURL,
		})
		return
	}

	var body []byte
	if rt.method == http.MethodGet {
		// A GET carries nothing. A body here would be unsigned-but-present
		// data that no handler reads — refused rather than ignored.
		if n, _ := io.ReadFull(io.LimitReader(r.Body, 1), make([]byte, 1)); n != 0 {
			writeErr(w, http.StatusBadRequest, "a GET request must not have a body")
			return
		}
	} else {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			writeErr(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return
		}
		enc := r.Header.Values("Content-Encoding")
		if len(enc) > 1 || (len(enc) == 1 && enc[0] != "gzip" && enc[0] != "identity") {
			writeErr(w, http.StatusUnsupportedMediaType, "content encoding must be gzip or identity")
			return
		}
		var err error
		body, err = a.Svc.dec.ReadBody(r.Body, len(enc) == 1 && enc[0] == "gzip")
		switch {
		case errors.Is(err, ErrKeyMaterial):
			atomic.AddInt64(&a.Svc.RejectedKeyMaterial, 1)
			// 400 and a named reason: the collector operator must be able to
			// find and fix the bug that sent us a key.
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":  "payload contained private-key material and was rejected",
				"reason": "ingest.rejected_key_material",
			})
			return
		case errors.Is(err, ErrTooLarge):
			writeErr(w, http.StatusRequestEntityTooLarge, "payload too large")
			return
		case err != nil:
			writeErr(w, http.StatusBadRequest, "payload could not be read")
			return
		}
	}

	id, err := a.Auth.Authenticate(r.Context(), r, body)
	if err != nil {
		a.authFailed(w, err, now)
		return
	}
	rt.h(w, r, id, body, dep)
}

func (a *API) authFailed(w http.ResponseWriter, err error, now time.Time) {
	switch {
	case errors.Is(err, mode2.ErrSkew):
		// The one failure the collector can act on: its clock is wrong. The
		// server's time is public information and it is what the operator
		// needs to see the size of the error.
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":  "request timestamp outside the permitted clock skew",
			"reason": "protocol.clock_skew", "server_time": now.Format(time.RFC3339),
		})
	case errors.Is(err, mode2.ErrReplay):
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "nonce already used", "reason": "protocol.replay",
		})
	case errors.Is(err, ErrTenantMismatch):
		writeErr(w, http.StatusForbidden, "signature identity does not match the enrolled key")
	default:
		// Deliberately undifferentiated: forged, wrong key, unknown key,
		// revoked, expired and malformed all look the same from outside.
		writeErr(w, http.StatusUnauthorized, "collector not authenticated")
	}
}

func (a *API) observations(w http.ResponseWriter, r *http.Request, id enroll.Identity, body []byte, _ *Deprecation) {
	b, err := DecodeBatch(body)
	switch {
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
	res, err := a.Svc.AcceptBatch(r.Context(), id, b)
	switch {
	case errors.Is(err, ErrTenantMismatch):
		writeErr(w, http.StatusForbidden, "payload tenant does not match the client certificate")
		return
	case err != nil:
		a.logErr("ingest failed", err)
		// Never echo the database error: it can carry schema and data.
		writeErr(w, http.StatusInternalServerError, "could not store the batch")
		return
	}
	dups := 0
	if res.Duplicate {
		dups = len(b.Observations)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"batch_id": b.BatchID, "accepted": res.Accepted, "rejected": 0,
		"duplicates": dups, "duplicate": res.Duplicate, "task_completed": res.TaskCompleted,
	})
}

// Task is the wire form of one task. TaskType is a closed enum on both ends.
type Task struct {
	TaskID   string        `json:"task_id"`
	Type     string        `json:"type"`
	Endpoint *TaskEndpoint `json:"endpoint,omitempty"`
	Deadline time.Time     `json:"deadline"`
}

// TaskEndpoint names what a VERIFY_ENDPOINT task checks.
type TaskEndpoint struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	SNI      string `json:"sni"`
}

// TasksResponse is the body of GET /v1/tasks.
type TasksResponse struct {
	Tasks            []Task `json:"tasks"`
	PollAfterSeconds int    `json:"poll_after_seconds"`
}

func (a *API) tasks(w http.ResponseWriter, r *http.Request, id enroll.Identity, _ []byte, _ *Deprecation) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "malformed query")
		return
	}
	wait, max := a.MaxWait, 10
	for k, v := range q {
		// Each parameter once. Parameter pollution — two values where the
		// proxy reads one and we read the other — is refused, not resolved.
		if len(v) != 1 {
			writeErr(w, http.StatusBadRequest, "query parameter repeated")
			return
		}
		n, err := strconv.Atoi(v[0])
		switch {
		case k == "wait" && err == nil && n >= 0 && time.Duration(n)*time.Second <= a.MaxWait:
			wait = time.Duration(n) * time.Second
		case k == "max" && err == nil && n >= 1 && n <= 100:
			max = n
		default:
			writeErr(w, http.StatusBadRequest, "unsupported or out-of-range query parameter")
			return
		}
	}
	if !a.acquire(id.CollectorID) {
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusTooManyRequests, "too many concurrent task requests")
		return
	}
	defer a.release(id.CollectorID)

	tctx := tenancy.WithTenant(r.Context(), id.TenantID)
	// Wall-clock, not a.Now: this is how long a connection is held open,
	// which no injected clock can shorten.
	deadline := time.Now().Add(wait)
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C
	for {
		got, err := a.Queue.ClaimForCollector(tctx, id.CollectorID, max, a.TaskLease)
		if err != nil {
			if r.Context().Err() != nil {
				return // the collector went away; nothing to answer
			}
			a.logErr("task claim failed", err)
			writeErr(w, http.StatusInternalServerError, "could not fetch tasks")
			return
		}
		if len(got) > 0 {
			out := TasksResponse{Tasks: make([]Task, 0, len(got)), PollAfterSeconds: 0}
			for _, t := range got {
				out.Tasks = append(out.Tasks, Task{TaskID: t.ID, Type: "VERIFY_ENDPOINT",
					Endpoint: &TaskEndpoint{Hostname: t.Hostname, Port: t.Port, SNI: t.SNI},
					Deadline: t.LeasedUntil})
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		left := time.Until(deadline)
		if left <= 0 {
			writeJSON(w, http.StatusOK, TasksResponse{Tasks: []Task{}, PollAfterSeconds: 0})
			return
		}
		if left > a.PollInterval {
			left = a.PollInterval
		}
		timer.Reset(left)
		wake, stop := a.signals()
		select {
		case <-r.Context().Done():
			return
		case <-stop:
			writeJSON(w, http.StatusOK, TasksResponse{Tasks: []Task{}, PollAfterSeconds: 5})
			return
		case <-wake:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
}

func (a *API) acquire(collector string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.perColl == nil {
		a.perColl = map[string]int{}
	}
	if a.waiting >= a.MaxWaiting || a.perColl[collector] >= a.MaxPerCollector {
		return false
	}
	a.waiting++
	a.perColl[collector]++
	return true
}

func (a *API) release(collector string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.waiting--
	if a.perColl[collector]--; a.perColl[collector] <= 0 {
		delete(a.perColl, collector)
	}
}

// Heartbeat is A7. Schema-closed like everything else a collector sends.
type Heartbeat struct {
	CollectorID    string   `json:"collector_id"`
	Version        string   `json:"version"`
	ScopeDigest    string   `json:"scope_digest"`
	UptimeSeconds  int64    `json:"uptime_seconds"`
	SpoolBytes     int64    `json:"spool_bytes"`
	SpoolPctFull   float64  `json:"spool_pct_full"`
	TasksCompleted int64    `json:"tasks_completed"`
	TasksFailed    int64    `json:"tasks_failed"`
	LastError      string   `json:"last_error"`
	ReachableCIDRs []string `json:"reachable_cidrs"`
}

// HeartbeatResponse tells the collector the server's time (for skew) and, for
// an old protocol, when it stops being served.
type HeartbeatResponse struct {
	ServerTime               time.Time    `json:"server_time"`
	HeartbeatIntervalSeconds int          `json:"heartbeat_interval_seconds"`
	Deprecation              *Deprecation `json:"deprecation,omitempty"`
}

var (
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionSW = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,64}$`)
)

func (a *API) heartbeat(w http.ResponseWriter, r *http.Request, id enroll.Identity, body []byte, dep *Deprecation) {
	var hb Heartbeat
	if err := decodeClosed(body, &hb); err != nil {
		if errors.Is(err, ErrUnknownField) {
			writeErr(w, http.StatusBadRequest, "payload contains an unknown field")
		} else {
			writeErr(w, http.StatusBadRequest, "payload could not be decoded")
		}
		return
	}
	if hb.CollectorID != id.CollectorID {
		_ = auditIn(r.Context(), a.Svc.st, id, "collector.heartbeat_identity_mismatch",
			map[string]string{"claimed_collector": hb.CollectorID})
		writeErr(w, http.StatusForbidden, "heartbeat collector does not match the authenticated collector")
		return
	}
	cidrs := make([]netip.Prefix, 0, len(hb.ReachableCIDRs))
	for _, c := range hb.ReachableCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "reachable_cidrs contains an invalid prefix")
			return
		}
		cidrs = append(cidrs, p.Masked())
	}
	if !versionSW.MatchString(hb.Version) || (hb.ScopeDigest != "" && !digestRE.MatchString(hb.ScopeDigest)) ||
		hb.UptimeSeconds < 0 || hb.SpoolBytes < 0 || hb.SpoolPctFull < 0 || hb.SpoolPctFull > 1 ||
		hb.TasksCompleted < 0 || hb.TasksFailed < 0 || len(hb.LastError) > 1000 || len(cidrs) > 1024 {
		writeErr(w, http.StatusBadRequest, "heartbeat field out of range")
		return
	}
	now := a.Now().UTC()
	proto, _, _ := a.Versions.Check(r.Header.Values(ProtocolVersionHeader), now)
	tctx := tenancy.WithTenant(r.Context(), id.TenantID)
	err := a.Svc.st.InTenantTx(tctx, func(ctx context.Context, tx *store.Tx) error {
		var prev *string
		if err := tx.Conn().QueryRow(ctx, `SELECT scope_digest FROM collectors WHERE id = $1::uuid FOR UPDATE`,
			id.CollectorID).Scan(&prev); err != nil {
			return err
		}
		if _, err := tx.Conn().Exec(ctx, `
			UPDATE collectors SET last_heartbeat_at = $2, last_seen_at = $2, version = $3,
			       scope_digest = COALESCE(NULLIF($4::text,''), scope_digest),
			       protocol_version = $5, spool_bytes = $6, spool_pct_full = $7,
			       tasks_completed = $8, tasks_failed = $9, last_error = NULLIF($10::text,''),
			       reachable_cidrs = $11
			 WHERE id = $1::uuid`,
			id.CollectorID, now, hb.Version, hb.ScopeDigest, proto, hb.SpoolBytes,
			hb.SpoolPctFull, hb.TasksCompleted, hb.TasksFailed, hb.LastError, cidrs); err != nil {
			return err
		}
		// A changed scope is a change in what the collector is allowed to
		// touch. It is recorded where the customer can see it.
		if hb.ScopeDigest != "" && prev != nil && *prev != hb.ScopeDigest {
			return auditTx(ctx, tx, id, "collector.scope_changed",
				map[string]string{"from": *prev, "to": hb.ScopeDigest})
		}
		return nil
	})
	if err != nil {
		a.logErr("heartbeat failed", err)
		writeErr(w, http.StatusInternalServerError, "could not record the heartbeat")
		return
	}
	writeJSON(w, http.StatusOK, HeartbeatResponse{ServerTime: now,
		HeartbeatIntervalSeconds: 300, Deprecation: dep})
}

func (a *API) logErr(msg string, err error) {
	if a.Log != nil {
		a.Log.Error(msg, safelog.Err(err))
	}
}

func auditIn(ctx context.Context, st *store.Store, id enroll.Identity, action string, detail map[string]string) error {
	return st.InTenantTx(tenancy.WithTenant(ctx, id.TenantID), func(ctx context.Context, tx *store.Tx) error {
		return auditTx(ctx, tx, id, action, detail)
	})
}

func auditTx(ctx context.Context, tx *store.Tx, id enroll.Identity, action string, detail map[string]string) error {
	d, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Conn().Exec(ctx, `
		INSERT INTO audit_events (tenant_id, actor_kind, action, object_kind, object_id, detail)
		VALUES ($1::uuid,'collector',$2,'collector',$3::uuid,$4::jsonb)`,
		id.TenantID.String(), action, id.CollectorID, string(d))
	return err
}
