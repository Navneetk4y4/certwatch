// Package alert turns confirmed state transitions into delivered notifications.
//
// E13.
//
// # Why there is an outbox
//
// Network delivery is NEVER coupled to the transaction that records a state
// change. If it were, a notification provider being slow would hold a database
// transaction open, and a provider being down would roll back the state change
// that caused it — so the next observation would see an unchanged state, emit
// nothing, and the finding would be lost entirely.
//
// Instead the transition writes an alert and a PENDING delivery row in the
// same transaction, and a separate worker drains that outbox. A provider
// outage delays notifications; it never loses findings.
//
// # Three separate things that all get called "deduplication"
//
//  1. pkg/state      does not emit on an unchanged state at all.
//  2. alerts         a partial unique index: at most ONE open alert per
//     dedupe key per tenant. Two workers racing cannot both
//     create one.
//  3. cooldown       a REPEAT of an already-open alert does not re-notify
//     until the cooldown has passed.
//
// The first stops repeat observations becoming events. The second stops a race
// becoming two alerts. The third stops a long-running problem becoming hourly
// noise. Removing any one of them produces a different failure.
package alert

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
	"github.com/certwatch/certwatch/pkg/state"
)

// Config tunes the pipeline.
type Config struct {
	// Cooldown is the minimum gap between notifications for the SAME open
	// alert. A problem that lasts a week should not page every cycle.
	Cooldown time.Duration
	// MaxAttempts bounds delivery retries before a delivery is abandoned.
	MaxAttempts int
	// BaseBackoff doubles per attempt.
	BaseBackoff time.Duration
	// Channels are the destinations to fan out to.
	Channels []string
}

// DefaultConfig is deliberately quiet.
func DefaultConfig() Config {
	return Config{
		Cooldown:    4 * time.Hour,
		MaxAttempts: 5,
		BaseBackoff: time.Minute,
		Channels:    []string{"email"},
	}
}

// Notifier delivers one notification. Implementations are expected to be
// network calls and to fail.
type Notifier interface {
	// Channel names the destination this notifier serves.
	Channel() string
	// Send delivers. An error schedules a retry.
	Send(ctx context.Context, n Notification) error
}

// Notification is what a channel receives.
type Notification struct {
	AlertID   string
	TenantID  tenancy.Tenant
	Kind      string // hard_transition | recovery | escalation
	Severity  string
	SubReason string
	Summary   string
	Endpoint  string
	At        time.Time
}

// Pipeline creates alerts and drains the outbox.
type Pipeline struct {
	st        *store.Store
	log       *safelog.Logger
	cfg       Config
	now       func() time.Time
	notifiers map[string]Notifier
}

// New builds the pipeline.
func New(st *store.Store, log *safelog.Logger, cfg Config, now func() time.Time,
	notifiers ...Notifier) *Pipeline {
	if now == nil {
		now = time.Now
	}
	if cfg.MaxAttempts <= 0 {
		cfg = DefaultConfig()
	}
	m := map[string]Notifier{}
	for _, n := range notifiers {
		m[n.Channel()] = n
	}
	return &Pipeline{st: st, log: log, cfg: cfg, now: now, notifiers: m}
}

// RecordEvents turns state events into alerts and queued deliveries.
//
// MUST be called in the same logical unit as the state change it came from —
// see internal/history, which calls it inside its transaction via Tx.
func (p *Pipeline) RecordEvents(ctx context.Context, tx *store.Tx, endpointID string,
	events []state.Event) (created int, err error) {
	for _, e := range events {
		switch e.Kind {
		case state.EventRecovery:
			n, err := p.resolveOpen(ctx, tx, endpointID, e)
			if err != nil {
				return created, err
			}
			created += n
		default:
			n, err := p.openOrRefresh(ctx, tx, endpointID, e)
			if err != nil {
				return created, err
			}
			created += n
		}
	}
	return created, nil
}

// openOrRefresh creates an alert, or refreshes an existing open one.
//
// The partial unique index on (tenant, dedupe_key) WHERE state <> 'resolved'
// means at most one open alert per finding, whatever two racing workers do.
//
// MEASURED EQUIVALENCE, recorded so nobody re-derives it. Removing the
// ON CONFLICT clause fails NO test, and that is correct rather than a gap:
// internal/history upserts endpoint_state in the same transaction, and that
// upsert takes a ROW LOCK on the endpoint. Concurrent folds for one endpoint
// therefore serialize there — the second fold reads the already-hard state and
// pkg/state emits nothing, so a second INSERT never happens. Racing the
// CONFIRMING observation with eight goroutines does not reach it either.
//
// The clause stays as defence in depth: it costs nothing and it is what would
// hold if the endpoint_state lock were ever removed. Writing a test that
// pretends to distinguish it would be inventing coverage.
func (p *Pipeline) openOrRefresh(ctx context.Context, tx *store.Tx, endpointID string,
	e state.Event) (int, error) {
	tid := tx.Tenant().String()
	now := p.now().UTC()

	var alertID string
	err := tx.Conn().QueryRow(ctx, `
		INSERT INTO alerts
		  (tenant_id, endpoint_id, severity, sub_reason, summary, dedupe_key, created_at)
		VALUES ($1::uuid,$2::uuid,$3::severity,$4,$5,$6,$7)
		ON CONFLICT (tenant_id, dedupe_key) WHERE state <> 'resolved' DO NOTHING
		RETURNING id::text`,
		tid, endpointID, string(e.Severity), e.SubReason, e.Summary,
		e.DedupeKey, now).Scan(&alertID)

	if errors.Is(err, pgx.ErrNoRows) {
		// Already open: nothing created, nothing queued. Reminders are
		// RenotifyOverdue's job, on a schedule.
		return p.alreadyOpen()
	}
	if err != nil {
		return 0, fmt.Errorf("alert: creating: %w", err)
	}
	if err := p.queue(ctx, tx, alertID, now); err != nil {
		return 0, err
	}
	return 1, nil
}

// alreadyOpen is the ON CONFLICT path: an alert for this finding is already
// open, so nothing is created and nothing is queued.
//
// Re-notification deliberately does NOT happen here. It cannot: this path is
// only reached when there is an EVENT, and pkg/state correctly emits no event
// for an unchanged hard state — so a long-running problem produces exactly one
// event, ever. Hanging the cooldown off this path made it dead code that could
// never fire. Found by a test that expected a second notification after the
// cooldown and never got one.
//
// Reminding somebody about a still-open alert is a periodic sweep over open
// alerts, which is what RenotifyOverdue does.
func (p *Pipeline) alreadyOpen() (int, error) { return 0, nil }

// RenotifyOverdue queues another notification for every open alert whose last
// delivery is older than the cooldown.
//
// Call it on a schedule, not from the fold. It is the reminder path: a problem
// that has been open for a week should be mentioned again, but not every cycle.
func (p *Pipeline) RenotifyOverdue(ctx context.Context) (int, error) {
	now := p.now().UTC()
	queued := 0
	err := p.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		rows, err := tx.Conn().Query(ctx, `
			SELECT a.id::text
			  FROM alerts a
			 WHERE a.state <> 'resolved'
			   AND COALESCE(
			         (SELECT max(d.created_at) FROM alert_deliveries d WHERE d.alert_id = a.id),
			         a.created_at) <= $1`,
			now.Add(-p.cfg.Cooldown))
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			if err := p.queue(ctx, tx, id, now); err != nil {
				return err
			}
			queued++
		}
		return nil
	})
	return queued, err
}

// resolveOpen closes the matching open alert and queues a recovery notice.
func (p *Pipeline) resolveOpen(ctx context.Context, tx *store.Tx, endpointID string,
	e state.Event) (int, error) {
	now := p.now().UTC()
	// The recovery event's dedupe key names the recovery; the alert that is
	// being resolved was keyed on the ORIGINAL finding. Match on the endpoint
	// and the previous sub-reason.
	var alertID string
	err := tx.Conn().QueryRow(ctx, `
		UPDATE alerts SET state='resolved', resolved_at=$3
		 WHERE endpoint_id = $1::uuid AND state <> 'resolved'
		   AND ($2 = '' OR sub_reason = $2)
		RETURNING id::text`, endpointID, e.PreviousSubReason, now).Scan(&alertID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Nothing was open. A recovery notice for an alert nobody received is
		// noise, so nothing is queued.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return 0, p.queue(ctx, tx, alertID, now)
}

// queue writes one PENDING delivery per configured channel. This is the
// outbox: nothing here touches the network.
func (p *Pipeline) queue(ctx context.Context, tx *store.Tx, alertID string, now time.Time) error {
	for _, ch := range p.cfg.Channels {
		if _, err := tx.Conn().Exec(ctx, `
			INSERT INTO alert_deliveries
			  (tenant_id, alert_id, channel, status, next_attempt_at, created_at)
			VALUES ($1::uuid,$2::uuid,$3,'pending',$4,$4)`,
			tx.Tenant().String(), alertID, ch, now); err != nil {
			return fmt.Errorf("alert: queueing delivery: %w", err)
		}
	}
	return nil
}

// Drain delivers pending notifications for the tenant in ctx.
//
// Separate from the transaction that created them. A provider outage delays
// notifications and never rolls back a state change.
func (p *Pipeline) Drain(ctx context.Context, limit int) (sent, failed int, err error) {
	if limit <= 0 {
		limit = 50
	}
	type pending struct {
		id, alertID, channel string
		attempts             int
		n                    Notification
	}
	var batch []pending
	now := p.now().UTC()

	err = p.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		rows, err := tx.Conn().Query(ctx, `
			SELECT d.id::text, d.alert_id::text, d.channel, d.attempts,
			       a.severity::text, COALESCE(a.sub_reason,''), a.summary,
			       COALESCE(e.hostname,''), COALESCE(e.port,0), a.created_at, a.state
			  FROM alert_deliveries d
			  JOIN alerts a ON a.id = d.alert_id
			  LEFT JOIN endpoints e ON e.id = a.endpoint_id
			 WHERE d.status = 'pending'
			   AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= $1)
			 ORDER BY d.created_at
			 FOR UPDATE OF d SKIP LOCKED
			 LIMIT $2`, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var pd pending
			var host, aState string
			var port int
			if err := rows.Scan(&pd.id, &pd.alertID, &pd.channel, &pd.attempts,
				&pd.n.Severity, &pd.n.SubReason, &pd.n.Summary, &host, &port,
				&pd.n.At, &aState); err != nil {
				return err
			}
			pd.n.AlertID = pd.alertID
			pd.n.TenantID = tx.Tenant()
			pd.n.Endpoint = fmt.Sprintf("%s:%d", host, port)
			pd.n.Kind = "hard_transition"
			if aState == "resolved" {
				pd.n.Kind = "recovery"
			}
			batch = append(batch, pd)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, 0, err
	}

	for _, pd := range batch {
		n, ok := p.notifiers[pd.channel]
		if !ok {
			// No notifier for this channel. Drop it explicitly rather than
			// retrying forever against something that does not exist.
			_ = p.mark(ctx, pd.id, "dropped", "no notifier configured for this channel", 0)
			failed++
			continue
		}
		sendErr := n.Send(ctx, pd.n)
		if sendErr == nil {
			if err := p.mark(ctx, pd.id, "delivered", "", 0); err != nil {
				return sent, failed, err
			}
			sent++
			continue
		}
		failed++
		attempts := pd.attempts + 1
		if attempts >= p.cfg.MaxAttempts {
			// Terminal. The row stays as evidence: "why was nobody told"
			// must be answerable.
			if err := p.mark(ctx, pd.id, "failed", sendErr.Error(), 0); err != nil {
				return sent, failed, err
			}
			continue
		}
		backoff := p.cfg.BaseBackoff
		for i := 1; i < attempts; i++ {
			backoff *= 2
		}
		if err := p.mark(ctx, pd.id, "pending", sendErr.Error(), backoff); err != nil {
			return sent, failed, err
		}
	}
	return sent, failed, nil
}

func (p *Pipeline) mark(ctx context.Context, deliveryID, status, errText string,
	backoff time.Duration) error {
	now := p.now().UTC()
	return p.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var next any
		if status == "pending" {
			next = now.Add(backoff)
		}
		var delivered any
		if status == "delivered" {
			delivered = now
		}
		_, err := tx.Conn().Exec(ctx, `
			UPDATE alert_deliveries
			   SET status = $2, attempts = attempts + 1,
			       last_error = NULLIF($3,''), next_attempt_at = $4, delivered_at = $5
			 WHERE id = $1::uuid`,
			deliveryID, status, truncate(errText, 1000), next, delivered)
		return err
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Open returns the tenant's open alerts, newest first.
func (p *Pipeline) Open(ctx context.Context, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []Notification
	err := p.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		rows, err := tx.Conn().Query(ctx, `
			SELECT a.id::text, a.severity::text, COALESCE(a.sub_reason,''), a.summary,
			       COALESCE(e.hostname,''), COALESCE(e.port,0), a.created_at
			  FROM alerts a LEFT JOIN endpoints e ON e.id = a.endpoint_id
			 WHERE a.state <> 'resolved'
			 ORDER BY a.created_at DESC LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n Notification
			var host string
			var port int
			if err := rows.Scan(&n.AlertID, &n.Severity, &n.SubReason, &n.Summary,
				&host, &port, &n.At); err != nil {
				return err
			}
			n.TenantID = tx.Tenant()
			n.Endpoint = fmt.Sprintf("%s:%d", host, port)
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}
