// Package history persists observations and state transitions.
//
// E12. It is the bridge between pkg/state, which is a pure function over one
// observation, and a database that remembers what happened.
//
// # The division of labour
//
//	pkg/state   decides. Pure, no clock, no I/O, fully testable.
//	history     remembers. Loads the previous state, calls Observe, writes the
//	            new state and any events, in ONE transaction.
//
// Keeping the decision pure and the memory separate is what lets a five-day
// sequence be replayed in a millisecond in pkg/state's tests, while the
// durability question is tested here against real PostgreSQL.
//
// # Why the whole fold is one transaction
//
// Writing the new state and its events separately means a crash between them
// leaves a state that says "hard" with no event recorded — an endpoint that is
// failing and will never page, because the next observation sees an unchanged
// state and correctly emits nothing. One transaction makes that unreachable.
package history

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/state"
	"github.com/certwatch/certwatch/pkg/verify"
)

// EventSink receives the events a fold produced, inside the SAME transaction.
//
// internal/alert implements this. Keeping it an interface means history does
// not import alert, so the dependency runs one way and a test can observe
// events without an alert pipeline.
type EventSink interface {
	RecordEvents(ctx context.Context, tx *store.Tx, endpointID string,
		events []state.Event) (int, error)
}

// Recorder folds verification results into durable state.
type Recorder struct {
	st         *store.Store
	thresholds state.Thresholds
	sink       EventSink
}

// New builds a Recorder.
func New(st *store.Store, th state.Thresholds) *Recorder {
	if th.Default == 0 && th.BySubReason == nil {
		th = state.DefaultThresholds()
	}
	return &Recorder{st: st, thresholds: th}
}

// WithSink attaches an event sink — in production, the alert pipeline.
//
// It runs inside the fold's transaction on purpose: an alert that exists
// without the state change that caused it, or a state change whose alert was
// lost, are both worse than either succeeding or both failing.
func (r *Recorder) WithSink(s EventSink) *Recorder {
	r.sink = s
	return r
}

// Outcome is what one recorded observation produced.
type Outcome struct {
	State  state.EndpointState
	Events []state.Event
	// Duplicate is true when this exact run was already recorded and nothing
	// was changed. Idempotency, not an error.
	Duplicate bool
}

// Record persists one verification result for one endpoint.
//
// runID makes it idempotent: a collector that retries after a network timeout
// must not double-count an observation, because double-counting advances the
// consecutive counter and can confirm a finding that was only seen once.
func (r *Recorder) Record(ctx context.Context, endpointID string,
	res verify.Result, now time.Time, runID string) (Outcome, error) {
	if _, err := tenancy.FromContext(ctx); err != nil {
		return Outcome{}, err
	}
	var out Outcome
	err := r.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		tid := tx.Tenant().String()

		// Idempotency first. A unique index on (tenant, endpoint, run_id)
		// backs this; the check here turns the conflict into a clean answer
		// instead of an error.
		if runID != "" {
			var exists bool
			if err := tx.Conn().QueryRow(ctx, `
				SELECT EXISTS(SELECT 1 FROM verification_results
				               WHERE endpoint_id = $1::uuid AND run_id = $2)`,
				endpointID, runID).Scan(&exists); err != nil {
				return err
			}
			if exists {
				out.Duplicate = true
				st, err := r.loadState(ctx, tx, endpointID)
				if err != nil {
					return err
				}
				out.State = st
				return nil
			}
		}

		prev, err := r.loadState(ctx, tx, endpointID)
		if err != nil {
			return err
		}

		// The decision. Pure, and the only place it happens.
		next, events := state.Observe(prev, res, now, r.thresholds)
		out.State, out.Events = next, events

		perIP, err := json.Marshal(res.PerIP)
		if err != nil {
			return err
		}
		if _, err := tx.Conn().Exec(ctx, `
			INSERT INTO verification_results
			  (tenant_id, endpoint_id, outcome, sub_reason, summary,
			   ips_resolved, ips_checked, ips_matching, ips_unreachable,
			   ips_tls_error, ips_skipped, partial_rollout, divergence,
			   suppressed, alertable, per_ip, run_id, checked_at)
			VALUES ($1::uuid,$2::uuid,$3::verify_outcome,$4,$5,
			        $6::inet[],$7::inet[],$8::inet[],$9::inet[],
			        $10::inet[],$11::inet[],$12,$13,$14,$15,$16::jsonb,
			        NULLIF($17::text,''),$18)`,
			tid, endpointID, string(res.Outcome), res.SubReason, res.Summary,
			// A nil slice means "none", not "unknown". Passing nil would send
			// SQL NULL and defeat the column default, so every address list is
			// normalised to an empty array first.
			addrs(res.IPsResolved), addrs(res.IPsChecked), addrs(res.IPsMatching),
			addrs(res.IPsUnreachable), addrs(res.IPsTLSError), addrs(res.IPsSkipped),
			res.PartialRollout,
			res.FingerprintDivergence, res.Suppressed, res.Alertable,
			perIP, runID, now.UTC()); err != nil {
			return fmt.Errorf("history: recording result: %w", err)
		}

		if err := r.saveState(ctx, tx, tid, endpointID, next); err != nil {
			return err
		}
		// Same transaction as the state. A crash between the two would leave
		// a "hard" state with no event, which never pages and never retries.
		for _, e := range events {
			if _, err := tx.Conn().Exec(ctx, `
				INSERT INTO drift_events
				  (tenant_id, endpoint_id, kind, to_status, outcome, sub_reason,
				   previous_sub_reason, severity, summary, observations, dedupe_key, at)
				VALUES ($1::uuid,$2::uuid,$3,$4::state_status,$5::verify_outcome,$6,$7,
				        $8::severity,$9,$10,$11,$12)`,
				tid, endpointID, string(e.Kind), string(next.Status),
				nullableOutcome(e.Outcome), e.SubReason, e.PreviousSubReason,
				string(e.Severity), e.Summary, e.Observations, e.DedupeKey,
				e.At.UTC()); err != nil {
				return fmt.Errorf("history: recording event: %w", err)
			}
		}
		if r.sink != nil && len(events) > 0 {
			if _, err := r.sink.RecordEvents(ctx, tx, endpointID, events); err != nil {
				return fmt.Errorf("history: alerting: %w", err)
			}
		}
		return nil
	})
	return out, err
}

// addrs normalises a possibly-nil address list to an empty slice.
func addrs(a []string) []string {
	if a == nil {
		return []string{}
	}
	return a
}

func nullableOutcome(o verify.Outcome) any {
	if o == "" {
		return nil
	}
	return string(o)
}

func (r *Recorder) loadState(ctx context.Context, tx *store.Tx, endpointID string) (state.EndpointState, error) {
	var s state.EndpointState
	var (
		status, sub, sev, outcome        *string
		first, last, changed, soft, next *time.Time
	)
	err := tx.Conn().QueryRow(ctx, `
		SELECT status::text, outcome::text, sub_reason, severity::text,
		       consecutive, threshold, alerted, first_observed, last_observed,
		       last_changed, soft_since, next_check_at,
		       total_observations, total_hard_events
		  FROM endpoint_state WHERE endpoint_id = $1::uuid`, endpointID).
		Scan(&status, &outcome, &sub, &sev, &s.Consecutive, &s.Threshold,
			&s.Alerted, &first, &last, &changed, &soft, &next,
			&s.TotalObservations, &s.TotalHardEvents)
	if errors.Is(err, pgx.ErrNoRows) {
		// No prior state is the zero value, which pkg/state treats as
		// "nothing observed yet". Not an error.
		return state.EndpointState{}, nil
	}
	if err != nil {
		return state.EndpointState{}, err
	}
	if status != nil {
		s.Status = state.Status(*status)
	}
	if outcome != nil {
		s.Outcome = verify.Outcome(*outcome)
	}
	if sub != nil {
		s.SubReason = *sub
	}
	if sev != nil {
		s.Severity = state.Severity(*sev)
	}
	for dst, src := range map[*time.Time]*time.Time{
		&s.FirstObserved: first, &s.LastObserved: last, &s.LastChanged: changed,
		&s.SoftSince: soft, &s.NextCheckAt: next,
	} {
		if src != nil {
			*dst = *src
		}
	}
	return s, nil
}

func (r *Recorder) saveState(ctx context.Context, tx *store.Tx, tid, endpointID string,
	s state.EndpointState) error {
	_, err := tx.Conn().Exec(ctx, `
		INSERT INTO endpoint_state
		  (endpoint_id, tenant_id, status, outcome, sub_reason, severity,
		   consecutive, threshold, alerted, first_observed, last_observed,
		   last_changed, soft_since, next_check_at, total_observations, total_hard_events)
		VALUES ($1::uuid,$2::uuid,$3::state_status,
		        NULLIF($4,'')::verify_outcome, NULLIF($5,''), NULLIF($6,'')::severity,
		        $7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (endpoint_id) DO UPDATE SET
		  status=EXCLUDED.status, outcome=EXCLUDED.outcome,
		  sub_reason=EXCLUDED.sub_reason, severity=EXCLUDED.severity,
		  consecutive=EXCLUDED.consecutive, threshold=EXCLUDED.threshold,
		  alerted=EXCLUDED.alerted, first_observed=EXCLUDED.first_observed,
		  last_observed=EXCLUDED.last_observed, last_changed=EXCLUDED.last_changed,
		  soft_since=EXCLUDED.soft_since, next_check_at=EXCLUDED.next_check_at,
		  total_observations=EXCLUDED.total_observations,
		  total_hard_events=EXCLUDED.total_hard_events`,
		endpointID, tid, string(s.Status), string(s.Outcome), s.SubReason,
		string(s.Severity), s.Consecutive, s.Threshold, s.Alerted,
		nullableTime(s.FirstObserved), nullableTime(s.LastObserved),
		nullableTime(s.LastChanged), nullableTime(s.SoftSince),
		nullableTime(s.NextCheckAt), s.TotalObservations, s.TotalHardEvents)
	return err
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

// StateOf returns the durable state for one endpoint.
func (r *Recorder) StateOf(ctx context.Context, endpointID string) (state.EndpointState, error) {
	var s state.EndpointState
	err := r.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		var e error
		s, e = r.loadState(ctx, tx, endpointID)
		return e
	})
	return s, err
}

// Transition is one row of the history view.
type Transition struct {
	At                time.Time
	Kind              string
	ToStatus          string
	Outcome           string
	SubReason         string
	PreviousSubReason string
	Severity          string
	Summary           string
	Observations      int
}

// TransitionsFor returns an endpoint's transition history, newest first.
//
// TRANSITIONS, not readings. A reading every five minutes for a year is
// 105,000 rows of noise; the transitions are the story.
func (r *Recorder) TransitionsFor(ctx context.Context, endpointID string, limit int) ([]Transition, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []Transition
	err := r.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		rows, err := tx.Conn().Query(ctx, `
			SELECT at, kind, COALESCE(to_status::text,''), COALESCE(outcome::text,''),
			       COALESCE(sub_reason,''), COALESCE(previous_sub_reason,''),
			       severity::text, COALESCE(summary,''), observations
			  FROM drift_events
			 WHERE endpoint_id = $1::uuid
			 ORDER BY at DESC, id DESC
			 LIMIT $2`, endpointID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Transition
			if err := rows.Scan(&t.At, &t.Kind, &t.ToStatus, &t.Outcome,
				&t.SubReason, &t.PreviousSubReason, &t.Severity,
				&t.Summary, &t.Observations); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// Due returns endpoints whose next check has come due, for the scheduler.
func (r *Recorder) Due(ctx context.Context, now time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []string
	err := r.st.InTenantTx(ctx, func(ctx context.Context, tx *store.Tx) error {
		rows, err := tx.Conn().Query(ctx, `
			SELECT e.id::text
			  FROM endpoints e
			  LEFT JOIN endpoint_state s ON s.endpoint_id = e.id
			 WHERE e.disabled_at IS NULL
			   AND (s.next_check_at IS NULL OR s.next_check_at <= $1)
			 ORDER BY COALESCE(s.next_check_at, 'epoch'::timestamptz)
			 LIMIT $2`, now.UTC(), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}
