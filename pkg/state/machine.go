package state

import (
	"time"

	"github.com/certwatch/certwatch/pkg/verify"
)

// Observe folds one verification result into an endpoint's state and returns
// the new state plus any events that fold produced.
//
// PURE: no clock, no I/O, no mutation of the input. The caller owns `now`,
// persistence and scheduling. Give it a slice of results and a stepping clock
// and you can replay five days of history in a millisecond, which is how the
// scenario tests in this package work.
//
// Events are emitted ONLY on a confirmed change:
//
//	SOFT -> HARD          EventHardTransition   (this is what pages)
//	HARD -> OK            EventRecovery         (only if the HARD actually paged)
//	HARD -> worse HARD    EventEscalation       (near_expiry becoming expired)
//
// A repeated observation of an unchanged HARD state emits NOTHING. That is the
// deduplication requirement, and it is structural here rather than a filter
// bolted on afterwards: there is no code path that emits on an unchanged state.
func Observe(prev EndpointState, r verify.Result, now time.Time, th Thresholds) (EndpointState, []Event) {
	if th.Default == 0 && th.BySubReason == nil {
		th = DefaultThresholds()
	}
	if th.HistoryLimit <= 0 {
		th.HistoryLimit = DefaultThresholds().HistoryLimit
	}

	next := prev
	next.Endpoint = r.Endpoint
	next.History = append([]Transition(nil), prev.History...) // never alias the caller's slice
	next.LastObserved = now
	next.TotalObservations = prev.TotalObservations + 1
	if prev.FirstObserved.IsZero() {
		next.FirstObserved = now
	}
	if prev.Status == "" {
		next.Status = StatusUnknown
	}

	var events []Event
	clean := r.Outcome == verify.OutcomePass

	// An outcome that is not alertable must never page. R1: no alert without a
	// human-confirmed expectation; and a finding inside a grace window has been
	// deliberately suppressed. State is still tracked so the UI can show it —
	// invisible is worse than quiet.
	eventable := r.Alertable

	switch {
	case clean:
		next.Outcome = r.Outcome
		next.SubReason = ""
		next.Severity = SeverityInfo
		next.Consecutive = 0
		next.Threshold = 0
		next.SoftSince = time.Time{}

		if prev.Status == StatusHard {
			// Only announce recovery for something that actually announced a
			// problem. A recovery notice for an event nobody received is noise
			// that teaches people to mute the channel.
			if prev.Alerted {
				events = append(events, Event{
					Kind: EventRecovery, At: now, Endpoint: r.Endpoint,
					Outcome: r.Outcome, Severity: SeverityInfo,
					PreviousSubReason: prev.SubReason,
					Summary: "recovered: " + prev.SubReason + " cleared; " +
						r.Summary,
					Observations: 1,
					DedupeKey:    dedupeKey(r.Endpoint, EventRecovery, prev.SubReason),
				})
			}
			next.History = appendTransition(next.History, th.HistoryLimit, Transition{
				At: now, From: prev.Status, To: StatusOK, Outcome: r.Outcome,
				Note: "cleared: " + prev.SubReason,
			})
			next.LastChanged = now
		} else if prev.Status != StatusOK {
			next.History = appendTransition(next.History, th.HistoryLimit, Transition{
				At: now, From: prev.Status, To: StatusOK, Outcome: r.Outcome,
			})
			next.LastChanged = now
		}
		next.Status = StatusOK
		next.Alerted = false
		next.NextCheckAt = now.Add(th.NormalInterval)

	default:
		sev := SeverityFor(r.SubReason)
		sameFinding := prev.SubReason == r.SubReason && prev.Status != StatusOK &&
			prev.Status != StatusUnknown && prev.Status != ""

		if sameFinding {
			next.Consecutive = prev.Consecutive + 1
		} else {
			// A different sub-reason is a different finding. Two unrelated
			// problems are not corroborating evidence for each other, so the
			// count restarts rather than carrying over.
			next.Consecutive = 1
			next.SoftSince = now
		}
		threshold := th.For(r.SubReason)
		next.Outcome = r.Outcome
		next.SubReason = r.SubReason
		next.Severity = sev
		next.Threshold = threshold

		confirmed := next.Consecutive >= threshold
		// A finding still unconfirmed when the re-check window closes is
		// promoted on the evidence available. Re-checking forever is just a
		// slower way of never reporting it.
		if !confirmed && !next.SoftSince.IsZero() &&
			th.RecheckWindow > 0 && now.Sub(next.SoftSince) >= th.RecheckWindow {
			confirmed = true
		}

		switch {
		case confirmed && prev.Status == StatusHard && sameFinding:
			// Already hard, same finding, nothing new to say.
			next.Status = StatusHard

		case confirmed && prev.Status == StatusHard && !sameFinding:
			next.Status = StatusHard
			kind := EventHardTransition
			if sev.Rank() > SeverityFor(prev.SubReason).Rank() {
				kind = EventEscalation
			}
			if eventable {
				events = append(events, Event{
					Kind: kind, At: now, Endpoint: r.Endpoint,
					Outcome: r.Outcome, SubReason: r.SubReason, Severity: sev,
					PreviousSubReason: prev.SubReason,
					Summary:           r.Summary,
					Observations:      next.Consecutive,
					DedupeKey:         dedupeKey(r.Endpoint, kind, r.SubReason),
				})
				next.TotalHardEvents = prev.TotalHardEvents + 1
				next.Alerted = true
			}
			next.History = appendTransition(next.History, th.HistoryLimit, Transition{
				At: now, From: StatusHard, To: StatusHard, Outcome: r.Outcome,
				SubReason: r.SubReason, Severity: sev,
				Note: "changed from " + prev.SubReason,
			})
			next.LastChanged = now

		case confirmed:
			next.Status = StatusHard
			if eventable {
				events = append(events, Event{
					Kind: EventHardTransition, At: now, Endpoint: r.Endpoint,
					Outcome: r.Outcome, SubReason: r.SubReason, Severity: sev,
					Summary:      r.Summary,
					Observations: next.Consecutive,
					DedupeKey:    dedupeKey(r.Endpoint, EventHardTransition, r.SubReason),
				})
				next.TotalHardEvents = prev.TotalHardEvents + 1
				next.Alerted = true
			}
			next.History = appendTransition(next.History, th.HistoryLimit, Transition{
				At: now, From: prev.Status, To: StatusHard, Outcome: r.Outcome,
				SubReason: r.SubReason, Severity: sev,
			})
			next.LastChanged = now

		default:
			if prev.Status != StatusSoft || !sameFinding {
				next.History = appendTransition(next.History, th.HistoryLimit, Transition{
					At: now, From: prev.Status, To: StatusSoft, Outcome: r.Outcome,
					SubReason: r.SubReason, Severity: sev,
				})
				next.LastChanged = now
			}
			next.Status = StatusSoft
			next.Alerted = false
		}

		// Item 081: while a finding is unconfirmed, look again soon. This is
		// the short-interval re-check that separates a rolling deploy from a
		// pool that never converged — the whole reason this package exists.
		if next.Status == StatusSoft && th.RecheckInterval > 0 {
			next.NextCheckAt = now.Add(th.RecheckInterval)
		} else {
			next.NextCheckAt = now.Add(th.NormalInterval)
		}
	}

	sortEvents(events)
	return next, events
}

// appendTransition keeps the newest entries and bounds memory. An unbounded
// history on a flapping endpoint is a slow memory leak.
func appendTransition(h []Transition, limit int, t Transition) []Transition {
	h = append(h, t)
	if len(h) > limit {
		h = append([]Transition(nil), h[len(h)-limit:]...)
	}
	return h
}

// DueAt reports whether this endpoint is due for another observation.
func (s EndpointState) DueAt(now time.Time) bool {
	return s.NextCheckAt.IsZero() || !now.Before(s.NextCheckAt)
}

// Alerting reports whether the endpoint is currently in a confirmed, announced
// bad state. This is what a dashboard's "needs attention" count is built from.
func (s EndpointState) Alerting() bool {
	return s.Status == StatusHard && s.Alerted
}
