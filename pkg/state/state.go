// Package state turns a SEQUENCE of point-in-time verification results into a
// state that can be alerted on.
//
// # Why this package has to exist
//
// pkg/verify.Classify is a pure function of ONE observation. At one instant a
// rolling deployment and a pool that will never converge are indistinguishable:
// both show some addresses serving the expected certificate and some not.
// Alerting on the first sight of that pages someone for every deploy, which is
// R2 in the risk register, rated Fatal.
//
// The discriminator is time. A rolling deploy converges within minutes; a stuck
// backend does not. So a finding is SOFT when first seen and becomes HARD only
// after it has survived N consecutive observations. Only a HARD transition
// produces an event.
//
// # Two design rules, inherited from pkg/verify
//
//  1. Observe is a PURE function of (state, result, now). No I/O, no clock, no
//     network. Persistence and scheduling live above it. A state machine that
//     reads the clock cannot be tested against a five-day sequence in a
//     millisecond.
//  2. The caller supplies `now`. Never time.Now() in here.
//
// # What SOFT does not mean
//
// SOFT is not "probably fine". It is "seen once, not yet confirmed". A SOFT
// expired certificate is still an outage — which is why the threshold table
// below gives expiry N=1 and partial rollout N=3.
package state

import (
	"fmt"
	"sort"
	"time"

	"github.com/certwatch/certwatch/pkg/verify"
)

// Status is where an endpoint sits in the soft/hard lifecycle.
type Status string

const (
	// StatusOK means the last observation was clean.
	StatusOK Status = "ok"
	// StatusSoft means a non-clean outcome has been seen but not yet
	// confirmed by enough consecutive observations.
	StatusSoft Status = "soft"
	// StatusHard means the finding is confirmed. Only this produces an event.
	StatusHard Status = "hard"
	// StatusUnknown means nothing has been observed yet.
	StatusUnknown Status = "unknown"
)

// Severity is what an operator sorts by. Deliberately separate from Outcome:
// two endpoints can both be FAILURE and not deserve the same response.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank orders severities for sorting. Higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// severityBySubReason is build item 084, the severity mapping table.
//
// The ordering argument, written down so it can be disagreed with:
//
//   - An EXPIRED certificate is a live outage. Nothing outranks it.
//   - A PARTIAL ROLLOUT is critical because it is invisible to every
//     hostname-level monitor the customer already owns. They will not find it
//     any other way, and a fraction of their traffic is already failing.
//   - Complete drift to a still-valid certificate is HIGH, not critical: the
//     endpoint works, but it is not serving what anyone approved.
//   - A configuration error is MEDIUM and never critical. It is our problem or
//     a typo, not their outage, and paging on it teaches people to ignore us.
var severityBySubReason = map[string]Severity{
	verify.ReasonExpired:                SeverityCritical,
	verify.ReasonPartialRollout:         SeverityCritical,
	verify.ReasonAllUnreachable:         SeverityHigh,
	verify.ReasonNotYetValid:            SeverityHigh,
	verify.ReasonSANMismatch:            SeverityHigh,
	verify.ReasonUnexpectedButValid:     SeverityHigh,
	verify.ReasonIssuerNotAllowed:       SeverityHigh,
	verify.ReasonWeakKey:                SeverityHigh,
	verify.ReasonKeyAlgorithmNotAllowed: SeverityHigh,
	verify.ReasonFingerprintDivergence:  SeverityMedium,
	verify.ReasonNearExpiry:             SeverityMedium,
	verify.ReasonPartialReachability:    SeverityMedium,
	verify.ReasonChainIncomplete:        SeverityMedium,
	verify.ReasonInvalidExpectation:     SeverityMedium,
	verify.ReasonNotInForce:             SeverityLow,
	verify.ReasonNoConfirmedExpectation: SeverityInfo,
	verify.ReasonSettling:               SeverityInfo,
	verify.ReasonDNSFailure:             SeverityHigh,
}

// SeverityFor maps a sub-reason to its severity. An unmapped sub-reason is
// MEDIUM rather than INFO: an outcome nobody has classified yet is more likely
// to be an oversight than to be unimportant, and silently filing it as INFO is
// how a new failure mode goes unnoticed.
func SeverityFor(subReason string) Severity {
	if s, ok := severityBySubReason[subReason]; ok {
		return s
	}
	if subReason == "" {
		return SeverityInfo
	}
	return SeverityMedium
}

// Thresholds is build item 080: how many consecutive observations a sub-reason
// needs before it becomes HARD, per sub-reason.
//
// Per-sub-reason rather than one global N, because the evidence differs. An
// expired certificate is unambiguous on a single observation — the notAfter is
// in the past, and waiting three cycles to say so adds delay and no certainty.
// A partial rollout is exactly the case where one observation proves nothing.
type Thresholds struct {
	// Default applies to any sub-reason with no specific entry.
	Default int
	// BySubReason overrides Default.
	BySubReason map[string]int
	// RecheckInterval is how soon to look again while a finding is SOFT.
	// Build item 081: 60s for the partial-rollout case.
	RecheckInterval time.Duration
	// RecheckWindow bounds the short-interval re-checking. After it elapses,
	// a still-unconfirmed finding is promoted on the evidence available
	// rather than re-checked forever.
	RecheckWindow time.Duration
	// NormalInterval is the cadence when everything is OK.
	NormalInterval time.Duration
	// HistoryLimit bounds retained transitions per endpoint.
	HistoryLimit int
}

// DefaultThresholds implements item 081's "60s x 10 min" for partial rollout.
//
// N=3 at 60s means a partial rollout is confirmed about three minutes after it
// first appears. A rolling deploy that has not converged in three minutes is
// not a rolling deploy any more.
func DefaultThresholds() Thresholds {
	return Thresholds{
		Default: 3,
		BySubReason: map[string]int{
			// Unambiguous from one observation. Waiting adds delay, not certainty.
			verify.ReasonExpired:     1,
			verify.ReasonNotYetValid: 1,
			verify.ReasonNearExpiry:  1,
			// The case this whole package exists for.
			verify.ReasonPartialRollout:        3,
			verify.ReasonFingerprintDivergence: 3,
			// A single failed connection is usually a network blip.
			verify.ReasonAllUnreachable:      3,
			verify.ReasonPartialReachability: 3,
			// Configuration errors are stable by nature; no point re-checking.
			verify.ReasonInvalidExpectation: 1,
			verify.ReasonNotInForce:         1,
		},
		RecheckInterval: 60 * time.Second,
		RecheckWindow:   10 * time.Minute,
		NormalInterval:  15 * time.Minute,
		HistoryLimit:    50,
	}
}

// For returns the confirmation count for a sub-reason.
func (t Thresholds) For(subReason string) int {
	if n, ok := t.BySubReason[subReason]; ok && n > 0 {
		return n
	}
	if t.Default > 0 {
		return t.Default
	}
	return 1
}

// Transition is one recorded change of state, for the history view.
type Transition struct {
	At        time.Time      `json:"at"`
	From      Status         `json:"from"`
	To        Status         `json:"to"`
	Outcome   verify.Outcome `json:"outcome"`
	SubReason string         `json:"sub_reason,omitempty"`
	Severity  Severity       `json:"severity,omitempty"`
	Note      string         `json:"note,omitempty"`
}

// EndpointState is everything remembered about one endpoint between
// observations. It is the only thing that needs to be persisted.
type EndpointState struct {
	Endpoint verify.Endpoint `json:"endpoint"`

	Status    Status         `json:"status"`
	Outcome   verify.Outcome `json:"outcome,omitempty"`
	SubReason string         `json:"sub_reason,omitempty"`
	Severity  Severity       `json:"severity,omitempty"`

	// Consecutive counts observations of the CURRENT sub-reason in a row. A
	// different sub-reason resets it: two different problems are not
	// corroborating evidence for each other.
	Consecutive int `json:"consecutive"`
	// Threshold is the count that would promote this finding to HARD, copied
	// in so a stored state explains itself without the config that made it.
	Threshold int `json:"threshold,omitempty"`

	FirstObserved time.Time `json:"first_observed,omitempty"`
	LastObserved  time.Time `json:"last_observed,omitempty"`
	// LastChanged is when Status last changed, not when it was last observed.
	LastChanged time.Time `json:"last_changed,omitempty"`
	// SoftSince is when the current SOFT run began; it bounds RecheckWindow.
	SoftSince time.Time `json:"soft_since,omitempty"`
	// NextCheckAt is the scheduler's instruction, computed here because the
	// decision to look again sooner is part of the state, not of the schedule.
	NextCheckAt time.Time `json:"next_check_at,omitempty"`

	// Alerted records whether the CURRENT hard state actually produced an
	// event. A finding that never paged must not produce a recovery notice
	// when it clears — that is a page for good news, and it is how people
	// learn to mute a channel.
	Alerted bool `json:"alerted,omitempty"`

	// TotalObservations and TotalHardEvents are lifetime counters, useful for
	// spotting a flapping endpoint that never stays broken long enough to page.
	TotalObservations int `json:"total_observations"`
	TotalHardEvents   int `json:"total_hard_events"`

	History []Transition `json:"history,omitempty"`
}

// EventKind distinguishes the three things worth telling somebody about.
type EventKind string

const (
	// EventHardTransition is a confirmed finding. This is what pages.
	EventHardTransition EventKind = "hard_transition"
	// EventRecovery is a confirmed finding that has cleared.
	EventRecovery EventKind = "recovery"
	// EventEscalation is a HARD finding whose sub-reason got worse, such as
	// near_expiry becoming expired. It is a new event, not a repeat.
	EventEscalation EventKind = "escalation"
)

// Event is emitted on a confirmed change. Nothing else emits.
type Event struct {
	Kind      EventKind       `json:"kind"`
	At        time.Time       `json:"at"`
	Endpoint  verify.Endpoint `json:"endpoint"`
	Outcome   verify.Outcome  `json:"outcome,omitempty"`
	SubReason string          `json:"sub_reason,omitempty"`
	Severity  Severity        `json:"severity"`
	Summary   string          `json:"summary"`

	// PreviousSubReason is set on an escalation so a notifier can say what
	// changed rather than repeating the whole finding.
	PreviousSubReason string `json:"previous_sub_reason,omitempty"`

	// Observations is how many consecutive observations confirmed this. It is
	// the evidence for the event, and a notifier should show it.
	Observations int `json:"observations"`

	// DedupeKey is stable for the same finding on the same endpoint, so a
	// notifier can suppress repeats without re-deriving the identity.
	DedupeKey string `json:"dedupe_key"`
}

func dedupeKey(ep verify.Endpoint, kind EventKind, sub string) string {
	return fmt.Sprintf("%s|%s|%s", ep.String(), kind, sub)
}

// sortEvents keeps output deterministic for callers that compare it.
func sortEvents(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		if evs[i].Severity.Rank() != evs[j].Severity.Rank() {
			return evs[i].Severity.Rank() > evs[j].Severity.Rank()
		}
		return evs[i].DedupeKey < evs[j].DedupeKey
	})
}
