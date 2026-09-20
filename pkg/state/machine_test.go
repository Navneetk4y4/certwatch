package state

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/verify"
)

var (
	t0 = time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	ep = verify.Endpoint{Hostname: "api.example.com", Port: 443}
)

// res builds a verification result of the shape Classify produces. Alertable
// defaults true so the common case reads cleanly; the R1 tests set it false.
func res(outcome verify.Outcome, sub string) verify.Result {
	return verify.Result{
		Endpoint: ep, Outcome: outcome, SubReason: sub,
		Summary:   "synthetic result for " + string(outcome) + "/" + sub,
		Alertable: outcome != verify.OutcomePass,
	}
}

func pass() verify.Result { return res(verify.OutcomePass, "") }

// run folds a sequence of results, stepping the clock by step each time.
func run(t *testing.T, th Thresholds, step time.Duration, rs ...verify.Result) (EndpointState, []Event) {
	t.Helper()
	var st EndpointState
	var all []Event
	now := t0
	for _, r := range rs {
		var evs []Event
		st, evs = Observe(st, r, now, th)
		all = append(all, evs...)
		now = now.Add(step)
	}
	return st, all
}

func kinds(evs []Event) []EventKind {
	out := make([]EventKind, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

// ---------------------------------------------------------------------------
// The scenarios the whole package exists for
// ---------------------------------------------------------------------------

// healthy -> temporary divergence -> convergence.
//
// This is a rolling deployment. It MUST NOT page. If this test ever fails, the
// product pages on every deploy, which is R2 and rated Fatal.
func TestScenario_RollingDeployConvergesWithoutPaging(t *testing.T) {
	st, evs := run(t, DefaultThresholds(), 60*time.Second,
		pass(),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout), // deploy starts
		res(verify.OutcomeFailure, verify.ReasonPartialRollout), // still rolling
		pass(), // converged
	)

	if len(evs) != 0 {
		t.Fatalf("a rolling deploy that converged in 2 minutes paged: %v", kinds(evs))
	}
	if st.Status != StatusOK {
		t.Errorf("Status = %s, want ok", st.Status)
	}
	if st.TotalHardEvents != 0 {
		t.Errorf("TotalHardEvents = %d, want 0", st.TotalHardEvents)
	}
	// It must still be visible in history: quiet is not the same as hidden.
	if len(st.History) == 0 {
		t.Error("the divergence left no trace in history")
	}
}

// healthy -> divergence -> divergence persists -> hard failure.
//
// A pool that has not converged after three consecutive checks is not a
// rolling deploy any more.
func TestScenario_PersistentDivergenceBecomesHardAndPages(t *testing.T) {
	st, evs := run(t, DefaultThresholds(), 60*time.Second,
		pass(),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout), // N=3 reached
	)

	if len(evs) != 1 || evs[0].Kind != EventHardTransition {
		t.Fatalf("want exactly one hard_transition, got %v", kinds(evs))
	}
	if evs[0].Severity != SeverityCritical {
		t.Errorf("Severity = %s, want critical", evs[0].Severity)
	}
	if evs[0].Observations != 3 {
		t.Errorf("Observations = %d, want 3 — the event must carry its evidence",
			evs[0].Observations)
	}
	if st.Status != StatusHard || !st.Alerting() {
		t.Errorf("Status = %s alerting = %v, want hard/true", st.Status, st.Alerting())
	}
}

// divergence -> recovery.
func TestScenario_RecoveryAfterHardEmitsExactlyOneRecovery(t *testing.T) {
	st, evs := run(t, DefaultThresholds(), 60*time.Second,
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout), // hard
		pass(), // fixed
	)

	if got := kinds(evs); len(got) != 2 ||
		got[0] != EventHardTransition || got[1] != EventRecovery {
		t.Fatalf("want [hard_transition recovery], got %v", got)
	}
	if st.Status != StatusOK {
		t.Errorf("Status = %s, want ok", st.Status)
	}
	if st.Alerting() {
		t.Error("still alerting after recovery")
	}
}

// near expiry -> expired. The second is worse, so it is an escalation and a
// NEW event, not a duplicate of the first.
func TestScenario_NearExpiryEscalatesToExpired(t *testing.T) {
	_, evs := run(t, DefaultThresholds(), time.Hour,
		res(verify.OutcomeWarning, verify.ReasonNearExpiry), // N=1, hard at once
		res(verify.OutcomeWarning, verify.ReasonNearExpiry), // unchanged, silent
		res(verify.OutcomeFailure, verify.ReasonExpired),    // worse
	)

	got := kinds(evs)
	if len(got) != 2 {
		t.Fatalf("want 2 events (hard, escalation), got %d: %v", len(got), got)
	}
	if got[1] != EventEscalation {
		t.Errorf("second event = %s, want escalation", got[1])
	}
	if evs[1].PreviousSubReason != verify.ReasonNearExpiry {
		t.Errorf("PreviousSubReason = %q, want near_expiry — an escalation must say what changed",
			evs[1].PreviousSubReason)
	}
	if evs[1].Severity != SeverityCritical {
		t.Errorf("Severity = %s, want critical", evs[1].Severity)
	}
}

// ---------------------------------------------------------------------------
// Deduplication, the alert-fatigue guarantee
// ---------------------------------------------------------------------------

// The same finding observed twenty times emits ONE event. Never send a
// duplicate alert merely because the same observation repeated.
func TestRepeatedObservationOfAnUnchangedFindingEmitsOneEvent(t *testing.T) {
	rs := make([]verify.Result, 20)
	for i := range rs {
		rs[i] = res(verify.OutcomeFailure, verify.ReasonPartialRollout)
	}
	st, evs := run(t, DefaultThresholds(), 60*time.Second, rs...)

	if len(evs) != 1 {
		t.Fatalf("20 identical observations produced %d events, want 1: %v",
			len(evs), kinds(evs))
	}
	if st.TotalObservations != 20 {
		t.Errorf("TotalObservations = %d, want 20", st.TotalObservations)
	}
	if st.TotalHardEvents != 1 {
		t.Errorf("TotalHardEvents = %d, want 1", st.TotalHardEvents)
	}
}

// A flapping endpoint that never stays broken long enough to confirm must
// never page, and the flapping must still be visible.
func TestFlappingNeverConfirmsAndNeverPages(t *testing.T) {
	var rs []verify.Result
	for i := 0; i < 10; i++ {
		rs = append(rs,
			res(verify.OutcomeFailure, verify.ReasonPartialRollout),
			pass())
	}
	st, evs := run(t, DefaultThresholds(), 60*time.Second, rs...)

	if len(evs) != 0 {
		t.Fatalf("flapping paged %d times: %v", len(evs), kinds(evs))
	}
	if len(st.History) < 4 {
		t.Errorf("flapping left only %d history entries; it must stay visible", len(st.History))
	}
}

// ---------------------------------------------------------------------------
// R1 — no alert without a confirmed expectation, preserved through the machine
// ---------------------------------------------------------------------------

func TestNonAlertableResultTracksStateButNeverEmits(t *testing.T) {
	r := res(verify.OutcomeWarning, verify.ReasonFingerprintDivergence)
	r.Alertable = false // unconfirmed expectation

	st, evs := run(t, DefaultThresholds(), 60*time.Second, r, r, r, r, r)

	if len(evs) != 0 {
		t.Fatalf("R1 violated: a non-alertable result emitted %v", kinds(evs))
	}
	if st.Status != StatusHard {
		t.Errorf("Status = %s, want hard — state is still tracked, just not announced", st.Status)
	}
	if st.Alerting() {
		t.Error("Alerting() true for a finding that never paged")
	}
	if st.TotalHardEvents != 0 {
		t.Errorf("TotalHardEvents = %d, want 0", st.TotalHardEvents)
	}
}

// A hard state that never paged must not produce a recovery notice. A recovery
// for an alert nobody received is noise.
func TestRecoveryIsSilentIfTheProblemWasNeverAnnounced(t *testing.T) {
	r := res(verify.OutcomeWarning, verify.ReasonFingerprintDivergence)
	r.Alertable = false

	_, evs := run(t, DefaultThresholds(), 60*time.Second, r, r, r, pass())
	if len(evs) != 0 {
		t.Fatalf("silent problem produced a recovery notice: %v", kinds(evs))
	}
}

// A result suppressed by the grace window must not escalate.
func TestGraceWindowSuppressedResultNeverPages(t *testing.T) {
	r := res(verify.OutcomeWarning, verify.ReasonSettling)
	r.Alertable = false
	r.Suppressed = true

	_, evs := run(t, DefaultThresholds(), 60*time.Second, r, r, r, r)
	if len(evs) != 0 {
		t.Fatalf("a suppressed result paged: %v", kinds(evs))
	}
}

// ---------------------------------------------------------------------------
// Thresholds, re-check scheduling, and the rest
// ---------------------------------------------------------------------------

// An expired certificate is unambiguous on one observation. Waiting three
// cycles to report a live outage adds delay and no certainty.
func TestExpiredConfirmsImmediately(t *testing.T) {
	st, evs := run(t, DefaultThresholds(), time.Minute,
		res(verify.OutcomeFailure, verify.ReasonExpired))

	if len(evs) != 1 || evs[0].Kind != EventHardTransition {
		t.Fatalf("expired did not page on first observation: %v", kinds(evs))
	}
	if st.Status != StatusHard {
		t.Errorf("Status = %s, want hard", st.Status)
	}
}

// Item 081: while SOFT, the next check is the short interval, not the normal one.
func TestSoftStateSchedulesTheShortIntervalRecheck(t *testing.T) {
	th := DefaultThresholds()
	st, _ := run(t, th, time.Minute, res(verify.OutcomeFailure, verify.ReasonPartialRollout))

	if st.Status != StatusSoft {
		t.Fatalf("Status = %s, want soft", st.Status)
	}
	want := t0.Add(th.RecheckInterval)
	if !st.NextCheckAt.Equal(want) {
		t.Errorf("NextCheckAt = %s, want %s (the 60s re-check)", st.NextCheckAt, want)
	}

	// And a clean result returns to the normal cadence.
	st2, _ := Observe(st, pass(), t0.Add(time.Minute), th)
	if !st2.NextCheckAt.Equal(t0.Add(time.Minute).Add(th.NormalInterval)) {
		t.Errorf("NextCheckAt after recovery = %s, want the normal interval", st2.NextCheckAt)
	}
}

// A finding still unconfirmed when the re-check window closes is promoted on
// the evidence available. Re-checking forever is a slower way of never
// reporting it.
func TestUnconfirmedFindingIsPromotedWhenTheRecheckWindowCloses(t *testing.T) {
	th := DefaultThresholds()
	th.Default = 99 // unreachable by count alone
	th.BySubReason = nil

	var st EndpointState
	var all []Event
	now := t0
	for i := 0; i < 3; i++ {
		var evs []Event
		st, evs = Observe(st, res(verify.OutcomeFailure, verify.ReasonPartialRollout), now, th)
		all = append(all, evs...)
		now = now.Add(6 * time.Minute) // crosses the 10-minute window
	}
	if len(all) != 1 {
		t.Fatalf("window expiry produced %d events, want 1: %v", len(all), kinds(all))
	}
	if st.Status != StatusHard {
		t.Errorf("Status = %s, want hard", st.Status)
	}
}

// A different sub-reason is a different finding; the count must restart.
// Two unrelated problems are not corroborating evidence for each other.
func TestDifferentSubReasonResetsTheConsecutiveCount(t *testing.T) {
	st, evs := run(t, DefaultThresholds(), time.Minute,
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeWarning, verify.ReasonFingerprintDivergence), // different
	)
	if st.Consecutive != 1 {
		t.Errorf("Consecutive = %d, want 1 after the finding changed", st.Consecutive)
	}
	if len(evs) != 0 {
		t.Fatalf("a changed finding paged before confirmation: %v", kinds(evs))
	}
}

func TestSeverityMappingIsTotalAndOrdered(t *testing.T) {
	if SeverityFor(verify.ReasonExpired) != SeverityCritical {
		t.Error("expired must be critical")
	}
	if SeverityFor(verify.ReasonPartialRollout) != SeverityCritical {
		t.Error("partial rollout must be critical: no other monitor the customer owns will find it")
	}
	if SeverityFor(verify.ReasonInvalidExpectation).Rank() >= SeverityCritical.Rank() {
		t.Error("a configuration error must not be critical")
	}
	// An unmapped reason must not silently become INFO.
	if got := SeverityFor("some_new_reason_nobody_mapped"); got != SeverityMedium {
		t.Errorf("unmapped sub-reason = %s, want medium", got)
	}
	if SeverityCritical.Rank() <= SeverityInfo.Rank() {
		t.Error("severity ranking is inverted")
	}
}

// ---------------------------------------------------------------------------
// Purity, persistence and input safety
// ---------------------------------------------------------------------------

// Observe must not mutate the state it was given. A caller holding the
// previous state for comparison must still have it afterwards.
func TestObserveDoesNotMutateItsInput(t *testing.T) {
	st, _ := run(t, DefaultThresholds(), time.Minute,
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout))

	before, _ := json.Marshal(st)
	historyLenBefore := len(st.History)

	_, _ = Observe(st, res(verify.OutcomeFailure, verify.ReasonExpired), t0.Add(time.Hour),
		DefaultThresholds())

	after, _ := json.Marshal(st)
	if string(before) != string(after) {
		t.Errorf("Observe mutated its input:\n before %s\n after  %s", before, after)
	}
	if len(st.History) != historyLenBefore {
		t.Error("Observe appended to the caller's history slice")
	}
}

// Comparing JSON and length does NOT catch slice aliasing: appending into a
// slice that has spare capacity writes through to the caller's backing array
// without changing the caller's length or its JSON. Found by mutating
// machine.go to alias the slice and noticing every test still passed.
func TestObserveDoesNotWriteThroughTheCallersHistoryCapacity(t *testing.T) {
	var st EndpointState
	st.Endpoint = ep
	st.Status = StatusSoft
	st.SubReason = verify.ReasonPartialRollout
	st.Consecutive = 1

	// len 1, cap 8: seven slots of spare capacity to scribble on.
	backing := make([]Transition, 1, 8)
	backing[0] = Transition{At: t0, To: StatusSoft, Note: "sentinel"}
	st.History = backing

	_, _ = Observe(st, res(verify.OutcomeFailure, verify.ReasonExpired),
		t0.Add(time.Minute), DefaultThresholds())

	// Read the spare capacity the caller still owns.
	spare := backing[:cap(backing)]
	for i := 1; i < len(spare); i++ {
		if !spare[i].At.IsZero() || spare[i].To != "" || spare[i].Note != "" {
			t.Fatalf("Observe wrote into the caller's spare capacity at index %d: %+v",
				i, spare[i])
		}
	}
	if spare[0].Note != "sentinel" {
		t.Error("Observe overwrote an existing entry in the caller's history")
	}
}

// State must survive a persistence round trip unchanged; it is the only thing
// the control plane needs to store.
func TestStateSurvivesAJSONRoundTrip(t *testing.T) {
	st, _ := run(t, DefaultThresholds(), time.Minute,
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		pass())

	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var back EndpointState
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(back)
	if string(raw) != string(again) {
		t.Errorf("state changed across a round trip:\n %s\n %s", raw, again)
	}

	// And continuing from the restored state behaves identically.
	a, evA := Observe(st, res(verify.OutcomeFailure, verify.ReasonExpired), t0.Add(time.Hour), DefaultThresholds())
	b, evB := Observe(back, res(verify.OutcomeFailure, verify.ReasonExpired), t0.Add(time.Hour), DefaultThresholds())
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) || len(evA) != len(evB) {
		t.Error("restored state diverged from live state on the next observation")
	}
}

// A zero Thresholds must not disable confirmation or divide by zero.
func TestZeroThresholdsFallBackToTheDefaults(t *testing.T) {
	st, evs := run(t, Thresholds{}, time.Minute,
		res(verify.OutcomeFailure, verify.ReasonPartialRollout))
	if st.Status != StatusSoft {
		t.Errorf("Status = %s, want soft — a zero config must not confirm on sight", st.Status)
	}
	if len(evs) != 0 {
		t.Errorf("zero config paged immediately: %v", kinds(evs))
	}
}

func TestHistoryIsBounded(t *testing.T) {
	th := DefaultThresholds()
	th.HistoryLimit = 5
	var rs []verify.Result
	for i := 0; i < 40; i++ {
		rs = append(rs, res(verify.OutcomeFailure, verify.ReasonExpired), pass())
	}
	st, _ := run(t, th, time.Minute, rs...)
	if len(st.History) > 5 {
		t.Errorf("history grew to %d with a limit of 5", len(st.History))
	}
	if len(st.History) == 0 {
		t.Error("history is empty")
	}
}

func TestUnreachableEndpointBehaviour(t *testing.T) {
	st, evs := run(t, DefaultThresholds(), time.Minute,
		pass(),
		res(verify.OutcomeUnreachable, verify.ReasonAllUnreachable),
		res(verify.OutcomeUnreachable, verify.ReasonAllUnreachable))
	// A single failed connection is usually a blip; two is not yet three.
	if len(evs) != 0 {
		t.Fatalf("two unreachable observations paged: %v", kinds(evs))
	}
	if st.Status != StatusSoft {
		t.Errorf("Status = %s, want soft", st.Status)
	}
	st, evs = Observe(st, res(verify.OutcomeUnreachable, verify.ReasonAllUnreachable),
		t0.Add(3*time.Minute), DefaultThresholds())
	if len(evs) != 1 || st.Status != StatusHard {
		t.Errorf("third unreachable did not confirm: events=%v status=%s", kinds(evs), st.Status)
	}
}

func TestInvalidExpectationConfirmsOnceAndIsNotCritical(t *testing.T) {
	r := res(verify.OutcomeUnknown, verify.ReasonInvalidExpectation)
	r.Alertable = false // Classify never makes a config error alertable
	st, evs := run(t, DefaultThresholds(), time.Minute, r, r, r)

	if len(evs) != 0 {
		t.Fatalf("a configuration error paged: %v", kinds(evs))
	}
	if st.Severity == SeverityCritical {
		t.Error("a configuration error was mapped to critical")
	}
	if st.Status != StatusHard {
		t.Errorf("Status = %s, want hard — it is a real, persistent state", st.Status)
	}
}

func TestDueAt(t *testing.T) {
	var zero EndpointState
	if !zero.DueAt(t0) {
		t.Error("an endpoint never observed must be due immediately")
	}
	st, _ := run(t, DefaultThresholds(), time.Minute, pass())
	if st.DueAt(t0) {
		t.Error("due immediately after a clean observation")
	}
	if !st.DueAt(t0.Add(time.Hour)) {
		t.Error("not due an hour after a 15-minute interval")
	}
}

func TestEventsCarryAStableDedupeKey(t *testing.T) {
	_, evs := run(t, DefaultThresholds(), time.Minute,
		res(verify.OutcomeFailure, verify.ReasonExpired))
	if len(evs) != 1 {
		t.Fatal("expected one event")
	}
	if evs[0].DedupeKey == "" {
		t.Fatal("empty dedupe key")
	}
	_, evs2 := run(t, DefaultThresholds(), time.Minute,
		res(verify.OutcomeFailure, verify.ReasonExpired))
	if evs[0].DedupeKey != evs2[0].DedupeKey {
		t.Error("dedupe key is not stable across runs")
	}
}
