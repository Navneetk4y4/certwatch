package verify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/scan"
)

// Every test here locks down a defect that was actually present in Classify and
// was found by attacking it, not by reading it. Each one is named for the
// consequence it prevents, because a name like TestGraceWindow tells a future
// reader nothing about why deleting the test would be expensive.

// A future EffectiveFrom produced a NEGATIVE elapsed time, and negative is less
// than any window, so the endpoint sat in a grace window that never closed.
// A real partial rollout was suppressed forever.
func TestRegression_FutureEffectiveFromDoesNotSuppressForever(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	stale := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 3, 0))

	e := pinned(expected.Fingerprint)
	e.EffectiveFrom = now.AddDate(10, 0, 0)

	r := Classify(e, []scan.Probe{
		probeAt("10.0.0.10", expected),
		probeAt("10.0.0.11", stale),
	}, now, DefaultConfig())

	if r.SubReason == ReasonSettling {
		t.Fatalf("a future EffectiveFrom reopened the grace window: %s/%s", r.Outcome, r.SubReason)
	}
	// The expectation is not in force, so nothing is compared against it — but
	// the addresses still disagree with each other, and that must be visible.
	if !r.FingerprintDivergence {
		t.Error("divergence went unreported while the expectation was not in force")
	}
	if r.Outcome != OutcomeWarning {
		t.Errorf("Outcome = %s, want WARNING: two addresses serve different certificates", r.Outcome)
	}
}

// Classify never called Validate, so policy mode with a nil Policy dereferenced
// nil and took down the whole scan.
func TestRegression_InvalidExpectationIsAConfigErrorNotAPanicOrFailure(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))

	for _, tc := range []struct {
		name string
		e    Expectation
	}{
		{"policy mode, nil policy", Expectation{
			Endpoint: Endpoint{Hostname: "api.example.com", Port: 443},
			Mode:     ModePolicy, Confirmed: true}},
		{"unknown mode", Expectation{
			Endpoint: Endpoint{Hostname: "api.example.com", Port: 443},
			Mode:     Mode("whatever"), Confirmed: true}},
		{"pinned, no fingerprint", Expectation{
			Endpoint: Endpoint{Hostname: "api.example.com", Port: 443},
			Mode:     ModePinned, Confirmed: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("Classify panicked: %v", rec)
				}
			}()
			r := Classify(tc.e, []scan.Probe{probeAt("10.0.0.10", cert)}, now, DefaultConfig())

			// The endpoint is fine. The configuration is not. Reporting FAILURE
			// would page someone about a typo in a file.
			if r.Outcome == OutcomeFailure {
				t.Errorf("a broken expectation blamed the endpoint: %s/%s", r.Outcome, r.SubReason)
			}
			if r.Alertable {
				t.Error("a configuration error was alertable")
			}
			if r.SubReason != ReasonInvalidExpectation {
				t.Errorf("SubReason = %q, want %q", r.SubReason, ReasonInvalidExpectation)
			}
		})
	}
}

// Describe() dereferenced Policy before Validate could reject it.
func TestRegression_DescribeSurvivesNilPolicy(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Describe panicked: %v", rec)
		}
	}()
	e := Expectation{Endpoint: Endpoint{Hostname: "h", Port: 443}, Mode: ModePolicy}
	if s := e.Describe(); s == "" {
		t.Error("Describe returned nothing for an invalid expectation")
	}
}

// Duplicate addresses were counted twice in every denominator, so probing one
// address twice could fabricate "1 of 2 addresses match" — a partial rollout
// that does not exist.
func TestRegression_DuplicateAddressesDoNotFabricateAPartialRollout(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	e := pinned(cert.Fingerprint)

	r := Classify(e, []scan.Probe{
		probeAt("10.0.0.10", cert),
		probeAt("10.0.0.10", cert),
	}, now, DefaultConfig())

	if r.PartialRollout {
		t.Errorf("one address counted twice became a partial rollout: %s", r.Summary)
	}
	if len(r.IPsResolved) != 1 || len(r.IPsChecked) != 1 {
		t.Errorf("denominators counted a duplicate: resolved=%v checked=%v", r.IPsResolved, r.IPsChecked)
	}
	if len(r.PerIP) != 2 {
		t.Errorf("PerIP dropped evidence: got %d rows, want 2", len(r.PerIP))
	}
	if r.Outcome != OutcomePass {
		t.Errorf("Outcome = %s, want PASS", r.Outcome)
	}
}

// PerIP was sorted with sort.Slice, which is NOT stable, so rows sharing an
// address were ordered by luck. firstFailureReason, nonMatching and the
// degraded check all read PerIP in order, so the verdict itself could change
// with probe input order.
func TestRegression_VerdictDoesNotDependOnProbeOrder(t *testing.T) {
	good := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	bad := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, 2))
	e := pinned(good.Fingerprint)

	forward := []scan.Probe{probeAt("10.0.0.10", good), probeAt("10.0.0.10", bad), probeAt("10.0.0.11", good)}
	reverse := []scan.Probe{forward[2], forward[1], forward[0]}

	a := Classify(e, forward, now, DefaultConfig())
	b := Classify(e, reverse, now, DefaultConfig())

	if a.Outcome != b.Outcome || a.SubReason != b.SubReason {
		t.Errorf("verdict depends on probe order: %s/%s vs %s/%s",
			a.Outcome, a.SubReason, b.Outcome, b.SubReason)
	}
	if len(a.PerIP) != len(b.PerIP) {
		t.Fatalf("PerIP length differs: %d vs %d", len(a.PerIP), len(b.PerIP))
	}
	for i := range a.PerIP {
		// DaysRemaining is a pointer; %+v would compare addresses.
		x, y := a.PerIP[i], b.PerIP[i]
		x.DaysRemaining, y.DaysRemaining = nil, nil
		if fmt.Sprintf("%+v", x) != fmt.Sprintf("%+v", y) {
			t.Errorf("PerIP[%d] differs between orderings:\n %+v\n %+v", i, x, y)
		}
	}
}

// Config was only replaced by DefaultConfig when EVERY field was zero, so a
// caller who set GraceWindow silently got NearExpiryDays=0 — which disables
// near-expiry detection entirely.
func TestRegression_PartialConfigDoesNotDisableNearExpiry(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, 3))
	e := pinned(cert.Fingerprint)

	r := Classify(e, []scan.Probe{probeAt("10.0.0.10", cert)},
		now, Config{GraceWindow: 30 * time.Minute}) // NearExpiryDays left unset

	if r.Outcome == OutcomePass {
		t.Fatalf("a certificate 3 days from expiry reported PASS: %s", r.Summary)
	}
	if r.SubReason != ReasonNearExpiry {
		t.Errorf("SubReason = %q, want %q", r.SubReason, ReasonNearExpiry)
	}
}

// Zero meant "use the default", which left no way to switch the grace window
// off. Negative now means "explicitly off".
func TestRegression_GraceWindowCanBeDisabled(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	other := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 5, 0))
	e := pinned(expected.Fingerprint)
	e.Confirmed = true
	e.EffectiveFrom = now.Add(-1 * time.Minute) // deep inside any default window

	probes := []scan.Probe{probeAt("10.0.0.10", expected), probeAt("10.0.0.11", other)}

	if r := Classify(e, probes, now, DefaultConfig()); r.SubReason != ReasonSettling {
		t.Fatalf("precondition: want the default window to suppress, got %s/%s", r.Outcome, r.SubReason)
	}
	r := Classify(e, probes, now, Config{GraceWindow: -1})
	if r.SubReason == ReasonSettling || !r.Alertable {
		t.Errorf("GraceWindow:-1 did not disable suppression: %s/%s alertable=%v",
			r.Outcome, r.SubReason, r.Alertable)
	}
}

// A grace window absorbs a rotation in flight. An EXPIRED certificate is not a
// rotation in flight; it is an outage that has already begun.
func TestRegression_GraceWindowNeverSuppressesAnExpiredCertificate(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	expired := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, -5))

	e := pinned(expected.Fingerprint)
	e.Confirmed = true
	e.EffectiveFrom = now.Add(-1 * time.Minute)

	for _, tc := range []struct {
		name   string
		probes []scan.Probe
	}{
		{"half the pool expired", []scan.Probe{
			probeAt("10.0.0.10", expected), probeAt("10.0.0.11", expired)}},
		{"the whole pool expired", []scan.Probe{
			probeAt("10.0.0.10", expired), probeAt("10.0.0.11", expired)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Classify(e, tc.probes, now, DefaultConfig())
			if r.SubReason == ReasonSettling {
				t.Errorf("an expired certificate was filed as settling: %s", r.Summary)
			}
			if !r.Alertable {
				t.Errorf("an expired certificate did not alert: %s/%s", r.Outcome, r.SubReason)
			}
		})
	}
}

// PartialRollout stayed true when the grace window downgraded the verdict, and
// cmd/certscan headlines that flag — so the report announced a finding the
// classifier had just silenced.
func TestRegression_SuppressedPartialRolloutIsMarkedSuppressed(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	other := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 5, 0))

	e := pinned(expected.Fingerprint)
	e.Confirmed = true
	e.EffectiveFrom = now.Add(-1 * time.Minute)

	r := Classify(e, []scan.Probe{
		probeAt("10.0.0.10", expected), probeAt("10.0.0.11", other),
	}, now, DefaultConfig())

	if r.SubReason != ReasonSettling {
		t.Fatalf("precondition: want a suppressed result, got %s/%s", r.Outcome, r.SubReason)
	}
	if r.PartialRollout && !r.Suppressed {
		t.Error("PartialRollout is true and Suppressed is false: a caller would headline a silenced finding")
	}
}

// allServedCertificatesValid claimed in its own comment to check that the
// certificate covers the host, and never did. A certificate whose only SAN was
// an unrelated hostname was reported as "a different but valid certificate —
// likely a rotation".
func TestRegression_DriftRequiresTheCertificateToCoverTheHostname(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	foreign := makeCert(t, "totally-unrelated.evil.test", "Corp Issuing CA",
		now.AddDate(0, 6, 0), "totally-unrelated.evil.test")

	e := pinned(expected.Fingerprint)
	e.Confirmed = true

	r := Classify(e, []scan.Probe{
		probeAt("10.0.0.10", foreign), probeAt("10.0.0.11", foreign),
	}, now, DefaultConfig())

	if r.Outcome == OutcomeDrift {
		t.Errorf("a certificate for another hostname was called a benign rotation: %s", r.Summary)
	}
	if !r.Alertable {
		t.Error("a certificate for another hostname did not alert")
	}
}

// openssl prints fingerprints uppercase and colon-separated. Pasting one made
// every address mismatch, so a perfectly healthy pool reported DRIFT.
func TestRegression_FingerprintComparisonIgnoresCaseAndColons(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))

	var colonised strings.Builder
	for i := 0; i < len(cert.Fingerprint); i += 2 {
		if i > 0 {
			colonised.WriteByte(':')
		}
		colonised.WriteString(strings.ToUpper(cert.Fingerprint[i : i+2]))
	}

	for _, form := range []string{
		strings.ToUpper(cert.Fingerprint),
		colonised.String(),
		"sha256:" + cert.Fingerprint,
		"  " + cert.Fingerprint + "\n",
	} {
		e := pinned(form)
		e.Confirmed = true
		r := Classify(e, []scan.Probe{probeAt("10.0.0.10", cert)}, now, DefaultConfig())
		if r.Outcome != OutcomePass {
			t.Errorf("fingerprint %.20q… reported %s/%s, want PASS", form, r.Outcome, r.SubReason)
		}
	}
}

// A certificate that could not be parsed has a zero NotAfter, which reads as
// expired in the year 1. The verdict was FAILURE/expired — a false alert whose
// stated reason was also false.
func TestRegression_UnparseableCertificateIsNotReportedAsExpired(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	broken := *cert
	broken.ParseStatus = model.ParseUnparseable
	broken.NotAfter = time.Time{}
	broken.NotBefore = time.Time{}

	e := pinned(cert.Fingerprint)
	e.Confirmed = true

	r := Classify(e, []scan.Probe{probeAt("10.0.0.10", &broken)}, now, DefaultConfig())
	if r.SubReason == ReasonExpired {
		t.Errorf("an unparseable certificate was reported as expired: %s", r.Summary)
	}
	for _, row := range r.PerIP {
		if strings.Contains(row.Reason, "0001-01-01") {
			t.Errorf("per-IP reason states a year-1 expiry date: %q", row.Reason)
		}
	}
}

// A policy demanding 4096 bits passed a certificate whose key size could not be
// read — failing open on exactly the certificates least worth trusting.
func TestRegression_UnknownKeySizeFailsAMinimumKeyBitsPolicy(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	cert.KeySize = nil

	e := Expectation{
		Endpoint:  Endpoint{Hostname: "api.example.com", Port: 443},
		Mode:      ModePolicy,
		Policy:    &Policy{MinKeyBits: 4096},
		Confirmed: true,
	}
	r := Classify(e, []scan.Probe{probeAt("10.0.0.10", cert)}, now, DefaultConfig())
	if r.Outcome == OutcomePass {
		t.Errorf("unknown key size satisfied MinKeyBits=4096: %s", r.Summary)
	}
}

// D14/R1: an alert requires a human-confirmed expectation. Divergence is
// REPORTED without one — it compares addresses to each other, not to the
// expectation — but it still must not page anyone, because a single
// observation cannot tell a rolling deploy from a pool that never converged.
func TestRegression_UnconfirmedExpectationReportsButNeverAlerts(t *testing.T) {
	a := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	b := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 5, 0))

	e := pinned(a.Fingerprint)
	e.Confirmed = false

	r := Classify(e, []scan.Probe{probeAt("10.0.0.10", a), probeAt("10.0.0.11", b)},
		now, DefaultConfig())

	if r.Alertable {
		t.Error("R1 violated: an unconfirmed expectation produced an alertable result")
	}
	if !r.FingerprintDivergence {
		t.Error("divergence was not reported for an unconfirmed expectation")
	}
	if r.Outcome != OutcomeWarning {
		t.Errorf("Outcome = %s, want WARNING so the divergence is visible", r.Outcome)
	}
}
