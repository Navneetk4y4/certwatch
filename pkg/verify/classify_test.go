package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/scan"
	"github.com/certwatch/certwatch/pkg/x509norm"
)

var now = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

// makeCert builds a real certificate and returns its normalised form.
func makeCert(t *testing.T, cn, issuerCN string, notAfter time.Time, sans ...string) *model.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(sans) == 0 {
		sans = []string{cn}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: issuerCN},
		NotBefore:    now.AddDate(0, -1, 0),
		NotAfter:     notAfter,
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509norm.ParseDER(der)
	if err != nil {
		t.Fatal(err)
	}
	// Self-signed fixtures carry their own subject as issuer; override so
	// policy-mode issuer tests are meaningful.
	c.IssuerDN = "CN=" + issuerCN
	return c
}

// probeAt builds a probe from a GENUINELY DIFFERENT IP ADDRESS.
//
// Distinct addresses, not distinct ports. A fixture that used ports would not
// exercise the thing the product claims — that it checks every address a
// hostname resolves to.
func probeAt(ip string, cert *model.Certificate) scan.Probe {
	return scan.Probe{
		Target:     scan.Target{Addr: netip.MustParseAddr(ip), Port: 443, Hostname: "api.example.com"},
		ObservedAt: now,
		Chain:      &model.Chain{Leaf: cert},
		TLSVersion: "TLS1.3",
	}
}

func unreachable(ip string) scan.Probe {
	return scan.Probe{
		Target:     scan.Target{Addr: netip.MustParseAddr(ip), Port: 443, Hostname: "api.example.com"},
		ObservedAt: now,
		ConnectErr: "dial tcp " + ip + ":443: i/o timeout",
	}
}

func pinned(fp string) Expectation {
	return Expectation{
		Endpoint:    Endpoint{Hostname: "api.example.com", Port: 443},
		Mode:        ModePinned,
		Fingerprint: fp,
		Confirmed:   true,
		ConfirmedBy: "ops@example.com",
		ConfirmedAt: now.AddDate(0, 0, -30),
	}
}

func policy(p *Policy) Expectation {
	return Expectation{
		Endpoint:  Endpoint{Hostname: "api.example.com", Port: 443},
		Mode:      ModePolicy,
		Policy:    p,
		Confirmed: true,
	}
}

// ---------------------------------------------------------------------------
// REQUIRED CASE 1 — MATCH
// ---------------------------------------------------------------------------

func TestMatch_AllIPsServeExpectedCertificate(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	r := Classify(pinned(cert.Fingerprint), []scan.Probe{
		probeAt("10.0.0.10", cert),
		probeAt("10.0.0.11", cert),
		probeAt("10.0.0.12", cert),
	}, now, DefaultConfig())

	if r.Outcome != OutcomePass {
		t.Fatalf("Outcome = %s (%s), want PASS", r.Outcome, r.Summary)
	}
	if r.PartialRollout {
		t.Fatal("PartialRollout set on a healthy pool")
	}
	if r.FingerprintDivergence {
		t.Fatal("FingerprintDivergence set when all IPs serve the same certificate")
	}
	if len(r.IPsMatching) != 3 || len(r.IPsChecked) != 3 {
		t.Fatalf("matching=%v checked=%v, want 3 each", r.IPsMatching, r.IPsChecked)
	}
	for _, row := range r.PerIP {
		if !row.Match {
			t.Fatalf("%s reported as non-matching: %s", row.IP, row.Reason)
		}
	}
}

// ---------------------------------------------------------------------------
// REQUIRED CASE 2 — COMPLETE DRIFT
// ---------------------------------------------------------------------------

func TestCompleteDrift_AllIPsChangedTogether(t *testing.T) {
	oldCert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	newCert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 9, 0))

	r := Classify(pinned(oldCert.Fingerprint), []scan.Probe{
		probeAt("10.0.0.10", newCert),
		probeAt("10.0.0.11", newCert),
	}, now, DefaultConfig())

	// A complete, valid rotation is DRIFT, not FAILURE. Paging someone for a
	// successful certificate renewal is how a product gets muted.
	if r.Outcome != OutcomeDrift {
		t.Fatalf("Outcome = %s (%s), want DRIFT", r.Outcome, r.Summary)
	}
	if r.SubReason != ReasonUnexpectedButValid {
		t.Fatalf("SubReason = %s", r.SubReason)
	}
	if r.PartialRollout {
		t.Fatal("a complete rotation must NOT be reported as partial rollout")
	}
	if len(r.IPsMatching) != 0 {
		t.Fatalf("matching = %v, want none", r.IPsMatching)
	}
}

func TestCompleteDrift_ToAnExpiredCertificateIsFailure(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	expiredCert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, -5))

	r := Classify(pinned(expected.Fingerprint), []scan.Probe{
		probeAt("10.0.0.10", expiredCert),
		probeAt("10.0.0.11", expiredCert),
	}, now, DefaultConfig())

	if r.Outcome != OutcomeFailure {
		t.Fatalf("Outcome = %s (%s), want FAILURE — an expired certificate is not benign drift",
			r.Outcome, r.Summary)
	}
	if r.SubReason != ReasonExpired {
		t.Fatalf("SubReason = %s, want %s", r.SubReason, ReasonExpired)
	}
}

// ---------------------------------------------------------------------------
// REQUIRED CASE 3 — PARTIAL ROLLOUT.  The product.
// ---------------------------------------------------------------------------

func TestPartialRollout_SomeIPsUpdatedAndSomeNot(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	stale := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, 6))

	r := Classify(pinned(expected.Fingerprint), []scan.Probe{
		probeAt("10.0.0.10", expected), // updated
		probeAt("10.0.0.11", stale),    // never reloaded
	}, now, DefaultConfig())

	if r.Outcome != OutcomeFailure {
		t.Fatalf("Outcome = %s (%s), want FAILURE", r.Outcome, r.Summary)
	}
	if r.SubReason != ReasonPartialRollout {
		t.Fatalf("SubReason = %s, want %s", r.SubReason, ReasonPartialRollout)
	}
	if !r.PartialRollout {
		t.Fatal("PartialRollout flag not set — this is THE finding the product exists for")
	}
	if len(r.IPsMatching) != 1 || len(r.IPsChecked) != 2 {
		t.Fatalf("matching=%v checked=%v, want 1 of 2", r.IPsMatching, r.IPsChecked)
	}

	// The evidence must name WHICH address is wrong. "Something is wrong
	// somewhere" is not actionable.
	byIP := map[string]IPResult{}
	for _, row := range r.PerIP {
		byIP[row.IP] = row
	}
	if !byIP["10.0.0.10"].Match {
		t.Error("10.0.0.10 should match")
	}
	if byIP["10.0.0.11"].Match {
		t.Error("10.0.0.11 should NOT match")
	}
	if byIP["10.0.0.11"].Reason == "" {
		t.Error("the non-matching address has no reason recorded")
	}
	if byIP["10.0.0.10"].Fingerprint == byIP["10.0.0.11"].Fingerprint {
		t.Fatal("fixture error: both addresses serve the same certificate")
	}
	t.Logf("%s -> %s MATCH", "10.0.0.10", short(byIP["10.0.0.10"].Fingerprint))
	t.Logf("%s -> %s DRIFT (%s)", "10.0.0.11", short(byIP["10.0.0.11"].Fingerprint), byIP["10.0.0.11"].Reason)
	t.Logf("RESULT: %s / %s", r.Outcome, r.SubReason)
}

// Three of four wrong is still partial — the arithmetic must not have an
// off-by-one that only triggers at exactly half.
func TestPartialRollout_ThreeOfFour(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	stale := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, 20))

	r := Classify(pinned(expected.Fingerprint), []scan.Probe{
		probeAt("10.0.0.10", expected),
		probeAt("10.0.0.11", stale),
		probeAt("10.0.0.12", stale),
		probeAt("10.0.0.13", stale),
	}, now, DefaultConfig())

	if !r.PartialRollout || r.SubReason != ReasonPartialRollout {
		t.Fatalf("outcome=%s sub=%s partial=%v, want partial rollout",
			r.Outcome, r.SubReason, r.PartialRollout)
	}
	if len(r.IPsMatching) != 1 {
		t.Fatalf("matching = %v, want exactly 1", r.IPsMatching)
	}
}

// POLICY MODE: two DIFFERENT certificates that BOTH satisfy the policy. The
// expectation comparison cannot see this — divergence detection is the only
// signal, and without it a stuck pool member is invisible in policy mode.
func TestPartialRollout_PolicyModeDivergence(t *testing.T) {
	a := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	b := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 8, 0))
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("fixture error")
	}

	r := Classify(policy(&Policy{
		Issuers: []string{"CN=Corp Issuing CA"}, RequireSANMatch: true, MinDaysRemaining: 14,
	}), []scan.Probe{
		probeAt("10.0.0.10", a),
		probeAt("10.0.0.11", b),
	}, now, DefaultConfig())

	if !r.FingerprintDivergence {
		t.Fatal("FingerprintDivergence not set — in policy mode this is the ONLY way a " +
			"half-completed rollout becomes visible")
	}
	if r.Outcome != OutcomeWarning || r.SubReason != ReasonFingerprintDivergence {
		t.Fatalf("Outcome = %s / %s, want WARNING / %s", r.Outcome, r.SubReason, ReasonFingerprintDivergence)
	}
	// Both comply, so neither is a failure — calling this FAILURE is how policy
	// mode becomes as noisy as pinned mode.
	if len(r.IPsMatching) != 2 {
		t.Fatalf("matching = %v, want both", r.IPsMatching)
	}
}

// POLICY MODE: a compliant rotation across the WHOLE pool must be SILENT.
// Without this, a customer rotating 500 certificates a year gets 500 alarms.
func TestPolicyMode_CompliantRotationIsSilent(t *testing.T) {
	rotated := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 9, 0))

	r := Classify(policy(&Policy{
		Issuers: []string{"CN=Corp Issuing CA"}, RequireSANMatch: true, MinDaysRemaining: 14,
	}), []scan.Probe{
		probeAt("10.0.0.10", rotated),
		probeAt("10.0.0.11", rotated),
	}, now, DefaultConfig())

	if r.Outcome != OutcomePass {
		t.Fatalf("Outcome = %s (%s), want PASS — a compliant rotation must be silent",
			r.Outcome, r.Summary)
	}
	if r.Alertable {
		t.Fatal("a compliant rotation is alertable; this is the alert-fatigue failure mode")
	}
}

func TestPolicyMode_RejectsDisallowedIssuer(t *testing.T) {
	rogue := makeCert(t, "api.example.com", "Some Other CA", now.AddDate(0, 6, 0))
	r := Classify(policy(&Policy{Issuers: []string{"CN=Corp Issuing CA"}, RequireSANMatch: true}),
		[]scan.Probe{probeAt("10.0.0.10", rogue)}, now, DefaultConfig())

	if r.Outcome != OutcomeFailure || r.SubReason != ReasonIssuerNotAllowed {
		t.Fatalf("Outcome = %s / %s, want FAILURE / %s", r.Outcome, r.SubReason, ReasonIssuerNotAllowed)
	}
}

func TestPolicyMode_RejectsWrongHostname(t *testing.T) {
	wrong := makeCert(t, "other.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0), "other.example.com")
	r := Classify(policy(&Policy{Issuers: []string{"CN=Corp Issuing CA"}, RequireSANMatch: true}),
		[]scan.Probe{probeAt("10.0.0.10", wrong)}, now, DefaultConfig())

	if r.Outcome != OutcomeFailure || r.SubReason != ReasonSANMismatch {
		t.Fatalf("Outcome = %s / %s, want FAILURE / %s", r.Outcome, r.SubReason, ReasonSANMismatch)
	}
}

// ---------------------------------------------------------------------------
// Reachability, confirmation, grace window
// ---------------------------------------------------------------------------

func TestPartialReachability_IsNotPassAndNotFailure(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	r := Classify(pinned(cert.Fingerprint), []scan.Probe{
		probeAt("10.0.0.10", cert),
		unreachable("10.0.0.11"),
	}, now, DefaultConfig())

	if r.Outcome != OutcomeWarning || r.SubReason != ReasonPartialReachability {
		t.Fatalf("Outcome = %s / %s, want WARNING / %s. It is not PASS (that address was never "+
			"checked) and not FAILURE (nothing is known to be wrong)",
			r.Outcome, r.SubReason, ReasonPartialReachability)
	}
	if len(r.IPsUnreachable) != 1 {
		t.Fatalf("unreachable = %v", r.IPsUnreachable)
	}
}

func TestAllUnreachable(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	r := Classify(pinned(cert.Fingerprint),
		[]scan.Probe{unreachable("10.0.0.10"), unreachable("10.0.0.11")}, now, DefaultConfig())
	if r.Outcome != OutcomeUnreachable {
		t.Fatalf("Outcome = %s, want UNREACHABLE", r.Outcome)
	}
}

// An UNCONFIRMED expectation must never be alertable, whatever is observed.
func TestUnconfirmedExpectationNeverAlerts(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	stale := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, 3))

	e := pinned(expected.Fingerprint)
	e.Confirmed = false

	r := Classify(e, []scan.Probe{
		probeAt("10.0.0.10", expected),
		probeAt("10.0.0.11", stale),
	}, now, DefaultConfig())

	if r.Alertable {
		t.Fatal("an unconfirmed expectation produced an alertable result")
	}
	if r.Outcome != OutcomeUnknown || r.SubReason != ReasonNoConfirmedExpectation {
		t.Fatalf("Outcome = %s / %s, want UNKNOWN / %s", r.Outcome, r.SubReason, ReasonNoConfirmedExpectation)
	}
	// Evidence must STILL be recorded — the operator needs to see it to decide
	// whether to confirm.
	if len(r.PerIP) != 2 {
		t.Fatalf("per-IP evidence dropped for an unconfirmed expectation: %d rows", len(r.PerIP))
	}
}

func TestGraceWindowDowngradesButNeverHidesExpiry(t *testing.T) {
	expected := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	stale := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, 30))
	expired := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, -1))

	e := pinned(expected.Fingerprint)
	e.EffectiveFrom = now.Add(-2 * time.Minute) // inside a 15m window

	// A partial rollout during the window is downgraded — it may still converge.
	r := Classify(e, []scan.Probe{probeAt("10.0.0.10", expected), probeAt("10.0.0.11", stale)},
		now, DefaultConfig())
	if r.Outcome != OutcomeWarning || r.SubReason != ReasonSettling {
		t.Fatalf("in-grace partial = %s / %s, want WARNING / %s", r.Outcome, r.SubReason, ReasonSettling)
	}
	if r.Alertable {
		t.Fatal("an in-grace result is alertable")
	}

	// An EXPIRED certificate is never downgraded. There is no propagation
	// excuse for expiry.
	r2 := Classify(e, []scan.Probe{probeAt("10.0.0.10", expired)}, now, DefaultConfig())
	if r2.Outcome != OutcomeFailure || r2.SubReason != ReasonExpired {
		t.Fatalf("in-grace expiry = %s / %s, want FAILURE / %s — the grace window must never "+
			"suppress expiry", r2.Outcome, r2.SubReason, ReasonExpired)
	}
}

// A blocked probe must not be counted in any denominator; counting a refused
// IMDS address would silently turn a PASS into a partial rollout.
func TestSkippedProbeIsNotCounted(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	skipped := scan.Probe{
		Target:     scan.Target{Addr: netip.MustParseAddr("169.254.169.254"), Port: 443, Hostname: "api.example.com"},
		Skipped:    true,
		SkipReason: "cloud instance-metadata endpoint",
	}
	r := Classify(pinned(cert.Fingerprint),
		[]scan.Probe{probeAt("10.0.0.10", cert), skipped}, now, DefaultConfig())

	if r.Outcome != OutcomePass {
		t.Fatalf("Outcome = %s (%s), want PASS — a skipped probe must not create a false partial",
			r.Outcome, r.Summary)
	}
	if len(r.IPsChecked) != 1 {
		t.Fatalf("checked = %v, want only the real address", r.IPsChecked)
	}
}

func TestNearExpiryWarnsWhileStillMatching(t *testing.T) {
	soon := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 0, 5))
	r := Classify(pinned(soon.Fingerprint), []scan.Probe{probeAt("10.0.0.10", soon)}, now, DefaultConfig())
	if r.Outcome != OutcomeWarning || r.SubReason != ReasonNearExpiry {
		t.Fatalf("Outcome = %s / %s, want WARNING / %s", r.Outcome, r.SubReason, ReasonNearExpiry)
	}
}

// Properties.
func TestInvariants(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	other := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 7, 0))
	sets := [][]scan.Probe{
		{},
		{probeAt("10.0.0.10", cert)},
		{probeAt("10.0.0.10", cert), probeAt("10.0.0.11", other)},
		{probeAt("10.0.0.10", cert), unreachable("10.0.0.11")},
		{unreachable("10.0.0.10")},
	}
	for i, probes := range sets {
		r := Classify(pinned(cert.Fingerprint), probes, now, DefaultConfig())
		if r.Outcome == "" {
			t.Fatalf("set %d: no outcome", i)
		}
		if r.Summary == "" {
			t.Fatalf("set %d: no summary — every result must explain itself", i)
		}
		if len(r.IPsMatching) > len(r.IPsChecked) {
			t.Fatalf("set %d: matching > checked", i)
		}
		if len(r.IPsChecked) > len(r.IPsResolved) {
			t.Fatalf("set %d: checked > resolved", i)
		}
		if r.PartialRollout && r.SubReason != ReasonPartialRollout {
			t.Fatalf("set %d: partial flag without the sub-reason", i)
		}
	}
}

func TestSANCovers(t *testing.T) {
	cases := []struct {
		sans []string
		host string
		want bool
	}{
		{[]string{"DNS:example.com"}, "example.com", true},
		{[]string{"DNS:*.example.com"}, "a.example.com", true},
		{[]string{"DNS:*.example.com"}, "example.com", false},
		{[]string{"DNS:*.example.com"}, "a.b.example.com", false},
		{[]string{"DNS:*.example.com"}, ".example.com", false},
		{[]string{"DNS:EXAMPLE.COM"}, "example.com", true},
		{[]string{"DNS:example.com."}, "example.com", true},
		{[]string{}, "example.com", false},
		{[]string{"DNS:other.com"}, "example.com", false},
	}
	for _, c := range cases {
		if got := SANCovers(c.sans, c.host); got != c.want {
			t.Errorf("SANCovers(%v, %q) = %v, want %v", c.sans, c.host, got, c.want)
		}
	}
}

func TestInferMode(t *testing.T) {
	for issuer, want := range map[string]Mode{
		"CN=R13,O=Let's Encrypt,C=US":     ModePolicy,
		"CN=Amazon RSA 2048 M03,O=Amazon": ModePolicy,
		"CN=ZeroSSL ECC Domain Secure":    ModePolicy,
		"CN=Corp Internal Issuing CA":     ModePinned,
		"":                                ModePinned,
	} {
		if got, why := InferMode(issuer); got != want {
			t.Errorf("InferMode(%q) = %v (%s), want %v", issuer, got, why, want)
		}
	}
}

func TestExpectationValidation(t *testing.T) {
	bad := []Expectation{
		{Endpoint: Endpoint{Port: 443}, Mode: ModePinned, Fingerprint: "x"},
		{Endpoint: Endpoint{Hostname: "a", Port: 443}, Mode: ModePinned},
		{Endpoint: Endpoint{Hostname: "a", Port: 443}, Mode: ModePinned, Fingerprint: "tooshort"},
		{Endpoint: Endpoint{Hostname: "a", Port: 443}, Mode: ModePolicy},
		{Endpoint: Endpoint{Hostname: "a", Port: 443}, Mode: ModePolicy, Policy: &Policy{}},
		{Endpoint: Endpoint{Hostname: "a", Port: 443}, Mode: "other"},
		{Endpoint: Endpoint{Hostname: "a", Port: 0}, Mode: ModePinned, Fingerprint: "x"},
	}
	for i, e := range bad {
		if err := e.Validate(); err == nil {
			t.Errorf("case %d accepted an invalid expectation", i)
		}
	}
	good := pinned("ab" + "cd" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"[:60])
	if err := good.Validate(); err != nil {
		t.Errorf("valid expectation rejected: %v", err)
	}
}

// A refused address must still be VISIBLE. Excluding it from the denominators
// is correct; hiding it would be a silent coverage gap.
func TestSkippedProbeIsStillReported(t *testing.T) {
	cert := makeCert(t, "api.example.com", "Corp Issuing CA", now.AddDate(0, 6, 0))
	skipped := scan.Probe{
		Target:     scan.Target{Addr: netip.MustParseAddr("169.254.169.254"), Port: 443, Hostname: "api.example.com"},
		Skipped:    true,
		SkipReason: "cloud instance-metadata endpoint",
	}
	r := Classify(pinned(cert.Fingerprint),
		[]scan.Probe{probeAt("10.0.0.10", cert), skipped}, now, DefaultConfig())

	if len(r.IPsSkipped) != 1 || r.IPsSkipped[0] != "169.254.169.254" {
		t.Fatalf("IPsSkipped = %v; a refused address must be recorded", r.IPsSkipped)
	}
	found := false
	for _, row := range r.PerIP {
		if row.IP == "169.254.169.254" {
			found = true
			if row.Error == "" {
				t.Error("the skipped address has no explanation")
			}
			if row.Match {
				t.Error("a skipped address was counted as matching")
			}
		}
	}
	if !found {
		t.Fatal("the skipped address vanished from the evidence entirely")
	}
	// And it must not appear in any denominator.
	for _, list := range [][]string{r.IPsResolved, r.IPsChecked, r.IPsMatching, r.IPsUnreachable} {
		for _, ip := range list {
			if ip == "169.254.169.254" {
				t.Fatalf("the skipped address leaked into a denominator: %v", list)
			}
		}
	}
}
