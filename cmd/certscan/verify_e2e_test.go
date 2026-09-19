package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/scan"
	"github.com/certwatch/certwatch/pkg/verify"
	"github.com/certwatch/certwatch/pkg/x509norm"
)

// End to end across the whole capability:
//
//	expectation -> distinct IPs -> real TLS handshakes -> per-IP comparison
//	            -> partial rollout -> JSON evidence -> HTML report
//
// The only step not exercised here is the SSRF-gated dial, because the
// production policy refuses loopback — correctly, and that refusal has its own
// tests in pkg/scan. Everything else is the production path.
func TestEndToEndPartialRolloutProducesEvidenceAndReport(t *testing.T) {
	const host = "api.internal.test"

	a := startBackend(t, host, "expected.lab")
	stale := startBackend(t, host, "stale.lab")

	if a.addr == stale.addr {
		t.Fatal("fixture error: backends must be on distinct IP addresses")
	}
	expectedFP := x509norm.Fingerprint(a.certDER)

	probes := []scan.Probe{
		probeBackend(t, a, host),
		probeBackend(t, stale, host),
	}
	exp := verify.Expectation{
		Endpoint:    verify.Endpoint{Hostname: host, Port: a.port},
		Mode:        verify.ModePinned,
		Fingerprint: expectedFP,
		Confirmed:   true,
		ConfirmedBy: "ops@example.com",
		ConfirmedAt: time.Now().Add(-24 * time.Hour).UTC(),
	}
	if err := exp.Validate(); err != nil {
		t.Fatal(err)
	}

	res := verify.Classify(exp, probes, time.Now().UTC(), verify.DefaultConfig())

	// --- the verdict ---
	if res.Outcome != verify.OutcomeFailure || res.SubReason != verify.ReasonPartialRollout {
		t.Fatalf("Outcome = %s / %s, want FAILURE / %s. Summary: %s",
			res.Outcome, res.SubReason, verify.ReasonPartialRollout, res.Summary)
	}
	if !res.PartialRollout {
		t.Fatal("PartialRollout not set")
	}
	if !res.Alertable {
		t.Fatal("a confirmed expectation with a real partial rollout is not alertable")
	}

	// --- the evidence: distinct addresses, each with its own certificate ---
	if len(res.PerIP) != 2 {
		t.Fatalf("per-IP rows = %d, want 2", len(res.PerIP))
	}
	addrs := map[string]bool{}
	for _, row := range res.PerIP {
		addrs[row.IP] = true
		if row.Fingerprint == "" {
			t.Fatalf("%s has no fingerprint recorded", row.IP)
		}
	}
	if len(addrs) != 2 {
		t.Fatalf("evidence covers %d distinct addresses, want 2: %v", len(addrs), addrs)
	}

	// --- JSON evidence must be complete enough to explain the finding ---
	rep := &VerifyReport{
		SchemaVersion: 1, Tool: "certscan", ToolVersion: Version,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
		Results: []verify.Result{res},
		Summary: VerifySummary{
			EndpointsChecked: 1, Failure: 1, PartialRollouts: 1,
			TotalIPsChecked: len(res.IPsChecked), Alertable: 1,
		},
	}
	payload, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	js := string(payload)
	for _, must := range []string{
		"partial_rollout", "per_ip", "ips_matching", "ips_checked",
		"expectation_confirmed", "fingerprint", "\"match\"", "alertable",
	} {
		if !strings.Contains(js, must) {
			t.Errorf("JSON evidence is missing %q — a consumer could not explain the finding", must)
		}
	}
	// Round-trips.
	var back VerifyReport
	if err := json.Unmarshal(payload, &back); err != nil {
		t.Fatalf("evidence does not round-trip: %v", err)
	}
	if !back.Results[0].PartialRollout {
		t.Fatal("PartialRollout lost in the round trip")
	}

	// --- the HTML report ---
	html, err := renderVerifyHTML(rep)
	if err != nil {
		t.Fatal(err)
	}
	h := string(html)
	for _, must := range []string{
		"PARTIAL ROLLOUT", host, "Expected", "Resolved IPs", "Actual", "Match", "Result",
		expectedFP[:16], "MATCH", "DRIFT",
	} {
		if !strings.Contains(h, must) {
			t.Errorf("HTML report is missing %q", must)
		}
	}
	for _, addr := range []string{a.addr.String(), stale.addr.String()} {
		if !strings.Contains(h, addr) {
			t.Errorf("HTML report does not name address %s", addr)
		}
	}

	// SELF-CONTAINED. A report that loaded a remote asset would falsify the
	// product's central promise that it sends nothing anywhere.
	for _, forbidden := range []string{
		"http://", "https://", "//cdn", "<script", "@import", "googleapis",
	} {
		if strings.Contains(h, forbidden) {
			t.Errorf("HTML report contains %q — it must be fully self-contained "+
				"with no external asset and no script", forbidden)
		}
	}

	if os.Getenv("CERTSCAN_WRITE_SAMPLE") != "" {
		_ = os.WriteFile("/tmp/certscan-sample-report.html", html, 0o644)
		_ = os.WriteFile("/tmp/certscan-sample-report.json", payload, 0o644)
		t.Logf("sample written to /tmp/certscan-sample-report.html")
	}
}

// A healthy pool must produce a PASS report with no alarm and no banner.
func TestEndToEndHealthyPoolProducesCleanReport(t *testing.T) {
	const host = "healthy.internal.test"
	a := startBackend(t, host, "same.lab")

	probes := []scan.Probe{probeBackend(t, a, host), probeBackend(t, a, host)}
	exp := verify.Expectation{
		Endpoint:    verify.Endpoint{Hostname: host, Port: a.port},
		Mode:        verify.ModePinned,
		Fingerprint: x509norm.Fingerprint(a.certDER),
		Confirmed:   true,
	}
	res := verify.Classify(exp, probes, time.Now().UTC(), verify.DefaultConfig())
	if res.Outcome != verify.OutcomePass {
		t.Fatalf("Outcome = %s (%s), want PASS", res.Outcome, res.Summary)
	}
	if res.Alertable {
		t.Fatal("a healthy pool is alertable")
	}

	rep := &VerifyReport{SchemaVersion: 1, Tool: "certscan", ToolVersion: Version,
		Results: []verify.Result{res}, Summary: VerifySummary{EndpointsChecked: 1, Pass: 1}}
	html, err := renderVerifyHTML(rep)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "partial rollout") {
		t.Error("a healthy report shows the partial-rollout banner")
	}
}

// The expectations file must round-trip, and an invalid one must be refused
// rather than silently producing an expectation that accepts anything.
func TestExpectationFileRoundTripAndValidation(t *testing.T) {
	ef := ExpectationFile{Version: 1, Expectations: []verify.Expectation{
		{
			Endpoint: verify.Endpoint{Hostname: "a.example", Port: 443},
			Mode:     verify.ModePinned, Confirmed: true,
			Fingerprint: strings.Repeat("ab", 32),
		},
		{
			Endpoint: verify.Endpoint{Hostname: "b.example", Port: 443},
			Mode:     verify.ModePolicy, Confirmed: false,
			Policy: &verify.Policy{Issuers: []string{"CN=Corp CA"}, RequireSANMatch: true},
		},
	}}
	b, err := json.Marshal(ef)
	if err != nil {
		t.Fatal(err)
	}
	var back ExpectationFile
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Expectations) != 2 {
		t.Fatalf("round trip lost expectations")
	}
	for i, e := range back.Expectations {
		if err := e.Validate(); err != nil {
			t.Errorf("expectation %d failed validation after round trip: %v", i, err)
		}
	}
	if back.Expectations[1].Confirmed {
		t.Error("confirmation state was not preserved")
	}
}

var _ = context.Background
