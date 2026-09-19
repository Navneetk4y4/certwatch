package verify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/scan"
)

// Outcome is the verdict for one endpoint at one moment.
type Outcome string

const (
	// OutcomePass: every resolved IP satisfied the expectation, nothing degraded.
	OutcomePass Outcome = "PASS"
	// OutcomeWarning: expectation satisfied, but some non-identity property is
	// degraded — near expiry, incomplete chain, or divergent-but-compliant
	// certificates across IPs. The right certificate is being served.
	OutcomeWarning Outcome = "WARNING"
	// OutcomeDrift: identity differs from a PINNED expectation but the served
	// certificate is itself valid. The normal shape of a rotation nobody told
	// us about. Never exists in policy mode.
	OutcomeDrift Outcome = "DRIFT"
	// OutcomeFailure: expired, wrong SAN, disallowed issuer, or — the one that
	// matters — SOME IPs match and some do not.
	OutcomeFailure Outcome = "FAILURE"
	// OutcomeUnreachable: no resolved IP completed a handshake.
	OutcomeUnreachable Outcome = "UNREACHABLE"
	// OutcomeUnknown: no confirmed expectation, DNS failure, or a stale result.
	// A verification that did not happen must never display as PASS.
	OutcomeUnknown Outcome = "UNKNOWN"
)

// Sub-reasons. These are what an operator acts on; the Outcome alone is not
// actionable.
const (
	ReasonPartialRollout         = "partial_rollout"
	ReasonFingerprintDivergence  = "fingerprint_divergence"
	ReasonPartialReachability    = "partial_reachability"
	ReasonExpired                = "expired"
	ReasonNotYetValid            = "not_yet_valid"
	ReasonSANMismatch            = "san_mismatch"
	ReasonIssuerNotAllowed       = "issuer_not_allowed"
	ReasonWeakKey                = "weak_key"
	ReasonKeyAlgorithmNotAllowed = "key_algorithm_not_allowed"
	ReasonNearExpiry             = "near_expiry"
	ReasonChainIncomplete        = "chain_incomplete"
	ReasonUnexpectedButValid     = "unexpected_but_valid_certificate"
	ReasonNoConfirmedExpectation = "no_confirmed_expectation"
	ReasonDNSFailure             = "dns_failure"
	ReasonAllUnreachable         = "all_ips_unreachable"
	ReasonSettling               = "settling_grace_window"
	// A configuration error, not an endpoint fault. These must never alert:
	// paging someone about a typo in an expectations file trains them to
	// ignore the product.
	ReasonInvalidExpectation = "invalid_expected_state"
	ReasonNotInForce         = "expected_state_not_yet_in_force"
)

// Config tunes the classifier.
//
// A zero field means "unset — use the default". A NEGATIVE field means the
// caller has explicitly switched that behaviour off. The distinction matters:
// treating zero as "off" would let a partially-filled Config silently disable
// near-expiry detection, and treating it only as "default" would leave no way
// to turn the grace window off at all.
type Config struct {
	// GraceWindow after an expectation change, during which identity
	// differences are informational. Absorbs CDN propagation and rolling
	// restarts. Expiry is never suppressed by it.
	GraceWindow time.Duration
	// NearExpiryDays below which a matching certificate still raises WARNING.
	NearExpiryDays int
}

// DefaultConfig is the starting point, not a tuned answer.
func DefaultConfig() Config {
	return Config{GraceWindow: 15 * time.Minute, NearExpiryDays: 14}
}

// IPResult is the evidence for one address. This is the row an operator reads.
type IPResult struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Reachable   bool   `json:"reachable"`
	Handshake   bool   `json:"handshake_completed"`
	Fingerprint string `json:"fingerprint,omitempty"`
	SubjectCN   string `json:"subject_cn,omitempty"`

	// Skipped marks an address the scanner declined to touch.
	Skipped bool `json:"skipped,omitempty"`

	// SANs is evidence, and it is also what lets a DRIFT verdict check that
	// the unexpected certificate is actually for THIS hostname.
	SANs          []string `json:"sans,omitempty"`
	IssuerDN      string   `json:"issuer_dn,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	DaysRemaining *int     `json:"days_remaining,omitempty"`
	Match         bool     `json:"match"`
	// Reason explains a non-match, in words an operator can act on.
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Result is the full verdict plus the evidence that produced it.
type Result struct {
	Endpoint  Endpoint  `json:"endpoint"`
	CheckedAt time.Time `json:"checked_at"`

	Outcome   Outcome `json:"outcome"`
	SubReason string  `json:"sub_reason,omitempty"`
	Summary   string  `json:"summary"`

	ExpectationMode      Mode   `json:"expectation_mode"`
	ExpectationConfirmed bool   `json:"expectation_confirmed"`
	Expected             string `json:"expected"`

	PerIP []IPResult `json:"per_ip"`

	IPsResolved    []string `json:"ips_resolved"`
	IPsChecked     []string `json:"ips_checked"`
	IPsMatching    []string `json:"ips_matching"`
	IPsUnreachable []string `json:"ips_unreachable,omitempty"`
	IPsTLSError    []string `json:"ips_tls_error,omitempty"`
	// IPsSkipped were resolved but refused by policy (a metadata endpoint, a
	// blocked range). They are recorded for transparency and excluded from
	// every denominator: counting a refused address would turn a healthy pool
	// into a false partial rollout.
	IPsSkipped []string `json:"ips_skipped,omitempty"`

	// PartialRollout is the headline finding: some addresses serve the expected
	// certificate and some do not.
	PartialRollout bool `json:"partial_rollout"`

	// Suppressed is true when a real finding was downgraded by the grace
	// window. PartialRollout stays TRUE in that case — it is a fact about the
	// pool, not a verdict — so a caller that headlines the flag without
	// checking this one announces a finding the classifier has just silenced.
	Suppressed bool `json:"suppressed,omitempty"`
	// FingerprintDivergence is true when checked addresses disagree on the
	// certificate, regardless of whether each satisfies the expectation. In
	// policy mode this is the ONLY way partial rollout becomes visible, because
	// two different certificates can both be compliant.
	FingerprintDivergence bool `json:"fingerprint_divergence"`
	// Alertable is false whenever the expectation is unconfirmed or the grace
	// window is open. Nothing may notify on a false value.
	Alertable bool `json:"alertable"`
}

// Classify is the product, expressed as a pure function.
//
// Rules are evaluated in order; the first match wins. The order is the design:
// partial rollout is checked BEFORE total mismatch, because "some IPs are
// wrong" is a different and more urgent problem than "all IPs are wrong", and
// an operator triaging the second would take the wrong action on the first.
func Classify(e Expectation, probes []scan.Probe, now time.Time, cfg Config) Result {
	// Fill each field INDEPENDENTLY. Filling only when both were zero meant a
	// caller who set GraceWindow silently got NearExpiryDays=0, which disables
	// near-expiry detection entirely — a certificate three days from expiry
	// reported PASS. A partially-specified config must not silently switch a
	// check off.
	// Zero means "unset, use the default". NEGATIVE means "the caller
	// explicitly turned this off" — without that distinction there was no way
	// to disable the grace window at all, and a caller who wanted no
	// suppression silently got fifteen minutes of it.
	def := DefaultConfig()
	if cfg.GraceWindow == 0 {
		cfg.GraceWindow = def.GraceWindow
	}
	if cfg.NearExpiryDays == 0 {
		cfg.NearExpiryDays = def.NearExpiryDays
	}

	r := Result{
		Endpoint:             e.Endpoint,
		CheckedAt:            now.UTC(),
		ExpectationMode:      e.Mode,
		ExpectationConfirmed: e.Confirmed,
		Expected:             e.Describe(),
		PerIP:                []IPResult{},
		IPsResolved:          []string{},
		IPsChecked:           []string{},
		IPsMatching:          []string{},
	}

	// An invalid expectation is a CONFIGURATION error. Reporting FAILURE would
	// blame the endpoint and page someone for a typo in a file, and policy mode
	// with a nil Policy used to panic outright — Classify does not call
	// Validate, and a pure function must survive whatever it is handed.
	invalidErr := e.Validate()

	// Evidence is gathered for EVERY probe, whatever the verdict. A result
	// without per-IP evidence is an assertion, not a finding.
	// Duplicate addresses would inflate every denominator and could fabricate a
	// partial rollout from a caller that probed one address twice. Evidence
	// keeps every row; the counts keep each address once.
	for _, p := range probes {
		ip := p.Target.Addr.String()
		row := IPResult{IP: ip, Port: p.Target.Port}

		switch {
		case p.Skipped:
			row.Skipped = true
			row.Error = "skipped: " + p.SkipReason
			// Recorded for transparency, excluded from every denominator —
			// including IPsResolved. A refused metadata address is not an
			// address we failed to reach; it is one we declined to touch, and
			// counting it would fabricate a partial rollout.
			r.PerIP = append(r.PerIP, row)
			continue
		}

		switch {
		case p.ConnectErr != "":
			row.Error = p.ConnectErr
			r.PerIP = append(r.PerIP, row)
			continue
		}
		row.Reachable = true

		if p.Chain == nil || p.Chain.Leaf == nil {
			row.Error = p.HandshakeErr
			if row.Error == "" {
				row.Error = "no certificate presented"
			}
			r.PerIP = append(r.PerIP, row)
			continue
		}

		leaf := p.Chain.Leaf
		row.Handshake = true
		row.Fingerprint = leaf.Fingerprint
		row.SubjectCN = leaf.SubjectCN
		row.IssuerDN = leaf.IssuerDN
		if !leaf.NotAfter.IsZero() {
			row.SANs = leaf.SANs
			row.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
			d := leaf.DaysRemaining(now)
			row.DaysRemaining = &d
		}
		if p.HandshakeErr != "" {
			// An mTLS endpoint that rejected us still told us what it serves.
			row.Error = "handshake incomplete, certificate captured: " + p.HandshakeErr
		}

		var match bool
		var why string
		if invalidErr == nil {
			match, why = matches(e, leaf, r.Endpoint.Hostname, now)
		} else {
			why = "not compared: the expected state is unusable"
		}
		row.Match = match
		row.Reason = why

		r.PerIP = append(r.PerIP, row)
	}

	deriveCounts(&r)
	// Sort on the full identity, not the address alone. sort.Slice is not
	// stable, so rows sharing an address were ordered by luck — and
	// firstFailureReason, nonMatching and the degraded check all read PerIP in
	// order, which made the verdict itself depend on probe input order.
	sort.SliceStable(r.PerIP, func(i, j int) bool {
		a, b := r.PerIP[i], r.PerIP[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Fingerprint < b.Fingerprint
	})

	// Divergence is evaluated independently of the expectation comparison. In
	// policy mode two different certificates can both be compliant, and this is
	// then the ONLY signal that the pool is inconsistent.
	r.FingerprintDivergence = distinctFingerprints(r.PerIP) > 1

	n, c, m := len(r.IPsResolved), len(r.IPsChecked), len(r.IPsMatching)
	// The grace window is the interval AFTER an expectation takes effect.
	//
	// The elapsed time must be non-negative. Without that check a future
	// EffectiveFrom gave a negative duration, which is less than any window, so
	// the endpoint sat in a PERMANENT grace window and a real partial rollout
	// was suppressed forever. That is the worst failure this product can have:
	// silently reporting healthy while half the traffic hits the wrong
	// certificate.
	elapsed := now.Sub(e.EffectiveFrom)
	inGrace := !e.EffectiveFrom.IsZero() && cfg.GraceWindow > 0 &&
		elapsed >= 0 && elapsed < cfg.GraceWindow

	// A grace window exists to absorb the minutes during which a planned
	// rotation is still propagating. An EXPIRED certificate is not a rotation
	// in progress — it is an outage that has already started, and no
	// expectation change can make it acceptable. Suppressing it is the single
	// most damaging false negative this product could produce.
	if inGrace && anyServedCertificateExpired(r.PerIP, now) {
		inGrace = false
	}
	// An expectation dated in the future is not in force yet. Verifying against
	// it would compare reality to a state nobody has deployed.
	notYetInForce := !e.EffectiveFrom.IsZero() && elapsed < 0

	// ---- the decision table, in order ----
	switch {

	// 0a. No usable expectation — invalid, unconfirmed, or not yet in force.
	//
	//     Even here the addresses are compared AGAINST EACH OTHER. Divergence
	//     needs no expected state: "these two IPs serve different certificates"
	//     is a fact about reality, and it is the finding this product exists to
	//     make. decision_register.md GAP-3 requires the divergence check to be
	//     "evaluated independently of the expectation comparison"; returning
	//     UNKNOWN here without looking would have violated that, and would have
	//     let anyone silence a real partial rollout by dating an expectation in
	//     the future, leaving it unconfirmed, or corrupting one field of it.
	//
	//     D14 is not weakened. D14 forbids alerting on drift FROM AN
	//     UNCONFIRMED EXPECTATION. This alert is not measured against the
	//     expectation at all.
	case invalidErr != nil, notYetInForce, !e.Confirmed:
		switch {
		case invalidErr != nil:
			r.Outcome, r.SubReason = OutcomeUnknown, ReasonInvalidExpectation
			r.Summary = "the expected state is not usable: " + invalidErr.Error()
		case notYetInForce:
			r.Outcome, r.SubReason = OutcomeUnknown, ReasonNotInForce
			r.Summary = fmt.Sprintf("the expected state does not take effect until %s",
				e.EffectiveFrom.UTC().Format(time.RFC3339))
		default:
			r.Outcome, r.SubReason = OutcomeUnknown, ReasonNoConfirmedExpectation
			r.Summary = "no confirmed expected state; recording what is served, comparing nothing"
		}
		if r.FingerprintDivergence {
			r.Outcome, r.SubReason = OutcomeWarning, ReasonFingerprintDivergence
			r.Summary = fmt.Sprintf("%d addresses serve %d different certificates. %s "+
				"The addresses disagree with each other, which needs no expected state to see.",
				c, distinctFingerprints(r.PerIP), r.Summary)
		}

	// 1. Nothing resolved.
	case n == 0:
		r.Outcome, r.SubReason = OutcomeUnknown, ReasonDNSFailure
		r.Summary = "the hostname resolved to no addresses"

	// 2. Nothing answered.
	case c == 0:
		r.Outcome, r.SubReason = OutcomeUnreachable, ReasonAllUnreachable
		r.Summary = fmt.Sprintf("none of the %d resolved address(es) completed a TLS handshake", n)

	// 3. THE SIGNATURE FINDING. Some addresses serve the expected certificate
	//    and some do not. Checked before total mismatch deliberately.
	case m > 0 && m < c:
		r.Outcome, r.SubReason = OutcomeFailure, ReasonPartialRollout
		r.PartialRollout = true
		r.Summary = fmt.Sprintf("PARTIAL ROLLOUT — %d of %d addresses serve the expected certificate; %s do not",
			m, c, strings.Join(nonMatching(r), ", "))

	// 4. Pinned mode, everything changed, but what is served is itself valid.
	//    The normal shape of a rotation nobody recorded. A prompt, not an alarm.
	case m == 0 && e.Mode == ModePinned && allServedCertificatesValid(e, r, now):
		r.Outcome, r.SubReason = OutcomeDrift, ReasonUnexpectedButValid
		r.Summary = fmt.Sprintf("all %d address(es) serve a different but valid certificate — "+
			"likely a rotation; confirm it to make this the new expected state", c)

	// 5. Everything is wrong.
	case m == 0:
		reason := firstFailureReason(r)
		r.Outcome, r.SubReason = OutcomeFailure, reason
		r.Summary = fmt.Sprintf("none of the %d checked address(es) satisfy the expected state (%s)",
			c, humanReason(reason))

	// 6. Everything that answered is correct, but not everything answered.
	//    Neither PASS (they were not checked) nor UNREACHABLE (some answered).
	case m == c && c < n:
		r.Outcome, r.SubReason = OutcomeWarning, ReasonPartialReachability
		r.Summary = fmt.Sprintf("%d of %d addresses are correct; %d could not be reached and are unverified",
			m, n, n-c)

	// 7. All correct, but they do not agree with each other. Only reachable in
	//    policy mode — two compliant certificates on one pool.
	case r.FingerprintDivergence:
		r.Outcome, r.SubReason = OutcomeWarning, ReasonFingerprintDivergence
		r.Summary = fmt.Sprintf("all %d addresses satisfy the policy but serve %d DIFFERENT certificates — "+
			"a rollout in progress, or a pool that never converged", c, distinctFingerprints(r.PerIP))

	// 8. All correct, something degraded.
	default:
		if reason, detail := degraded(r, cfg); reason != "" {
			r.Outcome, r.SubReason = OutcomeWarning, reason
			r.Summary = detail
		} else {
			// 9. Everything is right.
			r.Outcome = OutcomePass
			r.Summary = fmt.Sprintf("all %d address(es) serve the expected certificate", c)
		}
	}

	// The grace window downgrades identity findings only. An expired
	// certificate has no propagation excuse.
	if inGrace && (r.Outcome == OutcomeFailure || r.Outcome == OutcomeDrift) &&
		r.SubReason != ReasonExpired {
		r.Outcome = OutcomeWarning
		r.SubReason = ReasonSettling
		r.Suppressed = true
		r.Summary = "within the grace window after an expectation change — " + r.Summary
	}

	// THE alerting predicate, in exactly one place.
	// R1 holds without exception: no alert without a human-confirmed
	// expectation.
	//
	// Divergence with no confirmed expectation is REPORTED (WARNING, visible in
	// the report) but does not page anyone. Classify sees a single point in
	// time, and at a single point in time a rolling deploy and a pool that
	// never converged look identical. Separating them needs two observations
	// separated by time, which this function does not have. Alerting anyway
	// would page on every rolling deploy — R2, rated Fatal.
	r.Alertable = e.Confirmed && !inGrace &&
		(r.Outcome == OutcomeFailure || r.Outcome == OutcomeDrift ||
			r.Outcome == OutcomeUnreachable || r.Outcome == OutcomeWarning)

	return r
}

// matches applies the expectation to one served certificate.
func matches(e Expectation, leaf *model.Certificate, hostname string, now time.Time) (bool, string) {
	// An unparseable certificate has a zero NotAfter, which reads as expired in
	// the year 1. Reporting "expired on 0001-01-01" is both a false alert and a
	// false statement: the certificate is not expired, we could not read it.
	// Validity cannot be judged from fields that were never decoded.
	if leaf.ParseStatus == model.ParseUnparseable {
		return false, "certificate could not be parsed, so it cannot be verified"
	}
	if leaf.Expired(now) {
		return false, "certificate expired on " + leaf.NotAfter.UTC().Format("2006-01-02")
	}
	if leaf.NotYetValid(now) {
		return false, "certificate is not valid until " + leaf.NotBefore.UTC().Format("2006-01-02")
	}

	switch e.Mode {
	case ModePinned:
		// openssl prints fingerprints uppercase and colon-separated. A
		// fingerprint pasted from it used to match nothing, so every address
		// reported DRIFT — a false alert caused purely by the shape of the
		// text the operator copied.
		if NormaliseFingerprint(leaf.Fingerprint) == NormaliseFingerprint(e.Fingerprint) {
			return true, ""
		}
		return false, "serves " + short(leaf.Fingerprint) + ", expected " + short(e.Fingerprint)

	case ModePolicy:
		p := e.Policy
		if p == nil {
			// Unreachable now that Classify validates first; kept because a
			// nil dereference here would take down a whole scan, and defence
			// in depth costs two lines.
			return false, "policy mode with no policy"
		}
		if len(p.Issuers) > 0 && !containsFold(p.Issuers, leaf.IssuerDN) {
			return false, "issuer not in the allowlist: " + leaf.IssuerDN
		}
		if p.RequireSANMatch && !SANCovers(leaf.SANs, hostname) {
			return false, "no SAN covers " + hostname
		}
		if len(p.AllowedKeyAlgorithms) > 0 && !containsFold(p.AllowedKeyAlgorithms, string(leaf.KeyAlgorithm)) {
			return false, "key algorithm " + string(leaf.KeyAlgorithm) + " is not allowed"
		}
		if p.MinKeyBits > 0 {
			// An unknown key size cannot satisfy a minimum. Skipping the check
			// meant a policy demanding 4096 bits passed a certificate whose
			// key size could not be read — failing open on exactly the
			// certificates least worth trusting.
			if leaf.KeySize == nil {
				return false, fmt.Sprintf("key size could not be read, minimum is %d", p.MinKeyBits)
			}
			if *leaf.KeySize < p.MinKeyBits {
				return false, fmt.Sprintf("key is %d bits, minimum is %d", *leaf.KeySize, p.MinKeyBits)
			}
		}
		if p.MinDaysRemaining > 0 {
			if d := leaf.DaysRemaining(now); d < p.MinDaysRemaining {
				return false, fmt.Sprintf("%d days remaining, minimum is %d", d, p.MinDaysRemaining)
			}
		}
		return true, ""
	}
	return false, "invalid expectation mode"
}

func allServedCertificatesValid(e Expectation, r Result, now time.Time) bool {
	any := false
	for _, row := range r.PerIP {
		if !row.Handshake {
			continue
		}
		any = true
		// Valid means: not expired, not future-dated, AND it covers the host.
		//
		// The host check was named in this comment but never implemented, so a
		// certificate whose only SAN was an unrelated hostname was classified
		// DRIFT — "a different but valid certificate, likely a rotation". That
		// downgrades a genuine misdeploy, or a swapped-in foreign certificate,
		// into a routine-sounding notice.
		if row.DaysRemaining != nil && *row.DaysRemaining < 0 {
			return false
		}
		if strings.Contains(row.Reason, "expired") || strings.Contains(row.Reason, "not valid until") {
			return false
		}
		if !SANCovers(row.SANs, e.Endpoint.Hostname) {
			return false
		}
	}
	return any
}

// anyServedCertificateExpired reports whether any address that completed a
// handshake is serving an expired certificate.
func anyServedCertificateExpired(rows []IPResult, now time.Time) bool {
	for _, row := range rows {
		if !row.Handshake {
			continue
		}
		if row.DaysRemaining != nil && *row.DaysRemaining < 0 {
			return true
		}
		if strings.Contains(row.Reason, "expired") {
			return true
		}
	}
	return false
}

func firstFailureReason(r Result) string {
	// Ordered by how actionable each is: an expired certificate is unambiguous,
	// a SAN mismatch is a misdeploy, an issuer problem may be a policy gap.
	order := []struct{ needle, reason string }{
		{"expired", ReasonExpired},
		{"not valid until", ReasonNotYetValid},
		{"no SAN covers", ReasonSANMismatch},
		{"issuer not in", ReasonIssuerNotAllowed},
		{"key algorithm", ReasonKeyAlgorithmNotAllowed},
		{"bits, minimum", ReasonWeakKey},
		{"key size could not be read", ReasonWeakKey},
		{"days remaining, minimum", ReasonNearExpiry},
	}
	for _, o := range order {
		for _, row := range r.PerIP {
			if !row.Match && strings.Contains(row.Reason, o.needle) {
				return o.reason
			}
		}
	}
	return ReasonUnexpectedButValid
}

func degraded(r Result, cfg Config) (string, string) {
	for _, row := range r.PerIP {
		if row.Handshake && row.DaysRemaining != nil && *row.DaysRemaining < cfg.NearExpiryDays {
			return ReasonNearExpiry, fmt.Sprintf(
				"the expected certificate is being served, but expires in %d days (%s)",
				*row.DaysRemaining, row.IP)
		}
	}
	return "", ""
}

func distinctFingerprints(rows []IPResult) int {
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Fingerprint != "" {
			seen[r.Fingerprint] = true
		}
	}
	return len(seen)
}

func nonMatching(r Result) []string {
	var out []string
	for _, row := range r.PerIP {
		if row.Handshake && !row.Match {
			out = append(out, row.IP)
		}
	}
	return sortedCopy(out)
}

func containsFold(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.EqualFold(strings.TrimSpace(h), strings.TrimSpace(needle)) {
			return true
		}
	}
	return false
}

func humanReason(r string) string {
	switch r {
	case ReasonExpired:
		return "expired"
	case ReasonSANMismatch:
		return "wrong hostname"
	case ReasonIssuerNotAllowed:
		return "issuer not allowed"
	case ReasonWeakKey:
		return "key too small"
	case ReasonNearExpiry:
		return "too close to expiry"
	case ReasonKeyAlgorithmNotAllowed:
		return "key algorithm not allowed"
	case ReasonNotYetValid:
		return "not yet valid"
	}
	return strings.ReplaceAll(r, "_", " ")
}

// deriveCounts computes every denominator from the sorted evidence, once.
//
// The counts used to be accumulated inside the probe loop with a "have I seen
// this address" map, which made them depend on the ORDER probes arrived in:
// when one address appeared twice with different results, whichever row came
// first decided the verdict. The same pool could report PASS or FAILURE
// depending on the order the scanner happened to produce.
//
// Deriving from sorted evidence removes the ordering input entirely, and lets
// duplicates be resolved by a stated rule rather than by arrival time.
func deriveCounts(r *Result) {
	// Sort on the full identity. sort.Slice is not stable, so rows sharing an
	// address were previously ordered by luck — and firstFailureReason,
	// nonMatching and the degraded check all read PerIP in order.
	sort.SliceStable(r.PerIP, func(i, j int) bool {
		a, b := r.PerIP[i], r.PerIP[j]
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Fingerprint < b.Fingerprint
	})

	type agg struct {
		skipped, resolved, reachable, handshake, allMatch bool
	}
	order := []string{}
	seen := map[string]*agg{}
	for _, row := range r.PerIP {
		a, ok := seen[row.IP]
		if !ok {
			a = &agg{allMatch: true}
			seen[row.IP] = a
			order = append(order, row.IP)
		}
		if row.Skipped {
			a.skipped = true
			continue
		}
		// A skipped address is not "an address we failed to reach"; it is one
		// we declined to touch. Counting it would fabricate a partial rollout.
		a.resolved = true
		a.reachable = a.reachable || row.Reachable
		a.handshake = a.handshake || row.Handshake
		if row.Handshake && !row.Match {
			// Fail closed. An address that served the expected certificate on
			// one probe and something else on another does not reliably serve
			// the expected certificate.
			a.allMatch = false
		}
	}
	sort.Strings(order)

	r.IPsResolved, r.IPsChecked, r.IPsMatching = []string{}, []string{}, []string{}
	r.IPsUnreachable, r.IPsTLSError, r.IPsSkipped = nil, nil, nil
	for _, ip := range order {
		a := seen[ip]
		switch {
		case !a.resolved && a.skipped:
			r.IPsSkipped = append(r.IPsSkipped, ip)
		case !a.reachable:
			r.IPsResolved = append(r.IPsResolved, ip)
			r.IPsUnreachable = append(r.IPsUnreachable, ip)
		case !a.handshake:
			r.IPsResolved = append(r.IPsResolved, ip)
			r.IPsTLSError = append(r.IPsTLSError, ip)
		default:
			r.IPsResolved = append(r.IPsResolved, ip)
			r.IPsChecked = append(r.IPsChecked, ip)
			if a.allMatch {
				r.IPsMatching = append(r.IPsMatching, ip)
			}
		}
	}
}
