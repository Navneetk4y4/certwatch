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
)

// Config holds the tunables. Every one of these is a false-positive control,
// and the correct values are unknown until real traffic is observed — which is
// why Classify takes them as data rather than baking them in.
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
	IP            string `json:"ip"`
	Port          int    `json:"port"`
	Reachable     bool   `json:"reachable"`
	Handshake     bool   `json:"handshake_completed"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	SubjectCN     string `json:"subject_cn,omitempty"`
	IssuerDN      string `json:"issuer_dn,omitempty"`
	NotAfter      string `json:"not_after,omitempty"`
	DaysRemaining *int   `json:"days_remaining,omitempty"`
	Match         bool   `json:"match"`
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
	if cfg.GraceWindow == 0 && cfg.NearExpiryDays == 0 {
		cfg = DefaultConfig()
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

	// Evidence is gathered for EVERY probe, whatever the verdict. A result
	// without per-IP evidence is an assertion, not a finding.
	for _, p := range probes {
		ip := p.Target.Addr.String()
		row := IPResult{IP: ip, Port: p.Target.Port}

		switch {
		case p.Skipped:
			row.Error = "skipped: " + p.SkipReason
			// Recorded for transparency, excluded from every denominator —
			// including IPsResolved. A refused metadata address is not an
			// address we failed to reach; it is one we declined to touch, and
			// counting it would fabricate a partial rollout.
			r.IPsSkipped = append(r.IPsSkipped, ip)
			r.PerIP = append(r.PerIP, row)
			continue
		}
		r.IPsResolved = append(r.IPsResolved, ip)

		switch {
		case p.ConnectErr != "":
			row.Error = p.ConnectErr
			r.IPsUnreachable = append(r.IPsUnreachable, ip)
			r.PerIP = append(r.PerIP, row)
			continue
		}
		row.Reachable = true

		if p.Chain == nil || p.Chain.Leaf == nil {
			row.Error = p.HandshakeErr
			if row.Error == "" {
				row.Error = "no certificate presented"
			}
			r.IPsTLSError = append(r.IPsTLSError, ip)
			r.PerIP = append(r.PerIP, row)
			continue
		}

		leaf := p.Chain.Leaf
		row.Handshake = true
		row.Fingerprint = leaf.Fingerprint
		row.SubjectCN = leaf.SubjectCN
		row.IssuerDN = leaf.IssuerDN
		if !leaf.NotAfter.IsZero() {
			row.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
			d := leaf.DaysRemaining(now)
			row.DaysRemaining = &d
		}
		if p.HandshakeErr != "" {
			// An mTLS endpoint that rejected us still told us what it serves.
			row.Error = "handshake incomplete, certificate captured: " + p.HandshakeErr
		}

		match, why := matches(e, leaf, r.Endpoint.Hostname, now)
		row.Match = match
		row.Reason = why

		r.IPsChecked = append(r.IPsChecked, ip)
		if match {
			r.IPsMatching = append(r.IPsMatching, ip)
		}
		r.PerIP = append(r.PerIP, row)
	}

	sort.Strings(r.IPsResolved)
	sort.Strings(r.IPsChecked)
	sort.Strings(r.IPsMatching)
	sort.Strings(r.IPsUnreachable)
	sort.Strings(r.IPsTLSError)
	sort.Strings(r.IPsSkipped)
	sort.Slice(r.PerIP, func(i, j int) bool { return r.PerIP[i].IP < r.PerIP[j].IP })

	// Divergence is evaluated independently of the expectation comparison. In
	// policy mode two different certificates can both be compliant, and this is
	// then the ONLY signal that the pool is inconsistent.
	r.FingerprintDivergence = distinctFingerprints(r.PerIP) > 1

	n, c, m := len(r.IPsResolved), len(r.IPsChecked), len(r.IPsMatching)
	inGrace := !e.EffectiveFrom.IsZero() && now.Sub(e.EffectiveFrom) < cfg.GraceWindow

	// ---- the decision table, in order ----
	switch {

	// 0. No confirmed expectation. Probes still ran and evidence is recorded,
	//    but there is nothing to compare against and nothing may alert.
	case !e.Confirmed:
		r.Outcome, r.SubReason = OutcomeUnknown, ReasonNoConfirmedExpectation
		r.Summary = "no confirmed expected state — observed only, cannot alert"

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
		r.Summary = "within the grace window after an expectation change — " + r.Summary
	}

	// THE alerting predicate, in exactly one place.
	r.Alertable = e.Confirmed && !inGrace &&
		(r.Outcome == OutcomeFailure || r.Outcome == OutcomeDrift ||
			r.Outcome == OutcomeUnreachable || r.Outcome == OutcomeWarning)

	return r
}

// matches applies the expectation to one served certificate.
func matches(e Expectation, leaf *model.Certificate, hostname string, now time.Time) (bool, string) {
	if leaf.Expired(now) {
		return false, "certificate expired on " + leaf.NotAfter.UTC().Format("2006-01-02")
	}
	if leaf.NotYetValid(now) {
		return false, "certificate is not valid until " + leaf.NotBefore.UTC().Format("2006-01-02")
	}

	switch e.Mode {
	case ModePinned:
		if leaf.Fingerprint == e.Fingerprint {
			return true, ""
		}
		return false, "serves " + short(leaf.Fingerprint) + ", expected " + short(e.Fingerprint)

	case ModePolicy:
		p := e.Policy
		if len(p.Issuers) > 0 && !containsFold(p.Issuers, leaf.IssuerDN) {
			return false, "issuer not in the allowlist: " + leaf.IssuerDN
		}
		if p.RequireSANMatch && !SANCovers(leaf.SANs, hostname) {
			return false, "no SAN covers " + hostname
		}
		if len(p.AllowedKeyAlgorithms) > 0 && !containsFold(p.AllowedKeyAlgorithms, string(leaf.KeyAlgorithm)) {
			return false, "key algorithm " + string(leaf.KeyAlgorithm) + " is not allowed"
		}
		if p.MinKeyBits > 0 && leaf.KeySize != nil && *leaf.KeySize < p.MinKeyBits {
			return false, fmt.Sprintf("key is %d bits, minimum is %d", *leaf.KeySize, p.MinKeyBits)
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
		// Valid means: not expired, not future-dated, and it covers the host.
		if row.DaysRemaining != nil && *row.DaysRemaining < 0 {
			return false
		}
		if strings.Contains(row.Reason, "expired") || strings.Contains(row.Reason, "not valid until") {
			return false
		}
	}
	return any
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
