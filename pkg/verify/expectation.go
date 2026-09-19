// Package verify compares what an endpoint SHOULD serve against what every one
// of its resolved IPs ACTUALLY serves.
//
// This is the product. Everything else — discovery, normalisation, scanning —
// exists to feed this comparison.
//
// # The failure it exists to catch
//
//	api.example.com
//	  10.0.0.10:443 -> AAA...  MATCH
//	  10.0.0.11:443 -> BBB...  DRIFT
//	  => PARTIAL ROLLOUT
//
// A hostname-level monitor connects once, gets whichever address answers, and
// reports healthy. Half the traffic is hitting the wrong certificate.
//
// # Two design rules
//
//  1. Classify is a PURE function of (expectation, probes, now). No I/O, no
//     clock, no network. The whole false-positive problem is about time —
//     grace windows, days remaining, consecutive checks — and a classifier that
//     cannot be evaluated at an arbitrary instant cannot be tuned.
//  2. An UNCONFIRMED expectation can never produce an alertable outcome. A
//     baseline no human endorsed may be an already-broken state, and alerting
//     on it is how monitoring products get muted.
package verify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
)

// Mode is how an expectation is expressed.
type Mode string

const (
	// ModePinned expects one exact certificate, by fingerprint. Default for
	// manually-managed endpoints. A legitimate rotation shows as DRIFT, which
	// is a prompt to confirm, not an alarm.
	ModePinned Mode = "pinned"

	// ModePolicy expects any certificate satisfying a set of properties.
	// Default where the issuer indicates automation. A compliant renewal is
	// silent — without this, a customer rotating 500 certificates a year gets
	// 500 false alarms and mutes the product.
	ModePolicy Mode = "policy"
)

// Policy is the property set for ModePolicy.
type Policy struct {
	// Issuers is an allowlist of exact issuer DNs. Exact, not fuzzy: CAs
	// rotate intermediates, and a fuzzy match would fire on every rotation.
	Issuers []string `json:"issuers"`
	// AllowedKeyAlgorithms is empty for "any".
	AllowedKeyAlgorithms []string `json:"allowed_key_algorithms,omitempty"`
	MinKeyBits           int      `json:"min_key_bits,omitempty"`
	MinDaysRemaining     int      `json:"min_days_remaining,omitempty"`
	RequireSANMatch      bool     `json:"require_san_match"`
}

// Endpoint identity: what the CLIENT asks for. Not the IP — an autoscaling
// group would otherwise churn identity weekly and reset all history.
type Endpoint struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	// SNI empty means "send SNI equal to the hostname", the common case.
	SNI string `json:"sni,omitempty"`
}

func (e Endpoint) String() string {
	if e.SNI != "" && e.SNI != e.Hostname {
		return fmt.Sprintf("%s:%d (sni=%s)", e.Hostname, e.Port, e.SNI)
	}
	return fmt.Sprintf("%s:%d", e.Hostname, e.Port)
}

// EffectiveSNI is what is actually presented in the handshake.
func (e Endpoint) EffectiveSNI() string {
	if e.SNI == "" {
		return e.Hostname
	}
	return e.SNI
}

// Expectation is what an endpoint should serve, and whether a human said so.
type Expectation struct {
	Endpoint Endpoint `json:"endpoint"`
	Mode     Mode     `json:"mode"`

	// Fingerprint is the expected SHA-256 of the full DER. ModePinned only.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Policy applies to ModePolicy only.
	Policy *Policy `json:"policy,omitempty"`

	// Confirmed records that a human endorsed this baseline. An unconfirmed
	// expectation produces informational output and NEVER an alert.
	Confirmed   bool      `json:"confirmed"`
	ConfirmedBy string    `json:"confirmed_by,omitempty"`
	ConfirmedAt time.Time `json:"confirmed_at,omitempty"`

	// EffectiveFrom starts the grace window, during which identity differences
	// are informational — CDN propagation and rolling restarts are not faults.
	EffectiveFrom time.Time `json:"effective_from,omitempty"`

	// Source records where the expectation came from.
	Source string `json:"source,omitempty"`
}

// Validate reports whether the expectation is self-consistent.
func (e Expectation) Validate() error {
	if e.Endpoint.Hostname == "" {
		return fmt.Errorf("verify: expectation has no hostname")
	}
	if e.Endpoint.Port < 1 || e.Endpoint.Port > 65535 {
		return fmt.Errorf("verify: %s has an invalid port", e.Endpoint.Hostname)
	}
	switch e.Mode {
	case ModePinned:
		if e.Fingerprint == "" {
			return fmt.Errorf("verify: %s is pinned but has no fingerprint", e.Endpoint)
		}
		if e.Policy != nil {
			return fmt.Errorf("verify: %s is pinned but also carries a policy", e.Endpoint)
		}
		if len(e.Fingerprint) != 64 {
			return fmt.Errorf("verify: %s fingerprint is %d chars, want 64 (SHA-256 hex)",
				e.Endpoint, len(e.Fingerprint))
		}
	case ModePolicy:
		if e.Policy == nil {
			return fmt.Errorf("verify: %s is policy mode but has no policy", e.Endpoint)
		}
		if e.Fingerprint != "" {
			return fmt.Errorf("verify: %s is policy mode but also pins a fingerprint", e.Endpoint)
		}
		if len(e.Policy.Issuers) == 0 && !e.Policy.RequireSANMatch &&
			e.Policy.MinDaysRemaining == 0 && e.Policy.MinKeyBits == 0 {
			return fmt.Errorf("verify: %s has an empty policy, which would accept anything", e.Endpoint)
		}
	default:
		return fmt.Errorf("verify: %s has unknown mode %q", e.Endpoint, e.Mode)
	}
	return nil
}

// Describe renders the expectation for a report or a UI.
func (e Expectation) Describe() string {
	switch e.Mode {
	case ModePinned:
		return "certificate " + short(e.Fingerprint)
	case ModePolicy:
		var parts []string
		if len(e.Policy.Issuers) > 0 {
			parts = append(parts, "issuer ∈ ["+strings.Join(e.Policy.Issuers, " | ")+"]")
		}
		if e.Policy.RequireSANMatch {
			parts = append(parts, "SAN covers hostname")
		}
		if e.Policy.MinKeyBits > 0 {
			parts = append(parts, fmt.Sprintf("key ≥ %d bits", e.Policy.MinKeyBits))
		}
		if len(e.Policy.AllowedKeyAlgorithms) > 0 {
			parts = append(parts, "algorithm ∈ ["+strings.Join(e.Policy.AllowedKeyAlgorithms, " | ")+"]")
		}
		if e.Policy.MinDaysRemaining > 0 {
			parts = append(parts, fmt.Sprintf("≥ %d days remaining", e.Policy.MinDaysRemaining))
		}
		return strings.Join(parts, " AND ")
	}
	return "(invalid expectation)"
}

// InferMode picks a default mode from the observed issuer.
//
// The customer is never asked to choose on first setup — Gate B2 measures
// whether expectations can be established at all, and a question per endpoint
// is how that fails. An issuer that indicates automation gets policy mode,
// because pinning an auto-renewing endpoint generates an alarm on every
// legitimate renewal.
//
// Uncertain cases default to PINNED deliberately: over-pinning produces visible
// noise a user can bulk-correct in one action, while over-policying produces an
// invisible missed detection.
func InferMode(issuerDN string) (Mode, string) {
	lower := strings.ToLower(issuerDN)
	automated := []struct{ needle, why string }{
		{"let's encrypt", "Let's Encrypt issues short-lived certificates via ACME"},
		{"lets encrypt", "Let's Encrypt issues short-lived certificates via ACME"},
		{"isrg", "ISRG is the Let's Encrypt root"},
		{"amazon", "ACM rotates managed certificates automatically"},
		{"zerossl", "ZeroSSL issues via ACME"},
		{"google trust services", "Google Trust Services issues via ACME"},
		{"buypass", "Buypass issues via ACME"},
		{"cert-manager", "cert-manager rotates automatically"},
	}
	for _, a := range automated {
		if strings.Contains(lower, a.needle) {
			return ModePolicy, a.why
		}
	}
	return ModePinned, "issuer does not indicate automated renewal; pinned by default so a " +
		"change is surfaced rather than silently accepted"
}

// SANCovers reports whether any SAN covers host.
//
// Wildcard semantics are single-label and exact: "*.example.com" covers
// "a.example.com" but NOT "example.com" and NOT "a.b.example.com". A coverage
// check that assumed otherwise would report PASS on an endpoint browsers reject.
func SANCovers(sans []string, host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, raw := range sans {
		s := strings.ToLower(strings.TrimSpace(raw))
		s = strings.TrimPrefix(s, "dns:")
		s = strings.TrimSuffix(s, ".")
		if s == "" {
			continue
		}
		if s == h {
			return true
		}
		if strings.HasPrefix(s, "*.") {
			suffix := s[1:] // ".example.com"
			if !strings.HasSuffix(h, suffix) {
				continue
			}
			label := h[:len(h)-len(suffix)]
			// Exactly one label, and it must be non-empty.
			if label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

func short(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "…"
	}
	return fp
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

var _ = model.ParseOK
