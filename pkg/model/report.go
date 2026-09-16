package model

import "time"

// Report is the machine-readable output of a certscan run.
//
// This schema IS the validation instrument. It is what a prospect sends back,
// what the untracked-rate number is computed from, and what the aggregate
// research publication is built on — so it must be stable, comparable across
// environments, and honest about what was NOT covered.
//
// Coverage honesty is a first-class field, not a footnote: a report that
// presents a partial scan as complete is worse than no report, because the
// customer will believe it.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"tool_version"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	DurationSec   float64   `json:"duration_seconds"`

	// EnvironmentLabel is a free-text label the operator supplies so results
	// from different environments can be compared. No customer identity is
	// collected automatically, and none is required.
	EnvironmentLabel string `json:"environment_label,omitempty"`

	Scope    ReportScope    `json:"scope"`
	Coverage ReportCoverage `json:"coverage"`
	Summary  ReportSummary  `json:"summary"`

	Certificates []ReportCertificate `json:"certificates"`
	Endpoints    []ReportEndpoint    `json:"endpoints"`
	Skips        []ReportSkip        `json:"skips"`
	Violations   []string            `json:"scope_violations,omitempty"`
	Notes        []string            `json:"notes,omitempty"`
}

type ReportScope struct {
	CIDRs       []string `json:"cidrs,omitempty"`
	Hostnames   []string `json:"hostnames,omitempty"`
	Ports       []int    `json:"ports,omitempty"`
	Directories []string `json:"certificate_directories,omitempty"`
	ScopeDigest string   `json:"scope_digest,omitempty"`
	DryRun      bool     `json:"dry_run"`
	Offline     bool     `json:"offline"`
	RatePerSec  int      `json:"rate_limit_per_second"`
	Concurrency int      `json:"concurrency"`
}

// ReportCoverage exists because an incomplete inventory presented as complete
// is the worst failure this tool can have (risk R8).
type ReportCoverage struct {
	TargetsRequested    int      `json:"targets_requested"`
	TargetsAttempted    int      `json:"targets_attempted"`
	TargetsSkipped      int      `json:"targets_skipped"`
	TargetsUnreachable  int      `json:"targets_unreachable"`
	NotAttempted        int      `json:"targets_not_attempted"`
	DeadlineHit         bool     `json:"deadline_hit"`
	FilesystemTruncated bool     `json:"filesystem_walk_truncated"`
	Caveats             []string `json:"caveats,omitempty"`
}

type ReportSummary struct {
	UniqueCertificates  int `json:"unique_certificates"`
	TotalObservations   int `json:"total_observations"`
	EndpointsResponding int `json:"endpoints_responding"`

	// PubliclyResolvable is the internal-visibility claim, as a tri-state count.
	// Unknown is reported separately and never folded into either other bucket.
	PubliclyResolvable    int `json:"publicly_resolvable"`
	NotPubliclyResolvable int `json:"not_publicly_resolvable"`
	ResolvabilityUnknown  int `json:"resolvability_unknown"`

	ExpiringWithin7Days  int `json:"expiring_within_7_days"`
	ExpiringWithin30Days int `json:"expiring_within_30_days"`
	ExpiringWithin60Days int `json:"expiring_within_60_days"`
	AlreadyExpired       int `json:"already_expired"`
	NotYetValid          int `json:"not_yet_valid"`

	SelfSigned      int `json:"self_signed"`
	ChainIncomplete int `json:"chain_incomplete"`

	ByIssuer       map[string]int `json:"by_issuer"`
	ByKeyAlgorithm map[string]int `json:"by_key_algorithm"`
	ByTLSVersion   map[string]int `json:"by_tls_version"`
	ByParseStatus  map[string]int `json:"by_parse_status"`

	// IPDisagreements counts hostnames where resolved IPs served DIFFERENT
	// certificates. This is the only pre-build evidence that verification will
	// find anything, and therefore the earliest signal on the retention risk.
	IPDisagreements int `json:"ip_disagreements"`
}

type ReportCertificate struct {
	Certificate   *Certificate `json:"certificate"`
	SeenAt        []string     `json:"seen_at"`
	Sources       []string     `json:"sources"`
	Resolvability *bool        `json:"publicly_resolvable"`
}

type ReportEndpoint struct {
	Hostname            string `json:"hostname,omitempty"`
	Address             string `json:"address"`
	Port                int    `json:"port"`
	SNISent             string `json:"sni_sent,omitempty"`
	TLSVersion          string `json:"tls_version,omitempty"`
	CipherSuite         string `json:"cipher_suite,omitempty"`
	LeafFingerprint     string `json:"leaf_sha256,omitempty"`
	ChainLength         int    `json:"chain_length,omitempty"`
	Error               string `json:"error,omitempty"`
	DefaultVhostDiffers *bool  `json:"default_vhost_differs,omitempty"`
}

type ReportSkip struct {
	Class  string `json:"class"`
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}
