package model

import "time"

// The collector <-> control-plane protocol (project_1_api_spec.md Part A).
//
// PROTO-001: defined ONCE, here, and imported by both the collector and the
// server, so the two cannot disagree about a field name. The golden file in
// testdata/protocol_golden.json freezes the encoding.

// ProtocolVersionHeader carries the protocol version on every request and
// response.
const ProtocolVersionHeader = "X-Certwatch-Protocol"

// IngestBatch is the body of POST /v1/ingest/observations (A4). Every field is explicit; the decoder is closed.
type IngestBatch struct {
	BatchID     string    `json:"batch_id"`
	TenantID    string    `json:"tenant_id"`
	CollectorID string    `json:"collector_id"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	ScopeDigest string    `json:"scope_digest,omitempty"`
	// TaskID names the task these results answer, if any. Accepted by the
	// server BEFORE any collector sends it: the decoder is schema-closed, so
	// a collector that shipped the field first would have every batch refused.
	TaskID       string              `json:"task_id,omitempty"`
	Observations []IngestObservation `json:"observations"`
}

// IngestObservation is one certificate seen at one address.
type IngestObservation struct {
	Hostname     string    `json:"hostname,omitempty"`
	Address      string    `json:"address"`
	Port         int       `json:"port"`
	SNI          string    `json:"sni,omitempty"`
	Fingerprint  string    `json:"sha256"`
	SubjectCN    string    `json:"subject_cn,omitempty"`
	SubjectDN    string    `json:"subject_dn,omitempty"`
	IssuerDN     string    `json:"issuer_dn,omitempty"`
	SANs         []string  `json:"sans,omitempty"`
	Serial       string    `json:"serial,omitempty"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	KeyAlgorithm string    `json:"key_algorithm,omitempty"`
	KeySize      *int      `json:"key_size,omitempty"`
	ParseStatus  string    `json:"parse_status,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// Deprecation is the notice an old collector receives.
type Deprecation struct {
	Version        int    `json:"protocol_version"`
	SupportedUntil string `json:"supported_until"`
	Message        string `json:"message"`
	UpgradeURL     string `json:"upgrade_url"`
}

// TaskType is a CLOSED enum (A6). There is no command, no script and no URL
// task, and a collector rejects a type it does not know rather than guessing
// what it means. A new type requires a protocol version bump.
type TaskType = string

const (
	TaskScanCIDR       TaskType = "SCAN_CIDR"
	TaskVerifyEndpoint TaskType = "VERIFY_ENDPOINT"
	TaskEnumerateAWS   TaskType = "ENUMERATE_AWS"
	TaskEnumerateK8s   TaskType = "ENUMERATE_K8S"
	TaskReadCertDir    TaskType = "READ_CERT_DIR"
)

// KnownTaskType reports whether t is in the closed enum.
func KnownTaskType(t string) bool {
	switch t {
	case TaskScanCIDR, TaskVerifyEndpoint, TaskEnumerateAWS, TaskEnumerateK8s, TaskReadCertDir:
		return true
	}
	return false
}

// Task is the wire form of one VERIFY_ENDPOINT task as the server emits it.
type Task struct {
	TaskID   string        `json:"task_id"`
	Type     string        `json:"type"`
	Endpoint *TaskEndpoint `json:"endpoint,omitempty"`
	Deadline time.Time     `json:"deadline"`
}

// TaskEndpoint names what a VERIFY_ENDPOINT task checks.
type TaskEndpoint struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
	SNI      string `json:"sni"`
}

// TasksResponse is the body of GET /v1/tasks.
type TasksResponse struct {
	Tasks            []Task `json:"tasks"`
	PollAfterSeconds int    `json:"poll_after_seconds"`
}

// Heartbeat is A7. Schema-closed like everything else a collector sends.
type Heartbeat struct {
	CollectorID    string   `json:"collector_id"`
	Version        string   `json:"version"`
	ScopeDigest    string   `json:"scope_digest"`
	UptimeSeconds  int64    `json:"uptime_seconds"`
	SpoolBytes     int64    `json:"spool_bytes"`
	SpoolPctFull   float64  `json:"spool_pct_full"`
	TasksCompleted int64    `json:"tasks_completed"`
	TasksFailed    int64    `json:"tasks_failed"`
	LastError      string   `json:"last_error"`
	ReachableCIDRs []string `json:"reachable_cidrs"`
}

// HeartbeatResponse tells the collector the server's time (for skew) and, for
// an old protocol, when it stops being served.
type HeartbeatResponse struct {
	ServerTime               time.Time    `json:"server_time"`
	HeartbeatIntervalSeconds int          `json:"heartbeat_interval_seconds"`
	Deprecation              *Deprecation `json:"deprecation,omitempty"`
}
