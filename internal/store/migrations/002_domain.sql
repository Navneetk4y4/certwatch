-- 002: the domain tables — collectors, credentials, certificates, endpoints,
-- expected state, verification results, state history, and alerts.
--
-- SCHEMA-002..010, build item 095. Every table here is tenant-owned and gets
-- the same three lines from tenant_rls(). None of them is trusted to filter
-- itself in application code.

BEGIN;

-- ---------------------------------------------------------------------------
-- Collectors and enrolment
-- ---------------------------------------------------------------------------
CREATE TABLE collectors (
    id                      uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id               uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                    text NOT NULL,
    client_cert_fingerprint text NOT NULL,
    version                 text,
    scope_digest            text,
    status                  collector_status NOT NULL DEFAULT 'active',
    declared_cidrs          cidr[] NOT NULL DEFAULT '{}',
    reachable_cidrs         cidr[] NOT NULL DEFAULT '{}',
    last_seen_at            timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    revoked_at              timestamptz
);
-- GLOBALLY unique, not per-tenant. A client certificate fingerprint is an
-- authentication identity: if the same fingerprint could exist in two tenants,
-- authenticating it would be ambiguous and the resolution would be a guess.
CREATE UNIQUE INDEX collectors_cert_fp_key ON collectors (client_cert_fingerprint);
CREATE INDEX collectors_tenant_idx ON collectors (tenant_id);
SELECT tenant_rls('collectors');

CREATE TABLE enrollment_tokens (
    id         uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The token itself is NEVER stored. Only its SHA-256. A database dump
    -- must not be a bag of working enrolment credentials.
    token_hash bytea NOT NULL,
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    used_by_collector uuid REFERENCES collectors(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX enrollment_tokens_hash_key ON enrollment_tokens (token_hash);
CREATE INDEX enrollment_tokens_tenant_idx ON enrollment_tokens (tenant_id);
SELECT tenant_rls('enrollment_tokens');

-- ---------------------------------------------------------------------------
-- credentials / certificates (D5: generic parent, x509 specialisation)
-- ---------------------------------------------------------------------------
CREATE TABLE credentials (
    id          uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind        credential_kind NOT NULL DEFAULT 'x509',
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX credentials_tenant_fp_key ON credentials (tenant_id, fingerprint);
SELECT tenant_rls('credentials');

CREATE TABLE certificates (
    credential_id        uuid PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
    tenant_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    serial               text,
    subject_dn           text,
    subject_cn           text,
    sans                 text[] NOT NULL DEFAULT '{}',
    sans_truncated_count int NOT NULL DEFAULT 0,
    issuer_dn            text,
    issuer_credential_id uuid REFERENCES credentials(id) ON DELETE SET NULL,
    not_before           timestamptz,
    not_after            timestamptz,
    key_algorithm        text,
    key_size             int,
    self_signed          boolean NOT NULL DEFAULT false,
    parse_status         text NOT NULL DEFAULT 'ok'
        CHECK (parse_status IN ('ok','partial','unparseable')),
    -- No column for a private key exists anywhere in this schema, and none
    -- may be added. INV-1 is a property of the product, not of one package.
    CHECK (key_size IS NULL OR key_size > 0)
);
CREATE INDEX certificates_tenant_notafter_idx ON certificates (tenant_id, not_after);
CREATE INDEX certificates_sans_idx ON certificates USING gin (sans);
SELECT tenant_rls('certificates');

-- ---------------------------------------------------------------------------
-- endpoints. Identity is (tenant, hostname, port, sni) — D-decision, one-way
-- door: changing it invalidates every stored expectation and result.
--
-- sni is NOT NULL DEFAULT '' deliberately. The earlier coalesce(sni,'') index
-- collided "no SNI" with "SNI equals the hostname", which are different
-- endpoints that can serve different certificates.
-- ---------------------------------------------------------------------------
CREATE TABLE endpoints (
    id         uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hostname   text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 253),
    port       int  NOT NULL CHECK (port BETWEEN 1 AND 65535),
    sni        text NOT NULL DEFAULT '',
    source     text NOT NULL DEFAULT 'discovered',
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);
CREATE UNIQUE INDEX endpoints_identity_key ON endpoints (tenant_id, hostname, port, sni);
SELECT tenant_rls('endpoints');

CREATE TABLE observations (
    id            uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    credential_id uuid NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
    endpoint_id   uuid REFERENCES endpoints(id) ON DELETE CASCADE,
    collector_id  uuid REFERENCES collectors(id) ON DELETE SET NULL,
    address       inet,
    port          int CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    source        text NOT NULL DEFAULT 'network',
    observed_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX observations_tenant_endpoint_idx ON observations (tenant_id, endpoint_id, observed_at DESC);
SELECT tenant_rls('observations');

-- ---------------------------------------------------------------------------
-- expected_states. D14: nothing alerts until a human confirms.
-- ---------------------------------------------------------------------------
CREATE TABLE expected_states (
    id             uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id    uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    mode           expectation_mode NOT NULL,
    credential_id  uuid REFERENCES credentials(id) ON DELETE RESTRICT,
    policy         jsonb,
    confirmed      boolean NOT NULL DEFAULT false,
    confirmed_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    confirmed_at   timestamptz,
    effective_from timestamptz,
    source         text,
    is_current     boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT expected_state_shape CHECK (
        (mode = 'pinned' AND credential_id IS NOT NULL AND policy IS NULL) OR
        (mode = 'policy' AND policy IS NOT NULL AND credential_id IS NULL)
    ),
    -- Confirmation must carry who and when. "confirmed = true" with nobody
    -- attached is exactly the trust-on-first-use that D14 exists to prevent.
    CONSTRAINT confirmation_is_attributable CHECK (
        confirmed = false OR (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX expected_states_current_key
    ON expected_states (endpoint_id) WHERE is_current;
SELECT tenant_rls('expected_states');

-- ---------------------------------------------------------------------------
-- verification_results. One row per verification run per endpoint, carrying
-- the per-IP evidence that makes a finding explainable.
-- ---------------------------------------------------------------------------
CREATE TABLE verification_results (
    id                 uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id        uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    expected_state_id  uuid REFERENCES expected_states(id) ON DELETE SET NULL,
    collector_id       uuid REFERENCES collectors(id) ON DELETE SET NULL,
    outcome            verify_outcome NOT NULL,
    sub_reason         text,
    summary            text,
    ips_resolved       inet[] NOT NULL DEFAULT '{}',
    ips_checked        inet[] NOT NULL DEFAULT '{}',
    ips_matching       inet[] NOT NULL DEFAULT '{}',
    ips_unreachable    inet[] NOT NULL DEFAULT '{}',
    ips_tls_error      inet[] NOT NULL DEFAULT '{}',
    ips_skipped        inet[] NOT NULL DEFAULT '{}',
    partial_rollout    boolean NOT NULL DEFAULT false,
    divergence         boolean NOT NULL DEFAULT false,
    suppressed         boolean NOT NULL DEFAULT false,
    alertable          boolean NOT NULL DEFAULT false,
    per_ip             jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- Idempotency: the same collector run must not create two rows.
    run_id             text,
    checked_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX verification_results_tenant_endpoint_idx
    ON verification_results (tenant_id, endpoint_id, checked_at DESC);
CREATE UNIQUE INDEX verification_results_idempotency_key
    ON verification_results (tenant_id, endpoint_id, run_id) WHERE run_id IS NOT NULL;
SELECT tenant_rls('verification_results');

-- ---------------------------------------------------------------------------
-- endpoint_state: the durable soft/hard state pkg/state computes. One row per
-- endpoint; history lives in drift_events.
-- ---------------------------------------------------------------------------
CREATE TABLE endpoint_state (
    endpoint_id       uuid PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
    tenant_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status            state_status NOT NULL DEFAULT 'unknown',
    outcome           verify_outcome,
    sub_reason        text,
    severity          severity,
    consecutive       int NOT NULL DEFAULT 0,
    threshold         int NOT NULL DEFAULT 0,
    alerted           boolean NOT NULL DEFAULT false,
    first_observed    timestamptz,
    last_observed     timestamptz,
    last_changed      timestamptz,
    soft_since        timestamptz,
    next_check_at     timestamptz,
    total_observations bigint NOT NULL DEFAULT 0,
    total_hard_events  bigint NOT NULL DEFAULT 0
);
CREATE INDEX endpoint_state_due_idx ON endpoint_state (next_check_at)
    WHERE next_check_at IS NOT NULL;
SELECT tenant_rls('endpoint_state');

-- drift_events: TRANSITIONS, not readings. A reading every five minutes for a
-- year is 105,000 rows of noise; the transitions are what anyone reads.
CREATE TABLE drift_events (
    id          uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('hard_transition','recovery','escalation')),
    from_status state_status,
    to_status   state_status,
    outcome     verify_outcome,
    sub_reason  text,
    previous_sub_reason text,
    severity    severity NOT NULL DEFAULT 'info',
    summary     text,
    observations int NOT NULL DEFAULT 0,
    dedupe_key  text NOT NULL,
    at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX drift_events_tenant_at_idx ON drift_events (tenant_id, at DESC);
CREATE INDEX drift_events_endpoint_idx ON drift_events (endpoint_id, at DESC);
SELECT tenant_rls('drift_events');

-- ---------------------------------------------------------------------------
-- alerts and delivery
-- ---------------------------------------------------------------------------
CREATE TABLE alerts (
    id             uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id    uuid REFERENCES endpoints(id) ON DELETE CASCADE,
    drift_event_id uuid REFERENCES drift_events(id) ON DELETE SET NULL,
    severity       severity NOT NULL,
    sub_reason     text,
    summary        text NOT NULL,
    dedupe_key     text NOT NULL,
    state          text NOT NULL DEFAULT 'open' CHECK (state IN ('open','acknowledged','resolved')),
    acknowledged_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz
);
-- Deduplication is a DATABASE constraint, not a hopeful check in Go: at most
-- one OPEN alert per dedupe key per tenant. A race between two workers cannot
-- produce two pages for one finding.
CREATE UNIQUE INDEX alerts_open_dedupe_key
    ON alerts (tenant_id, dedupe_key) WHERE state <> 'resolved';
CREATE INDEX alerts_tenant_created_idx ON alerts (tenant_id, created_at DESC);
SELECT tenant_rls('alerts');

CREATE TABLE alert_deliveries (
    id         uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    alert_id   uuid NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    channel    text NOT NULL,
    status     text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','delivered','failed','dropped')),
    attempts   int NOT NULL DEFAULT 0,
    last_error text,
    next_attempt_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX alert_deliveries_pending_idx ON alert_deliveries (next_attempt_at)
    WHERE status = 'pending';
SELECT tenant_rls('alert_deliveries');

COMMIT;
