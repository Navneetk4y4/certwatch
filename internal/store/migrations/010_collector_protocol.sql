-- 010: collector protocol state — Mode 2 replay store and heartbeat facts.
--
-- PROTO-007 / PROTO-008, build items 118-119.
--
-- mode2_nonces is TENANT-OWNED, not pre-tenancy. A Mode 2 request names its
-- key (the certificate fingerprint); that is resolved through the existing
-- collector_cert route in pre_tenancy_lookup BEFORE the nonce is consumed, so
-- by the time a nonce is written the tenant is known and RLS applies. No new
-- routing table, and no exemption.
--
-- Replay protection is the PRIMARY KEY, not a lookup-then-insert in Go: two
-- concurrent requests carrying the same nonce race on the index and exactly
-- one wins.

BEGIN;

CREATE TABLE mode2_nonces (
    tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    collector_id uuid NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    nonce        text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{22,86}$'),
    expires_at   timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, collector_id, nonce)
);
CREATE INDEX mode2_nonces_expiry_idx ON mode2_nonces (collector_id, expires_at);
SELECT tenant_rls('mode2_nonces');

-- Heartbeat facts (A7). spool_pct_full is what tells an operator a collector
-- is about to start dropping observations; protocol_version is what the
-- deprecation notice is computed from.
ALTER TABLE collectors
    ADD COLUMN last_heartbeat_at timestamptz,
    ADD COLUMN protocol_version  int,
    ADD COLUMN spool_bytes       bigint CHECK (spool_bytes >= 0),
    ADD COLUMN spool_pct_full    real   CHECK (spool_pct_full BETWEEN 0 AND 1),
    ADD COLUMN tasks_completed   bigint CHECK (tasks_completed >= 0),
    ADD COLUMN tasks_failed      bigint CHECK (tasks_failed >= 0),
    ADD COLUMN last_error        text   CHECK (length(last_error) <= 1000);

COMMIT;
