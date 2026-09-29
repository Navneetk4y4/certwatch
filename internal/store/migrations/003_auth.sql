-- 003: sessions and OIDC state.
--
-- AUTH-002, build item 099.
--
-- The session TOKEN is never stored. Only its SHA-256. A database dump is then
-- a list of useless hashes rather than a set of working logins, which is the
-- difference between a breach that leaks metadata and one that hands over
-- every account.

BEGIN;

CREATE TABLE sessions (
    id          uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL,
    -- Absolute expiry bounds a stolen token's lifetime no matter how much it
    -- is used. Idle expiry bounds an abandoned session on a shared machine.
    -- Both are needed: either alone leaves one of those cases open.
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz,
    -- Recorded for the audit trail and for "sign out everywhere".
    user_agent   text,
    source_ip    inet,
    -- Rotation chain: a rotated session points at the one that replaced it, so
    -- a replayed old token is identifiable as a replay rather than merely
    -- unknown.
    rotated_to   uuid REFERENCES sessions(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX sessions_token_hash_key ON sessions (token_hash);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx ON sessions (expires_at);
SELECT tenant_rls('sessions');

-- session_index resolves a cookie to its tenant, and nothing else.
--
-- A cookie carries no tenant. Reading `sessions` needs app.tenant_id already
-- set, so resolving the cookie against `sessions` directly is impossible: the
-- policy uses current_setting(..., false) and the read errors rather than
-- silently returning nothing. That error is correct and must not be removed.
--
-- So authentication gets its own narrow index, deliberately NOT tenant-scoped
-- for the same reason oidc_flows is not: deciding which tenant is acting is a
-- PRE-tenancy question, and scoping the answer to a tenant requires knowing
-- the answer first.
--
-- What it costs: a row here maps a 256-bit token hash to a tenant and session
-- id. It holds no certificate, no endpoint, no user data. It cannot be
-- enumerated — the key is a SHA-256 of 256 bits of entropy — and it is
-- deleted with the session it points at.
CREATE TABLE session_index (
    token_hash bytea PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    tenant_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE
);

-- OIDC login attempts in flight. Holds the PKCE verifier and the nonce.
--
-- NOT tenant-scoped, and deliberately so: at the moment a login starts we do
-- not yet know which tenant the person belongs to — that is decided by the
-- email domain in the token that comes back. Scoping this table to a tenant
-- would require guessing the answer before asking the question.
--
-- It carries no tenant data: a state row is a random string, a verifier and a
-- timestamp, and it is deleted the moment it is used.
CREATE TABLE oidc_flows (
    state         text PRIMARY KEY,
    nonce         text NOT NULL,
    code_verifier text NOT NULL,
    redirect_uri  text NOT NULL,
    issuer        text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz
);
CREATE INDEX oidc_flows_expiry_idx ON oidc_flows (expires_at);

-- Identity providers, per tenant.
CREATE TABLE identity_providers (
    id            uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    issuer        text NOT NULL,
    client_id     text NOT NULL,
    -- The client secret is stored encrypted at rest by the application; the
    -- column holds ciphertext. It is never selected into a response DTO.
    client_secret_enc bytea,
    email_domain  citext NOT NULL,
    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX identity_providers_domain_key ON identity_providers (email_domain) WHERE enabled;
CREATE INDEX identity_providers_tenant_idx ON identity_providers (tenant_id);
SELECT tenant_rls('identity_providers');

COMMIT;
