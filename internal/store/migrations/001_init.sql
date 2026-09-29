-- 001: extensions, enums, tenancy, and the RLS scaffolding.
--
-- SCHEMA-001, build item 092. This migration is a ONE-WAY DOOR: row-level
-- security goes in here or it never goes in at all. Retrofitting RLS after
-- real customer rows exist means a migration that cannot be rehearsed safely
-- against production, and it is free to do now.
--
-- The whole tenancy model is three lines per table, applied by tenant_rls()
-- below. Read that function and you have read the isolation guarantee.

BEGIN;

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- UUIDv7: time-ordered, so index locality comes free without a sequence and
-- without leaking a row count the way a bigserial does.
CREATE OR REPLACE FUNCTION uuid_v7() RETURNS uuid AS $$
  SELECT encode(
    set_byte(
      set_byte(
        overlay(uuid_send(gen_random_uuid())
                PLACING substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint)
                                  FROM 3 FOR 6)
                FROM 1 FOR 6),
        6, (b'0111' || get_byte(uuid_send(gen_random_uuid()), 6)::bit(4))::bit(8)::int),
      8, (b'10'   || get_byte(uuid_send(gen_random_uuid()), 8)::bit(6))::bit(8)::int),
    'hex')::uuid;
$$ LANGUAGE sql VOLATILE;

CREATE TYPE user_role       AS ENUM ('admin', 'operator', 'viewer');
CREATE TYPE org_plan        AS ENUM ('free', 'pilot', 'entry', 'midmarket', 'enterprise');
CREATE TYPE credential_kind AS ENUM ('x509', 'ssh_cert', 'secret');
CREATE TYPE collector_status AS ENUM ('active', 'silent', 'revoked');
CREATE TYPE expectation_mode AS ENUM ('pinned', 'policy');
CREATE TYPE verify_outcome  AS ENUM ('PASS', 'FAILURE', 'DRIFT', 'WARNING', 'UNKNOWN', 'UNREACHABLE');
CREATE TYPE state_status    AS ENUM ('ok', 'soft', 'hard', 'unknown');
CREATE TYPE severity        AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- ---------------------------------------------------------------------------
-- The isolation guarantee, in one function.
--
-- FORCE ROW LEVEL SECURITY is the line that is almost always missed. Without
-- it the TABLE OWNER bypasses every policy — and the table owner is the
-- migration role, which is exactly who runs anything clever in an incident.
-- ENABLE alone gives a policy that protects everyone except the person most
-- able to cause damage.
--
-- The policy reads a transaction-local GUC, never a session GUC: see
-- internal/store.Begin for why that distinction is load-bearing with a
-- connection pool.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION tenant_rls(tbl regclass) RETURNS void AS $$
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
  EXECUTE format($f$
    CREATE POLICY tenant_isolation ON %s
      USING       (tenant_id = current_setting('app.tenant_id', false)::uuid)
      WITH CHECK  (tenant_id = current_setting('app.tenant_id', false)::uuid)
  $f$, tbl);
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- organizations is the tenant root. It is deliberately NOT tenant_rls()'d on
-- tenant_id: its own primary key IS the tenant id, so the policy compares id.
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
    id             uuid PRIMARY KEY DEFAULT uuid_v7(),
    name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    plan           org_plan NOT NULL DEFAULT 'free',
    endpoint_quota int NOT NULL DEFAULT 50 CHECK (endpoint_quota >= 0),
    email_domain   citext,
    created_at     timestamptz NOT NULL DEFAULT now(),
    deleted_at     timestamptz
);
CREATE UNIQUE INDEX organizations_email_domain_key
    ON organizations (email_domain) WHERE email_domain IS NOT NULL AND deleted_at IS NULL;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations
  USING      (id = current_setting('app.tenant_id', false)::uuid)
  WITH CHECK (id = current_setting('app.tenant_id', false)::uuid);

-- Creating the FIRST organization is a chicken-and-egg problem: the policy
-- above requires app.tenant_id to equal the row's id, and at signup there is
-- no tenant yet. The tempting fixes are both wrong — a policy that permits
-- INSERT when the GUC is unset is an open door, and letting the app role
-- bypass RLS defeats the entire model.
--
-- Instead: mint the id first, bind the transaction to it, then insert. The
-- WITH CHECK is satisfied honestly because the row really does belong to the
-- tenant the transaction is now acting as. No exception, no bypass.
CREATE OR REPLACE FUNCTION create_organization(p_name text, p_email_domain citext DEFAULT NULL)
RETURNS uuid AS $$
DECLARE new_id uuid := uuid_v7();
BEGIN
  PERFORM set_config('app.tenant_id', new_id::text, true);
  INSERT INTO organizations (id, name, email_domain) VALUES (new_id, p_name, p_email_domain);
  RETURN new_id;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE users (
    id           uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email        citext NOT NULL,
    sso_subject  text,
    sso_issuer   text,
    role         user_role NOT NULL DEFAULT 'viewer',
    last_seen_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    disabled_at  timestamptz
);
-- Email is unique per tenant, not globally: the same person may legitimately
-- belong to two organizations.
CREATE UNIQUE INDEX users_tenant_email_key ON users (tenant_id, email);
-- An OIDC subject is unique per issuer. Without the issuer in the key, two
-- identity providers that both mint sub="1234" would collide into one account.
CREATE UNIQUE INDEX users_issuer_subject_key
    ON users (sso_issuer, sso_subject) WHERE sso_subject IS NOT NULL;
CREATE INDEX users_tenant_idx ON users (tenant_id);
SELECT tenant_rls('users');

-- ---------------------------------------------------------------------------
-- audit_events. Written on every privileged action. Tenant-scoped like
-- everything else: an audit log that leaks across tenants is worse than none.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
    id         uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id   uuid REFERENCES users(id) ON DELETE SET NULL,
    actor_kind text NOT NULL DEFAULT 'user' CHECK (actor_kind IN ('user','collector','system')),
    action     text NOT NULL,
    object_kind text,
    object_id  uuid,
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_ip  inet,
    at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_tenant_at_idx ON audit_events (tenant_id, at DESC);
SELECT tenant_rls('audit_events');

COMMIT;
