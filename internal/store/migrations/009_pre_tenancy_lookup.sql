-- 009: consolidate pre-tenancy routing into ONE table, and close it to writes.
--
-- Six narrow routing tables (session_index, oidc_flows, provider_domain_index,
-- tenant_registry, collector_cert_index, enrollment_token_index) all had the
-- same shape: a hashed or opaque key, a tenant, and just enough to refuse
-- early. Migration 008 recorded that the pattern needed consolidating before a
-- seventh appeared. This is that consolidation, plus two things the six-table
-- design never had.
--
-- 1. NO DIRECT ACCESS. The application role gets no privilege on this table at
--    all — not SELECT, not INSERT. Every read and write goes through a
--    SECURITY DEFINER function that takes ONE key and returns only the fields
--    that lookup kind needs. "Each accessor exposes only its own fields" is
--    therefore enforced by the database, not merely by Go convention, and the
--    table cannot be enumerated: there is no function that lists domains,
--    sessions, certificates or tokens. The one listing function returns
--    opaque tenant ids for the scheduler.
--
--    The six-table design let the app role INSERT routing rows directly. That
--    meant a SQL injection anywhere could forge a session route or claim an
--    email domain for another tenant. Now it cannot: routing rows are written
--    only by triggers on RLS-protected tables (so a tenant can only route to
--    itself) and by the two OIDC flow functions.
--
-- 2. AN OIDC FLOW REMEMBERS ITS CLIENT. A flow used to store only the issuer,
--    and completion looked the client up again by issuer with LIMIT 1. Two
--    tenants that share an identity provider — Google Workspace, Microsoft
--    Entra, the common case — share an issuer, so the lookup picked an
--    arbitrary tenant's client, and the domain check compared issuers only.
--    Reproduced before this migration: a login started on tenant B, with a
--    token audienced to B's client and a verified email on A's domain, landed
--    in tenant A. The flow now records client_id and email_domain at start,
--    and completion requires the domain's registered (issuer, client_id) to
--    equal the flow's.
--
-- Per-kind CHECK constraints pin exactly which columns each kind may populate,
-- so this is a typed union, not a key/value store.

BEGIN;

CREATE TYPE pre_tenancy_kind AS ENUM (
    'session', 'oidc_flow', 'email_domain', 'tenant', 'collector_cert', 'enrollment_token'
);

CREATE TABLE pre_tenancy_lookup (
    kind          pre_tenancy_kind NOT NULL,
    lookup_key    text NOT NULL,
    tenant_id     uuid REFERENCES organizations(id) ON DELETE CASCADE,
    subject_id    uuid,
    issuer        text,
    client_id     text,
    email_domain  text,
    expires_at    timestamptz,
    refused       boolean NOT NULL DEFAULT false,
    nonce         text,
    code_verifier text,
    redirect_uri  text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, lookup_key),

    CONSTRAINT lookup_key_shape CHECK (CASE kind
        WHEN 'session'          THEN lookup_key ~ '^[0-9a-f]{64}$'
        WHEN 'enrollment_token' THEN lookup_key ~ '^[0-9a-f]{64}$'
        WHEN 'collector_cert'   THEN lookup_key ~ '^[0-9a-f]{64}$'
        WHEN 'tenant'           THEN lookup_key = tenant_id::text
        WHEN 'email_domain'     THEN lookup_key = lower(lookup_key) AND length(lookup_key) BETWEEN 1 AND 253
        WHEN 'oidc_flow'        THEN length(lookup_key) BETWEEN 32 AND 128
    END),

    -- Exactly which columns each kind may carry. Anything else is NULL.
    CONSTRAINT kind_shape CHECK (CASE kind
        WHEN 'session' THEN
            tenant_id IS NOT NULL AND subject_id IS NOT NULL
            AND issuer IS NULL AND client_id IS NULL AND email_domain IS NULL
            AND expires_at IS NULL AND nonce IS NULL AND code_verifier IS NULL
            AND redirect_uri IS NULL
        WHEN 'tenant' THEN
            tenant_id IS NOT NULL
            AND subject_id IS NULL AND issuer IS NULL AND client_id IS NULL
            AND email_domain IS NULL AND expires_at IS NULL AND nonce IS NULL
            AND code_verifier IS NULL AND redirect_uri IS NULL
        WHEN 'email_domain' THEN
            tenant_id IS NOT NULL AND issuer IS NOT NULL AND client_id IS NOT NULL
            AND subject_id IS NULL AND email_domain IS NULL AND expires_at IS NULL
            AND nonce IS NULL AND code_verifier IS NULL AND redirect_uri IS NULL
        WHEN 'collector_cert' THEN
            tenant_id IS NOT NULL AND subject_id IS NOT NULL AND expires_at IS NOT NULL
            AND issuer IS NULL AND client_id IS NULL AND email_domain IS NULL
            AND nonce IS NULL AND code_verifier IS NULL AND redirect_uri IS NULL
        WHEN 'enrollment_token' THEN
            tenant_id IS NOT NULL AND expires_at IS NOT NULL
            AND subject_id IS NULL AND issuer IS NULL AND client_id IS NULL
            AND email_domain IS NULL AND nonce IS NULL AND code_verifier IS NULL
            AND redirect_uri IS NULL
        WHEN 'oidc_flow' THEN
            -- No tenant: a login in flight has not decided one yet.
            tenant_id IS NULL AND subject_id IS NULL
            AND issuer IS NOT NULL AND client_id IS NOT NULL AND email_domain IS NOT NULL
            AND expires_at IS NOT NULL AND nonce IS NOT NULL
            AND code_verifier IS NOT NULL AND redirect_uri IS NOT NULL
    END)
);
CREATE INDEX pre_tenancy_lookup_tenant_idx ON pre_tenancy_lookup (tenant_id)
    WHERE tenant_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Carry existing rows across. Runs as the owner; none of the six source tables
-- is RLS-protected, so no FORCE lever is needed here.
-- ---------------------------------------------------------------------------
INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, subject_id)
SELECT 'session', encode(token_hash, 'hex'), tenant_id, session_id FROM session_index;

INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, refused)
SELECT 'tenant', tenant_id::text, tenant_id, NOT active FROM tenant_registry;

INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, issuer, client_id, refused)
SELECT 'email_domain', lower(email_domain::text), tenant_id, issuer, client_id, NOT enabled
  FROM provider_domain_index;

INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, subject_id, expires_at, refused)
SELECT 'collector_cert', fingerprint, tenant_id, collector_id, not_after, revoked
  FROM collector_cert_index;

INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, expires_at, refused)
SELECT 'enrollment_token', encode(token_hash, 'hex'), tenant_id, expires_at, used
  FROM enrollment_token_index;

-- In-flight OIDC logins are NOT migrated. They carry no client_id, which is the
-- defect being fixed, and they live ten minutes. Anyone mid-login restarts.

-- ---------------------------------------------------------------------------
-- Retire the six tables and their triggers.
-- ---------------------------------------------------------------------------
DROP TRIGGER IF EXISTS identity_providers_sync     ON identity_providers;
DROP TRIGGER IF EXISTS organizations_registry_sync ON organizations;
DROP TRIGGER IF EXISTS collector_certificates_sync ON collector_certificates;
DROP TRIGGER IF EXISTS enrollment_tokens_sync      ON enrollment_tokens;
DROP FUNCTION IF EXISTS sync_provider_domain_index();
DROP FUNCTION IF EXISTS sync_tenant_registry();
DROP FUNCTION IF EXISTS sync_collector_cert_index();
DROP FUNCTION IF EXISTS sync_enrollment_token_index();
DROP TABLE session_index, oidc_flows, provider_domain_index, tenant_registry,
           collector_cert_index, enrollment_token_index;

-- ---------------------------------------------------------------------------
-- Writers. Every one is a trigger on an RLS-protected source table, so a
-- tenant can only ever create routing for ITSELF.
--
-- SECURITY DEFINER with search_path pinned. Without the pin, a definer
-- function resolves unqualified names through the CALLER's search_path, and a
-- caller who can create objects can shadow pre_tenancy_lookup with their own.
-- The app role cannot CREATE in public, but the pin costs nothing.
-- ---------------------------------------------------------------------------
CREATE FUNCTION ptl_sync_session() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM pre_tenancy_lookup
     WHERE kind = 'session' AND lookup_key = encode(OLD.token_hash, 'hex');
    RETURN OLD;
  END IF;
  INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, subject_id)
  VALUES ('session', encode(NEW.token_hash, 'hex'), NEW.tenant_id, NEW.id);
  RETURN NEW;
END $$;
CREATE TRIGGER sessions_ptl AFTER INSERT OR DELETE ON sessions
  FOR EACH ROW EXECUTE FUNCTION ptl_sync_session();

CREATE FUNCTION ptl_sync_tenant() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM pre_tenancy_lookup WHERE kind = 'tenant' AND lookup_key = OLD.id::text;
    RETURN OLD;
  END IF;
  INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, refused)
  VALUES ('tenant', NEW.id::text, NEW.id, NEW.deleted_at IS NOT NULL)
  ON CONFLICT (kind, lookup_key) DO UPDATE SET refused = EXCLUDED.refused;
  RETURN NEW;
END $$;
CREATE TRIGGER organizations_ptl AFTER INSERT OR UPDATE OR DELETE ON organizations
  FOR EACH ROW EXECUTE FUNCTION ptl_sync_tenant();

-- Email domains are FIRST-COME and cannot be taken over. If a domain is routed
-- to tenant A, tenant B registering the same domain fails — including while
-- A's provider is merely DISABLED. Disabling is not releasing; only deleting
-- the provider frees the domain. The previous trigger did ON CONFLICT DO UPDATE
-- with no owner check, which would have reassigned the route.
--
-- Concurrency: INSERT ... ON CONFLICT DO NOTHING waits for an in-flight insert
-- of the same key to commit, so the ownership check that follows reads a
-- settled row.
CREATE FUNCTION ptl_sync_email_domain() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE owner uuid;
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') THEN
    DELETE FROM pre_tenancy_lookup
     WHERE kind = 'email_domain' AND lookup_key = lower(OLD.email_domain::text)
       AND tenant_id = OLD.tenant_id;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;

  -- One OAuth client registration belongs to one tenant. Client IDs are
  -- public — they sit in the authorization URL in every user's address bar —
  -- so without this a tenant could register ANOTHER tenant's (issuer, client)
  -- for its own domain. The advisory lock serializes two tenants racing to
  -- register the same client, so the check below reads a settled state.
  PERFORM pg_advisory_xact_lock(hashtext('ptl-client|' || NEW.issuer || '|' || NEW.client_id));
  IF EXISTS (SELECT 1 FROM pre_tenancy_lookup
              WHERE kind = 'email_domain' AND issuer = NEW.issuer
                AND client_id = NEW.client_id AND tenant_id <> NEW.tenant_id) THEN
    RAISE EXCEPTION 'that identity provider client is registered to another organization'
      USING ERRCODE = 'unique_violation';
  END IF;

  INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, issuer, client_id, refused)
  VALUES ('email_domain', lower(NEW.email_domain::text), NEW.tenant_id,
          NEW.issuer, NEW.client_id, NOT NEW.enabled)
  ON CONFLICT (kind, lookup_key) DO NOTHING;

  SELECT tenant_id INTO owner FROM pre_tenancy_lookup
   WHERE kind = 'email_domain' AND lookup_key = lower(NEW.email_domain::text);
  IF owner IS DISTINCT FROM NEW.tenant_id THEN
    RAISE EXCEPTION 'email domain is already routed to another organization'
      USING ERRCODE = 'unique_violation';
  END IF;

  UPDATE pre_tenancy_lookup
     SET issuer = NEW.issuer, client_id = NEW.client_id, refused = NOT NEW.enabled
   WHERE kind = 'email_domain' AND lookup_key = lower(NEW.email_domain::text);
  RETURN NEW;
END $$;
CREATE TRIGGER identity_providers_ptl AFTER INSERT OR UPDATE OR DELETE ON identity_providers
  FOR EACH ROW EXECUTE FUNCTION ptl_sync_email_domain();

CREATE FUNCTION ptl_sync_collector_cert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM pre_tenancy_lookup
     WHERE kind = 'collector_cert' AND lookup_key = OLD.fingerprint;
    RETURN OLD;
  END IF;
  INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, subject_id, expires_at, refused)
  VALUES ('collector_cert', NEW.fingerprint, NEW.tenant_id, NEW.collector_id,
          NEW.not_after, NEW.revoked_at IS NOT NULL)
  ON CONFLICT (kind, lookup_key) DO UPDATE
    SET expires_at = EXCLUDED.expires_at, refused = EXCLUDED.refused
    WHERE pre_tenancy_lookup.tenant_id = EXCLUDED.tenant_id;
  RETURN NEW;
END $$;
CREATE TRIGGER collector_certificates_ptl AFTER INSERT OR UPDATE OR DELETE
  ON collector_certificates FOR EACH ROW EXECUTE FUNCTION ptl_sync_collector_cert();

CREATE FUNCTION ptl_sync_enrollment_token() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM pre_tenancy_lookup
     WHERE kind = 'enrollment_token' AND lookup_key = encode(OLD.token_hash, 'hex');
    RETURN OLD;
  END IF;
  INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, expires_at, refused)
  VALUES ('enrollment_token', encode(NEW.token_hash, 'hex'), NEW.tenant_id,
          NEW.expires_at, NEW.used_at IS NOT NULL)
  ON CONFLICT (kind, lookup_key) DO UPDATE
    SET expires_at = EXCLUDED.expires_at, refused = EXCLUDED.refused
    WHERE pre_tenancy_lookup.tenant_id = EXCLUDED.tenant_id;
  RETURN NEW;
END $$;
CREATE TRIGGER enrollment_tokens_ptl AFTER INSERT OR UPDATE OR DELETE
  ON enrollment_tokens FOR EACH ROW EXECUTE FUNCTION ptl_sync_enrollment_token();

-- OIDC flows have no source table: the flow IS the record. Two functions, and
-- they are the only way in or out.
CREATE FUNCTION ptl_create_oidc_flow(
    p_state text, p_nonce text, p_verifier text, p_redirect text,
    p_issuer text, p_client text, p_domain text, p_expires timestamptz)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  INSERT INTO pre_tenancy_lookup
    (kind, lookup_key, issuer, client_id, email_domain, expires_at, nonce,
     code_verifier, redirect_uri)
  VALUES ('oidc_flow', p_state, p_issuer, p_client, lower(p_domain), p_expires,
          p_nonce, p_verifier, p_redirect);
$$;

-- Single use by construction: UPDATE ... WHERE NOT refused RETURNING means two
-- concurrent callbacks with the same state cannot both receive a row.
CREATE FUNCTION ptl_consume_oidc_flow(p_state text)
RETURNS TABLE (o_nonce text, o_verifier text, o_redirect text, o_issuer text,
               o_client text, o_domain text, o_expires timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
  UPDATE pre_tenancy_lookup p SET refused = true
   WHERE p.kind = 'oidc_flow' AND p.lookup_key = p_state AND NOT p.refused
  RETURNING p.nonce, p.code_verifier, p.redirect_uri, p.issuer, p.client_id,
            p.email_domain, p.expires_at;
$$;

-- ---------------------------------------------------------------------------
-- Readers. ONE key in, ONE kind's fields out. Nothing enumerates.
-- ---------------------------------------------------------------------------
CREATE FUNCTION ptl_session(p_token_hash bytea)
RETURNS TABLE (o_tenant uuid, o_session uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT p.tenant_id, p.subject_id FROM pre_tenancy_lookup p
   WHERE p.kind = 'session' AND p.lookup_key = encode(p_token_hash, 'hex');
$$;

-- Disabled domains are not returned: "unknown" and "disabled" must be
-- indistinguishable to a caller, or the difference reveals customers.
CREATE FUNCTION ptl_email_domain(p_domain text)
RETURNS TABLE (o_tenant uuid, o_issuer text, o_client text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT p.tenant_id, p.issuer, p.client_id FROM pre_tenancy_lookup p
   WHERE p.kind = 'email_domain' AND p.lookup_key = lower(p_domain) AND NOT p.refused;
$$;

CREATE FUNCTION ptl_collector_cert(p_fingerprint text)
RETURNS TABLE (o_tenant uuid, o_collector uuid, o_expires timestamptz, o_revoked boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT p.tenant_id, p.subject_id, p.expires_at, p.refused FROM pre_tenancy_lookup p
   WHERE p.kind = 'collector_cert' AND p.lookup_key = p_fingerprint;
$$;

CREATE FUNCTION ptl_enrollment_token(p_token_hash bytea)
RETURNS TABLE (o_tenant uuid, o_expires timestamptz, o_used boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT p.tenant_id, p.expires_at, p.refused FROM pre_tenancy_lookup p
   WHERE p.kind = 'enrollment_token' AND p.lookup_key = encode(p_token_hash, 'hex');
$$;

-- The one listing function. Opaque ids only, for a worker that serves every
-- tenant and must know who exists before it can scope anything.
CREATE FUNCTION ptl_active_tenants()
RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT p.tenant_id FROM pre_tenancy_lookup p
   WHERE p.kind = 'tenant' AND NOT p.refused ORDER BY p.tenant_id;
$$;

-- Backfill tenants created before this migration that were missing from the
-- registry (none should be, but the registry is now the scheduler's source of
-- truth and must be complete). organizations is FORCE RLS; the owner drops
-- FORCE for this one statement inside the migration transaction.
ALTER TABLE organizations NO FORCE ROW LEVEL SECURITY;
INSERT INTO pre_tenancy_lookup (kind, lookup_key, tenant_id, refused)
SELECT 'tenant', id::text, id, deleted_at IS NOT NULL FROM organizations
ON CONFLICT (kind, lookup_key) DO NOTHING;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

-- Functions are executable by PUBLIC by default. Narrow that to the app role
-- in bootstrap/grants.sql; revoke the default here.
REVOKE ALL ON FUNCTION
    ptl_create_oidc_flow(text,text,text,text,text,text,text,timestamptz),
    ptl_consume_oidc_flow(text), ptl_session(bytea), ptl_email_domain(text),
    ptl_collector_cert(text), ptl_enrollment_token(bytea), ptl_active_tenants()
  FROM PUBLIC;

COMMIT;
