-- Grants. Run as the migrator AFTER migrations, so that every table exists.
--
-- The application gets DML and nothing else. No CREATE, no ALTER, no DROP, no
-- TRUNCATE (TRUNCATE ignores RLS entirely, which makes it a cross-tenant
-- delete wearing a maintenance command's clothes).
GRANT USAGE ON SCHEMA public TO certwatch_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO certwatch_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO certwatch_app;
GRANT EXECUTE ON FUNCTION uuid_v7() TO certwatch_app;
GRANT EXECUTE ON FUNCTION create_organization(text, citext) TO certwatch_app;

-- Tables created by later migrations inherit the same grants.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO certwatch_app;

-- ---------------------------------------------------------------------------
-- pre_tenancy_lookup: NO direct privilege at all.
--
-- It is the one table without row-level security, because it answers
-- questions that precede tenancy. The blanket GRANT above would hand the app
-- role full DML on it, which would let a SQL injection anywhere forge a
-- session route or claim another tenant's email domain. So everything is taken
-- back here, and the app reaches it only through the ptl_* functions, each of
-- which takes one key and returns one kind's fields.
--
-- This REVOKE must stay AFTER the blanket GRANT. TestPreTenancyLookupIsNot
-- DirectlyAccessible asserts the result, so reordering these lines fails the
-- build rather than silently reopening the table.
-- ---------------------------------------------------------------------------
REVOKE ALL ON pre_tenancy_lookup FROM certwatch_app;
GRANT EXECUTE ON FUNCTION
    ptl_create_oidc_flow(text,text,text,text,text,text,text,timestamptz),
    ptl_consume_oidc_flow(text),
    ptl_session(bytea),
    ptl_email_domain(text),
    ptl_collector_cert(text),
    ptl_enrollment_token(bytea),
    ptl_active_tenants()
  TO certwatch_app;

-- Explicitly withheld, so the absence is a decision and not an oversight.
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM certwatch_app;
REVOKE CREATE ON SCHEMA public FROM certwatch_app;
