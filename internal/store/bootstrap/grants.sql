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

-- session_index and oidc_flows are the two deliberately un-policied tables.
-- Both answer PRE-tenancy questions: "which tenant does this cookie belong
-- to" and "which login is this callback for". Neither can be scoped to a
-- tenant, because the tenant is the thing being determined.

-- Tables created by later migrations inherit the same grants.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO certwatch_app;

-- Explicitly withheld, so the absence is a decision and not an oversight.
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM certwatch_app;
GRANT EXECUTE ON FUNCTION sync_provider_domain_index() TO certwatch_app;
GRANT EXECUTE ON FUNCTION sync_tenant_registry() TO certwatch_app;
REVOKE CREATE ON SCHEMA public FROM certwatch_app;
