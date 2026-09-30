-- 006: the tenant registry.
--
-- A background worker serves every tenant, so it must be able to ask "which
-- tenants exist" before it can scope anything to one of them. That question
-- is system-level by nature and cannot be answered from inside a tenant's own
-- policy — which is the same shape of problem as resolving a session cookie
-- or an email domain.
--
-- The alternative was to un-policy `jobs` so a worker could claim across
-- tenants in one query. That would have put real tenant data (endpoint ids,
-- error text) behind no policy at all, to save a loop. Not worth it.
--
-- This table holds ONE column: an opaque tenant id. No name, no plan, no
-- email domain, nothing that says who a customer is. A worker reads the ids,
-- then does every actual job read inside that tenant's own RLS scope.
BEGIN;

CREATE TABLE tenant_registry (
    tenant_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    active    boolean NOT NULL DEFAULT true
);

-- Maintained by trigger, not by application code: two writers who must both
-- remember to update two tables is how they drift, and a drifted registry
-- means a tenant silently stops being scheduled.
CREATE OR REPLACE FUNCTION sync_tenant_registry() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM tenant_registry WHERE tenant_id = OLD.id;
    RETURN OLD;
  END IF;
  INSERT INTO tenant_registry (tenant_id, active)
  VALUES (NEW.id, NEW.deleted_at IS NULL)
  ON CONFLICT (tenant_id) DO UPDATE SET active = (NEW.deleted_at IS NULL);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER organizations_registry_sync
  AFTER INSERT OR UPDATE OR DELETE ON organizations
  FOR EACH ROW EXECUTE FUNCTION sync_tenant_registry();

-- Backfill anything created before this migration.
--
-- organizations is FORCE RLS, so even the owner running this migration cannot
-- read it without a tenant bound — and a backfill has no single tenant. FORCE
-- is dropped for the length of THIS TRANSACTION only and restored below, so
-- the window is one statement wide inside DDL that already holds an exclusive
-- lock. This is the one legitimate use of that lever, and it is here rather
-- than in application code for exactly that reason.
ALTER TABLE organizations NO FORCE ROW LEVEL SECURITY;
INSERT INTO tenant_registry (tenant_id, active)
SELECT id, deleted_at IS NULL FROM organizations
ON CONFLICT DO NOTHING;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;

COMMIT;
