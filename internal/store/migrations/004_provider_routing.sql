-- 004: the login routing index.
--
-- Resolving an email domain to a tenant is PRE-tenancy, for exactly the same
-- reason session_index is: the domain is what DECIDES the tenant, so the
-- lookup cannot be scoped to the tenant it is trying to find.
--
-- identity_providers stays RLS-policied because it holds the client secret.
-- This table holds only what is needed to ROUTE a login:
--
--   email_domain -> (tenant_id, issuer, client_id)
--
-- No secret, no user, no certificate. client_id is public by design in OAuth —
-- it appears in the authorization URL in the user's own address bar.
--
-- It is the third and, on current evidence, final entry in
-- store.PreTenancyTables. That list is asserted to its exact contents by a
-- test, so this addition had to be argued for rather than slipped in.
BEGIN;

CREATE TABLE provider_domain_index (
    email_domain citext PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    issuer       text NOT NULL,
    client_id    text NOT NULL,
    enabled      boolean NOT NULL DEFAULT true
);
CREATE INDEX provider_domain_index_issuer_idx ON provider_domain_index (issuer);

-- Kept in step with identity_providers by trigger rather than by application
-- code. Two writers that must remember to update two tables is how they drift,
-- and a drifted routing table sends a login to the wrong tenant.
CREATE OR REPLACE FUNCTION sync_provider_domain_index() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM provider_domain_index WHERE email_domain = OLD.email_domain;
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.email_domain <> NEW.email_domain THEN
    DELETE FROM provider_domain_index WHERE email_domain = OLD.email_domain;
  END IF;
  INSERT INTO provider_domain_index (email_domain, tenant_id, issuer, client_id, enabled)
  VALUES (NEW.email_domain, NEW.tenant_id, NEW.issuer, NEW.client_id, NEW.enabled)
  ON CONFLICT (email_domain) DO UPDATE
    SET tenant_id = EXCLUDED.tenant_id, issuer = EXCLUDED.issuer,
        client_id = EXCLUDED.client_id, enabled = EXCLUDED.enabled;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER identity_providers_sync
  AFTER INSERT OR UPDATE OR DELETE ON identity_providers
  FOR EACH ROW EXECUTE FUNCTION sync_provider_domain_index();

COMMIT;
