-- 008: the enrolment token routing index.
--
-- Sixth and, by the numbers, the point at which this pattern deserves a note.
--
-- The token IS the tenant selector, so redeeming one is pre-tenancy for the
-- same reason a session cookie, an email domain and a client certificate are.
-- It holds the hash, the tenant, and the two facts needed to refuse without a
-- tenant-scoped read: whether it is spent, and when it expires. No creator, no
-- collector, no token.
--
-- NOTE FOR LATER. There are now six of these narrow routing tables, all the
-- same shape: a hashed or opaque key, a tenant id, and just enough to refuse
-- early. That repetition is a signal. The right consolidation is probably ONE
-- pre_tenancy_lookup(kind, key_hash, tenant_id, refuse_after, revoked) table
-- with a typed accessor per kind, which would make the exemption list a single
-- entry instead of six. It is not done here because changing it later is a
-- contained refactor, while getting enrolment wrong now is not — but it should
-- not grow to seven without doing it.
BEGIN;

CREATE TABLE enrollment_token_index (
    token_hash bytea PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used       boolean NOT NULL DEFAULT false
);

CREATE OR REPLACE FUNCTION sync_enrollment_token_index() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM enrollment_token_index WHERE token_hash = OLD.token_hash;
    RETURN OLD;
  END IF;
  INSERT INTO enrollment_token_index (token_hash, tenant_id, expires_at, used)
  VALUES (NEW.token_hash, NEW.tenant_id, NEW.expires_at, NEW.used_at IS NOT NULL)
  ON CONFLICT (token_hash) DO UPDATE
    SET expires_at = EXCLUDED.expires_at, used = EXCLUDED.used;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER enrollment_tokens_sync
  AFTER INSERT OR UPDATE OR DELETE ON enrollment_tokens
  FOR EACH ROW EXECUTE FUNCTION sync_enrollment_token_index();

COMMIT;
