-- 007: collector identity — issued certificates, revocation, and ingest
-- idempotency.
--
-- ENROL-002..004, INGEST-004. Build items 104, 106, 111.
--
-- There is no column for a private key here, and none may be added. The
-- collector generates its own key, keeps it, and sends a CSR. The server never
-- sees it, which is why "we hold no customer key material" is a property of
-- the schema rather than a promise in a document.

BEGIN;

CREATE TABLE collector_certificates (
    id            uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    collector_id  uuid NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    -- SHA-256 of the DER. This is the mTLS identity the server matches on.
    fingerprint   text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    serial        text NOT NULL,
    subject_cn    text NOT NULL,
    not_before    timestamptz NOT NULL,
    not_after     timestamptz NOT NULL,
    -- The issued certificate itself is public material; storing it lets an
    -- operator see exactly what identity a collector presents.
    certificate_pem text NOT NULL,
    revoked_at    timestamptz,
    revoked_reason text,
    -- Rotation chain, so a superseded certificate is identifiable as
    -- superseded rather than merely unknown.
    replaced_by   uuid REFERENCES collector_certificates(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX collector_certificates_fp_key ON collector_certificates (fingerprint);
CREATE INDEX collector_certificates_collector_idx ON collector_certificates (collector_id);
SELECT tenant_rls('collector_certificates');

-- The mTLS identity index. Resolving a client certificate to its tenant is
-- PRE-tenancy for exactly the reason a session cookie is: the certificate is
-- what decides the tenant.
--
-- Fifth entry in store.PreTenancyTables. It holds a fingerprint, the ids it
-- maps to, and the two facts needed to refuse a bad certificate WITHOUT a
-- tenant-scoped read: whether it is revoked and when it expires. Refusing
-- early matters — an expired or revoked client must not reach any
-- tenant-scoped code path at all.
CREATE TABLE collector_cert_index (
    fingerprint  text PRIMARY KEY CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    collector_id uuid NOT NULL REFERENCES collectors(id) ON DELETE CASCADE,
    not_after    timestamptz NOT NULL,
    revoked      boolean NOT NULL DEFAULT false
);

CREATE OR REPLACE FUNCTION sync_collector_cert_index() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM collector_cert_index WHERE fingerprint = OLD.fingerprint;
    RETURN OLD;
  END IF;
  INSERT INTO collector_cert_index (fingerprint, tenant_id, collector_id, not_after, revoked)
  VALUES (NEW.fingerprint, NEW.tenant_id, NEW.collector_id, NEW.not_after,
          NEW.revoked_at IS NOT NULL)
  ON CONFLICT (fingerprint) DO UPDATE
    SET not_after = EXCLUDED.not_after, revoked = EXCLUDED.revoked;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER collector_certificates_sync
  AFTER INSERT OR UPDATE OR DELETE ON collector_certificates
  FOR EACH ROW EXECUTE FUNCTION sync_collector_cert_index();

-- INGEST-004: idempotency by batch_id. A collector that retries after a
-- network timeout must change no row the second time (P-8).
CREATE TABLE ingest_batches (
    tenant_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    batch_id     text NOT NULL CHECK (length(batch_id) BETWEEN 8 AND 128),
    collector_id uuid REFERENCES collectors(id) ON DELETE SET NULL,
    observations int NOT NULL DEFAULT 0,
    accepted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, batch_id)
);
SELECT tenant_rls('ingest_batches');

COMMIT;
