-- Pre-tenancy routing. These are the ONLY queries that reach
-- pre_tenancy_lookup, and they do so through the ptl_* functions — the
-- application role has no privilege on the table itself.

-- name: PtlSession :one
SELECT o_tenant::text AS tenant, o_session::text AS session_id
  FROM ptl_session(@token_hash::bytea);

-- name: PtlEmailDomain :one
SELECT o_tenant::text AS tenant, o_issuer::text AS issuer, o_client::text AS client_id
  FROM ptl_email_domain(@domain::text);

-- name: PtlCollectorCert :one
SELECT o_tenant::text AS tenant, o_collector::text AS collector_id,
       o_expires::timestamptz AS expires_at, o_revoked::boolean AS revoked
  FROM ptl_collector_cert(@fingerprint::text);

-- name: PtlEnrollmentToken :one
SELECT o_tenant::text AS tenant, o_expires::timestamptz AS expires_at,
       o_used::boolean AS used
  FROM ptl_enrollment_token(@token_hash::bytea);

-- name: PtlActiveTenants :many
SELECT t::text AS tenant FROM ptl_active_tenants() AS t;

-- name: PtlCreateOIDCFlow :exec
SELECT ptl_create_oidc_flow(@state::text, @nonce::text, @code_verifier::text,
       @redirect_uri::text, @issuer::text, @client_id::text, @email_domain::text,
       @expires_at::timestamptz);

-- name: PtlConsumeOIDCFlow :one
SELECT o_nonce::text AS nonce, o_verifier::text AS code_verifier,
       o_redirect::text AS redirect_uri, o_issuer::text AS issuer,
       o_client::text AS client_id, o_domain::text AS email_domain,
       o_expires::timestamptz AS expires_at
  FROM ptl_consume_oidc_flow(@state::text);
