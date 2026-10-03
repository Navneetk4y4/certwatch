-- Scheduler. Runs inside a tenant transaction, so RLS scopes every row.

-- name: EnqueueJob :one
-- The endpoint id is cast to TEXT before NULLIF. In hand-written pgx,
-- NULLIF($3,'')::uuid had the parameter resolved as uuid and "" was rejected
-- before NULLIF ran; that broke twice.
--
-- Measured, and recorded so nobody over-trusts it: in THIS statement, emitted
-- through sqlc, the un-cast form also works — sqlc types the parameter as
-- interface{} and PostgreSQL resolves it as text. So the cast below is not
-- enforced by the compiler or by sqlc, and removing it fails no test. It stays
-- because an explicit type is the defensive form, and
-- TestEnqueueWithNoEndpointStoresNullNotAnError pins the BEHAVIOUR (an empty
-- endpoint id stores NULL and does not error) whichever form is used.
INSERT INTO jobs (tenant_id, kind, endpoint_id, dedupe_key, run_after)
VALUES (@tenant_id::uuid, @kind::text, NULLIF(@endpoint_id::text, '')::uuid,
        @dedupe_key::text, @run_after::timestamptz)
ON CONFLICT DO NOTHING
RETURNING id::text;
