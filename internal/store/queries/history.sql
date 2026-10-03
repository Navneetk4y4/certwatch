-- History reads. Run inside a tenant transaction; RLS scopes every row.

-- name: TransitionsForEndpoint :many
SELECT at,
       kind,
       COALESCE(to_status::text, '')::text           AS to_status,
       COALESCE(outcome::text, '')::text             AS outcome,
       COALESCE(sub_reason, '')::text                AS sub_reason,
       COALESCE(previous_sub_reason, '')::text       AS previous_sub_reason,
       severity::text                                AS severity,
       COALESCE(summary, '')::text                   AS summary,
       observations
  FROM drift_events
 WHERE endpoint_id = @endpoint_id::uuid
 ORDER BY at DESC, id DESC
 LIMIT @lim::int;

-- name: DueEndpoints :many
SELECT e.id::text AS id
  FROM endpoints e
  LEFT JOIN endpoint_state s ON s.endpoint_id = e.id
 WHERE e.disabled_at IS NULL
   AND (s.next_check_at IS NULL OR s.next_check_at <= @now::timestamptz)
 ORDER BY COALESCE(s.next_check_at, 'epoch'::timestamptz)
 LIMIT @lim::int;
