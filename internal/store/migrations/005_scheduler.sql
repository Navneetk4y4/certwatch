-- 005: the persistent job queue.
--
-- SCHED, build items 103-114 region. A scheduler that lives in a process's
-- memory loses every pending job when that process restarts, and "we did not
-- check your certificates for six hours because a pod rescheduled" is not a
-- monitoring product. State lives here; workers are disposable.
--
-- Worker coordination is FOR UPDATE SKIP LOCKED — the standard PostgreSQL
-- queue pattern. Two workers claiming concurrently each get a DIFFERENT row
-- rather than blocking on the same one, and a worker that dies mid-job
-- releases its lock when its transaction dies.
--
-- Duplicate prevention is a UNIQUE INDEX, not a check in Go. Two schedulers
-- racing to enqueue the same endpoint for the same minute cannot both win.

BEGIN;

CREATE TYPE job_state AS ENUM ('pending', 'running', 'done', 'failed', 'cancelled');

CREATE TABLE jobs (
    id            uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('verify_endpoint','discover','reap')),
    endpoint_id   uuid REFERENCES endpoints(id) ON DELETE CASCADE,
    state         job_state NOT NULL DEFAULT 'pending',

    run_after     timestamptz NOT NULL DEFAULT now(),
    attempts      int NOT NULL DEFAULT 0,
    max_attempts  int NOT NULL DEFAULT 5,
    -- The lease. A running job whose lease has expired is recoverable: its
    -- worker died without saying so, which is what a kill -9 looks like.
    leased_until  timestamptz,
    leased_by     text,

    last_error    text,
    -- dedupe_key collapses "the same work for the same endpoint in the same
    -- window" into one row.
    dedupe_key    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz
);

-- At most ONE unfinished job per dedupe key per tenant. This is what makes
-- duplicate prevention a database guarantee rather than a hope.
CREATE UNIQUE INDEX jobs_active_dedupe_key
    ON jobs (tenant_id, dedupe_key) WHERE state IN ('pending','running');
CREATE INDEX jobs_claimable_idx ON jobs (run_after)
    WHERE state = 'pending';
CREATE INDEX jobs_lease_idx ON jobs (leased_until)
    WHERE state = 'running';
CREATE INDEX jobs_tenant_idx ON jobs (tenant_id, created_at DESC);
SELECT tenant_rls('jobs');

-- job_runs is the history: one row per ATTEMPT, so a flapping job's whole
-- story is visible rather than only its latest error.
CREATE TABLE job_runs (
    id          uuid PRIMARY KEY DEFAULT uuid_v7(),
    tenant_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    job_id      uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    attempt     int NOT NULL,
    worker      text,
    outcome     text NOT NULL CHECK (outcome IN ('ok','error','timeout','lost')),
    detail      text,
    started_at  timestamptz NOT NULL,
    finished_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX job_runs_job_idx ON job_runs (job_id, attempt);
SELECT tenant_rls('job_runs');

COMMIT;
