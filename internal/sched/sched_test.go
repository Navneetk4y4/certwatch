package sched

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// Real PostgreSQL. The three guarantees under test — no duplicates, no
// double-claim, no lost work — are all properties of database constraints and
// locks. A mocked queue would satisfy every assertion below while the real one
// double-ran every job under concurrency.

type fx struct {
	st    *store.Store
	mig   *pgxpool.Pool
	clock time.Time
	a, b  tenancy.Tenant
	epA   string
}

func newFx(t *testing.T) *fx {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, "postgres://localhost:5432/postgres")
	if err != nil {
		t.Skipf("no PostgreSQL (%v). Run: make db-up", err)
	}
	defer admin.Close()
	if err := admin.Ping(ctx); err != nil {
		t.Skipf("PostgreSQL unreachable (%v). Run: make db-up", err)
	}
	name := fmt.Sprintf("certwatch_sched_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Skipf("cannot create test database: %v", err)
	}
	t.Cleanup(func() {
		a, e := pgxpool.New(context.Background(), "postgres://localhost:5432/postgres")
		if e != nil {
			return
		}
		defer a.Close()
		_, _ = a.Exec(context.Background(),
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1", name)
		_, _ = a.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name)
	})
	if _, err := admin.Exec(ctx,
		fmt.Sprintf("ALTER DATABASE %s OWNER TO certwatch_migrator", name)); err != nil {
		t.Fatal(err)
	}
	an, _ := pgxpool.New(ctx, fmt.Sprintf("postgres://localhost:5432/%s", name))
	if _, err := an.Exec(ctx, "ALTER SCHEMA public OWNER TO certwatch_migrator"); err != nil {
		an.Close()
		t.Fatal(err)
	}
	an.Close()

	mig, err := pgxpool.New(ctx, fmt.Sprintf(
		"postgres://certwatch_migrator:certwatch_dev_password_not_for_production@localhost:5432/%s", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mig.Close)
	if _, err := store.Migrate(ctx, mig); err != nil {
		t.Fatal(err)
	}
	grants, err := os.ReadFile("../store/bootstrap/grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mig.Exec(ctx, string(grants)); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, store.Config{DSN: fmt.Sprintf(
		"postgres://certwatch_app:certwatch_dev_password_not_for_production@localhost:5432/%s", name)},
		safelog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	f := &fx{st: st, mig: mig, clock: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	for _, p := range []*tenancy.Tenant{&f.a, &f.b} {
		var id string
		if err := mig.QueryRow(ctx, `SELECT create_organization($1)::text`,
			fmt.Sprintf("t%d", time.Now().UnixNano())).Scan(&id); err != nil {
			t.Fatal(err)
		}
		*p = tenancy.Tenant(id)
	}
	// One endpoint for tenant A.
	if err := st.InTenantTx(tenancy.WithTenant(ctx, f.a),
		func(ctx context.Context, tx *store.Tx) error {
			return tx.Conn().QueryRow(ctx,
				`INSERT INTO endpoints (tenant_id, hostname, port, sni)
				 VALUES ($1::uuid,'a.example.com',443,'') RETURNING id::text`,
				f.a.String()).Scan(&f.epA)
		}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fx) queue(worker string) *Queue {
	return New(f.st, safelog.Discard(), DefaultConfig(worker), func() time.Time { return f.clock })
}
func (f *fx) ctxA() context.Context { return tenancy.WithTenant(context.Background(), f.a) }
func (f *fx) ctxB() context.Context { return tenancy.WithTenant(context.Background(), f.b) }

// ---------------------------------------------------------------------------

func TestEnqueueClaimComplete(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	id, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "k1", f.clock)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := q.Claim(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].ID != id {
		t.Fatalf("claimed %d jobs, want the one we queued", len(jobs))
	}
	if jobs[0].TenantID != f.a {
		t.Errorf("job tenant = %s, want %s", jobs[0].TenantID, f.a)
	}
	if jobs[0].Attempts != 1 {
		t.Errorf("attempts = %d, want 1 — claiming IS an attempt", jobs[0].Attempts)
	}
	if err := q.Complete(context.Background(), jobs[0], "verified"); err != nil {
		t.Fatal(err)
	}
	s, err := q.StatsFor(f.ctxA())
	if err != nil {
		t.Fatal(err)
	}
	if s.Done != 1 || s.Pending != 0 {
		t.Errorf("stats = %+v, want 1 done", s)
	}
}

// Duplicate prevention is a database constraint, so a race cannot beat it.
func TestDuplicateEnqueueIsRefused(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "same-key", f.clock); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "same-key", f.clock); !errors.Is(err, ErrAlreadyQueued) {
		t.Fatalf("err = %v, want ErrAlreadyQueued", err)
	}
	s, _ := q.StatsFor(f.ctxA())
	if s.Pending != 1 {
		t.Errorf("pending = %d, want exactly 1 row for one dedupe key", s.Pending)
	}
}

// The same key becomes enqueueable again once the first job FINISHES — the
// unique index is partial on (pending, running), so the next window is free.
func TestSameKeyIsEnqueueableAfterTheJobFinishes(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "k", f.clock); err != nil {
		t.Fatal(err)
	}
	jobs, _ := q.Claim(context.Background(), 1)
	if err := q.Complete(context.Background(), jobs[0], ""); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "k", f.clock); err != nil {
		t.Fatalf("the key stayed blocked after completion: %v", err)
	}
}

// Concurrent enqueues of one key: exactly one wins. This is the race the
// unique index exists for.
func TestConcurrentEnqueueOfOneKeyProducesOneRow(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	var wg sync.WaitGroup
	ok := make([]bool, 12)
	for i := range ok {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "racing-key", f.clock)
			ok[i] = err == nil
		}(i)
	}
	wg.Wait()
	won := 0
	for _, v := range ok {
		if v {
			won++
		}
	}
	if won != 1 {
		t.Errorf("%d of 12 concurrent enqueues succeeded, want exactly 1", won)
	}
}

// SKIP LOCKED: two workers claiming at once get DIFFERENT jobs, and no job is
// handed to both.
func TestConcurrentWorkersNeverClaimTheSameJob(t *testing.T) {
	f := newFx(t)
	q1, q2 := f.queue("w1"), f.queue("w2")
	const n = 20
	for i := 0; i < n; i++ {
		if _, err := q1.Enqueue(f.ctxA(), KindVerify, f.epA, fmt.Sprintf("k%d", i), f.clock); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for _, q := range []*Queue{q1, q2, f.queue("w3"), f.queue("w4")} {
		wg.Add(1)
		go func(q *Queue) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				jobs, err := q.Claim(context.Background(), 3)
				if err != nil {
					continue
				}
				mu.Lock()
				for _, j := range jobs {
					seen[j.ID]++
				}
				mu.Unlock()
			}
		}(q)
	}
	wg.Wait()
	dup := 0
	for id, c := range seen {
		if c > 1 {
			dup++
			t.Errorf("job %s was claimed %d times; SKIP LOCKED is not holding", id, c)
		}
	}
	if dup == 0 && len(seen) != n {
		t.Errorf("claimed %d distinct jobs, want %d", len(seen), n)
	}
}

// THE restart test. A worker claims a job and dies without reporting. The
// lease lapses and the work becomes claimable again by a different process.
func TestWorkLostToACrashedWorkerIsRecovered(t *testing.T) {
	f := newFx(t)
	dead := f.queue("worker-that-dies")
	if _, err := dead.Enqueue(f.ctxA(), KindVerify, f.epA, "k", f.clock); err != nil {
		t.Fatal(err)
	}
	claimed, err := dead.Claim(context.Background(), 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v (%d)", err, len(claimed))
	}
	// The worker now dies. No Complete, no Fail — nothing.

	// A fresh process. Before the lease expires there is nothing to take.
	fresh := f.queue("worker-that-survives")
	if jobs, _ := fresh.Claim(context.Background(), 5); len(jobs) != 0 {
		t.Fatalf("a job under a LIVE lease was claimed by another worker (%d)", len(jobs))
	}
	if n, err := fresh.Recover(context.Background()); err != nil || n != 0 {
		t.Fatalf("Recover reclaimed %d jobs whose lease had not expired (err=%v)", n, err)
	}

	// Time passes past the lease.
	f.clock = f.clock.Add(DefaultConfig("").LeaseDuration + time.Minute)
	n, err := fresh.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("Recover returned %d jobs to pending, want 1 — a crashed worker "+
			"must not strand work permanently", n)
	}
	jobs, err := fresh.Claim(context.Background(), 5)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("recovered work was not claimable: %v (%d)", err, len(jobs))
	}
	if jobs[0].Attempts != 2 {
		t.Errorf("attempts = %d, want 2 — the lost attempt still counts", jobs[0].Attempts)
	}
}

// Jobs survive a full "process restart": a brand-new Queue over the same
// database sees the same pending work.
func TestPendingWorkSurvivesAProcessRestart(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	for i := 0; i < 5; i++ {
		if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, fmt.Sprintf("k%d", i), f.clock); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate the process going away entirely.
	restarted := New(f.st, safelog.Discard(), DefaultConfig("w-after-restart"),
		func() time.Time { return f.clock })
	s, err := restarted.StatsFor(f.ctxA())
	if err != nil {
		t.Fatal(err)
	}
	if s.Pending != 5 {
		t.Fatalf("after restart, pending = %d, want 5. An in-memory scheduler "+
			"would show 0 here, which is the whole reason this is in PostgreSQL.", s.Pending)
	}
}

func TestRetryBackoffThenExhaustion(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "k", f.clock); err != nil {
		t.Fatal(err)
	}
	var last Job
	for attempt := 1; attempt <= 5; attempt++ {
		jobs, err := q.Claim(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(jobs) != 1 {
			t.Fatalf("attempt %d: nothing claimable (backoff not elapsed?)", attempt)
		}
		last = jobs[0]
		if err := q.Fail(context.Background(), last, "endpoint unreachable"); err != nil {
			t.Fatal(err)
		}
		// Advance past the backoff for the next attempt.
		f.clock = f.clock.Add(q.cfg.MaxBackoff + time.Minute)
	}
	// Attempts are exhausted; nothing more should be claimable.
	if jobs, _ := q.Claim(context.Background(), 1); len(jobs) != 0 {
		t.Errorf("a job past max_attempts was claimed again")
	}
	s, _ := q.StatsFor(f.ctxA())
	if s.Failed != 1 {
		t.Errorf("stats = %+v, want 1 failed", s)
	}
	// And the whole attempt history is preserved.
	var runs int
	if err := f.st.InTenantTx(f.ctxA(), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx,
			`SELECT count(*) FROM job_runs WHERE job_id = $1::uuid`, last.ID).Scan(&runs)
	}); err != nil {
		t.Fatal(err)
	}
	if runs != 5 {
		t.Errorf("job_runs = %d, want 5 — one row per attempt, so a flapping job's "+
			"whole story is visible", runs)
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	q := New(nil, nil, Config{BaseBackoff: time.Second, MaxBackoff: 8 * time.Second}, nil)
	want := []time.Duration{time.Second, time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 8 * time.Second, 8 * time.Second}
	for i, w := range want {
		if got := q.backoffFor(i); got != w {
			t.Errorf("backoffFor(%d) = %s, want %s", i, got, w)
		}
	}
}

func TestCancelPreventsExecution(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	id, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "k", f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Cancel(f.ctxA(), id); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := q.Claim(context.Background(), 5); len(jobs) != 0 {
		t.Errorf("a cancelled job was claimed")
	}
}

// A running job cannot be cancelled out from under its worker — that would
// mean two things believing they own the work.
func TestCancelDoesNotAffectARunningJob(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	id, _ := q.Enqueue(f.ctxA(), KindVerify, f.epA, "k", f.clock)
	jobs, _ := q.Claim(context.Background(), 1)
	if err := q.Cancel(f.ctxA(), id); err != nil {
		t.Fatal(err)
	}
	if err := q.Complete(context.Background(), jobs[0], "finished anyway"); err != nil {
		t.Fatalf("the worker could not finish its own running job: %v", err)
	}
	s, _ := q.StatsFor(f.ctxA())
	if s.Done != 1 {
		t.Errorf("stats = %+v, want the running job to have completed", s)
	}
}

// Tenant isolation. A worker claims across tenants by design, but a tenant's
// own view must show only its own jobs.
func TestQueueStatsAreTenantScoped(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "ka", f.clock); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(f.ctxB(), KindDiscover, "", "kb", f.clock); err != nil {
		t.Fatal(err)
	}
	sa, _ := q.StatsFor(f.ctxA())
	sb, _ := q.StatsFor(f.ctxB())
	if sa.Pending != 1 || sb.Pending != 1 {
		t.Fatalf("A=%+v B=%+v, want one each", sa, sb)
	}
	// And A cannot cancel B's job by id.
	var bJob string
	if err := f.st.InTenantTx(f.ctxB(), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT id::text FROM jobs LIMIT 1`).Scan(&bJob)
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.Cancel(f.ctxA(), bJob); err != nil {
		t.Fatal(err)
	}
	sb2, _ := q.StatsFor(f.ctxB())
	if sb2.Cancelled != 0 || sb2.Pending != 1 {
		t.Errorf("tenant A cancelled tenant B's job: %+v", sb2)
	}
}

func TestEnqueueRequiresATenantAndADedupeKey(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	if _, err := q.Enqueue(context.Background(), KindVerify, f.epA, "k", f.clock); err == nil {
		t.Error("Enqueue succeeded with no tenant in context")
	}
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "", f.clock); err == nil {
		t.Error("Enqueue accepted an empty dedupe key; duplicates could not be prevented")
	}
}

func TestFutureJobsAreNotClaimedEarly(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "k", f.clock.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := q.Claim(context.Background(), 5); len(jobs) != 0 {
		t.Fatal("a job scheduled an hour out was claimed now")
	}
	f.clock = f.clock.Add(2 * time.Hour)
	if jobs, _ := q.Claim(context.Background(), 5); len(jobs) != 1 {
		t.Fatal("the job did not become claimable after its run_after")
	}
}

func TestDedupeKeyForIncludesTheWindow(t *testing.T) {
	t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	a := DedupeKeyFor(KindVerify, "ep1", t0)
	b := DedupeKeyFor(KindVerify, "ep1", t0.Add(15*time.Minute))
	if a == b {
		t.Error("two different windows produced the same key; the same endpoint " +
			"could never be re-checked")
	}
	if DedupeKeyFor(KindVerify, "ep1", t0) != a {
		t.Error("the key is not stable for the same inputs")
	}
}

// A genuine database failure must NOT be reported as successful
// deduplication. An earlier version collapsed every error into
// ErrAlreadyQueued, so a dead database looked exactly like "this work is
// already queued" and the job was silently dropped. Found by mutating away
// ON CONFLICT DO NOTHING and watching no test fail.
func TestEnqueueDistinguishesDuplicateFromRealFailure(t *testing.T) {
	f := newFx(t)
	q := f.queue("w1")

	// A real duplicate: ErrAlreadyQueued.
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "dup", f.clock); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(f.ctxA(), KindVerify, f.epA, "dup", f.clock); !errors.Is(err, ErrAlreadyQueued) {
		t.Fatalf("duplicate err = %v, want ErrAlreadyQueued", err)
	}

	// A real failure: a foreign key that cannot resolve. This is NOT a
	// duplicate, and reporting it as one would drop the work silently.
	_, err := q.Enqueue(f.ctxA(), KindVerify,
		"00000000-0000-0000-0000-000000000000", "fk-violation", f.clock)
	if err == nil {
		t.Fatal("an endpoint id that does not exist was accepted")
	}
	if errors.Is(err, ErrAlreadyQueued) {
		t.Errorf("a foreign-key failure was reported as ErrAlreadyQueued: %v\n"+
			"The caller would treat dropped work as successful deduplication.", err)
	}
}
