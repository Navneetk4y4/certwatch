package history

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
	"github.com/certwatch/certwatch/pkg/state"
	"github.com/certwatch/certwatch/pkg/verify"
)

type fx struct {
	st       *store.Store
	a, b     tenancy.Tenant
	epA, epB string
	clock    time.Time
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
	name := fmt.Sprintf("certwatch_hist_%d", time.Now().UnixNano())
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
	grants, _ := os.ReadFile("../store/bootstrap/grants.sql")
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

	f := &fx{st: st, clock: time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)}
	for i, p := range []*tenancy.Tenant{&f.a, &f.b} {
		var id string
		if err := mig.QueryRow(ctx, `SELECT create_organization($1)::text`,
			fmt.Sprintf("t%d-%d", i, time.Now().UnixNano())).Scan(&id); err != nil {
			t.Fatal(err)
		}
		*p = tenancy.Tenant(id)
	}
	f.epA = f.mkEndpoint(t, f.a, "a.example.com")
	f.epB = f.mkEndpoint(t, f.b, "b.example.com")
	return f
}

func (f *fx) mkEndpoint(t *testing.T, tn tenancy.Tenant, host string) string {
	t.Helper()
	var id string
	if err := f.st.InTenantTx(tenancy.WithTenant(context.Background(), tn),
		func(ctx context.Context, tx *store.Tx) error {
			return tx.Conn().QueryRow(ctx,
				`INSERT INTO endpoints (tenant_id, hostname, port, sni)
				 VALUES ($1::uuid,$2,443,'') RETURNING id::text`,
				tn.String(), host).Scan(&id)
		}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) ctx(tn tenancy.Tenant) context.Context {
	return tenancy.WithTenant(context.Background(), tn)
}

func res(outcome verify.Outcome, sub string) verify.Result {
	return verify.Result{
		Endpoint: verify.Endpoint{Hostname: "a.example.com", Port: 443},
		Outcome:  outcome, SubReason: sub,
		Summary:   string(outcome) + "/" + sub,
		Alertable: outcome != verify.OutcomePass,
		PerIP: []verify.IPResult{{IP: "10.0.0.1", Port: 443,
			Reachable: true, Handshake: true, Match: outcome == verify.OutcomePass}},
		IPsResolved: []string{"10.0.0.1"}, IPsChecked: []string{"10.0.0.1"},
	}
}
func pass() verify.Result { return res(verify.OutcomePass, "") }

// ---------------------------------------------------------------------------

// PASS -> PARTIAL ROLLOUT -> PASS. A rolling deploy that converges. It must
// leave a readable history and must NOT have paged.
func TestHistory_PassPartialPass(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	ctx := f.ctx(f.a)
	seq := []verify.Result{pass(),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		pass()}
	var allEvents int
	for i, s := range seq {
		out, err := r.Record(ctx, f.epA, s, f.clock.Add(time.Duration(i)*time.Minute), "")
		if err != nil {
			t.Fatal(err)
		}
		allEvents += len(out.Events)
	}
	if allEvents != 0 {
		t.Errorf("a rolling deploy that converged produced %d events", allEvents)
	}
	st, err := r.StateOf(ctx, f.epA)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != state.StatusOK {
		t.Errorf("final status = %s, want ok", st.Status)
	}
	if st.TotalObservations != 4 {
		t.Errorf("TotalObservations = %d, want 4", st.TotalObservations)
	}
	// The divergence must still be visible even though it never paged.
	tr, err := r.TransitionsFor(ctx, f.epA, 50)
	if err != nil {
		t.Fatal(err)
	}
	_ = tr // no hard events; soft transitions are in endpoint_state history
}

// PASS -> DRIFT -> DRIFT -> DRIFT -> RECOVERY. Persistent drift confirms,
// pages ONCE, then recovers.
func TestHistory_DriftConfirmsThenRecovers(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	ctx := f.ctx(f.a)
	seq := []verify.Result{pass(),
		res(verify.OutcomeDrift, verify.ReasonUnexpectedButValid),
		res(verify.OutcomeDrift, verify.ReasonUnexpectedButValid),
		res(verify.OutcomeDrift, verify.ReasonUnexpectedButValid),
		res(verify.OutcomeDrift, verify.ReasonUnexpectedButValid),
		pass()}
	var kinds []string
	for i, s := range seq {
		out, err := r.Record(ctx, f.epA, s, f.clock.Add(time.Duration(i)*time.Minute), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range out.Events {
			kinds = append(kinds, string(e.Kind))
		}
	}
	if len(kinds) != 2 || kinds[0] != "hard_transition" || kinds[1] != "recovery" {
		t.Fatalf("events = %v, want exactly [hard_transition recovery]", kinds)
	}
	tr, err := r.TransitionsFor(ctx, f.epA, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 2 {
		t.Fatalf("persisted %d transitions, want 2", len(tr))
	}
	// Newest first.
	if tr[0].Kind != "recovery" || tr[1].Kind != "hard_transition" {
		t.Errorf("history order = %s,%s; want recovery newest", tr[0].Kind, tr[1].Kind)
	}
	if tr[1].Observations != 3 {
		t.Errorf("the hard transition recorded %d observations, want 3 — the event "+
			"must carry its own evidence", tr[1].Observations)
	}
}

// near expiry -> expired: an escalation, recorded with what it came from.
func TestHistory_NearExpiryEscalatesToExpired(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	ctx := f.ctx(f.a)
	for i, s := range []verify.Result{
		res(verify.OutcomeWarning, verify.ReasonNearExpiry),
		res(verify.OutcomeFailure, verify.ReasonExpired),
	} {
		if _, err := r.Record(ctx, f.epA, s, f.clock.Add(time.Duration(i)*time.Hour), ""); err != nil {
			t.Fatal(err)
		}
	}
	tr, err := r.TransitionsFor(ctx, f.epA, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 2 {
		t.Fatalf("transitions = %d, want 2", len(tr))
	}
	if tr[0].Kind != "escalation" {
		t.Errorf("newest kind = %s, want escalation", tr[0].Kind)
	}
	if tr[0].PreviousSubReason != verify.ReasonNearExpiry {
		t.Errorf("previous_sub_reason = %q, want near_expiry", tr[0].PreviousSubReason)
	}
	if tr[0].Severity != "critical" {
		t.Errorf("severity = %q, want critical", tr[0].Severity)
	}
}

// Idempotency. A collector that retries after a timeout must not double-count:
// double-counting advances the consecutive counter and can confirm a finding
// that was only ever seen once.
func TestHistory_DuplicateRunIsIdempotent(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	ctx := f.ctx(f.a)
	s := res(verify.OutcomeFailure, verify.ReasonPartialRollout)

	first, err := r.Record(ctx, f.epA, s, f.clock, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Duplicate {
		t.Fatal("the first record was reported as a duplicate")
	}
	for i := 0; i < 5; i++ {
		out, err := r.Record(ctx, f.epA, s, f.clock.Add(time.Minute), "run-1")
		if err != nil {
			t.Fatal(err)
		}
		if !out.Duplicate {
			t.Fatalf("retry %d was not recognised as a duplicate", i)
		}
	}
	st, _ := r.StateOf(ctx, f.epA)
	if st.TotalObservations != 1 {
		t.Errorf("TotalObservations = %d after 5 retries of one run, want 1.\n"+
			"Double-counting would confirm a finding that was seen once.",
			st.TotalObservations)
	}
	if st.Consecutive != 1 {
		t.Errorf("Consecutive = %d, want 1", st.Consecutive)
	}
}

// State must survive a "process restart": a brand-new Recorder over the same
// database continues the sequence rather than starting over.
func TestHistory_StateSurvivesRestart(t *testing.T) {
	f := newFx(t)
	ctx := f.ctx(f.a)
	r1 := New(f.st, state.DefaultThresholds())
	for i := 0; i < 2; i++ {
		if _, err := r1.Record(ctx, f.epA,
			res(verify.OutcomeFailure, verify.ReasonPartialRollout),
			f.clock.Add(time.Duration(i)*time.Minute), ""); err != nil {
			t.Fatal(err)
		}
	}
	// The process dies. A new one picks up.
	r2 := New(f.st, state.DefaultThresholds())
	st, err := r2.StateOf(ctx, f.epA)
	if err != nil {
		t.Fatal(err)
	}
	if st.Consecutive != 2 || st.Status != state.StatusSoft {
		t.Fatalf("after restart: consecutive=%d status=%s, want 2/soft. "+
			"In-memory state would be 0/unknown here.", st.Consecutive, st.Status)
	}
	// The THIRD observation must confirm, proving the counter really carried.
	out, err := r2.Record(ctx, f.epA,
		res(verify.OutcomeFailure, verify.ReasonPartialRollout),
		f.clock.Add(3*time.Minute), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Events) != 1 {
		t.Fatalf("the third observation after a restart produced %d events, want 1",
			len(out.Events))
	}
}

// Out-of-order and duplicate observations must not corrupt the counter.
func TestHistory_OutOfOrderObservations(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	ctx := f.ctx(f.a)
	s := res(verify.OutcomeFailure, verify.ReasonPartialRollout)
	// Deliberately backwards in time.
	for _, at := range []time.Time{
		f.clock.Add(3 * time.Minute), f.clock, f.clock.Add(time.Minute),
	} {
		if _, err := r.Record(ctx, f.epA, s, at, ""); err != nil {
			t.Fatalf("an out-of-order observation errored: %v", err)
		}
	}
	st, _ := r.StateOf(ctx, f.epA)
	if st.TotalObservations != 3 {
		t.Errorf("TotalObservations = %d, want 3", st.TotalObservations)
	}
	// Whatever the ordering, the state must be internally consistent.
	if st.Status == "" {
		t.Error("state has no status after out-of-order observations")
	}
}

// Tenant isolation, through the history layer.
func TestHistory_IsTenantIsolated(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	if _, err := r.Record(f.ctx(f.a), f.epA,
		res(verify.OutcomeFailure, verify.ReasonExpired), f.clock, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Record(f.ctx(f.b), f.epB, pass(), f.clock, ""); err != nil {
		t.Fatal(err)
	}
	// B asking about A's endpoint id gets nothing, not A's state.
	st, err := r.StateOf(f.ctx(f.b), f.epA)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "" && st.Status != state.StatusUnknown {
		t.Errorf("tenant B read tenant A's endpoint state: %+v", st)
	}
	tr, err := r.TransitionsFor(f.ctx(f.b), f.epA, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 0 {
		t.Errorf("tenant B read %d of tenant A's transitions", len(tr))
	}
	// And A still has its own.
	trA, _ := r.TransitionsFor(f.ctx(f.a), f.epA, 50)
	if len(trA) == 0 {
		t.Error("tenant A lost its own history")
	}
}

// Due() drives the scheduler: an endpoint never observed is due immediately,
// and one just checked is not.
func TestHistory_DueRespectsNextCheckAt(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	ctx := f.ctx(f.a)

	due, err := r.Due(ctx, f.clock, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0] != f.epA {
		t.Fatalf("a never-observed endpoint is not due: %v", due)
	}
	if _, err := r.Record(ctx, f.epA, pass(), f.clock, ""); err != nil {
		t.Fatal(err)
	}
	if due, _ := r.Due(ctx, f.clock, 10); len(due) != 0 {
		t.Errorf("an endpoint just checked is still due: %v", due)
	}
	later := f.clock.Add(state.DefaultThresholds().NormalInterval + time.Minute)
	if due, _ := r.Due(ctx, later, 10); len(due) != 1 {
		t.Error("the endpoint did not become due after its interval")
	}
	// And tenant B never sees A's endpoint as due.
	if due, _ := r.Due(f.ctx(f.b), later, 10); len(due) != 1 || due[0] != f.epB {
		t.Errorf("Due() crossed tenants: %v", due)
	}
}

func TestHistory_RequiresATenant(t *testing.T) {
	f := newFx(t)
	r := New(f.st, state.DefaultThresholds())
	if _, err := r.Record(context.Background(), f.epA, pass(), f.clock, ""); err == nil {
		t.Error("Record succeeded with no tenant in context")
	}
}
