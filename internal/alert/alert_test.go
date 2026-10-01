package alert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/certwatch/certwatch/internal/history"
	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
	"github.com/certwatch/certwatch/pkg/state"
	"github.com/certwatch/certwatch/pkg/verify"
)

// Real PostgreSQL. Deduplication is a partial unique index and delivery is an
// outbox drained in a separate transaction; a mock would prove neither.

// recorder is a Notifier that records what it was asked to send and can be
// told to fail.
type recorder struct {
	mu       sync.Mutex
	sent     []Notification
	failNext int
	failAll  bool
}

func (r *recorder) Channel() string { return "email" }
func (r *recorder) Send(_ context.Context, n Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failAll || r.failNext > 0 {
		if r.failNext > 0 {
			r.failNext--
		}
		return errors.New("notification provider unavailable")
	}
	r.sent = append(r.sent, n)
	return nil
}
func (r *recorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.sent) }

type fx struct {
	st    *store.Store
	rec   *history.Recorder
	pipe  *Pipeline
	note  *recorder
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
	name := fmt.Sprintf("certwatch_alert_%d", time.Now().UnixNano())
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

	f := &fx{st: st, clock: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC), note: &recorder{}}
	f.pipe = New(st, safelog.Discard(), DefaultConfig(),
		func() time.Time { return f.clock }, f.note)
	f.rec = history.New(st, state.DefaultThresholds()).WithSink(f.pipe)

	for _, p := range []*tenancy.Tenant{&f.a, &f.b} {
		var id string
		if err := mig.QueryRow(ctx, `SELECT create_organization($1)::text`,
			fmt.Sprintf("t%d", time.Now().UnixNano())).Scan(&id); err != nil {
			t.Fatal(err)
		}
		*p = tenancy.Tenant(id)
	}
	f.epA = f.mkEndpoint(t, f.a, "a.example.com")
	return f
}

func (f *fx) mkEndpoint(t *testing.T, tn tenancy.Tenant, host string) string {
	t.Helper()
	var id string
	if err := f.st.InTenantTx(f.ctx(tn), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx,
			`INSERT INTO endpoints (tenant_id, hostname, port, sni)
			 VALUES ($1::uuid,$2,443,'') RETURNING id::text`, tn.String(), host).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}
func (f *fx) ctx(tn tenancy.Tenant) context.Context {
	return tenancy.WithTenant(context.Background(), tn)
}

func res(o verify.Outcome, sub string) verify.Result {
	return verify.Result{
		Endpoint: verify.Endpoint{Hostname: "a.example.com", Port: 443},
		Outcome:  o, SubReason: sub, Summary: string(o) + "/" + sub,
		Alertable:   o != verify.OutcomePass,
		IPsResolved: []string{"10.0.0.1"}, IPsChecked: []string{"10.0.0.1"},
	}
}
func pass() verify.Result { return res(verify.OutcomePass, "") }

// observe folds n identical results, advancing the clock a minute each time.
func (f *fx) observe(t *testing.T, r verify.Result, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := f.rec.Record(f.ctx(f.a), f.epA, r, f.clock, ""); err != nil {
			t.Fatal(err)
		}
		f.clock = f.clock.Add(time.Minute)
	}
}

func (f *fx) openAlerts(t *testing.T, tn tenancy.Tenant) int {
	t.Helper()
	var n int
	if err := f.st.InTenantTx(f.ctx(tn), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx,
			`SELECT count(*) FROM alerts WHERE state <> 'resolved'`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fx) deliveries(t *testing.T, tn tenancy.Tenant) int {
	t.Helper()
	var n int
	if err := f.st.InTenantTx(f.ctx(tn), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT count(*) FROM alert_deliveries`).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---------------------------------------------------------------------------

// A SINGLE transient divergence must not become an alert. This is the whole
// point of the temporal model and must survive the alert layer.
func TestSingleTransientDivergenceCreatesNoAlert(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 1)
	f.observe(t, pass(), 1)
	if n := f.openAlerts(t, f.a); n != 0 {
		t.Fatalf("one transient divergence created %d alerts", n)
	}
	if f.deliveries(t, f.a) != 0 {
		t.Error("a transient divergence queued a notification")
	}
}

// Persistent drift: confirms, creates exactly ONE alert and ONE delivery.
func TestPersistentDriftCreatesOneAlert(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 3)
	if n := f.openAlerts(t, f.a); n != 1 {
		t.Fatalf("open alerts = %d, want 1", n)
	}
	if d := f.deliveries(t, f.a); d != 1 {
		t.Fatalf("queued deliveries = %d, want 1", d)
	}
}

// Repeated observation of the SAME finding must not create more alerts, and
// must not re-notify inside the cooldown.
func TestRepeatedDriftDoesNotDuplicate(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 20)
	if n := f.openAlerts(t, f.a); n != 1 {
		t.Errorf("open alerts = %d after 20 observations, want 1", n)
	}
	if d := f.deliveries(t, f.a); d != 1 {
		t.Errorf("deliveries = %d after 20 observations, want 1 — the cooldown "+
			"must stop a long-running problem paging every cycle", d)
	}
}

// After the cooldown, a still-open alert notifies again — once.
func TestCooldownExpiryRenotifiesOnce(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 3)
	if d := f.deliveries(t, f.a); d != 1 {
		t.Fatalf("precondition: deliveries = %d", d)
	}
	f.clock = f.clock.Add(DefaultConfig().Cooldown + time.Minute)
	// The reminder is a SWEEP, not an event path. More observations of an
	// unchanged hard state produce no events at all, which is correct — so
	// hanging re-notification off the event path made it unreachable.
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 1)
	if d := f.deliveries(t, f.a); d != 1 {
		t.Errorf("deliveries = %d; more observations must NOT re-notify by themselves", d)
	}
	n, err := f.pipe.RenotifyOverdue(f.ctx(f.a))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("RenotifyOverdue queued %d, want 1", n)
	}
	if d := f.deliveries(t, f.a); d != 2 {
		t.Errorf("deliveries = %d after the sweep, want 2", d)
	}
	// And sweeping again immediately must do nothing.
	if n, _ := f.pipe.RenotifyOverdue(f.ctx(f.a)); n != 0 {
		t.Errorf("a second sweep inside the cooldown queued %d, want 0", n)
	}
	if n := f.openAlerts(t, f.a); n != 1 {
		t.Errorf("open alerts = %d, want still 1", n)
	}
}

// Recovery resolves the alert and queues a recovery notice.
func TestRecoveryResolvesAndNotifies(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 3)
	f.observe(t, pass(), 1)
	if n := f.openAlerts(t, f.a); n != 0 {
		t.Errorf("open alerts = %d after recovery, want 0", n)
	}
	if d := f.deliveries(t, f.a); d != 2 {
		t.Errorf("deliveries = %d, want 2 (the alert and its recovery)", d)
	}
}

// A recovery with nothing open must notify nobody. A recovery notice for an
// alert nobody received is noise.
func TestRecoveryWithNothingOpenIsSilent(t *testing.T) {
	f := newFx(t)
	f.observe(t, pass(), 3)
	if d := f.deliveries(t, f.a); d != 0 {
		t.Errorf("deliveries = %d with nothing ever open, want 0", d)
	}
}

func TestNearExpiryCreatesAMediumAlert(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeWarning, verify.ReasonNearExpiry), 1) // N=1
	open, err := f.pipe.Open(f.ctx(f.a), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("open alerts = %d, want 1", len(open))
	}
	if open[0].Severity != "medium" {
		t.Errorf("severity = %s, want medium", open[0].Severity)
	}
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

func TestDrainDelivers(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 3)
	sent, failed, err := f.pipe.Drain(f.ctx(f.a), 10)
	if err != nil {
		t.Fatal(err)
	}
	if sent != 1 || failed != 0 {
		t.Fatalf("sent=%d failed=%d, want 1/0", sent, failed)
	}
	if f.note.count() != 1 {
		t.Fatalf("notifier received %d, want 1", f.note.count())
	}
	n := f.note.sent[0]
	if n.SubReason != verify.ReasonPartialRollout || n.Severity != "critical" {
		t.Errorf("notification = %+v", n)
	}
	// Draining again sends nothing: delivered is terminal.
	sent2, _, _ := f.pipe.Drain(f.ctx(f.a), 10)
	if sent2 != 0 {
		t.Errorf("a delivered notification was sent again (%d)", sent2)
	}
}

// Delivery failure must retry with backoff, not lose the notification.
func TestDeliveryFailureRetriesThenGivesUp(t *testing.T) {
	f := newFx(t)
	f.note.failAll = true
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 3)

	cfg := DefaultConfig()
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		_, failed, err := f.pipe.Drain(f.ctx(f.a), 10)
		if err != nil {
			t.Fatal(err)
		}
		if failed != 1 {
			t.Fatalf("attempt %d: failed = %d, want 1", attempt, failed)
		}
		f.clock = f.clock.Add(2 * time.Hour) // past any backoff
	}
	// Attempts exhausted: the delivery is terminal and no longer retried.
	_, failed, _ := f.pipe.Drain(f.ctx(f.a), 10)
	if failed != 0 {
		t.Errorf("a delivery past max attempts was retried again")
	}
	var status string
	if err := f.st.InTenantTx(f.ctx(f.a), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT status FROM alert_deliveries LIMIT 1`).Scan(&status)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Errorf("status = %q, want failed — the row must stay as evidence that "+
			"nobody was told", status)
	}
}

// A provider outage must NOT roll back the state change that caused the alert.
// That is the entire argument for the outbox.
func TestProviderOutageDoesNotLoseTheFinding(t *testing.T) {
	f := newFx(t)
	f.note.failAll = true
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 3)

	if _, failed, _ := f.pipe.Drain(f.ctx(f.a), 10); failed != 1 {
		t.Fatal("precondition: the send did not fail")
	}
	// The alert still exists and the state is still hard.
	if n := f.openAlerts(t, f.a); n != 1 {
		t.Errorf("open alerts = %d after a provider outage, want 1", n)
	}
	st, err := f.rec.StateOf(f.ctx(f.a), f.epA)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != state.StatusHard {
		t.Errorf("state = %s after a provider outage, want hard. Coupling delivery "+
			"to the state transaction would have rolled this back.", st.Status)
	}
	// And when the provider recovers, it is delivered.
	f.note.failAll = false
	f.clock = f.clock.Add(time.Hour)
	if sent, _, _ := f.pipe.Drain(f.ctx(f.a), 10); sent != 1 {
		t.Error("the queued notification was not delivered once the provider recovered")
	}
}

// A channel with no configured notifier is dropped explicitly rather than
// retried forever against something that does not exist.
func TestUnknownChannelIsDroppedNotRetriedForever(t *testing.T) {
	f := newFx(t)
	cfg := DefaultConfig()
	cfg.Channels = []string{"carrier-pigeon"}
	f.pipe = New(f.st, safelog.Discard(), cfg, func() time.Time { return f.clock }, f.note)
	f.rec = history.New(f.st, state.DefaultThresholds()).WithSink(f.pipe)

	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 3)
	_, failed, err := f.pipe.Drain(f.ctx(f.a), 10)
	if err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Fatalf("failed = %d, want 1", failed)
	}
	var status string
	if err := f.st.InTenantTx(f.ctx(f.a), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT status FROM alert_deliveries LIMIT 1`).Scan(&status)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "dropped" {
		t.Errorf("status = %q, want dropped", status)
	}
}

// Concurrent folds of the CONFIRMING observation must still produce ONE alert.
//
// The moment matters. An earlier version of this test raced observations AFTER
// the state was already hard — and pkg/state correctly emits nothing for an
// unchanged state, so no second INSERT ever happened and the ON CONFLICT path
// was never exercised. Removing ON CONFLICT entirely failed no test.
//
// The reachable race is several workers folding the observation that CONFIRMS
// the finding: each sees consecutive = threshold-1, each emits a
// hard_transition, and each tries to insert an alert. Only the partial unique
// index can decide that, which is why it is a constraint and not a Go check.
func TestConcurrentConfirmingFoldsProduceOneAlert(t *testing.T) {
	f := newFx(t)
	// Two observations: SOFT, one short of the threshold of three.
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonPartialRollout), 2)
	st, err := f.rec.StateOf(f.ctx(f.a), f.epA)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != state.StatusSoft || st.Consecutive != 2 {
		t.Fatalf("precondition: status=%s consecutive=%d, want soft/2", st.Status, st.Consecutive)
	}

	// Now race the THIRD — the confirming one.
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.rec.Record(f.ctx(f.a), f.epA,
				res(verify.OutcomeFailure, verify.ReasonPartialRollout), f.clock, "")
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("concurrent fold %d errored: %v", i, e)
		}
	}
	if n := f.openAlerts(t, f.a); n != 1 {
		t.Errorf("open alerts = %d after racing the confirming fold, want exactly 1", n)
	}
}

// Tenant isolation: B must never see or receive A's alerts.
func TestAlertsAreTenantIsolated(t *testing.T) {
	f := newFx(t)
	f.observe(t, res(verify.OutcomeFailure, verify.ReasonExpired), 2)
	if n := f.openAlerts(t, f.a); n == 0 {
		t.Fatal("precondition: no alert for A")
	}
	if n := f.openAlerts(t, f.b); n != 0 {
		t.Errorf("tenant B sees %d of tenant A's alerts", n)
	}
	open, err := f.pipe.Open(f.ctx(f.b), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 {
		t.Errorf("Open() returned %d of another tenant's alerts", len(open))
	}
	// And draining as B delivers nothing.
	before := f.note.count()
	if sent, _, _ := f.pipe.Drain(f.ctx(f.b), 10); sent != 0 {
		t.Errorf("draining as tenant B sent %d of tenant A's notifications", sent)
	}
	if f.note.count() != before {
		t.Error("a notification crossed tenants")
	}
}

// A non-alertable result (R1: unconfirmed expectation) must never produce an
// alert, however many times it is observed.
func TestNonAlertableResultNeverCreatesAnAlert(t *testing.T) {
	f := newFx(t)
	r := res(verify.OutcomeWarning, verify.ReasonFingerprintDivergence)
	r.Alertable = false
	f.observe(t, r, 10)
	if n := f.openAlerts(t, f.a); n != 0 {
		t.Errorf("R1 violated: a non-alertable result created %d alerts", n)
	}
	if f.deliveries(t, f.a) != 0 {
		t.Error("a non-alertable result queued a notification")
	}
}
