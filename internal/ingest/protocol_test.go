package ingest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certwatch/certwatch/internal/enroll"
	"github.com/certwatch/certwatch/internal/mode2"
	"github.com/certwatch/certwatch/internal/sched"
	"github.com/certwatch/certwatch/internal/store"
	"github.com/certwatch/certwatch/internal/tenancy"
	"github.com/certwatch/certwatch/pkg/safelog"
)

// PROTO-003 / PROTO-007 / PROTO-008 against real PostgreSQL over real TLS.

type coll struct {
	res    enroll.Result
	key    *ecdsa.PrivateKey
	c      *http.Client
	tenant tenancy.Tenant
}

func (f *fx) coll(t *testing.T, tn tenancy.Tenant, name string) coll {
	t.Helper()
	res, key := f.enrolled(t, tn, name)
	return coll{res: res, key: key, c: f.client(t, res.CertificatePEM, key), tenant: tn}
}

func (f *fx) endpoint(t *testing.T, tn tenancy.Tenant, host string) string {
	t.Helper()
	var id string
	err := f.st.InTenantTx(f.ctx(tn), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `
			INSERT INTO endpoints (tenant_id, hostname, port, sni) VALUES ($1::uuid,$2,443,$2)
			RETURNING id::text`, tn.String(), host).Scan(&id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *fx) enqueue(t *testing.T, tn tenancy.Tenant, ep string, at time.Time) string {
	t.Helper()
	id, err := f.queue.Enqueue(f.ctx(tn), sched.KindVerify, ep,
		fmt.Sprintf("verify:%s:%d", ep, at.UnixNano()), at)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func do(t *testing.T, c *http.Client, method, url string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func pollTasks(t *testing.T, f *fx, c *http.Client, q string) TasksResponse {
	t.Helper()
	resp, b := do(t, c, "GET", f.srv.URL+"/v1/tasks"+q, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("tasks: %d %s", resp.StatusCode, b)
	}
	var out TasksResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fx) jobState(t *testing.T, tn tenancy.Tenant, id string) string {
	t.Helper()
	var s string
	err := f.st.InTenantTx(f.ctx(tn), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT state::text FROM jobs WHERE id=$1::uuid`, id).Scan(&s)
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fx) audits(t *testing.T, tn tenancy.Tenant, action string) int {
	t.Helper()
	var n int
	err := f.st.InTenantTx(f.ctx(tn), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1`, action).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ---------------------------------------------------------------------------
// PROTO-008: version skew
// ---------------------------------------------------------------------------

func TestProtocolVersionHeaderIsRequiredAndExact(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	raw := &http.Client{Transport: c.c.Transport.(versioned).rt, Timeout: 10 * time.Second}
	for name, hdr := range map[string][]string{
		"missing":      nil,
		"newer":        {"2"},
		"far future":   {"9999"},
		"zero":         {"0"},
		"leading zero": {"01"},
		"decimal":      {"1.0"},
		"negative":     {"-1"},
		"two headers":  {"1", "1"},
		"not a number": {"v1"},
		"overlong":     {"10000"},
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", f.srv.URL+"/v1/tasks?wait=0", nil)
			for _, v := range hdr {
				req.Header.Add(ProtocolVersionHeader, v)
			}
			resp, err := raw.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var out struct {
				Reason     string `json:"reason"`
				Supported  []int  `json:"supported"`
				UpgradeURL string `json:"upgrade_url"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			if resp.StatusCode != 400 || out.Reason != "protocol.unsupported_version" ||
				out.UpgradeURL == "" || len(out.Supported) == 0 {
				t.Fatalf("%d %+v", resp.StatusCode, out)
			}
			if resp.Header.Get(ProtocolVersionHeader) != "1" {
				t.Errorf("response does not echo the server's protocol version")
			}
		})
	}
}

// An older protocol is served with a deprecation notice until its date, and
// refused after it.
func TestDeprecatedProtocolIsServedWithANoticeUntilItsDate(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	until := f.clock.Add(180 * 24 * time.Hour)
	f.api.Versions = VersionPolicy{Current: 2, Deprecated: map[int]time.Time{1: until},
		UpgradeURL: "https://example.test/upgrade"}
	c := f.coll(t, f.a, "c")
	hb := func() (*http.Response, []byte) {
		body, _ := json.Marshal(Heartbeat{CollectorID: c.res.CollectorID, Version: "0.4.1",
			ReachableCIDRs: []string{}})
		return do(t, c.c, "POST", f.srv.URL+"/v1/collectors/heartbeat", body,
			map[string]string{ProtocolVersionHeader: "1"})
	}
	resp, b := hb()
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var out HeartbeatResponse
	_ = json.Unmarshal(b, &out)
	if out.Deprecation == nil || out.Deprecation.Version != 1 ||
		out.Deprecation.SupportedUntil != until.Format("2006-01-02") || out.Deprecation.UpgradeURL == "" {
		t.Fatalf("no usable deprecation notice: %s", b)
	}
	// The current protocol gets no notice.
	body, _ := json.Marshal(Heartbeat{CollectorID: c.res.CollectorID, Version: "0.5.0", ReachableCIDRs: []string{}})
	_, b2 := do(t, c.c, "POST", f.srv.URL+"/v1/collectors/heartbeat", body,
		map[string]string{ProtocolVersionHeader: "2"})
	if strings.Contains(string(b2), "deprecation") {
		t.Fatalf("current protocol told it is deprecated: %s", b2)
	}
	// After the date: refused.
	f.clock = until.Add(time.Hour)
	if resp, b := hb(); resp.StatusCode != 400 {
		t.Fatalf("a retired protocol was served: %d %s", resp.StatusCode, b)
	}
}

// ---------------------------------------------------------------------------
// PROTO-003: long-poll task API
// ---------------------------------------------------------------------------

func TestTaskIsDeliveredWithTheEndpointItNames(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	ep := f.endpoint(t, f.a, "api.internal.example")
	job := f.enqueue(t, f.a, ep, f.clock)

	out := pollTasks(t, f, c.c, "?wait=0")
	if len(out.Tasks) != 1 {
		t.Fatalf("tasks = %+v", out)
	}
	tk := out.Tasks[0]
	if tk.TaskID != job || tk.Type != "VERIFY_ENDPOINT" || tk.Endpoint == nil ||
		tk.Endpoint.Hostname != "api.internal.example" || tk.Endpoint.Port != 443 ||
		!tk.Deadline.After(f.clock) {
		t.Fatalf("task = %+v", tk)
	}
	if s := f.jobState(t, f.a, job); s != "running" {
		t.Fatalf("job state %s", s)
	}
	// Leased: a second poll does not get it again.
	if again := pollTasks(t, f, c.c, "?wait=0"); len(again.Tasks) != 0 {
		t.Fatalf("leased task delivered twice: %+v", again)
	}
}

func TestEmptyPollReturnsPromptlyAndATimedPollWaits(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	start := time.Now()
	if out := pollTasks(t, f, c.c, "?wait=0"); len(out.Tasks) != 0 || out.Tasks == nil {
		t.Fatalf("%+v", out)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("wait=0 took %s", d)
	}
	start = time.Now()
	pollTasks(t, f, c.c, "?wait=1")
	if d := time.Since(start); d < 900*time.Millisecond || d > 5*time.Second {
		t.Fatalf("wait=1 returned after %s", d)
	}
}

func TestWaitingPollIsWokenByNewWork(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	f.api.PollInterval = time.Hour // only Notify can wake it
	c := f.coll(t, f.a, "c")
	ep := f.endpoint(t, f.a, "wake.example")
	got := make(chan TasksResponse, 1)
	start := time.Now()
	go func() { got <- pollTasks(t, f, c.c, "?wait=20") }()
	time.Sleep(300 * time.Millisecond)
	f.enqueue(t, f.a, ep, f.clock)
	f.api.Notify()
	select {
	case out := <-got:
		if len(out.Tasks) != 1 {
			t.Fatalf("%+v", out)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("woken after %s", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waiting poll was not woken")
	}
}

// Work enqueued by ANOTHER process cannot Notify; the poll interval finds it.
func TestWaitingPollFindsWorkFromAnotherProcess(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	f.api.PollInterval = 100 * time.Millisecond
	c := f.coll(t, f.a, "c")
	ep := f.endpoint(t, f.a, "other-process.example")
	got := make(chan TasksResponse, 1)
	go func() { got <- pollTasks(t, f, c.c, "?wait=20") }()
	time.Sleep(300 * time.Millisecond)
	f.enqueue(t, f.a, ep, f.clock)
	select {
	case out := <-got:
		if len(out.Tasks) != 1 {
			t.Fatalf("%+v", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("work from another process never delivered")
	}
}

func TestTasksAreDeliveredOldestFirstAndMaxIsHonoured(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	var want []string
	for i := 0; i < 5; i++ {
		ep := f.endpoint(t, f.a, fmt.Sprintf("order-%d.example", i))
		want = append(want, f.enqueue(t, f.a, ep, f.clock.Add(time.Duration(i-10)*time.Second)))
	}
	var got []string
	for _, max := range []string{"2", "2", "1"} {
		out := pollTasks(t, f, c.c, "?wait=0&max="+max)
		if fmt.Sprint(len(out.Tasks)) != max {
			t.Fatalf("max=%s returned %d", max, len(out.Tasks))
		}
		for _, tk := range out.Tasks {
			got = append(got, tk.TaskID)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order\n got  %v\n want %v", got, want)
	}
}

func TestFutureWorkIsNotDeliveredEarly(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	f.enqueue(t, f.a, f.endpoint(t, f.a, "later.example"), f.clock.Add(time.Hour))
	if out := pollTasks(t, f, c.c, "?wait=0"); len(out.Tasks) != 0 {
		t.Fatalf("%+v", out)
	}
}

// Only verify work goes to collectors. discover and reap are server-side jobs;
// handing one out as VERIFY_ENDPOINT would make a collector probe whatever
// endpoint the job happened to reference.
func TestOnlyVerifyWorkIsHandedToCollectors(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	ep := f.endpoint(t, f.a, "server-side.example")
	for _, k := range []sched.Kind{sched.KindDiscover, sched.KindReap} {
		if _, err := f.queue.Enqueue(f.ctx(f.a), k, ep, "k:"+string(k), f.clock); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.queue.Enqueue(f.ctx(f.a), sched.KindVerify, "", "verify:no-endpoint", f.clock); err != nil {
		t.Fatal(err)
	}
	if out := pollTasks(t, f, c.c, "?wait=0&max=100"); len(out.Tasks) != 0 {
		t.Fatalf("server-side work handed to a collector: %+v", out)
	}
}

// The collector's certificate decides whose queue it reads.
func TestCollectorNeverReceivesAnotherTenantsTasks(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	f.enqueue(t, f.a, f.endpoint(t, f.a, "a-only.example"), f.clock)
	cb := f.coll(t, f.b, "b")
	if out := pollTasks(t, f, cb.c, "?wait=0&max=100"); len(out.Tasks) != 0 {
		t.Fatalf("tenant B received tenant A's task: %+v", out)
	}
}

// A collector that took a task and vanished (or a server that claimed and
// died before answering) loses the lease; the task is handed out again with
// the SAME id, so the collector can de-duplicate.
func TestUnansweredTaskIsRedeliveredAfterTheLease(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	job := f.enqueue(t, f.a, f.endpoint(t, f.a, "lost.example"), f.clock)
	first := pollTasks(t, f, c.c, "?wait=0")
	if len(first.Tasks) != 1 {
		t.Fatal("not delivered")
	}
	f.clock = f.clock.Add(f.api.TaskLease + time.Minute)
	if n, err := f.queue.Recover(context.Background()); err != nil || n != 1 {
		t.Fatalf("recover = %d, %v", n, err)
	}
	second := pollTasks(t, f, c.c, "?wait=0")
	if len(second.Tasks) != 1 || second.Tasks[0].TaskID != job {
		t.Fatalf("redelivery = %+v", second)
	}
}

// Results naming a task complete it in the same transaction — but only for
// the collector that holds it, and only once.
func TestTaskCompletionIsBoundToTheHoldingCollector(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	holder := f.coll(t, f.a, "holder")
	other := f.coll(t, f.a, "other")
	job := f.enqueue(t, f.a, f.endpoint(t, f.a, "bound.example"), f.clock)
	if out := pollTasks(t, f, holder.c, "?wait=0"); len(out.Tasks) != 1 {
		t.Fatal("not delivered")
	}
	send := func(c coll, batchID string) map[string]any {
		b := batch(batchID, 1)
		b.TaskID = job
		body, _ := json.Marshal(b)
		resp, rb := do(t, c.c, "POST", f.srv.URL+"/v1/ingest/observations", body, nil)
		if resp.StatusCode != 202 {
			t.Fatalf("%d %s", resp.StatusCode, rb)
		}
		var out map[string]any
		_ = json.Unmarshal(rb, &out)
		return out
	}
	if out := send(other, "batch-other-1"); out["task_completed"] != false {
		t.Fatalf("a collector completed a task it does not hold: %v", out)
	}
	if s := f.jobState(t, f.a, job); s != "running" {
		t.Fatalf("state after foreign completion = %s", s)
	}
	if out := send(holder, "batch-holder-1"); out["task_completed"] != true {
		t.Fatalf("holder could not complete: %v", out)
	}
	if s := f.jobState(t, f.a, job); s != "done" {
		t.Fatalf("state = %s", s)
	}
	if out := send(holder, "batch-holder-1"); out["duplicate"] != true || out["task_completed"] != false {
		t.Fatalf("replayed batch: %v", out)
	}
}

func TestMalformedTaskQueriesAreRefused(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	for _, q := range []string{"?wait=31", "?wait=-1", "?wait=abc", "?wait=1.5", "?max=0",
		"?max=101", "?max=x", "?limit=5", "?wait=1&wait=2", "?max=1&max=100", "?%zz"} {
		resp, b := do(t, c.c, "GET", f.srv.URL+"/v1/tasks"+q, nil, nil)
		if resp.StatusCode != 400 {
			t.Errorf("%s: %d %s", q, resp.StatusCode, b)
		}
	}
	req, _ := http.NewRequest("GET", f.srv.URL+"/v1/tasks?wait=0", strings.NewReader("x"))
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("GET with a body: %d", resp.StatusCode)
	}
	resp2, _ := do(t, c.c, "POST", f.srv.URL+"/v1/tasks", []byte("{}"), nil)
	if resp2.StatusCode != 405 || resp2.Header.Get("Allow") != "GET" {
		t.Errorf("POST /v1/tasks: %d", resp2.StatusCode)
	}
}

// A collector cannot hold more than MaxPerCollector long-polls open; a
// disconnected poll gives its slot back.
func TestConcurrentLongPollsAreBounded(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	f.api.MaxPerCollector = 1
	c := f.coll(t, f.a, "c")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequestWithContext(ctx, "GET", f.srv.URL+"/v1/tasks?wait=30", nil)
		if resp, err := c.c.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(300 * time.Millisecond)
	resp, _ := do(t, c.c, "GET", f.srv.URL+"/v1/tasks?wait=0", nil, nil)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second concurrent poll: %d", resp.StatusCode)
	}
	cancel()
	<-done
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, _ := do(t, c.c, "GET", f.srv.URL+"/v1/tasks?wait=0", nil, nil)
		if resp.StatusCode == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot never released after disconnect: %d", resp.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Another collector is not affected by this one's limit.
	other := f.coll(t, f.a, "other")
	if resp, _ := do(t, other.c, "GET", f.srv.URL+"/v1/tasks?wait=0", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("other collector: %d", resp.StatusCode)
	}
}

func TestStopReleasesWaitingPolls(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	got := make(chan TasksResponse, 1)
	go func() { got <- pollTasks(t, f, c.c, "?wait=30") }()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	f.api.Stop()
	select {
	case out := <-got:
		if len(out.Tasks) != 0 || time.Since(start) > 3*time.Second {
			t.Fatalf("%+v after %s", out, time.Since(start))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not release the poll")
	}
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

func TestHeartbeatRecordsStateAndReportsServerTime(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	d1 := "sha256:" + strings.Repeat("1", 64)
	d2 := "sha256:" + strings.Repeat("2", 64)
	send := func(digest string) (*http.Response, []byte) {
		body, _ := json.Marshal(Heartbeat{CollectorID: c.res.CollectorID, Version: "0.4.1",
			ScopeDigest: digest, UptimeSeconds: 60, SpoolBytes: 12480, SpoolPctFull: 0.25,
			TasksCompleted: 3, ReachableCIDRs: []string{"10.20.0.0/16"}})
		return do(t, c.c, "POST", f.srv.URL+"/v1/collectors/heartbeat", body, nil)
	}
	resp, b := send(d1)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var out HeartbeatResponse
	_ = json.Unmarshal(b, &out)
	if !out.ServerTime.Equal(f.clock.Truncate(time.Microsecond)) && out.ServerTime.Sub(f.clock).Abs() > time.Second {
		t.Fatalf("server_time %s, clock %s", out.ServerTime, f.clock)
	}
	var pct float64
	var spool int64
	err := f.st.InTenantTx(f.ctx(f.a), func(ctx context.Context, tx *store.Tx) error {
		return tx.Conn().QueryRow(ctx, `SELECT spool_pct_full, spool_bytes FROM collectors WHERE id=$1::uuid`,
			c.res.CollectorID).Scan(&pct, &spool)
	})
	if err != nil || pct != 0.25 || spool != 12480 {
		t.Fatalf("stored %v %v %v", pct, spool, err)
	}
	if n := f.audits(t, f.a, "collector.scope_changed"); n != 0 {
		t.Fatalf("first digest audited as a change: %d", n)
	}
	send(d2)
	if n := f.audits(t, f.a, "collector.scope_changed"); n != 1 {
		t.Fatalf("scope change audits = %d", n)
	}
}

func TestHeartbeatIsValidatedAndBoundToTheCollector(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	c := f.coll(t, f.a, "c")
	other := f.coll(t, f.a, "other")
	base := func() map[string]any {
		return map[string]any{"collector_id": c.res.CollectorID, "version": "0.4.1",
			"scope_digest": "", "uptime_seconds": 1, "spool_bytes": 0, "spool_pct_full": 0.0,
			"tasks_completed": 0, "tasks_failed": 0, "last_error": "", "reachable_cidrs": []string{}}
	}
	cases := map[string]struct {
		mut  func(map[string]any)
		want int
	}{
		"another collector's id": {func(m map[string]any) { m["collector_id"] = other.res.CollectorID }, 403},
		"unknown field":          {func(m map[string]any) { m["command"] = "rm -rf /" }, 400},
		"spool over 100%":        {func(m map[string]any) { m["spool_pct_full"] = 1.5 }, 400},
		"negative spool":         {func(m map[string]any) { m["spool_bytes"] = -1 }, 400},
		"bad cidr":               {func(m map[string]any) { m["reachable_cidrs"] = []string{"10.0.0.0/33"} }, 400},
		"bad digest":             {func(m map[string]any) { m["scope_digest"] = "md5:abc" }, 400},
		"bad version":            {func(m map[string]any) { m["version"] = "1.0; DROP TABLE" }, 400},
		"overlong error":         {func(m map[string]any) { m["last_error"] = strings.Repeat("e", 1001) }, 400},
		"wrong type":             {func(m map[string]any) { m["uptime_seconds"] = "a day" }, 400},
	}
	for name, cs := range cases {
		t.Run(name, func(t *testing.T) {
			m := base()
			cs.mut(m)
			body, _ := json.Marshal(m)
			resp, b := do(t, c.c, "POST", f.srv.URL+"/v1/collectors/heartbeat", body, nil)
			if resp.StatusCode != cs.want {
				t.Fatalf("%d %s", resp.StatusCode, b)
			}
		})
	}
	if n := f.audits(t, f.a, "collector.heartbeat_identity_mismatch"); n != 1 {
		t.Fatalf("identity mismatch audits = %d", n)
	}
	// Content type is enforced.
	body, _ := json.Marshal(base())
	req, _ := http.NewRequest("POST", f.srv.URL+"/v1/collectors/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 415 {
		t.Fatalf("text/plain heartbeat: %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// PROTO-007: Mode 2
// ---------------------------------------------------------------------------

func (f *fx) serveMode2(t *testing.T) *httptest.Server {
	t.Helper()
	api := NewAPI(f.svc, f.queue, Mode2Auth{Enroll: f.en, Store: f.st,
		Now: func() time.Time { return f.clock }}, safelog.Discard())
	s := httptest.NewUnstartedServer(api)
	s.TLS = Mode2ServerTLSConfig(f.srvCert)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// plain is a TLS client with NO client certificate, trusting the server.
func (f *fx) plain(minVersion uint16) *http.Client {
	return &http.Client{Transport: versioned{&http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: f.serverPool, ServerName: "localhost", MinVersion: minVersion,
		MaxVersion: minVersion}}}, Timeout: 10 * time.Second}
}

func (f *fx) sign(t *testing.T, c coll, method, pathq string, body []byte, mut func(*mode2.Claims)) string {
	t.Helper()
	n, _ := mode2.NewNonce()
	cl := mode2.Claims{Kid: c.res.Fingerprint, Cid: c.res.CollectorID, Tid: c.tenant.String(),
		Mth: method, Path: pathq, Nonce: n, Iat: f.clock.Unix(), Exp: f.clock.Add(time.Minute).Unix()}
	if mut != nil {
		mut(&cl)
	}
	s, err := mode2.Sign(c.key, cl, body)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func reason(b []byte) string {
	var m map[string]string
	_ = json.Unmarshal(b, &m)
	return m["reason"]
}

func TestMode2SignedBatchIsAcceptedOverTLS12(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")
	body, _ := json.Marshal(batch("m2-batch-0001", 3))
	sig := f.sign(t, c, "POST", "/v1/ingest/observations", body, nil)
	resp, b := do(t, f.plain(tls.VersionTLS12), "POST", m2.URL+"/v1/ingest/observations", body,
		map[string]string{mode2.Header: sig})
	if resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if n := f.countObservations(t, f.a); n != 3 {
		t.Fatalf("tenant A observations = %d", n)
	}
	if n := f.countObservations(t, f.b); n != 0 {
		t.Fatalf("tenant B observations = %d", n)
	}
}

func TestMode2ReplayIsRefused(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")
	body, _ := json.Marshal(batch("m2-replay-01", 1))
	sig := f.sign(t, c, "POST", "/v1/ingest/observations", body, nil)
	cl := f.plain(tls.VersionTLS13)
	if resp, b := do(t, cl, "POST", m2.URL+"/v1/ingest/observations", body,
		map[string]string{mode2.Header: sig}); resp.StatusCode != 202 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp, b := do(t, cl, "POST", m2.URL+"/v1/ingest/observations", body, map[string]string{mode2.Header: sig})
	if resp.StatusCode != 401 || reason(b) != "protocol.replay" {
		t.Fatalf("replay: %d %s", resp.StatusCode, b)
	}
}

// The nonce is a primary key: of N concurrent copies of one signed request,
// exactly one is accepted.
func TestMode2ConcurrentReplayAcceptsExactlyOne(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")
	sig := f.sign(t, c, "GET", "/v1/tasks?wait=0", nil, nil)
	cl := f.plain(tls.VersionTLS13)
	var mu sync.Mutex
	codes := map[int]int{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _ := do(t, cl, "GET", m2.URL+"/v1/tasks?wait=0", nil, map[string]string{mode2.Header: sig})
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[200] != 1 || codes[401] != 7 {
		t.Fatalf("codes = %v", codes)
	}
}

func TestMode2RejectsEveryForgery(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	a := f.coll(t, f.a, "a")
	a2 := f.coll(t, f.a, "a2")
	b := f.coll(t, f.b, "b")
	cl := f.plain(tls.VersionTLS13)
	path := "/v1/ingest/observations"
	body, _ := json.Marshal(batch("m2-forge-001", 1))

	type tc struct {
		sig      func() string
		body     []byte
		want     int
		wantWhy  string
		tenantOK bool
	}
	cases := map[string]tc{
		"no signature": {func() string { return "" }, body, 401, "", true},
		"signed by another collector's key, naming this key": {func() string {
			s := a2
			s.res.Fingerprint = a.res.Fingerprint
			s.res.CollectorID = a.res.CollectorID
			return f.sign(t, s, "POST", path, body, nil)
		}, body, 401, "", true},
		"kid of another tenant's collector": {func() string {
			return f.sign(t, a, "POST", path, body, func(c *mode2.Claims) { c.Kid = b.res.Fingerprint })
		}, body, 401, "", true},
		"wrong tenant claim": {func() string {
			return f.sign(t, a, "POST", path, body, func(c *mode2.Claims) { c.Tid = f.b.String() })
		}, body, 403, "", true},
		"wrong collector claim": {func() string {
			return f.sign(t, a, "POST", path, body, func(c *mode2.Claims) { c.Cid = a2.res.CollectorID })
		}, body, 403, "", true},
		"body altered after signing": {func() string {
			return f.sign(t, a, "POST", path, body, nil)
		}, []byte(strings.Replace(string(body), `"port":443`, `"port":444`, 1)), 401, "", true},
		"signed for another path": {func() string {
			return f.sign(t, a, "POST", "/v1/collectors/heartbeat", body, nil)
		}, body, 401, "", true},
		"expired": {func() string {
			return f.sign(t, a, "POST", path, body, func(c *mode2.Claims) {
				c.Iat = f.clock.Add(-2 * time.Minute).Unix()
				c.Exp = f.clock.Add(-time.Minute).Unix()
			})
		}, body, 401, "", true},
		"clock skew": {func() string {
			return f.sign(t, a, "POST", path, body, func(c *mode2.Claims) {
				c.Iat = f.clock.Add(10 * time.Minute).Unix()
				c.Exp = f.clock.Add(11 * time.Minute).Unix()
			})
		}, body, 401, "protocol.clock_skew", true},
		"alg none": {func() string {
			s := f.sign(t, a, "POST", path, body, nil)
			p, _ := mode2.Parse(s)
			cl := p.Claims
			cl.Alg = "none"
			hj, _ := json.Marshal(cl)
			return b64url(hj) + ".." + strings.Split(s, ".")[2]
		}, body, 401, "", true},
		"malformed": {func() string { return "not.a.jws" }, body, 401, "", true},
		"oversized": {func() string { return strings.Repeat("A", 5000) }, body, 401, "", true},
	}
	for name, cs := range cases {
		t.Run(name, func(t *testing.T) {
			hdr := map[string]string{}
			if s := cs.sig(); s != "" {
				hdr[mode2.Header] = s
			}
			resp, rb := do(t, cl, "POST", m2.URL+path, cs.body, hdr)
			if resp.StatusCode != cs.want || (cs.wantWhy != "" && reason(rb) != cs.wantWhy) {
				t.Fatalf("%d %s", resp.StatusCode, rb)
			}
			if cs.wantWhy == "protocol.clock_skew" && !strings.Contains(string(rb), "server_time") {
				t.Fatalf("skew response lacks server_time: %s", rb)
			}
		})
	}
	if n := f.countObservations(t, f.a) + f.countObservations(t, f.b); n != 0 {
		t.Fatalf("a forged request stored %d observations", n)
	}
	if n := f.audits(t, f.a, "ingest.mode2_identity_mismatch"); n != 2 {
		t.Fatalf("identity mismatch audits = %d, want 2", n)
	}
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Signed with the right key, but the payload names another tenant: the
// payload's tenant is checked against the key's, never used.
func TestMode2PayloadTenantCannotRedirect(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")
	bt := batch("m2-redirect1", 1)
	bt.TenantID = f.b.String()
	body, _ := json.Marshal(bt)
	resp, b := do(t, f.plain(tls.VersionTLS13), "POST", m2.URL+"/v1/ingest/observations", body,
		map[string]string{mode2.Header: f.sign(t, c, "POST", "/v1/ingest/observations", body, nil)})
	if resp.StatusCode != 403 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if n := f.countObservations(t, f.b); n != 0 {
		t.Fatalf("stored into tenant B: %d", n)
	}
}

func TestMode2RevokedKeyIsRefused(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")
	if err := f.en.Revoke(f.ctx(f.a), c.res.Fingerprint, "test"); err != nil {
		t.Fatal(err)
	}
	resp, b := do(t, f.plain(tls.VersionTLS13), "GET", m2.URL+"/v1/tasks?wait=0", nil,
		map[string]string{mode2.Header: f.sign(t, c, "GET", "/v1/tasks?wait=0", nil, nil)})
	if resp.StatusCode != 401 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

// The Mode 2 listener has no certificate path: a valid client certificate is
// not asked for, and a request without a signature is refused even if the
// client offers one.
func TestMode2ListenerHasNoCertificateFallback(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")
	tr := c.c.Transport.(versioned).rt.(*http.Transport).Clone()
	resp, b := do(t, &http.Client{Transport: versioned{tr}}, "GET", m2.URL+"/v1/tasks?wait=0", nil, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

// The plan's acceptance test: Mode 2 works through a TLS-INSPECTING proxy that
// terminates TLS and re-serialises JSON — and mTLS through the same proxy
// cannot, which is why Mode 2 exists.
func TestMode2WorksThroughAnInspectingProxy(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")

	upstream := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: f.serverPool, ServerName: "localhost"}}, Timeout: 10 * time.Second}
	var rewritten int
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			// Inspect and re-serialise, as DLP proxies do: keys reordered,
			// whitespace changed.
			var v any
			if err := json.Unmarshal(body, &v); err == nil {
				nb, _ := json.MarshalIndent(v, "", "    ")
				if !bytes.Equal(nb, body) {
					rewritten++
				}
				body = nb
			}
		}
		req, _ := http.NewRequest(r.Method, m2.URL+r.URL.RequestURI(), bytes.NewReader(body))
		req.Header = r.Header.Clone()
		resp, err := upstream.Do(req)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()
	viaProxy := &http.Client{Transport: versioned{proxy.Client().Transport}, Timeout: 10 * time.Second}

	ep := f.endpoint(t, f.a, "behind-proxy.example")
	job := f.enqueue(t, f.a, ep, f.clock)
	resp, b := do(t, viaProxy, "GET", proxy.URL+"/v1/tasks?wait=0", nil,
		map[string]string{mode2.Header: f.sign(t, c, "GET", "/v1/tasks?wait=0", nil, nil)})
	if resp.StatusCode != 200 || !strings.Contains(string(b), job) {
		t.Fatalf("tasks via proxy: %d %s", resp.StatusCode, b)
	}
	bt := batch("m2-proxy-001", 2)
	bt.TaskID = job
	body, _ := json.Marshal(bt)
	resp, b = do(t, viaProxy, "POST", proxy.URL+"/v1/ingest/observations", body,
		map[string]string{mode2.Header: f.sign(t, c, "POST", "/v1/ingest/observations", body, nil)})
	if resp.StatusCode != 202 || !strings.Contains(string(b), `"task_completed":true`) {
		t.Fatalf("batch via proxy: %d %s", resp.StatusCode, b)
	}
	if rewritten == 0 {
		t.Fatal("the proxy fixture did not actually rewrite the body; the test proves nothing")
	}
	// A proxy that tampers with the wait parameter breaks the signature.
	resp, _ = do(t, viaProxy, "GET", proxy.URL+"/v1/tasks?wait=1", nil,
		map[string]string{mode2.Header: f.sign(t, c, "GET", "/v1/tasks?wait=0", nil, nil)})
	if resp.StatusCode != 401 {
		t.Fatalf("tampered query accepted: %d", resp.StatusCode)
	}
}

// Expired nonces are deleted as the collector keeps talking; the replay store
// does not grow without bound.
func TestMode2NonceStoreIsBounded(t *testing.T) {
	f := newFx(t)
	f.serve(t)
	m2 := f.serveMode2(t)
	c := f.coll(t, f.a, "c")
	cl := f.plain(tls.VersionTLS13)
	for i := 0; i < 5; i++ {
		resp, b := do(t, cl, "GET", m2.URL+"/v1/tasks?wait=0", nil,
			map[string]string{mode2.Header: f.sign(t, c, "GET", "/v1/tasks?wait=0", nil, nil)})
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
	}
	count := func() int {
		var n int
		_ = f.st.InTenantTx(f.ctx(f.a), func(ctx context.Context, tx *store.Tx) error {
			return tx.Conn().QueryRow(ctx, `SELECT count(*) FROM mode2_nonces`).Scan(&n)
		})
		return n
	}
	if n := count(); n != 5 {
		t.Fatalf("nonces = %d", n)
	}
	f.clock = f.clock.Add(mode2.NonceTTL + time.Minute)
	resp, _ := do(t, cl, "GET", m2.URL+"/v1/tasks?wait=0", nil,
		map[string]string{mode2.Header: f.sign(t, c, "GET", "/v1/tasks?wait=0", nil, nil)})
	if resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	if n := count(); n != 1 {
		t.Fatalf("expired nonces not purged: %d remain", n)
	}
}
