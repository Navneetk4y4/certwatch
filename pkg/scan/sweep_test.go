package scan

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// SCAN-001: CIDR expansion, including the edge-address rule.
func TestExpandCIDR(t *testing.T) {
	cases := []struct {
		cidr      string
		want      int
		firstLast [2]string
	}{
		// /24 minus network and broadcast.
		{"10.0.0.0/24", 254, [2]string{"10.0.0.1", "10.0.0.254"}},
		{"10.0.0.0/30", 2, [2]string{"10.0.0.1", "10.0.0.2"}},
		// /31 is a point-to-point link: both addresses are usable.
		{"10.0.0.0/31", 2, [2]string{"10.0.0.0", "10.0.0.1"}},
		{"10.0.0.5/32", 1, [2]string{"10.0.0.5", "10.0.0.5"}},
		{"10.0.0.0/22", 1022, [2]string{"10.0.0.1", "10.0.3.254"}},
	}
	for _, c := range cases {
		t.Run(c.cidr, func(t *testing.T) {
			addrs, err := ExpandCIDR(netip.MustParsePrefix(c.cidr))
			if err != nil {
				t.Fatal(err)
			}
			if len(addrs) != c.want {
				t.Fatalf("expanded to %d addresses, want %d", len(addrs), c.want)
			}
			if addrs[0].String() != c.firstLast[0] {
				t.Fatalf("first = %s, want %s", addrs[0], c.firstLast[0])
			}
			if addrs[len(addrs)-1].String() != c.firstLast[1] {
				t.Fatalf("last = %s, want %s", addrs[len(addrs)-1], c.firstLast[1])
			}
		})
	}
}

// A range too large to enumerate is REFUSED, not silently truncated. A scan
// that silently covers 1% of what was asked for is worse than an error,
// because the customer believes it covered everything.
func TestExpandCIDRRefusesUnenumerableRanges(t *testing.T) {
	for _, c := range []string{"10.0.0.0/8", "0.0.0.0/0", "2001:db8::/64", "2001:db8::/32"} {
		if _, err := ExpandCIDR(netip.MustParsePrefix(c)); err == nil {
			t.Errorf("ExpandCIDR(%s) was accepted; an unenumerable range must be refused, "+
				"not silently truncated", c)
		}
	}
}

// A narrow IPv6 prefix is enumerable and must work.
func TestExpandCIDRIPv6Narrow(t *testing.T) {
	addrs, err := ExpandCIDR(netip.MustParsePrefix("2001:db8::/120"))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 256 {
		t.Fatalf("expanded to %d, want 256", len(addrs))
	}
}

// SCAN-002: bounded concurrency and a deterministic order.
func TestSweepIsDeterministicAndBounded(t *testing.T) {
	s := newTestServer(t)
	var targets []Target
	for p := 1; p <= 20; p++ {
		targets = append(targets, Target{Addr: netip.MustParseAddr("10.0.0.1"), Port: p})
	}
	_ = s

	// Dry run: no packets, but the full pipeline runs.
	a := Sweep(context.Background(), targets, Policy{DryRun: true, Concurrency: 4, RatePerSecond: 500})
	b := Sweep(context.Background(), shuffle(targets), Policy{DryRun: true, Concurrency: 4, RatePerSecond: 500})

	if len(a.Probes) != len(targets) || len(b.Probes) != len(targets) {
		t.Fatalf("probe counts: %d and %d, want %d", len(a.Probes), len(b.Probes), len(targets))
	}
	for i := range a.Probes {
		if a.Probes[i].Target.Port != b.Probes[i].Target.Port {
			t.Fatalf("sweep output is not deterministic at index %d: %d vs %d",
				i, a.Probes[i].Target.Port, b.Probes[i].Target.Port)
		}
	}
	if a.Skipped != len(targets) {
		t.Fatalf("dry run skipped %d of %d", a.Skipped, len(targets))
	}
}

func shuffle(in []Target) []Target {
	out := make([]Target, len(in))
	for i, t := range in {
		out[(i*7+3)%len(in)] = t
	}
	return out
}

// SCAN-008: an interrupted sweep reports what it did not reach, so it can resume
// rather than start again.
func TestSweepReportsResumeSet(t *testing.T) {
	var targets []Target
	for i := 1; i <= 200; i++ {
		targets = append(targets, Target{Addr: netip.MustParseAddr("10.0.0.1"), Port: i})
	}
	// A rate of 2/s against 200 targets cannot finish in 300ms.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	res := Sweep(ctx, targets, Policy{DryRun: true, RatePerSecond: 2, Concurrency: 1})

	if !res.DeadlineHit {
		t.Fatal("sweep did not report hitting the deadline")
	}
	if len(res.Resume) == 0 {
		t.Fatal("no resume set reported; an interrupted /16 would restart from zero")
	}
	if len(res.Probes)+len(res.Resume) != len(targets) {
		t.Fatalf("probes(%d) + resume(%d) != targets(%d); work was lost",
			len(res.Probes), len(res.Resume), len(targets))
	}
}

// SCAN-005: the rate ceiling is real.
func TestRateLimiterBoundsThroughput(t *testing.T) {
	b := newTokenBucket(10)
	start := time.Now()
	ctx := context.Background()
	// The bucket starts full (10 tokens), so 20 takes need ~1 second.
	for i := 0; i < 20; i++ {
		if err := b.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 800*time.Millisecond {
		t.Fatalf("20 tokens at 10/s took %v; the rate ceiling is not being enforced", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("20 tokens at 10/s took %v; the limiter is far too slow", elapsed)
	}
}

func TestRateLimiterRespectsContext(t *testing.T) {
	b := newTokenBucket(1)
	ctx := context.Background()
	_ = b.Wait(ctx) // drain the single token
	c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := b.Wait(c); err == nil {
		t.Fatal("Wait ignored a cancelled context")
	}
}

// SCAN-007: resolvability is a TRI-state. Unknown must never render as false.
func TestResolvabilityTriState(t *testing.T) {
	ctx := context.Background()

	if got := PubliclyResolvable(ctx, netip.MustParseAddr("10.20.30.40"), "x.internal", false); got != ResolvabilityPrivate {
		t.Errorf("RFC1918 address = %v, want private", got)
	}
	if got := PubliclyResolvable(ctx, netip.MustParseAddr("192.168.1.1"), "", false); got != ResolvabilityPrivate {
		t.Errorf("192.168 = %v, want private", got)
	}
	if got := PubliclyResolvable(ctx, netip.MustParseAddr("100.64.0.1"), "", false); got != ResolvabilityPrivate {
		t.Errorf("CGNAT 100.64.0.0/10 = %v, want private", got)
	}
	// Offline mode must yield unknown, never a guess.
	if got := PubliclyResolvable(ctx, netip.MustParseAddr("203.0.113.1"), "x.example", true); got != ResolvabilityUnknown {
		t.Errorf("offline = %v, want unknown; a scan that reports 0%% publicly resolvable "+
			"because it could not check is a lie", got)
	}
	// The JSON rendering must be null for unknown, not false.
	if ResolvabilityUnknown.JSON() != nil {
		t.Error("unknown resolvability must serialise as null, not false")
	}
	if v := ResolvabilityPrivate.JSON(); v == nil || *v {
		t.Error("private must serialise as false")
	}
	if v := ResolvabilityPublic.JSON(); v == nil || !*v {
		t.Error("public must serialise as true")
	}
}
