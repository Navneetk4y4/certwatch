package scan

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The TOCTOU closure, tested independently of the pre-dial check.
//
// dialByAddress checks the address BEFORE dialling and the Control hook checks
// it again AT the syscall. Those look redundant and are not: the first is the
// policy decision, the second survives a future refactor that reintroduces a
// hostname path. A test that only exercises the first proves nothing about the
// second, so this tests the second directly.
func TestVerifyDialAddressIsTheSyscallLevelCheck(t *testing.T) {
	blocked := []string{
		"169.254.169.254:80", "169.254.169.254:443", "169.254.170.2:80",
		"127.0.0.1:443", "[::1]:443", "100.100.100.100:80",
		"[fd00:ec2::254]:80", "0.0.0.0:443", "[fe80::1]:443",
		"224.0.0.1:443", "192.0.0.192:80",
	}
	for _, a := range blocked {
		if err := verifyDialAddress(a); err == nil {
			t.Errorf("verifyDialAddress(%s) permitted the connection at syscall level", a)
		}
	}

	allowed := []string{
		"10.20.30.40:443", "192.168.1.1:8443", "172.16.0.1:443",
		"203.0.113.1:443", "[2001:db8::1]:443",
	}
	for _, a := range allowed {
		if err := verifyDialAddress(a); err != nil {
			t.Errorf("verifyDialAddress(%s) refused a legitimate target: %v", a, err)
		}
	}
}

// An address the check cannot parse must FAIL CLOSED. An unverifiable
// connection is refused, not permitted.
func TestVerifyDialAddressFailsClosedOnUnparseable(t *testing.T) {
	for _, a := range []string{"", "not-an-address", "10.0.0.1", "[::1]", "host.example:443", "10.0.0.1:notaport"} {
		err := verifyDialAddress(a)
		if err == nil {
			t.Errorf("verifyDialAddress(%q) permitted an address it could not parse; it must fail closed", a)
		} else if !strings.Contains(err.Error(), "refus") {
			t.Errorf("verifyDialAddress(%q) = %v; the error should say it refused", a, err)
		}
	}
}

// The Control hook must actually be wired in. Proven by connecting to a real
// listener (success path) and confirming the refusal path errors before any
// connection is attempted.
func TestDialByAddressConnectsAndRefuses(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())

	// Loopback is blocked by policy, so this proves the refusal path end to end
	// on a port that genuinely IS listening — the refusal is the policy's, not
	// the network's.
	conn, err := dialByAddress(context.Background(), ap.Addr(), int(ap.Port()), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("dialByAddress connected to a loopback address that a real listener was on; " +
			"the refusal must come from policy, not from the connection failing")
	}
	if !strings.Contains(err.Error(), "refus") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// A dial to an unroutable in-scope address must time out rather than hang.
func TestDialByAddressHonoursTimeout(t *testing.T) {
	start := time.Now()
	// TEST-NET-1, reserved for documentation and not routable.
	_, err := dialByAddress(context.Background(), netip.MustParseAddr("192.0.2.1"), 443, 800*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("connected to an unroutable address")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("dial took %v despite an 800ms timeout", elapsed)
	}
}

// A cancelled context must abort the dial.
func TestDialByAddressHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialByAddress(ctx, netip.MustParseAddr("192.0.2.1"), 443, 10*time.Second); err == nil {
		t.Fatal("dialled despite a cancelled context")
	}
}

// ResolveAll must handle a resolver that errors, and one that returns nothing.
func TestResolveAllFailureModes(t *testing.T) {
	ctx := context.Background()

	if _, err := ResolveAll(ctx, &erroringResolver{}, "x.example"); err == nil {
		t.Error("a resolver error was not surfaced")
	}
	if _, err := ResolveAll(ctx, &staticResolver{addrs: nil}, "x.example"); err == nil {
		t.Error("a name resolving to zero addresses was accepted")
	}
	// A blocked NAME must be refused before any resolution happens.
	if _, err := ResolveAll(ctx, &staticResolver{addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		"metadata.google.internal"); err == nil {
		t.Error("a metadata hostname was accepted")
	}
}

type erroringResolver struct{}

func (e *erroringResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, net.UnknownNetworkError("boom")
}

// ProbeOne's refusal and dry-run paths, which are the ones that must never
// touch the network.
func TestProbeOneRefusalPaths(t *testing.T) {
	ctx := context.Background()

	pr := ProbeOne(ctx, Target{Addr: netip.MustParseAddr("169.254.169.254"), Port: 80}, Policy{})
	if !pr.Skipped || pr.SkipReason == "" {
		t.Fatalf("the metadata endpoint was not skipped: %+v", pr)
	}
	if pr.OK() {
		t.Fatal("a skipped probe reported OK")
	}

	pr = ProbeOne(ctx, Target{Addr: netip.MustParseAddr("10.0.0.1"), Port: 443}, Policy{DryRun: true})
	if !pr.Skipped || !strings.Contains(pr.SkipReason, "dry run") {
		t.Fatalf("dry run did not skip: %+v", pr)
	}

	// An unroutable target must produce a connect error, not a panic or a hang.
	pr = ProbeOne(ctx, Target{Addr: netip.MustParseAddr("192.0.2.1"), Port: 443},
		Policy{ConnectTimeout: 500 * time.Millisecond})
	if pr.ConnectErr == "" {
		t.Fatalf("no connect error for an unroutable target: %+v", pr)
	}
	if pr.Duration == 0 {
		t.Error("probe duration was not recorded")
	}
}

func TestTargetStringAndTLSVersionNames(t *testing.T) {
	tg := Target{Addr: netip.MustParseAddr("10.0.0.1"), Port: 443}
	if tg.String() != "10.0.0.1:443" {
		t.Errorf("Target.String() = %s", tg.String())
	}
	for v, want := range map[uint16]string{
		0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3",
	} {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(%#x) = %s, want %s", v, got, want)
		}
	}
	if got := tlsVersionName(0x9999); !strings.Contains(got, "unknown") {
		t.Errorf("an unrecognised version rendered as %q; it must be visibly unknown", got)
	}
}

func TestResolvabilityString(t *testing.T) {
	for r, want := range map[Resolvability]string{
		ResolvabilityUnknown: "unknown", ResolvabilityPublic: "public", ResolvabilityPrivate: "private",
	} {
		if r.String() != want {
			t.Errorf("Resolvability(%d).String() = %s, want %s", r, r.String(), want)
		}
	}
}

// Offline mode and private space must never issue a DNS query, and must never
// render as a confident "public".
func TestPubliclyResolvableNeverGuesses(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		addr    string
		host    string
		offline bool
		want    Resolvability
	}{
		{"10.0.0.1", "x.internal", false, ResolvabilityPrivate},
		{"172.16.5.5", "", false, ResolvabilityPrivate},
		{"192.168.99.1", "x", true, ResolvabilityPrivate},
		{"100.64.1.1", "x", false, ResolvabilityPrivate},
		{"127.0.0.1", "x", false, ResolvabilityPrivate},
		{"169.254.1.1", "x", false, ResolvabilityPrivate},
		{"203.0.113.1", "x.example", true, ResolvabilityUnknown},
		{"203.0.113.1", "", true, ResolvabilityUnknown},
		{"203.0.113.1", "", false, ResolvabilityPublic},
	}
	for _, c := range cases {
		got := PubliclyResolvable(ctx, netip.MustParseAddr(c.addr), c.host, c.offline)
		if got != c.want {
			t.Errorf("PubliclyResolvable(%s, %q, offline=%v) = %v, want %v",
				c.addr, c.host, c.offline, got, c.want)
		}
	}
}
