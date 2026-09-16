package scan

import (
	"context"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

// SCAN-003 / threat T3. These addresses are refused unconditionally.
func TestAddrBlocked(t *testing.T) {
	blocked := []string{
		"169.254.169.254", // AWS/Azure/DO/Oracle IMDS -- the one that matters most
		"169.254.170.2",   // ECS task metadata
		"100.100.100.100", // Alibaba
		"192.0.0.192",     // Oracle legacy
		"fd00:ec2::254",   // AWS IMDSv6
		"127.0.0.1", "127.1.2.3", "::1",
		"169.254.1.1", "fe80::1",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
		"255.255.255.255",
	}
	for _, s := range blocked {
		a := netip.MustParseAddr(s)
		if ok, why := AddrBlocked(a); !ok {
			t.Errorf("AddrBlocked(%s) = false; it must be refused unconditionally", s)
		} else if why == "" {
			t.Errorf("AddrBlocked(%s) gave no reason", s)
		}
	}

	allowed := []string{
		"10.20.30.40", "192.168.1.1", "172.16.0.1", // RFC1918 is IN scope: that is the product
		"8.8.8.8", "203.0.113.1",
		"2001:db8::1", "fd12:3456::1",
	}
	for _, s := range allowed {
		if ok, why := AddrBlocked(netip.MustParseAddr(s)); ok {
			t.Errorf("AddrBlocked(%s) = true (%s); internal ranges are the whole point of the product", s, why)
		}
	}
}

// IPv4-mapped IPv6 must not be a bypass: ::ffff:169.254.169.254 is the metadata
// endpoint wearing a different hat.
func TestIPv4MappedIsNotABypass(t *testing.T) {
	for _, s := range []string{"::ffff:169.254.169.254", "::ffff:127.0.0.1", "::ffff:169.254.170.2"} {
		a := netip.MustParseAddr(s)
		if ok, _ := AddrBlocked(a); !ok {
			t.Errorf("AddrBlocked(%s) = false; the IPv4-mapped form must be refused too", s)
		}
	}
}

func TestNameBlocked(t *testing.T) {
	for _, s := range []string{
		"metadata.google.internal", "METADATA.GOOGLE.INTERNAL", "metadata.google.internal.",
		"metadata.goog", "instance-data",
	} {
		if ok, _ := NameBlocked(s); !ok {
			t.Errorf("NameBlocked(%q) = false", s)
		}
	}
	for _, s := range []string{"api.internal.example", "metadata.example.com", ""} {
		if ok, _ := NameBlocked(s); ok {
			t.Errorf("NameBlocked(%q) = true", s)
		}
	}
}

// rebindResolver alternates its answer on every query — the DNS rebinding
// attack, reproduced exactly (threat T4).
type rebindResolver struct {
	calls atomic.Int64
	good  netip.Addr
	evil  netip.Addr
}

func (r *rebindResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	n := r.calls.Add(1)
	if n%2 == 1 {
		return []netip.Addr{r.good}, nil
	}
	return []netip.Addr{r.evil}, nil
}

// SCAN-004 / threat T4: 1,000 queries against a resolver that flips between an
// in-scope address and the metadata endpoint. Zero connections to the blocked
// address are permitted.
func TestDNSRebindingRefused(t *testing.T) {
	r := &rebindResolver{
		good: netip.MustParseAddr("10.20.30.40"),
		evil: netip.MustParseAddr("169.254.169.254"),
	}
	refused, allowed := 0, 0
	for i := 0; i < 1000; i++ {
		addrs, err := ResolveAll(context.Background(), r, "flip.example")
		if err != nil {
			refused++
			if !strings.Contains(err.Error(), "169.254.169.254") {
				t.Fatalf("refusal did not name the offending address: %v", err)
			}
			continue
		}
		allowed++
		for _, a := range addrs {
			if blocked, _ := AddrBlocked(a); blocked {
				t.Fatalf("iteration %d: ResolveAll returned a blocked address %s", i, a)
			}
		}
	}
	// Both interleavings must have been observed, or the test proved nothing.
	if refused == 0 {
		t.Fatal("the evil answer was never returned; the rebinding path was not exercised")
	}
	if allowed == 0 {
		t.Fatal("the good answer was never accepted; the test would pass by refusing everything")
	}
	t.Logf("rebinding fixture: %d refused, %d allowed across 1000 queries", refused, allowed)
}

// A hostname resolving to a mix of in-scope and blocked addresses is refused
// ENTIRELY. Picking the "good" answer is how a rebinding attack succeeds.
func TestMixedAnswerRefusedEntirely(t *testing.T) {
	r := &staticResolver{addrs: []netip.Addr{
		netip.MustParseAddr("10.20.30.40"),
		netip.MustParseAddr("169.254.169.254"),
	}}
	if _, err := ResolveAll(context.Background(), r, "mixed.example"); err == nil {
		t.Fatal("a name resolving to both an in-scope and a metadata address was accepted")
	}
}

type staticResolver struct{ addrs []netip.Addr }

func (s *staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return s.addrs, nil
}

// A literal metadata address passed as a "hostname" must not slip through.
func TestLiteralBlockedAddressRefused(t *testing.T) {
	r := &staticResolver{addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	for _, lit := range []string{"169.254.169.254", "127.0.0.1", "::1"} {
		if _, err := ResolveAll(context.Background(), r, lit); err == nil {
			t.Errorf("literal %s was accepted", lit)
		}
	}
}

// The dialler must refuse a blocked address even if a caller reaches it directly.
func TestDialByAddressRefusesBlocked(t *testing.T) {
	_, err := dialByAddress(context.Background(), netip.MustParseAddr("169.254.169.254"), 80, 0)
	if err == nil {
		t.Fatal("dialByAddress connected to the metadata endpoint")
	}
	if !strings.Contains(err.Error(), "refus") {
		t.Fatalf("unexpected error: %v", err)
	}
}
