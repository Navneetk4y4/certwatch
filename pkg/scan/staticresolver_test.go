package scan

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// The --resolve override must be subject to exactly the same block list as DNS.
// A static entry is attacker-influenced input whenever the expectations file is
// — if it could reach a metadata address, the flag would be an SSRF primitive
// wearing a convenience flag's clothes.
func TestStaticResolverDoesNotBypassTheBlockList(t *testing.T) {
	for _, tc := range []struct{ name, addr string }{
		{"AWS metadata", "169.254.169.254"},
		{"GCP metadata", "169.254.169.254"},
		{"loopback", "127.0.2.2"},
		{"unspecified", "0.0.0.0"},
		{"link-local", "169.254.1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &StaticResolver{Entries: map[string][]netip.Addr{
				"evil.test": {netip.MustParseAddr(tc.addr)},
			}}
			_, err := ResolveAll(context.Background(), r, "evil.test")
			if err == nil {
				t.Fatalf("--resolve smuggled %s past the block list", tc.addr)
			}
			if !strings.Contains(err.Error(), "refusing") {
				t.Errorf("error does not name the refusal: %v", err)
			}
		})
	}
}

// One good address does not redeem an entry that also names a blocked one.
func TestStaticResolverRefusesTheWholeEntry(t *testing.T) {
	r := &StaticResolver{Entries: map[string][]netip.Addr{
		"mixed.test": {netip.MustParseAddr("10.20.0.5"), netip.MustParseAddr("169.254.169.254")},
	}}
	if _, err := ResolveAll(context.Background(), r, "mixed.test"); err == nil {
		t.Fatal("a mixed entry was accepted; the good address must not redeem the blocked one")
	}
}

func TestParseResolveEntry(t *testing.T) {
	host, addrs, err := ParseResolveEntry("API.Example.com:10.0.0.1,10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if host != "api.example.com" {
		t.Errorf("host = %q, want lowercased", host)
	}
	if len(addrs) != 2 {
		t.Errorf("got %d addresses, want 2", len(addrs))
	}
	for _, bad := range []string{"noaddrs:", "nocolon", ":10.0.0.1", "h:notanip"} {
		if _, _, err := ParseResolveEntry(bad); err == nil {
			t.Errorf("ParseResolveEntry(%q) accepted invalid input", bad)
		}
	}
}
