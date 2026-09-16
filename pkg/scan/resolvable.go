package scan

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Resolvability is a tri-state. Unknown is a real answer and must never be
// rendered as false: a scan reporting "0% publicly resolvable" because it could
// not check is a lie, and the internal-visibility claim is the product's wedge.
type Resolvability int

const (
	ResolvabilityUnknown Resolvability = iota
	ResolvabilityPublic
	ResolvabilityPrivate
)

func (r Resolvability) String() string {
	switch r {
	case ResolvabilityPublic:
		return "public"
	case ResolvabilityPrivate:
		return "private"
	default:
		return "unknown"
	}
}

// JSON renders the tri-state for the report: true, false, or null.
func (r Resolvability) JSON() *bool {
	switch r {
	case ResolvabilityPublic:
		t := true
		return &t
	case ResolvabilityPrivate:
		f := false
		return &f
	default:
		return nil
	}
}

// publicResolvers are used to answer "can the outside world see this name?".
var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// PubliclyResolvable determines whether an observation is reachable from the
// public internet.
//
//	private address space          -> private, without any DNS query
//	hostname known, offline mode   -> unknown (never guessed)
//	hostname known, resolvers work -> public iff a public resolver returns this address
//	resolver failure               -> unknown
//
// The offline path matters: a customer scanning an air-gapped network gets
// `unknown` for every observation, and the report says so, rather than claiming
// everything is internal because nothing could be checked.
func PubliclyResolvable(ctx context.Context, addr netip.Addr, hostname string, offline bool) Resolvability {
	addr = addr.Unmap()
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return ResolvabilityPrivate
	}
	// RFC 6598 shared address space (100.64.0.0/10) is carrier-grade NAT and is
	// not publicly routable; netip has no helper for it.
	if cgnat.Contains(addr) {
		return ResolvabilityPrivate
	}
	if offline || hostname == "" {
		if offline {
			return ResolvabilityUnknown
		}
		// Globally routable with no name to check: the address itself is reachable.
		if addr.IsGlobalUnicast() {
			return ResolvabilityPublic
		}
		return ResolvabilityUnknown
	}

	for _, server := range publicResolvers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, network, server)
			},
		}
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		addrs, err := r.LookupNetIP(c, "ip", hostname)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.Unmap() == addr {
				return ResolvabilityPublic
			}
		}
		// A public resolver answered and this address was not among the answers.
		return ResolvabilityPrivate
	}
	return ResolvabilityUnknown
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
