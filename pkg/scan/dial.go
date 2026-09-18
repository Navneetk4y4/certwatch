package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// verifyDialAddress is the last check before the kernel connects.
//
// It is a named function rather than an inline closure so it can be tested
// independently of the pre-dial check in dialByAddress. Those two checks look
// redundant and are not: the first is the policy decision, this one is the
// TOCTOU closure, and a test that only exercises the first proves nothing about
// the second.
//
// address is in host:port form as the dialler resolved it.
func verifyDialAddress(address string) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		// Fail closed. A dial address we cannot parse is a dial address we
		// cannot check, and an unverifiable connection is refused.
		return fmt.Errorf("scan: refusing to connect: could not parse dial address %q", address)
	}
	if blocked, why := AddrBlocked(ap.Addr()); blocked {
		return fmt.Errorf("scan: refused at connect: %s", why)
	}
	return nil
}

// Resolver is the DNS interface, injectable so the rebinding defence can be
// tested against a resolver that deliberately changes its answers.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SystemResolver is the default.
type SystemResolver struct{ r net.Resolver }

func (s *SystemResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return s.r.LookupNetIP(ctx, network, host)
}

// ResolveAll resolves a hostname to every A and AAAA address, applying the
// block list to the RESULT.
//
// A hostname resolving to ANY blocked address is refused ENTIRELY, not
// partially. A name that answers with one in-scope address and one metadata
// address is not a name we want to touch at all — it is either misconfigured or
// hostile, and picking the "good" answer is how a rebinding attack succeeds.
func ResolveAll(ctx context.Context, r Resolver, host string) ([]netip.Addr, error) {
	if blocked, why := NameBlocked(host); blocked {
		return nil, fmt.Errorf("scan: refusing %s: %s", host, why)
	}
	// A literal address needs no resolution, and resolving it would be a way to
	// smuggle one past the check.
	if a, err := netip.ParseAddr(host); err == nil {
		if blocked, why := AddrBlocked(a); blocked {
			return nil, fmt.Errorf("scan: refusing %s: %s", host, why)
		}
		return []netip.Addr{a.Unmap()}, nil
	}

	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("scan: resolving %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("scan: %s resolved to no addresses", host)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if blocked, why := AddrBlocked(a); blocked {
			return nil, fmt.Errorf("scan: refusing %s entirely: it resolves to %s, and %s",
				host, a, why)
		}
		out = append(out, a)
	}
	return out, nil
}

// dialByAddress connects to a resolved IP literal, re-verifying the address
// against the block list inside the dialler's Control hook.
//
// # Why this shape closes DNS rebinding (threat T4)
//
// A dialler given a HOSTNAME re-resolves at connect time. That re-resolution is
// precisely the window a rebinding attack uses: the first answer is in scope,
// the second is 169.254.169.254. Checking the resolved address and then handing
// the hostname to Dial checks one thing and connects to another.
//
// Dialling by address removes the window. The Control hook then re-verifies the
// address the kernel is actually about to connect to, which closes it even if a
// future refactor reintroduces a hostname path — the check is at the syscall,
// not at the caller.
func dialByAddress(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (net.Conn, error) {
	if blocked, why := AddrBlocked(addr); blocked {
		return nil, fmt.Errorf("scan: refusing to connect: %s", why)
	}
	d := &net.Dialer{
		Timeout: timeout,
		// verifyDialAddress runs at the syscall, on whatever the kernel is
		// actually about to connect to — which is the check that survives a
		// future refactor reintroducing a hostname path.
		Control: func(network, address string, c syscall.RawConn) error {
			return verifyDialAddress(address)
		},
	}
	ap := netip.AddrPortFrom(addr, uint16(port))
	return d.DialContext(ctx, "tcp", ap.String())
}
