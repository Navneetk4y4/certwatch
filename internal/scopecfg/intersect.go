package scopecfg

import (
	"fmt"
	"net/netip"
)

// Target is one thing the collector has been asked to touch.
type Target struct {
	Addr netip.Addr
	Port int
}

func (t Target) String() string { return netip.AddrPortFrom(t.Addr, uint16(t.Port)).String() }

// Violation records a task element that was refused.
//
// Refusals are REPORTED, not silently dropped: a customer must be able to see
// that their control plane asked for something outside their declared scope,
// because that is either a bug on our side or a compromise on ours — and both
// are things they are entitled to know about (threat T2).
type Violation struct {
	What   string
	Reason string
}

// Intersect is the load-bearing function of the entire security model.
//
// It answers exactly one question: given something the control plane asked for,
// what subset of it is the customer actually permitted to have touched?
//
// The rules, in order, and there are only four:
//
//  1. The address must fall inside a declared CIDR.        (server cannot widen)
//  2. It must not fall inside an excluded CIDR.            (exclusions win)
//  3. It must not be an excluded host.                     (exclusions win)
//  4. The port must be a declared port.                    (server cannot widen)
//
// Anything not permitted by all four is dropped and returned as a Violation.
// There is no fifth rule, no override flag, and no field in any server message
// that changes this behaviour.
func (s *Scope) Intersect(requested []Target) (allowed []Target, violations []Violation) {
	portOK := make(map[int]bool, len(s.ports))
	for _, p := range s.ports {
		portOK[p] = true
	}

	for _, t := range requested {
		addr := t.Addr.Unmap()

		if !portOK[t.Port] {
			violations = append(violations, Violation{
				What:   t.String(),
				Reason: fmt.Sprintf("port %d is not declared in scope.yaml", t.Port),
			})
			continue
		}
		if !s.containsAddr(addr) {
			violations = append(violations, Violation{
				What:   t.String(),
				Reason: "address is not inside any declared CIDR",
			})
			continue
		}
		if p, excluded := s.excludedBy(addr); excluded {
			violations = append(violations, Violation{
				What:   t.String(),
				Reason: "address is inside the excluded range " + p,
			})
			continue
		}
		allowed = append(allowed, Target{Addr: addr, Port: t.Port})
	}
	return allowed, violations
}

// AllowsCIDR reports whether an entire requested prefix lies within scope, and
// returns the reason when it does not.
//
// Used before expanding a SCAN_CIDR task: expanding a /8 to discover that none
// of it is permitted wastes 16 million iterations.
func (s *Scope) AllowsCIDR(p netip.Prefix) (bool, string) {
	p = p.Masked()
	for _, allowed := range s.cidrs {
		if allowed.Overlaps(p) {
			if allowed.Bits() <= p.Bits() && allowed.Contains(p.Addr()) {
				return true, ""
			}
			return false, fmt.Sprintf("%s is only partially inside the declared range %s; "+
				"the overlapping portion will be scanned and the remainder refused", p, allowed)
		}
	}
	return false, fmt.Sprintf("%s does not overlap any declared CIDR", p)
}

// AllowsDirectory reports whether a filesystem path is a declared certificate
// directory, or lies beneath one.
func (s *Scope) AllowsDirectory(path string) bool {
	for _, d := range s.directories {
		if path == d || (len(path) > len(d) && path[:len(d)] == d && path[len(d)] == '/') {
			return true
		}
	}
	return false
}

func (s *Scope) containsAddr(a netip.Addr) bool {
	for _, p := range s.cidrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Scope) excludedBy(a netip.Addr) (string, bool) {
	for _, p := range s.excludeCIDRs {
		if p.Contains(a) {
			return p.String(), true
		}
	}
	for _, h := range s.excludeHosts {
		if h == a {
			return h.String(), true
		}
	}
	return "", false
}
