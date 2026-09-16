package scan

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// MaxExpandedTargets bounds a single CIDR expansion. A /8 is 16 million
// addresses; expanding it into memory is a mistake before it is a scan.
const MaxExpandedTargets = 1 << 20

// ExpandCIDR enumerates the host addresses of a prefix.
//
// Network and broadcast addresses are excluded for IPv4 prefixes shorter than
// /31, because scanning them is noise at best and triggers IDS at worst.
// IPv6 prefixes longer than /112 only: anything wider is refused rather than
// silently truncated, because a /64 is not enumerable and pretending otherwise
// produces a scan that never finishes.
func ExpandCIDR(p netip.Prefix) ([]netip.Addr, error) {
	p = p.Masked()
	addr := p.Addr()

	if addr.Is6() && !addr.Is4In6() {
		if p.Bits() < 112 {
			return nil, fmt.Errorf("scan: IPv6 prefix %s is wider than /112 and cannot be enumerated; "+
				"scan specific addresses or a narrower range", p)
		}
	}
	hostBits := addr.BitLen() - p.Bits()
	if hostBits > 20 {
		return nil, fmt.Errorf("scan: prefix %s expands to more than %d addresses", p, MaxExpandedTargets)
	}
	count := 1 << uint(hostBits)

	skipEdges := addr.Is4() && p.Bits() < 31 && p.Bits() > 0
	out := make([]netip.Addr, 0, count)
	cur := addr
	for i := 0; i < count; i++ {
		if skipEdges && (i == 0 || i == count-1) {
			cur = cur.Next()
			continue
		}
		if !cur.IsValid() {
			break
		}
		out = append(out, cur)
		cur = cur.Next()
	}
	return out, nil
}

// SweepResult is the outcome of a bounded sweep.
type SweepResult struct {
	Probes      []Probe
	Attempted   int
	Skipped     int
	Succeeded   int
	Failed      int
	Duration    time.Duration
	DeadlineHit bool
	// Resume, when non-empty, names the targets not attempted because the sweep
	// ran out of time. A /16 interrupted at 60% resumes at 60% rather than
	// starting again.
	Resume []Target
}

// Sweep probes many targets with bounded concurrency and a rate ceiling.
//
// Ordering is deterministic so that an interrupted sweep resumes predictably
// and two runs of the same scope produce comparable output.
func Sweep(ctx context.Context, targets []Target, p Policy) SweepResult {
	p = p.withDefaults()
	start := time.Now()

	sorted := make([]Target, len(targets))
	copy(sorted, targets)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Addr != sorted[j].Addr {
			return sorted[i].Addr.Less(sorted[j].Addr)
		}
		if sorted[i].Port != sorted[j].Port {
			return sorted[i].Port < sorted[j].Port
		}
		return sorted[i].SNI < sorted[j].SNI
	})

	bucket := newTokenBucket(p.RatePerSecond)
	sem := make(chan struct{}, p.Concurrency)

	var (
		mu        sync.Mutex
		probes    = make([]Probe, 0, len(sorted))
		completed = make(map[int]bool, len(sorted))
		wg        sync.WaitGroup
	)

	for i, t := range sorted {
		if ctx.Err() != nil {
			break
		}
		// Rate limiting happens BEFORE a worker slot is taken, so the ceiling is
		// on connections per second and not on in-flight work.
		if err := bucket.Wait(ctx); err != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			<-sem
			break
		}

		wg.Add(1)
		go func(idx int, tgt Target) {
			defer wg.Done()
			defer func() { <-sem }()
			pr := ProbeOne(ctx, tgt, p)
			mu.Lock()
			probes = append(probes, pr)
			completed[idx] = true
			mu.Unlock()
		}(i, t)
	}
	wg.Wait()

	res := SweepResult{Probes: probes, Duration: time.Since(start)}
	for _, pr := range probes {
		res.Attempted++
		switch {
		case pr.Skipped:
			res.Skipped++
		case pr.OK():
			res.Succeeded++
		default:
			res.Failed++
		}
	}
	if ctx.Err() != nil {
		res.DeadlineHit = true
	}
	mu.Lock()
	for i, t := range sorted {
		if !completed[i] {
			res.Resume = append(res.Resume, t)
		}
	}
	mu.Unlock()

	sort.Slice(res.Probes, func(i, j int) bool {
		if res.Probes[i].Target.Addr != res.Probes[j].Target.Addr {
			return res.Probes[i].Target.Addr.Less(res.Probes[j].Target.Addr)
		}
		return res.Probes[i].Target.Port < res.Probes[j].Target.Port
	})
	return res
}
