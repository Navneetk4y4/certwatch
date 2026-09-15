package safeio

import (
	"fmt"
	"sort"
)

// Counters make every skip visible. The guarantee they encode is:
//
//	FilesSeen == sum of every file-level disposition
//
// Two counter families, deliberately separated:
//
//   - File dispositions are mutually exclusive: exactly one per file seen.
//   - Block counters are not: a certificate bundle that also contains a private
//     key yields a certificate result AND one PrivateKeyBlocksSkipped.
//
// Collapsing these into one number would break the conservation check, and the
// conservation check is what proves no file was dropped without explanation.
type Counters struct {
	// FilesSeen counts every regular file the walk reached a decision about.
	FilesSeen int
	// DirsVisited counts directories descended into.
	DirsVisited int
	// BytesRead is the total number of file bytes actually read.
	BytesRead int64

	// Dispositions is the per-file outcome, one entry per file seen.
	Dispositions map[Classification]int

	// PrivateKeyBlocksSkipped counts PEM blocks labelled as private keys that
	// were skipped WITHOUT their bodies being buffered (INV-2). It is a block
	// counter, not a file counter.
	PrivateKeyBlocksSkipped int
	// UnknownPEMBlocksSkipped counts PEM blocks that were neither a certificate
	// nor a private key.
	UnknownPEMBlocksSkipped int
	// CertificatesReturned is the number of certificate DER blocks returned.
	CertificatesReturned int

	// Truncated records that the walk stopped early because a budget was hit.
	Truncated    bool
	TruncatedWhy string
	TimedOut     bool
}

func newCounters() *Counters {
	return &Counters{Dispositions: make(map[Classification]int)}
}

func (c *Counters) record(class Classification) {
	if c.Dispositions == nil {
		c.Dispositions = make(map[Classification]int)
	}
	c.Dispositions[class]++
	c.FilesSeen++
}

// TotalSkips is the number the security canary asserts against. It counts every
// file-level skip PLUS every private-key block skipped inside a file that was
// otherwise read.
//
// A mixed PEM bundle therefore contributes 1 here (its key block) while also
// contributing a certificate result — which is exactly right: the protection
// path was exercised, and the scanner still worked.
func (c *Counters) TotalSkips() int {
	n := c.PrivateKeyBlocksSkipped
	for class, count := range c.Dispositions {
		if !class.IsCertificate() {
			n += count
		}
	}
	return n
}

// SkipMultiset returns skip classes to counts, merging the block-level
// private-key counter into SkippedPrivateKeyBlock. This is the shape the canary
// compares against an expected multiset.
func (c *Counters) SkipMultiset() map[Classification]int {
	out := make(map[Classification]int)
	for class, count := range c.Dispositions {
		if !class.IsCertificate() {
			out[class] += count
		}
	}
	if c.PrivateKeyBlocksSkipped > 0 {
		out[SkippedPrivateKeyBlock] += c.PrivateKeyBlocksSkipped
	}
	return out
}

// Conserved reports whether FilesSeen reconciles with the file dispositions.
// A false result means a file was decided about without being counted, which is
// a bug in safeio, not in the filesystem.
func (c *Counters) Conserved() (bool, string) {
	sum := 0
	for _, n := range c.Dispositions {
		sum += n
	}
	if sum != c.FilesSeen {
		return false, fmt.Sprintf("FilesSeen=%d but dispositions sum to %d", c.FilesSeen, sum)
	}
	return true, ""
}

// Summary renders the plain-English skip breakdown. Every non-zero skip class is
// named. This is printed by the CLI so a user can see what was not looked at.
func (c *Counters) Summary() []string {
	type row struct {
		class Classification
		n     int
	}
	var rows []row
	for class, n := range c.Dispositions {
		if n > 0 && !class.IsCertificate() {
			rows = append(rows, row{class, n})
		}
	}
	if c.PrivateKeyBlocksSkipped > 0 {
		rows = append(rows, row{SkippedPrivateKeyBlock, c.PrivateKeyBlocksSkipped})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].class < rows[j].class
	})
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%6d  %s", r.n, r.class.Human()))
	}
	return out
}

func (c *Counters) merge(other *Counters) {
	c.FilesSeen += other.FilesSeen
	c.DirsVisited += other.DirsVisited
	c.BytesRead += other.BytesRead
	c.PrivateKeyBlocksSkipped += other.PrivateKeyBlocksSkipped
	c.UnknownPEMBlocksSkipped += other.UnknownPEMBlocksSkipped
	c.CertificatesReturned += other.CertificatesReturned
	if other.Truncated {
		c.Truncated = true
		c.TruncatedWhy = other.TruncatedWhy
	}
	if other.TimedOut {
		c.TimedOut = true
	}
	if c.Dispositions == nil {
		c.Dispositions = make(map[Classification]int)
	}
	for class, n := range other.Dispositions {
		c.Dispositions[class] += n
	}
}
