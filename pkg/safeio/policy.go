package safeio

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Default policy limits. Every one of these exists to bound a specific failure:
// a pathological tree, a hung NFS mount, a 4 GB file, a fork bomb of symlinks.
const (
	DefaultMaxDepth      = 8
	DefaultMaxFiles      = 10_000
	DefaultMaxFileBytes  = 1 << 20  // 1 MiB. A certificate is kilobytes.
	DefaultMaxTotalBytes = 64 << 20 // 64 MiB per scan task.
	DefaultTimeout       = 30 * time.Second
	// maxPEMLine bounds a single line read so a 1 GB line cannot exhaust memory.
	maxPEMLine = 64 << 10
)

// allowedExtensions is the allowlist. A file whose extension is not here is
// never opened. Matching is case-insensitive.
var allowedExtensions = map[string]bool{
	".pem": true,
	".crt": true,
	".cer": true,
	".der": true,
}

// deniedExtensions is redundant with the allowlist and kept deliberately:
// defence in depth, and it documents intent to a reader who is checking whether
// keystores can ever be opened. They cannot. See decision_register.md D3/C3.
var deniedExtensions = map[string]bool{
	".key":      true,
	".p12":      true,
	".pfx":      true,
	".jks":      true,
	".keystore": true,
	".bks":      true,
	".jceks":    true,
	".p8":       true,
	".pk8":      true,
}

// refusedPrefixes are refused by path before any stat or open. Reading from
// these can block indefinitely or expose process memory.
var refusedPrefixes = []string{"/proc", "/sys", "/dev"}

// Policy is immutable after construction. There is deliberately no exported
// mutator: the set of readable roots is fixed when the policy is built and is
// derived only from the customer-authored scope file.
type Policy struct {
	roots         []string // canonicalised, absolute, symlinks already resolved
	maxDepth      int
	maxFiles      int
	maxFileBytes  int64
	maxTotalBytes int64
	timeout       time.Duration
}

// PolicyOptions are the tunable limits. Zero values take the package defaults.
type PolicyOptions struct {
	MaxDepth      int
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
	Timeout       time.Duration
}

// NewPolicy canonicalises the given roots and returns an immutable Policy.
//
// A root that is relative, non-existent, unreadable, or under a refused prefix
// is a construction error, not a runtime skip: the caller must know at startup
// that its declared scope is unusable rather than discovering it as a silent
// gap in coverage later.
func NewPolicy(roots []string, opt PolicyOptions) (*Policy, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("safeio: at least one root is required")
	}
	p := &Policy{
		maxDepth:      firstPositive(opt.MaxDepth, DefaultMaxDepth),
		maxFiles:      firstPositive(opt.MaxFiles, DefaultMaxFiles),
		maxFileBytes:  firstPositive64(opt.MaxFileBytes, DefaultMaxFileBytes),
		maxTotalBytes: firstPositive64(opt.MaxTotalBytes, DefaultMaxTotalBytes),
		timeout:       opt.Timeout,
	}
	if p.timeout <= 0 {
		p.timeout = DefaultTimeout
	}
	seen := make(map[string]bool, len(roots))
	for _, r := range roots {
		if !filepath.IsAbs(r) {
			return nil, fmt.Errorf("safeio: root %q is not absolute", r)
		}
		if isRefusedPath(r) {
			return nil, fmt.Errorf("safeio: root %q is under a refused prefix (/proc, /sys, /dev)", r)
		}
		// EvalSymlinks once, at construction. From here on the resolved path is
		// the root, so a root that is itself a symlink is handled correctly and
		// every later containment check is against a real path.
		resolved, err := filepath.EvalSymlinks(r)
		if err != nil {
			return nil, fmt.Errorf("safeio: root %q cannot be resolved: %w", r, err)
		}
		resolved = filepath.Clean(resolved)
		if isRefusedPath(resolved) {
			return nil, fmt.Errorf("safeio: root %q resolves to %q which is under a refused prefix", r, resolved)
		}
		if !seen[resolved] {
			seen[resolved] = true
			p.roots = append(p.roots, resolved)
		}
	}
	return p, nil
}

// Roots returns a copy. Callers cannot widen the policy by mutating the slice.
func (p *Policy) Roots() []string {
	out := make([]string, len(p.roots))
	copy(out, p.roots)
	return out
}

func (p *Policy) MaxDepth() int          { return p.maxDepth }
func (p *Policy) MaxFiles() int          { return p.maxFiles }
func (p *Policy) MaxFileBytes() int64    { return p.maxFileBytes }
func (p *Policy) MaxTotalBytes() int64   { return p.maxTotalBytes }
func (p *Policy) Timeout() time.Duration { return p.timeout }

// Contains reports whether candidate lies at or below root. It is the
// containment check the walk relies on; a candidate that escapes via ".."
// is rejected.
func Contains(root, candidate string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isRefusedPath(path string) bool {
	clean := filepath.Clean(path)
	for _, pre := range refusedPrefixes {
		if clean == pre || strings.HasPrefix(clean, pre+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// extensionDecision reports whether a file may be opened based on its final
// extension alone. It runs BEFORE open(2): a .p12 is rejected without a single
// byte of it being read.
func extensionDecision(name string) (allowed bool, reason string) {
	ext := strings.ToLower(filepath.Ext(name))
	if deniedExtensions[ext] {
		return false, "extension " + ext + " is explicitly denied (keystore or private-key format)"
	}
	if !allowedExtensions[ext] {
		if ext == "" {
			return false, "no extension; only .pem .crt .cer .der are opened"
		}
		return false, "extension " + ext + " is not in the allowlist (.pem .crt .cer .der)"
	}
	return true, ""
}

func firstPositive(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func firstPositive64(v, def int64) int64 {
	if v > 0 {
		return v
	}
	return def
}
