// Package scopecfg loads and enforces scope.yaml — the customer-authored,
// AUTHORITATIVE definition of what the collector may touch.
//
// # Why this package is load-bearing
//
// A scanner designed to reach hosts that nothing else can reach, running inside
// hundreds of customer networks and calling home to one SaaS, is architecturally
// a distributed internal-scanning botnet with a business model. The answer to
// that is not a promise; it is this file.
//
// Every task the control plane sends is intersected with the local scope before
// execution. The control plane may NARROW scope; it can never widen it. There is
// no message the server can send that causes the collector to touch something
// the customer did not declare.
//
// A reviewer should be able to satisfy themselves by reading one function:
// Scope.Intersect.
//
// See project_1_security_model.md §1 control 2, and threat T2.
package scopecfg

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/certwatch/certwatch/pkg/safeio"
)

// Defaults chosen so that an unconfigured field is safe rather than permissive.
const (
	DefaultRatePerSecond = 50
	DefaultConcurrency   = 20
	MaxRatePerSecond     = 500
	MaxConcurrency       = 500
	MaxPorts             = 64
	MaxCIDRs             = 512
	MaxDirectories       = 64
)

// DefaultPorts are scanned when the file names none. Direct-TLS ports only:
// STARTTLS is a V1+ item and is deliberately not attempted.
var DefaultPorts = []int{443, 8443, 9443, 636, 993, 995, 5671, 8883}

// file is the on-disk shape. It is separate from Scope so that parsing and
// validation are distinct steps and a malformed file cannot produce a
// half-constructed Scope.
type file struct {
	Version                int      `yaml:"version"`
	CIDRs                  []string `yaml:"cidrs"`
	ExcludeCIDRs           []string `yaml:"exclude_cidrs"`
	ExcludeHosts           []string `yaml:"exclude_hosts"`
	Ports                  []int    `yaml:"ports"`
	CertificateDirectories []string `yaml:"certificate_directories"`
	RatePerSecond          int      `yaml:"rate_limit_per_second"`
	MaxConcurrency         int      `yaml:"max_concurrency"`
}

// Scope is immutable after Load. Nothing widens it at runtime.
type Scope struct {
	cidrs         []netip.Prefix
	excludeCIDRs  []netip.Prefix
	excludeHosts  []netip.Addr
	ports         []int
	directories   []string
	ratePerSecond int
	concurrency   int
	digest        string
}

// Load reads and validates scope.yaml.
//
// The file is read through safeio, which keeps "safeio is the only code that
// opens a file" literally true and applies the same symlink and size limits the
// certificate walk uses.
func Load(path string) (*Scope, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("scopecfg: %w", err)
	}
	raw, err := safeio.ReadConfigFile(abs)
	if err != nil {
		return nil, fmt.Errorf("scopecfg: %w", err)
	}
	return Parse(raw)
}

// Parse validates an in-memory scope document.
func Parse(raw []byte) (*Scope, error) {
	var f file
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	// Unknown fields are an ERROR, not a warning. A customer who misspells
	// `exclude_cidrs` must be told, not silently scanned outside their intent.
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("scopecfg: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("scopecfg: unsupported version %d (want 1)", f.Version)
	}

	s := &Scope{
		ratePerSecond: f.RatePerSecond,
		concurrency:   f.MaxConcurrency,
		digest:        safeio.Digest(raw),
	}

	if len(f.CIDRs) > MaxCIDRs {
		return nil, fmt.Errorf("scopecfg: %d cidrs, over the limit of %d", len(f.CIDRs), MaxCIDRs)
	}
	for _, c := range f.CIDRs {
		p, err := parsePrefix(c)
		if err != nil {
			return nil, err
		}
		s.cidrs = append(s.cidrs, p)
	}
	for _, c := range f.ExcludeCIDRs {
		p, err := parsePrefix(c)
		if err != nil {
			return nil, err
		}
		s.excludeCIDRs = append(s.excludeCIDRs, p)
	}
	for _, h := range f.ExcludeHosts {
		a, err := netip.ParseAddr(strings.TrimSpace(h))
		if err != nil {
			return nil, fmt.Errorf("scopecfg: exclude_hosts entry %q is not an IP address: %w", h, err)
		}
		s.excludeHosts = append(s.excludeHosts, a.Unmap())
	}

	s.ports = f.Ports
	if len(s.ports) == 0 {
		s.ports = append([]int(nil), DefaultPorts...)
	}
	if len(s.ports) > MaxPorts {
		return nil, fmt.Errorf("scopecfg: %d ports, over the limit of %d", len(s.ports), MaxPorts)
	}
	for _, p := range s.ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("scopecfg: port %d out of range", p)
		}
	}
	sort.Ints(s.ports)

	if len(f.CertificateDirectories) > MaxDirectories {
		return nil, fmt.Errorf("scopecfg: %d certificate_directories, over the limit of %d",
			len(f.CertificateDirectories), MaxDirectories)
	}
	for _, d := range f.CertificateDirectories {
		clean, err := validateDirectory(d)
		if err != nil {
			return nil, err
		}
		s.directories = append(s.directories, clean)
	}

	if s.ratePerSecond == 0 {
		s.ratePerSecond = DefaultRatePerSecond
	}
	if s.ratePerSecond < 1 || s.ratePerSecond > MaxRatePerSecond {
		return nil, fmt.Errorf("scopecfg: rate_limit_per_second %d out of range 1..%d",
			s.ratePerSecond, MaxRatePerSecond)
	}
	if s.concurrency == 0 {
		s.concurrency = DefaultConcurrency
	}
	if s.concurrency < 1 || s.concurrency > MaxConcurrency {
		return nil, fmt.Errorf("scopecfg: max_concurrency %d out of range 1..%d",
			s.concurrency, MaxConcurrency)
	}

	if len(s.cidrs) == 0 && len(s.directories) == 0 {
		return nil, fmt.Errorf("scopecfg: scope declares neither cidrs nor certificate_directories; " +
			"there is nothing this collector is permitted to do")
	}
	return s, nil
}

// validateDirectory rejects anything that is not an unambiguous absolute path.
//
// A relative path, a traversal sequence, or a NUL byte in a security-relevant
// config is either a mistake or an attack, and both deserve an error rather
// than a best-effort interpretation.
func validateDirectory(d string) (string, error) {
	if strings.ContainsRune(d, 0) {
		return "", fmt.Errorf("scopecfg: certificate directory contains a NUL byte")
	}
	if !filepath.IsAbs(d) {
		return "", fmt.Errorf("scopecfg: certificate directory %q is not absolute", d)
	}
	clean := filepath.Clean(d)
	if strings.Contains(d, "..") {
		return "", fmt.Errorf("scopecfg: certificate directory %q contains a traversal sequence", d)
	}
	for _, p := range []string{"/proc", "/sys", "/dev"} {
		if clean == p || strings.HasPrefix(clean, p+"/") {
			return "", fmt.Errorf("scopecfg: certificate directory %q is under a refused prefix", d)
		}
	}
	return clean, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("scopecfg: %q is not a CIDR: %w", s, err)
	}
	return p.Masked(), nil
}

// ---- accessors; all return copies so nothing can widen the scope ----

func (s *Scope) Ports() []int {
	out := make([]int, len(s.ports))
	copy(out, s.ports)
	return out
}

func (s *Scope) Directories() []string {
	out := make([]string, len(s.directories))
	copy(out, s.directories)
	return out
}

func (s *Scope) CIDRs() []netip.Prefix {
	out := make([]netip.Prefix, len(s.cidrs))
	copy(out, s.cidrs)
	return out
}

func (s *Scope) RatePerSecond() int { return s.ratePerSecond }
func (s *Scope) Concurrency() int   { return s.concurrency }

// Digest is the SHA-256 of the scope file as loaded. The control plane records
// it, and a change is an audit event — so a customer can see that the scope
// their collector is enforcing is the scope they wrote.
func (s *Scope) Digest() string { return s.digest }
