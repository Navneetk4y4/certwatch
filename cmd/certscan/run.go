package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/safeio"
	"github.com/certwatch/certwatch/pkg/safelog"
	"github.com/certwatch/certwatch/pkg/scan"
	"github.com/certwatch/certwatch/pkg/x509norm"
)

const schemaVersion = 1

func run(ctx context.Context, opt options, log *safelog.Logger) error {
	started := time.Now()

	plan, err := buildPlan(opt)
	if err != nil {
		return err
	}
	if plan.empty() {
		return fmt.Errorf("nothing to scan: give --cidr, --hosts, --hosts-file, --dirs or --scope (see --help)")
	}

	rep := &model.Report{
		SchemaVersion:    schemaVersion,
		Tool:             "certscan",
		ToolVersion:      Version,
		StartedAt:        started.UTC(),
		EnvironmentLabel: opt.label,
		Scope: model.ReportScope{
			CIDRs: plan.cidrStrings(), Hostnames: plan.hostnames, Ports: plan.ports,
			Directories: plan.dirs, DryRun: opt.dryRun, Offline: !opt.checkPublic,
			RatePerSec: plan.policy.RatePerSecond, Concurrency: plan.policy.Concurrency,
			ScopeDigest: plan.scopeDigest,
		},
		Summary: model.ReportSummary{
			ByIssuer: map[string]int{}, ByKeyAlgorithm: map[string]int{},
			ByTLSVersion: map[string]int{}, ByParseStatus: map[string]int{},
		},
	}

	agg := newAggregator()

	// ---- filesystem ----
	if len(plan.dirs) > 0 {
		if err := scanDirectories(ctx, plan, agg, rep, log); err != nil {
			return err
		}
	}

	// ---- network ----
	targets, resolveNotes := plan.expandTargets(ctx, log)
	rep.Notes = append(rep.Notes, resolveNotes...)
	rep.Coverage.TargetsRequested = len(targets)

	if opt.dryRun {
		printDryRun(targets, plan)
		rep.Coverage.Caveats = append(rep.Coverage.Caveats,
			"DRY RUN: no packets were sent and no endpoint was contacted.")
	}

	if len(targets) > 0 {
		log.Info("network scan starting",
			safelog.Int("targets", len(targets)),
			safelog.Int("rate_per_second", plan.policy.RatePerSecond),
			safelog.Bool("dry_run", opt.dryRun))

		res := scan.Sweep(ctx, targets, plan.policy)
		rep.Coverage.TargetsAttempted = res.Attempted
		rep.Coverage.TargetsSkipped = res.Skipped
		rep.Coverage.TargetsUnreachable = res.Failed
		rep.Coverage.NotAttempted = len(res.Resume)
		rep.Coverage.DeadlineHit = res.DeadlineHit

		if res.DeadlineHit {
			rep.Coverage.Caveats = append(rep.Coverage.Caveats, fmt.Sprintf(
				"INCOMPLETE: the run hit its deadline with %d of %d targets not attempted. "+
					"This report does NOT cover the whole range you asked for.",
				len(res.Resume), len(targets)))
		}
		for _, pr := range res.Probes {
			agg.addProbe(ctx, pr, opt.checkPublic)
		}
	}

	agg.finalise(rep)
	rep.FinishedAt = time.Now().UTC()
	rep.DurationSec = rep.FinishedAt.Sub(rep.StartedAt).Seconds()

	if err := writeReport(rep, opt); err != nil {
		return err
	}
	printHumanSummary(rep, opt)
	return nil
}

// ---- plan ----

type plan struct {
	cidrs       []netip.Prefix
	hostnames   []string
	dirs        []string
	ports       []int
	policy      scan.Policy
	scopeDigest string
}

func (p *plan) empty() bool {
	return len(p.cidrs) == 0 && len(p.hostnames) == 0 && len(p.dirs) == 0
}

func (p *plan) cidrStrings() []string {
	out := make([]string, 0, len(p.cidrs))
	for _, c := range p.cidrs {
		out = append(out, c.String())
	}
	return out
}

func buildPlan(opt options) (*plan, error) {
	p := &plan{policy: scan.Policy{
		RatePerSecond: opt.rate, Concurrency: opt.concurrency,
		DryRun: opt.dryRun, Offline: !opt.checkPublic,
	}}

	if opt.scopeFile != "" {
		if err := p.loadScope(opt.scopeFile); err != nil {
			return nil, err
		}
	}
	for _, c := range splitList(opt.cidrs) {
		pre, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("--cidr %q is not a CIDR range: %w", c, err)
		}
		p.cidrs = append(p.cidrs, pre.Masked())
	}
	p.hostnames = append(p.hostnames, splitList(opt.hosts)...)
	if opt.hostsFile != "" {
		hs, err := readHostsFile(opt.hostsFile)
		if err != nil {
			return nil, err
		}
		p.hostnames = append(p.hostnames, hs...)
	}
	for _, d := range splitList(opt.dirs) {
		abs, err := absDir(d)
		if err != nil {
			return nil, err
		}
		p.dirs = append(p.dirs, abs)
	}
	for _, s := range splitList(opt.ports) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--ports %q is not a valid port", s)
		}
		p.ports = append(p.ports, n)
	}
	if len(p.ports) == 0 {
		p.ports = []int{443, 8443, 9443, 636, 993, 995, 5671, 8883}
	}
	sort.Ints(p.ports)
	p.hostnames = dedupe(p.hostnames)

	// Apply defaults HERE, not only inside Sweep, so the values the report and
	// the log record are the values actually used. A report that says
	// "rate_limit_per_second: 0" is a report nobody can reproduce from.
	if p.policy.RatePerSecond <= 0 {
		p.policy.RatePerSecond = 50
	}
	if p.policy.Concurrency <= 0 {
		p.policy.Concurrency = 20
	}
	if p.policy.RatePerSecond > 500 {
		return nil, fmt.Errorf("--rate %d exceeds the maximum of 500 handshakes per second", p.policy.RatePerSecond)
	}
	if p.policy.Concurrency > 500 {
		return nil, fmt.Errorf("--concurrency %d exceeds the maximum of 500", p.policy.Concurrency)
	}
	sort.Ints(p.ports)
	return p, nil
}

// expandTargets turns CIDRs and hostnames into concrete targets.
//
// Resolution failures and refusals are collected as NOTES, not silently
// dropped: a hostname that could not be checked is a coverage gap the reader
// must see.
func (p *plan) expandTargets(ctx context.Context, log *safelog.Logger) ([]scan.Target, []string) {
	var targets []scan.Target
	var notes []string
	resolver := &scan.SystemResolver{}

	for _, c := range p.cidrs {
		addrs, err := scan.ExpandCIDR(c)
		if err != nil {
			notes = append(notes, fmt.Sprintf("range %s was not scanned: %v", c, err))
			log.Warn("range refused", safelog.Str("cidr", c.String()), safelog.Err(err))
			continue
		}
		for _, a := range addrs {
			if blocked, _ := scan.AddrBlocked(a); blocked {
				continue
			}
			for _, port := range p.ports {
				targets = append(targets, scan.Target{Addr: a, Port: port})
			}
		}
	}

	for _, h := range p.hostnames {
		addrs, err := scan.ResolveAll(ctx, resolver, h)
		if err != nil {
			notes = append(notes, fmt.Sprintf("hostname %s was not checked: %v", h, err))
			log.Warn("hostname refused or unresolvable", safelog.Str("host", h), safelog.Err(err))
			continue
		}
		for _, a := range addrs {
			for _, port := range p.ports {
				targets = append(targets, scan.Target{Addr: a, Port: port, SNI: h, Hostname: h})
			}
		}
	}
	return targets, notes
}

func (p *plan) loadScope(path string) error {
	abs, err := absPath(path)
	if err != nil {
		return err
	}
	// Read via safeio so file access stays inside the boundary.
	raw, err := safeio.ReadConfigFile(abs)
	if err != nil {
		return fmt.Errorf("reading scope file: %w", err)
	}
	// certscan deliberately does not import internal/scopecfg (CI-009 forbids
	// it: the open-source scanner depends on pkg/ only). It accepts the same
	// document shape via a local minimal reader.
	sc, err := parseScopeDocument(raw)
	if err != nil {
		return err
	}
	p.cidrs = append(p.cidrs, sc.cidrs...)
	p.dirs = append(p.dirs, sc.dirs...)
	if len(sc.ports) > 0 {
		p.ports = append(p.ports, sc.ports...)
	}
	if sc.rate > 0 && p.policy.RatePerSecond == 0 {
		p.policy.RatePerSecond = sc.rate
	}
	if sc.concurrency > 0 && p.policy.Concurrency == 0 {
		p.policy.Concurrency = sc.concurrency
	}
	p.scopeDigest = safeio.Digest(raw)
	return nil
}

// ---- filesystem scan ----

func scanDirectories(ctx context.Context, p *plan, agg *aggregator, rep *model.Report, log *safelog.Logger) error {
	pol, err := safeio.NewPolicy(p.dirs, safeio.PolicyOptions{})
	if err != nil {
		return fmt.Errorf("certificate directories: %w", err)
	}
	for _, root := range pol.Roots() {
		log.Info("reading certificate directory", safelog.Path("dir", root))
		results, counters, err := safeio.ReadCertificatesOnly(ctx, root, pol)
		if err != nil {
			return fmt.Errorf("reading %s: %w", root, err)
		}
		if counters.Truncated {
			rep.Coverage.FilesystemTruncated = true
			rep.Coverage.Caveats = append(rep.Coverage.Caveats,
				fmt.Sprintf("INCOMPLETE: the walk of %s stopped early (%s). Not every file was examined.",
					root, counters.TruncatedWhy))
		}
		for _, r := range results {
			if !r.Class.IsCertificate() {
				continue
			}
			for _, der := range r.CertificateDER {
				cert, _ := x509norm.ParseDER(der)
				agg.addCertificate(cert, r.Path, "filesystem", nil)
			}
		}
		agg.addSkips(counters)
	}
	return nil
}

// ---- output ----

func writeReport(rep *model.Report, opt options) error {
	var payload []byte
	var err error
	switch opt.format {
	case "json", "":
		payload, err = json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		payload = append(payload, '\n')
	case "csv":
		payload = renderCSV(rep)
	default:
		return fmt.Errorf("--format %q is not supported (want json or csv)", opt.format)
	}

	if opt.out == "" {
		_, err := os.Stdout.Write(payload)
		return err
	}
	// The report is program OUTPUT to a path the user named. It is written
	// directly rather than through safeio, which reads and never writes.
	f, err := os.Create(opt.out) //nolint:gosec // user-specified output path
	if err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(payload); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}

func printDryRun(targets []scan.Target, p *plan) {
	fmt.Fprintf(os.Stderr, "\nDRY RUN — no packets will be sent.\n\n")
	fmt.Fprintf(os.Stderr, "  %d targets across %d port(s): %v\n", len(targets), len(p.ports), p.ports)
	limit := 20
	for i, t := range targets {
		if i >= limit {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(targets)-limit)
			break
		}
		fmt.Fprintf(os.Stderr, "  %s\n", t)
	}
	fmt.Fprintf(os.Stderr, "\nRe-run without --dry-run to scan.\n\n")
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(s)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}
