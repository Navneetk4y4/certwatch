package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/safeio"
	"github.com/certwatch/certwatch/pkg/scan"
)

// aggregator deduplicates certificates by fingerprint and builds the summary
// counts that the validation programme turns on.
type aggregator struct {
	certs      map[string]*model.ReportCertificate
	endpoints  []model.ReportEndpoint
	skips      map[string]*model.ReportSkip
	violations []string

	// byHostCert tracks, per hostname, the distinct leaf fingerprints seen
	// across its resolved IPs. A hostname with more than one is an IP
	// disagreement — the earliest available evidence that live verification
	// would find something, and therefore the first signal on the retention risk.
	byHostCert map[string]map[string]bool
	now        time.Time
}

func newAggregator() *aggregator {
	return &aggregator{
		certs:      map[string]*model.ReportCertificate{},
		skips:      map[string]*model.ReportSkip{},
		byHostCert: map[string]map[string]bool{},
		now:        time.Now().UTC(),
	}
}

func (a *aggregator) addCertificate(c *model.Certificate, seenAt, source string, resolvable *bool) {
	if c == nil || c.Fingerprint == "" {
		return
	}
	e, ok := a.certs[c.Fingerprint]
	if !ok {
		e = &model.ReportCertificate{Certificate: c, Resolvability: resolvable}
		a.certs[c.Fingerprint] = e
	}
	if !containsStr(e.SeenAt, seenAt) {
		e.SeenAt = append(e.SeenAt, seenAt)
	}
	if !containsStr(e.Sources, source) {
		e.Sources = append(e.Sources, source)
	}
	// Once any observation of a certificate is publicly resolvable, the
	// certificate is. Unknown never overwrites a definite answer.
	if resolvable != nil && (e.Resolvability == nil || (*resolvable && !*e.Resolvability)) {
		e.Resolvability = resolvable
	}
}

func (a *aggregator) addProbe(ctx context.Context, pr scan.Probe, checkPublic bool) {
	ep := model.ReportEndpoint{
		Hostname: pr.Target.Hostname,
		Address:  pr.Target.Addr.String(),
		Port:     pr.Target.Port,
		SNISent:  pr.SNISent,
	}
	switch {
	case pr.Skipped:
		ep.Error = "skipped: " + pr.SkipReason
	case pr.ConnectErr != "":
		ep.Error = pr.ConnectErr
	case pr.HandshakeErr != "" && (pr.Chain == nil || pr.Chain.Leaf == nil):
		ep.Error = pr.HandshakeErr
	}

	if pr.Chain != nil && pr.Chain.Leaf != nil {
		ep.TLSVersion = pr.TLSVersion
		ep.CipherSuite = pr.CipherSuite
		ep.LeafFingerprint = pr.Chain.Leaf.Fingerprint
		ep.ChainLength = 1 + len(pr.Chain.Intermediates)
		if pr.HandshakeErr != "" {
			// An mTLS endpoint that rejected us still told us what it serves.
			ep.Error = "handshake incomplete (certificate still captured): " + pr.HandshakeErr
		}

		res := scan.PubliclyResolvable(ctx, pr.Target.Addr, pr.Target.Hostname, !checkPublic)
		seenAt := fmt.Sprintf("%s:%d", pr.Target.Addr, pr.Target.Port)
		a.addCertificate(pr.Chain.Leaf, seenAt, "network", res.JSON())
		for _, ic := range pr.Chain.Intermediates {
			a.addCertificate(ic, seenAt, "network-chain", nil)
		}

		if h := pr.Target.Hostname; h != "" {
			if a.byHostCert[h] == nil {
				a.byHostCert[h] = map[string]bool{}
			}
			a.byHostCert[h][pr.Chain.Leaf.Fingerprint] = true
		}
	}
	a.endpoints = append(a.endpoints, ep)
}

func (a *aggregator) addSkips(c *safeio.Counters) {
	for class, n := range c.SkipMultiset() {
		k := class.String()
		if a.skips[k] == nil {
			a.skips[k] = &model.ReportSkip{Class: k, Reason: class.Human()}
		}
		a.skips[k].Count += n
	}
}

func (a *aggregator) finalise(rep *model.Report) {
	for _, e := range a.certs {
		rep.Certificates = append(rep.Certificates, *e)
	}
	sort.Slice(rep.Certificates, func(i, j int) bool {
		return rep.Certificates[i].Certificate.NotAfter.Before(rep.Certificates[j].Certificate.NotAfter)
	})
	for _, s := range a.skips {
		rep.Skips = append(rep.Skips, *s)
	}
	sort.Slice(rep.Skips, func(i, j int) bool { return rep.Skips[i].Count > rep.Skips[j].Count })
	rep.Endpoints = a.endpoints
	rep.Violations = a.violations

	s := &rep.Summary
	s.UniqueCertificates = len(a.certs)
	for _, e := range a.certs {
		c := e.Certificate
		s.TotalObservations += len(e.SeenAt)

		switch {
		case e.Resolvability == nil:
			s.ResolvabilityUnknown++
		case *e.Resolvability:
			s.PubliclyResolvable++
		default:
			s.NotPubliclyResolvable++
		}

		d := c.DaysRemaining(a.now)
		switch {
		case c.Expired(a.now):
			s.AlreadyExpired++
		case d <= 7:
			s.ExpiringWithin7Days++
			s.ExpiringWithin30Days++
			s.ExpiringWithin60Days++
		case d <= 30:
			s.ExpiringWithin30Days++
			s.ExpiringWithin60Days++
		case d <= 60:
			s.ExpiringWithin60Days++
		}
		if c.NotYetValid(a.now) {
			s.NotYetValid++
		}
		if c.IsSelfSigned {
			s.SelfSigned++
		}
		issuer := c.IssuerDN
		if issuer == "" {
			issuer = "(unknown issuer)"
		}
		s.ByIssuer[issuer]++
		s.ByKeyAlgorithm[string(c.KeyAlgorithm)]++
		s.ByParseStatus[string(c.ParseStatus)]++
	}
	for _, ep := range rep.Endpoints {
		if ep.TLSVersion != "" {
			s.ByTLSVersion[ep.TLSVersion]++
		}
		if ep.LeafFingerprint != "" {
			s.EndpointsResponding++
		}
	}
	for _, fps := range a.byHostCert {
		if len(fps) > 1 {
			s.IPDisagreements++
		}
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// printHumanSummary is what a prospect actually reads in the ten minutes they
// gave you. Every number here is one the validation programme needs.
func printHumanSummary(rep *model.Report, opt options) {
	w := os.Stderr
	s := rep.Summary
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  certscan %s — %s\n", rep.ToolVersion, rep.FinishedAt.Format(time.RFC3339))
	if rep.EnvironmentLabel != "" {
		fmt.Fprintf(w, "  environment: %s\n", rep.EnvironmentLabel)
	}
	fmt.Fprintf(w, "  %.1fs elapsed\n\n", rep.DurationSec)

	fmt.Fprintf(w, "  %-34s %d\n", "unique certificates found", s.UniqueCertificates)
	fmt.Fprintf(w, "  %-34s %d\n", "endpoints responding", s.EndpointsResponding)
	fmt.Fprintf(w, "\n  reachability from the internet\n")
	fmt.Fprintf(w, "  %-34s %d\n", "not publicly resolvable", s.NotPubliclyResolvable)
	fmt.Fprintf(w, "  %-34s %d\n", "publicly resolvable", s.PubliclyResolvable)
	if s.ResolvabilityUnknown > 0 {
		fmt.Fprintf(w, "  %-34s %d   (not checked)\n", "unknown", s.ResolvabilityUnknown)
	}
	fmt.Fprintf(w, "\n  expiry\n")
	fmt.Fprintf(w, "  %-34s %d\n", "already expired", s.AlreadyExpired)
	fmt.Fprintf(w, "  %-34s %d\n", "expiring within 7 days", s.ExpiringWithin7Days)
	fmt.Fprintf(w, "  %-34s %d\n", "expiring within 30 days", s.ExpiringWithin30Days)
	fmt.Fprintf(w, "  %-34s %d\n", "expiring within 60 days", s.ExpiringWithin60Days)

	if s.IPDisagreements > 0 {
		fmt.Fprintf(w, "\n  ** %d hostname(s) served DIFFERENT certificates on different IPs **\n", s.IPDisagreements)
		fmt.Fprintf(w, "     This usually means a deploy updated some load-balancer members and not others.\n")
	}

	if len(rep.Skips) > 0 {
		fmt.Fprintf(w, "\n  files not read\n")
		for _, sk := range rep.Skips {
			fmt.Fprintf(w, "  %6d  %s\n", sk.Count, sk.Reason)
		}
	}
	if len(rep.Coverage.Caveats) > 0 || len(rep.Notes) > 0 {
		fmt.Fprintf(w, "\n  COVERAGE\n")
		for _, c := range rep.Coverage.Caveats {
			fmt.Fprintf(w, "  ! %s\n", c)
		}
		for _, n := range rep.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
	if opt.out != "" {
		fmt.Fprintf(w, "\n  full report written to %s\n", opt.out)
	}
	fmt.Fprintf(w, "\n  This tool sent nothing anywhere. The report is on your disk only.\n\n")
}

func renderCSV(rep *model.Report) []byte {
	var b strings.Builder
	b.WriteString("sha256,subject_cn,issuer_dn,not_before,not_after,days_remaining," +
		"key_algorithm,key_size,signature_algorithm,parse_status,publicly_resolvable,sans,seen_at\n")
	now := time.Now().UTC()
	for _, e := range rep.Certificates {
		c := e.Certificate
		size := ""
		if c.KeySize != nil {
			size = fmt.Sprintf("%d", *c.KeySize)
		}
		resolvable := "unknown"
		if e.Resolvability != nil {
			resolvable = fmt.Sprintf("%t", *e.Resolvability)
		}
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%s,%s\n",
			c.Fingerprint, csvQuote(c.SubjectCN), csvQuote(c.IssuerDN),
			c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339),
			c.DaysRemaining(now), c.KeyAlgorithm, size, csvQuote(c.SignatureAlgorithm),
			c.ParseStatus, resolvable,
			csvQuote(strings.Join(c.SANs, " ")), csvQuote(strings.Join(e.SeenAt, " ")))
	}
	return []byte(b.String())
}

func csvQuote(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
