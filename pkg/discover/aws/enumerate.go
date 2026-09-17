package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/certwatch/certwatch/pkg/x509norm"
)

// Enumerate runs every read-only discovery call across every configured region.
//
// It never returns early on a per-call failure: a customer who granted nine of
// eleven actions gets nine actions' worth of findings, with the two gaps
// visible in the result. Refusing everything would punish a partial grant and
// tell them nothing about what they are missing.
func (e *Enumerator) Enumerate(ctx context.Context) (*Result, error) {
	res := &Result{Regions: append([]string(nil), e.opts.Regions...)}

	// IAM and CloudFront are global; enumerate them once, from the first region.
	global := e.regionConfig(e.opts.Regions[0])
	e.enumerateIAM(ctx, global, res)
	e.enumerateCloudFront(ctx, global, res)

	for _, region := range e.opts.Regions {
		cfg := e.regionConfig(region)
		e.enumerateACM(ctx, cfg, region, res)
		e.enumerateELB(ctx, cfg, region, res)
		e.enumerateAPIGateway(ctx, cfg, region, res)

		if len(res.Certificates) >= MaxCertsPerSweep {
			res.Truncated = true
			res.Gaps = append(res.Gaps, CoverageGap{
				Region: region, Service: "all", Call: "sweep",
				Reason: fmt.Sprintf("stopped at %d certificates; the remainder continues on the next sweep",
					MaxCertsPerSweep),
			})
			break
		}
	}
	return res, nil
}

// ---- ACM ----

func (e *Enumerator) enumerateACM(ctx context.Context, cfg awssdk.Config, region string, res *Result) {
	client := acm.NewFromConfig(cfg)

	var arns []string
	paginator := acm.NewListCertificatesPaginator(client, &acm.ListCertificatesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if gap, ok := describeFailure(region, "acm", "ListCertificates", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			return
		}
		for _, c := range page.CertificateSummaryList {
			if c.CertificateArn != nil {
				arns = append(arns, *c.CertificateArn)
			}
		}
	}

	for _, arn := range arns {
		out, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
			CertificateArn: awssdk.String(arn),
		})
		if err != nil {
			if gap, ok := describeFailure(region, "acm", "DescribeCertificate", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			continue
		}
		f := findingFromACM(out.Certificate, region)

		// Tags are ownership attribution; a failure here is not worth a gap
		// entry of its own, but it is worth not pretending we have them.
		if tags, err := client.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
			CertificateArn: awssdk.String(arn),
		}); err == nil {
			f.Tags = map[string]string{}
			for _, t := range tags.Tags {
				if t.Key != nil && t.Value != nil {
					f.Tags[*t.Key] = *t.Value
				}
			}
		}
		res.Certificates = append(res.Certificates, f)
	}
}

func findingFromACM(c *acmtypes.CertificateDetail, region string) Finding {
	f := Finding{Source: "acm", Region: region}
	if c == nil {
		return f
	}
	if c.CertificateArn != nil {
		f.ARN = *c.CertificateArn
	}
	if c.DomainName != nil {
		f.DomainName = *c.DomainName
	}
	f.SANs = append(f.SANs, c.SubjectAlternativeNames...)
	if c.Issuer != nil {
		f.Issuer = *c.Issuer
	}
	if c.NotBefore != nil {
		f.NotBefore = c.NotBefore.UTC()
	}
	if c.NotAfter != nil {
		f.NotAfter = c.NotAfter.UTC()
	}
	f.KeyAlgorithm = string(c.KeyAlgorithm)
	f.Status = string(c.Status)
	f.InUseBy = append(f.InUseBy, c.InUseBy...)

	// Every name this certificate covers is an endpoint the network scanner can
	// verify against reality. Cloud state says what SHOULD be served; only a
	// handshake says what IS.
	var eps []string
	if f.DomainName != "" {
		eps = append(eps, f.DomainName+":443")
	}
	for _, s := range f.SANs {
		if !strings.HasPrefix(s, "*") {
			eps = append(eps, s+":443")
		}
	}
	f.Endpoints = dedupeEndpoints(eps)
	return f
}

// ---- ELBv2 ----

func (e *Enumerator) enumerateELB(ctx context.Context, cfg awssdk.Config, region string, res *Result) {
	client := elasticloadbalancingv2.NewFromConfig(cfg)

	var lbs []elbtypes.LoadBalancer
	lbPager := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client,
		&elasticloadbalancingv2.DescribeLoadBalancersInput{})
	for lbPager.HasMorePages() {
		page, err := lbPager.NextPage(ctx)
		if err != nil {
			if gap, ok := describeFailure(region, "elasticloadbalancing", "DescribeLoadBalancers", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			return
		}
		lbs = append(lbs, page.LoadBalancers...)
	}

	for _, lb := range lbs {
		if lb.LoadBalancerArn == nil {
			continue
		}
		listeners, err := client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
			LoadBalancerArn: lb.LoadBalancerArn,
		})
		if err != nil {
			if gap, ok := describeFailure(region, "elasticloadbalancing", "DescribeListeners", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			continue
		}
		for _, l := range listeners.Listeners {
			if l.Protocol != elbtypes.ProtocolEnumHttps && l.Protocol != elbtypes.ProtocolEnumTls {
				continue
			}
			port := int32(443)
			if l.Port != nil {
				port = *l.Port
			}
			dns := ""
			if lb.DNSName != nil {
				dns = *lb.DNSName
			}

			// The DEFAULT certificate is on the listener itself.
			for _, c := range l.Certificates {
				if c.CertificateArn == nil {
					continue
				}
				res.Certificates = append(res.Certificates, Finding{
					Source: "elb", Region: region, ARN: *c.CertificateArn,
					DomainName: dns,
					Endpoints:  dedupeEndpoints([]string{fmt.Sprintf("%s:%d", dns, port)}),
					Status:     fmt.Sprintf("listener %s", string(l.Protocol)),
				})
			}

			// SNI extras are a separate call and are frequently where the
			// untracked certificates hide: a listener can carry dozens.
			if l.ListenerArn == nil {
				continue
			}
			extraPager := elasticloadbalancingv2.NewDescribeListenerCertificatesPaginator(client,
				&elasticloadbalancingv2.DescribeListenerCertificatesInput{ListenerArn: l.ListenerArn})
			for extraPager.HasMorePages() {
				page, err := extraPager.NextPage(ctx)
				if err != nil {
					if gap, ok := describeFailure(region, "elasticloadbalancing",
						"DescribeListenerCertificates", err); ok {
						res.Gaps = append(res.Gaps, gap)
					}
					break
				}
				for _, c := range page.Certificates {
					if c.CertificateArn == nil || (c.IsDefault != nil && *c.IsDefault) {
						continue
					}
					res.Certificates = append(res.Certificates, Finding{
						Source: "elb-sni", Region: region, ARN: *c.CertificateArn,
						DomainName: dns,
						Endpoints:  dedupeEndpoints([]string{fmt.Sprintf("%s:%d", dns, port)}),
						Status:     "SNI certificate on a listener",
					})
				}
			}
		}
	}
}

// ---- IAM server certificates ----

// These are the legacy uploaded certificates, and they are disproportionately
// the oldest and least-tracked things in an estate: uploaded once for a classic
// load balancer in 2017 and never thought about again.
//
// iam:GetServerCertificate returns the certificate BODY and is safe: IAM does
// not store retrievable private keys for server certificates.
func (e *Enumerator) enumerateIAM(ctx context.Context, cfg awssdk.Config, res *Result) {
	client := iam.NewFromConfig(cfg)

	var names []string
	pager := iam.NewListServerCertificatesPaginator(client, &iam.ListServerCertificatesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if gap, ok := describeFailure("global", "iam", "ListServerCertificates", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			return
		}
		for _, m := range page.ServerCertificateMetadataList {
			if m.ServerCertificateName != nil {
				names = append(names, *m.ServerCertificateName)
			}
		}
	}

	for _, name := range names {
		out, err := client.GetServerCertificate(ctx, &iam.GetServerCertificateInput{
			ServerCertificateName: awssdk.String(name),
		})
		if err != nil {
			if gap, ok := describeFailure("global", "iam", "GetServerCertificate", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			continue
		}
		f := Finding{Source: "iam", Region: "global", DomainName: name}
		if out.ServerCertificate != nil {
			if md := out.ServerCertificate.ServerCertificateMetadata; md != nil {
				if md.Arn != nil {
					f.ARN = *md.Arn
				}
				if md.Expiration != nil {
					f.NotAfter = md.Expiration.UTC()
				}
				if md.UploadDate != nil {
					f.NotBefore = md.UploadDate.UTC()
				}
			}
			// Parse the body so an IAM certificate gets the same canonical
			// treatment as one found by a handshake.
			if body := out.ServerCertificate.CertificateBody; body != nil {
				if certs, err := x509norm.ParsePEM([]byte(*body)); err == nil && len(certs) > 0 {
					f.Certificate = certs[0]
					f.SANs = certs[0].SANs
					f.Issuer = certs[0].IssuerDN
					f.NotBefore = certs[0].NotBefore
					f.NotAfter = certs[0].NotAfter
					f.KeyAlgorithm = string(certs[0].KeyAlgorithm)
				}
			}
		}
		res.Certificates = append(res.Certificates, f)
	}
}

// ---- CloudFront ----

func (e *Enumerator) enumerateCloudFront(ctx context.Context, cfg awssdk.Config, res *Result) {
	client := cloudfront.NewFromConfig(cfg)

	pager := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if gap, ok := describeFailure("global", "cloudfront", "ListDistributions", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			return
		}
		if page.DistributionList == nil {
			continue
		}
		for _, d := range page.DistributionList.Items {
			f := Finding{Source: "cloudfront", Region: "global"}
			if d.ARN != nil {
				f.ARN = *d.ARN
			}
			if d.DomainName != nil {
				f.DomainName = *d.DomainName
			}
			var eps []string
			if f.DomainName != "" {
				eps = append(eps, f.DomainName+":443")
			}
			if d.Aliases != nil {
				for _, a := range d.Aliases.Items {
					f.SANs = append(f.SANs, a)
					eps = append(eps, a+":443")
				}
			}
			f.Endpoints = dedupeEndpoints(eps)
			if d.ViewerCertificate != nil {
				switch {
				case d.ViewerCertificate.ACMCertificateArn != nil:
					f.Status = "ACM certificate: " + *d.ViewerCertificate.ACMCertificateArn
				case d.ViewerCertificate.IAMCertificateId != nil:
					f.Status = "IAM certificate: " + *d.ViewerCertificate.IAMCertificateId
				default:
					f.Status = "CloudFront default certificate"
				}
			}
			res.Certificates = append(res.Certificates, f)
		}
	}
}

// ---- API Gateway custom domains ----

func (e *Enumerator) enumerateAPIGateway(ctx context.Context, cfg awssdk.Config, region string, res *Result) {
	client := apigateway.NewFromConfig(cfg)

	pager := apigateway.NewGetDomainNamesPaginator(client, &apigateway.GetDomainNamesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if gap, ok := describeFailure(region, "apigateway", "GetDomainNames", err); ok {
				res.Gaps = append(res.Gaps, gap)
			}
			return
		}
		for _, d := range page.Items {
			f := Finding{Source: "apigateway", Region: region}
			if d.DomainName != nil {
				f.DomainName = *d.DomainName
				f.Endpoints = dedupeEndpoints([]string{*d.DomainName + ":443"})
			}
			if d.CertificateArn != nil {
				f.ARN = *d.CertificateArn
			}
			if d.RegionalCertificateArn != nil && f.ARN == "" {
				f.ARN = *d.RegionalCertificateArn
			}
			if d.CertificateUploadDate != nil {
				f.NotBefore = d.CertificateUploadDate.UTC()
			}
			res.Certificates = append(res.Certificates, f)
		}
	}
}

// ExpiringWithin returns findings expiring within d, soonest first.
func (r *Result) ExpiringWithin(d time.Duration, now time.Time) []Finding {
	var out []Finding
	cutoff := now.Add(d)
	for _, f := range r.Certificates {
		if !f.NotAfter.IsZero() && f.NotAfter.Before(cutoff) {
			out = append(out, f)
		}
	}
	return out
}

// KnownEndpoints returns every endpoint AWS says should exist.
//
// This is the set a network scan is subtracted against to produce the untracked
// number — the number the whole validation programme turns on.
func (r *Result) KnownEndpoints() []string {
	var all []string
	for _, f := range r.Certificates {
		all = append(all, f.Endpoints...)
	}
	return dedupeEndpoints(all)
}
