package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/scan"
	"github.com/certwatch/certwatch/pkg/x509norm"
)

// THE DECISIVE TEST.
//
// The entire remaining commercial hypothesis for this product is:
//
//	"nobody both discovers endpoints the customer never registered AND
//	 verifies each resolved IP against a confirmed expected state"
//
// Before asking whether a competitor can do it, the product must be able to do
// it. Until this file existed, the capability had NO TEST — the differentiator
// was asserted in every planning document and never once exercised.
//
// The scenario, which is scenario S2 from project_1_testing_strategy.md:
//
//	lab.internal.test
//	     |-- 10.x.0.1  -> certificate A   (the expected one)
//	     `-- 10.x.0.2  -> certificate B   (a stale one, as after a partial deploy)
//
// A hostname-level monitor connects once, gets whichever address answers, and
// reports healthy. This must not.

// usedIPs tracks which distinct addresses are already bound in this test run.
var usedIPs = map[string]bool{}

// labBackend is one TLS server standing in for a load-balancer pool member.
type labBackend struct {
	ln      net.Listener
	addr    netip.Addr
	port    int
	certDER []byte
	name    string
}

// distinctIPs are genuinely different addresses on this host, not one address
// with different ports. The whole claim is that every address a hostname
// resolves to is checked separately; a fixture using ports would not exercise
// it, and an earlier version of this file had exactly that weakness.
var distinctIPs = []string{"127.0.2.2", "127.0.2.3", "127.0.2.4", "127.0.2.5"}

func startBackend(t *testing.T, serverName, certCN string) *labBackend {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: certCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		DNSNames:     []string{serverName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	// Each backend gets its own IP address.
	var ln net.Listener
	var lastErr error
	for _, ip := range distinctIPs {
		if usedIPs[ip] {
			continue
		}
		l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
		if err != nil {
			lastErr = err
			continue
		}
		usedIPs[ip] = true
		t.Cleanup(func() { delete(usedIPs, ip) })
		ln = l
		break
	}
	if ln == nil {
		t.Skipf("no distinct loopback alias available (need 127.0.2.2+): %v.\n"+
			"Create them with: sudo ifconfig lo0 alias 127.0.2.2", lastErr)
	}
	ap := netip.MustParseAddrPort(ln.Addr().String())
	b := &labBackend{ln: ln, addr: ap.Addr(), port: int(ap.Port()), certDER: der, name: certCN}

	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := tls.Server(c, cfg)
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				_ = tc.Handshake()
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return b
}

// probeBackend performs a real TLS handshake and returns a real scan.Probe.
//
// It dials the listener directly because the production SSRF policy refuses
// loopback — correctly, and that refusal is tested separately in
// pkg/scan/ssrf_test.go. Everything downstream of the dial is the production
// path: real handshake, real chain capture, real x509norm parsing, real
// aggregation.
func probeBackend(t *testing.T, b *labBackend, hostname string) scan.Probe {
	t.Helper()
	pr := scan.Probe{
		Target:     scan.Target{Addr: b.addr, Port: b.port, SNI: hostname, Hostname: hostname},
		ObservedAt: time.Now().UTC(),
		SNISent:    hostname,
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp", netip.AddrPortFrom(b.addr, uint16(b.port)).String())
	if err != nil {
		t.Fatalf("dial %s: %v", b.name, err)
	}
	defer conn.Close()

	tc := tls.Client(conn, &tls.Config{
		ServerName: hostname, InsecureSkipVerify: true, //nolint:gosec // capturing, not trusting
		ClientSessionCache: nil, MinVersion: tls.VersionTLS12,
	})
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake %s: %v", b.name, err)
	}
	st := tc.ConnectionState()
	ders := make([][]byte, 0, len(st.PeerCertificates))
	for _, c := range st.PeerCertificates {
		ders = append(ders, c.Raw)
	}
	ch, err := x509norm.ParseChain(ders)
	if err != nil {
		t.Fatalf("parse chain %s: %v", b.name, err)
	}
	pr.Chain = ch
	pr.TLSVersion = "TLS1.2"
	return pr
}

// S2: two pool members, two different certificates, one hostname.
func TestDetectsPerIPCertificateDivergence(t *testing.T) {
	const host = "lab.internal.test"

	expected := startBackend(t, host, "expected.lab")
	stale := startBackend(t, host, "stale.lab")

	if string(expected.certDER) == string(stale.certDER) {
		t.Fatal("fixture error: both backends serve the same certificate")
	}

	agg := newAggregator()
	ctx := context.Background()
	agg.addProbe(ctx, probeBackend(t, expected, host), false)
	agg.addProbe(ctx, probeBackend(t, stale, host), false)

	rep := &model.Report{Summary: model.ReportSummary{
		ByIssuer: map[string]int{}, ByKeyAlgorithm: map[string]int{},
		ByTLSVersion: map[string]int{}, ByParseStatus: map[string]int{},
	}}
	agg.finalise(rep)

	// 1. The divergence must be detected.
	if rep.Summary.IPDisagreements != 1 {
		t.Fatalf("IPDisagreements = %d, want 1.\n"+
			"THIS IS THE PRODUCT'S ENTIRE REMAINING DIFFERENTIATOR. If it does not fire here, "+
			"there is nothing to sell.", rep.Summary.IPDisagreements)
	}

	// 2. Both certificates must be recorded, not just whichever answered first.
	if rep.Summary.UniqueCertificates != 2 {
		t.Fatalf("UniqueCertificates = %d, want 2; a hostname-level monitor would record 1",
			rep.Summary.UniqueCertificates)
	}

	// 3. The report must identify WHICH address served what. "Something is
	//    wrong somewhere" is not actionable; an operator needs the address.
	byFingerprint := map[string]string{}
	for _, ep := range rep.Endpoints {
		if ep.LeafFingerprint != "" {
			byFingerprint[ep.LeafFingerprint] = ep.Address
		}
	}
	if len(byFingerprint) != 2 {
		t.Fatalf("endpoints recorded %d distinct certificates, want 2: %+v", len(byFingerprint), rep.Endpoints)
	}
	expFP := x509norm.Fingerprint(expected.certDER)
	staleFP := x509norm.Fingerprint(stale.certDER)
	if byFingerprint[expFP] == "" || byFingerprint[staleFP] == "" {
		t.Fatalf("the report does not attribute each certificate to an address: %+v", byFingerprint)
	}
	// GENUINELY DIFFERENT ADDRESSES. This assertion is the one that was missing
	// before: the earlier fixture distinguished backends by PORT, so it could
	// not prove per-address attribution at all.
	if byFingerprint[expFP] == byFingerprint[staleFP] {
		t.Fatalf("both certificates attributed to the same address %s; the fixture is not "+
			"testing cross-IP behaviour", byFingerprint[expFP])
	}
	if expected.addr == stale.addr {
		t.Fatal("fixture error: both backends share an IP address")
	}
	t.Logf("DIVERGENCE DETECTED: %s served %s, %s served %s",
		byFingerprint[expFP], expFP[:16], byFingerprint[staleFP], staleFP[:16])
}

// The converse: a consistent pool must NOT be reported as divergent. A detector
// that fires on everything is as useless as one that fires on nothing.
func TestConsistentPoolIsNotReportedAsDivergent(t *testing.T) {
	const host = "consistent.internal.test"
	a := startBackend(t, host, "same.lab")

	agg := newAggregator()
	ctx := context.Background()
	// Same backend probed twice, as two pool members would be if both were
	// correctly updated.
	agg.addProbe(ctx, probeBackend(t, a, host), false)
	agg.addProbe(ctx, probeBackend(t, a, host), false)

	rep := &model.Report{Summary: model.ReportSummary{
		ByIssuer: map[string]int{}, ByKeyAlgorithm: map[string]int{},
		ByTLSVersion: map[string]int{}, ByParseStatus: map[string]int{},
	}}
	agg.finalise(rep)

	if rep.Summary.IPDisagreements != 0 {
		t.Fatalf("IPDisagreements = %d for a consistent pool; a false positive here would "+
			"fire on every healthy load balancer", rep.Summary.IPDisagreements)
	}
	if rep.Summary.UniqueCertificates != 1 {
		t.Fatalf("UniqueCertificates = %d, want 1 (deduplicated by fingerprint)",
			rep.Summary.UniqueCertificates)
	}
}

// Divergence must be tracked per hostname, not globally. Two unrelated
// hostnames serving different certificates is normal, not a finding.
func TestDivergenceIsScopedToHostname(t *testing.T) {
	a := startBackend(t, "alpha.test", "alpha.lab")
	b := startBackend(t, "beta.test", "beta.lab")

	agg := newAggregator()
	ctx := context.Background()
	agg.addProbe(ctx, probeBackend(t, a, "alpha.test"), false)
	agg.addProbe(ctx, probeBackend(t, b, "beta.test"), false)

	rep := &model.Report{Summary: model.ReportSummary{
		ByIssuer: map[string]int{}, ByKeyAlgorithm: map[string]int{},
		ByTLSVersion: map[string]int{}, ByParseStatus: map[string]int{},
	}}
	agg.finalise(rep)

	if rep.Summary.IPDisagreements != 0 {
		t.Fatalf("IPDisagreements = %d; two different hostnames serving different certificates "+
			"is normal and must not be reported", rep.Summary.IPDisagreements)
	}
}

// A hostname-level monitor is simulated by recording only the first response.
// This exists to make the difference concrete and measurable, because it is the
// whole sales argument.
func TestHostnameLevelMonitorWouldMissIt(t *testing.T) {
	const host = "lab.internal.test"
	expected := startBackend(t, host, "expected.lab")
	stale := startBackend(t, host, "stale.lab")

	ctx := context.Background()

	// What a hostname-level monitor sees: one connection, one answer.
	single := newAggregator()
	single.addProbe(ctx, probeBackend(t, expected, host), false)
	repSingle := &model.Report{Summary: model.ReportSummary{
		ByIssuer: map[string]int{}, ByKeyAlgorithm: map[string]int{},
		ByTLSVersion: map[string]int{}, ByParseStatus: map[string]int{},
	}}
	single.finalise(repSingle)

	// What per-IP verification sees.
	perIP := newAggregator()
	perIP.addProbe(ctx, probeBackend(t, expected, host), false)
	perIP.addProbe(ctx, probeBackend(t, stale, host), false)
	repPerIP := &model.Report{Summary: model.ReportSummary{
		ByIssuer: map[string]int{}, ByKeyAlgorithm: map[string]int{},
		ByTLSVersion: map[string]int{}, ByParseStatus: map[string]int{},
	}}
	perIP.finalise(repPerIP)

	if repSingle.Summary.IPDisagreements != 0 {
		t.Fatal("fixture error: a single observation cannot show disagreement")
	}
	if repPerIP.Summary.IPDisagreements != 1 {
		t.Fatal("per-IP observation failed to show the disagreement")
	}
	t.Logf("hostname-level monitor: %d certificates, %d disagreements (reports healthy)",
		repSingle.Summary.UniqueCertificates, repSingle.Summary.IPDisagreements)
	t.Logf("per-IP verification:    %d certificates, %d disagreements (reports the problem)",
		repPerIP.Summary.UniqueCertificates, repPerIP.Summary.IPDisagreements)
}
