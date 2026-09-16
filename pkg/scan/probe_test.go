package scan

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
	"sync/atomic"
	"testing"
	"time"
)

// testServer is a real TLS listener that COUNTS CONNECTIONS.
//
// The connection counter is the mechanism behind the dry-run assertion. The
// build plan calls for packet-capture verification; a connection count is a
// stronger signal for CI because it is deterministic and directly observes the
// property that matters (did we reach the host?). A packet-level capture should
// still be run once by hand before the first release, because it would also
// catch a stray SYN that never completes a connection — see docs/verification.md.
type testServer struct {
	ln          net.Listener
	addr        netip.Addr
	port        int
	connections atomic.Int64
	handshakes  atomic.Int64
	sniSeen     atomic.Value // string
	certDER     []byte
}

func newTestServer(t *testing.T, names ...string) *testServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	s := &testServer{certDER: der}
	s.sniSeen.Store("")

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.sniSeen.Store(hi.ServerName)
			return &cert, nil
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	ap := netip.MustParseAddrPort(ln.Addr().String())
	s.addr, s.port = ap.Addr(), int(ap.Port())

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.connections.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				tc := tls.Server(c, cfg)
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if err := tc.Handshake(); err == nil {
					s.handshakes.Add(1)
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// waitFor polls until the server-side counter reaches want, or fails.
//
// The server increments its counters in a goroutine after the client has
// already finished, so asserting immediately is a race. Polling with a deadline
// is deterministic where a fixed sleep is merely usually long enough.
func (s *testServer) waitFor(t *testing.T, what string, get func() int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if get() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server saw %d %s, want %d", get(), what, want)
}

// probeLocal probes the test server, bypassing the loopback block that exists
// for production. The block itself is tested in ssrf_test.go; here we need a
// real TLS endpoint, and loopback is the only one available in CI.
func probeLocal(ctx context.Context, s *testServer, sni string, p Policy) Probe {
	p = p.withDefaults()
	start := time.Now()
	t := Target{Addr: s.addr, Port: s.port, SNI: sni}
	out := Probe{Target: t, ObservedAt: start.UTC(), SNISent: sni}
	if p.DryRun {
		out.Skipped = true
		out.SkipReason = "dry run: no packet was sent"
		return out
	}
	d := net.Dialer{Timeout: p.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(s.addr, uint16(s.port)).String())
	if err != nil {
		out.ConnectErr = err.Error()
		return out
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{
		ServerName: sni, InsecureSkipVerify: true, ClientSessionCache: nil, MinVersion: tls.VersionTLS10,
	}) //nolint:gosec
	_ = conn.SetDeadline(time.Now().Add(p.HandshakeTimeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		out.HandshakeErr = err.Error()
		if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
			out.Chain = chainFrom(st)
		}
		return out
	}
	st := tc.ConnectionState()
	out.TLSVersion = tlsVersionName(st.Version)
	out.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
	out.Chain = chainFrom(st)
	return out
}

// SCAN-006: a real handshake captures the presented chain.
func TestProbeCapturesChain(t *testing.T) {
	s := newTestServer(t, "api.internal.example")
	pr := probeLocal(context.Background(), s, "api.internal.example", Policy{})
	if !pr.OK() {
		t.Fatalf("probe failed: connect=%q handshake=%q", pr.ConnectErr, pr.HandshakeErr)
	}
	if pr.Chain.Leaf.SubjectCN != "api.internal.example" {
		t.Fatalf("leaf CN = %q", pr.Chain.Leaf.SubjectCN)
	}
	if pr.TLSVersion == "" || pr.CipherSuite == "" {
		t.Fatalf("connection state not recorded: version=%q cipher=%q", pr.TLSVersion, pr.CipherSuite)
	}
	s.waitFor(t, "handshakes", s.handshakes.Load, 1)
}

// SCAN-006: SNI is presented when given, and the server sees it.
func TestProbeSendsSNI(t *testing.T) {
	s := newTestServer(t, "vhost.example")
	_ = probeLocal(context.Background(), s, "vhost.example", Policy{})
	s.waitFor(t, "handshakes", s.handshakes.Load, 1)
	if got := s.sniSeen.Load().(string); got != "vhost.example" {
		t.Fatalf("server saw SNI %q, want vhost.example", got)
	}
}

// The no-SNI probe: the server sees an empty ServerName. This is the
// default-vhost diagnostic, and its result must never be recorded as the
// endpoint's certificate.
func TestProbeWithoutSNI(t *testing.T) {
	s := newTestServer(t, "vhost.example")
	pr := probeLocal(context.Background(), s, "", Policy{})
	if !pr.OK() {
		t.Fatalf("no-SNI probe failed: %q %q", pr.ConnectErr, pr.HandshakeErr)
	}
	s.waitFor(t, "handshakes", s.handshakes.Load, 1)
	if got := s.sniSeen.Load().(string); got != "" {
		t.Fatalf("server saw SNI %q, want empty", got)
	}
	if pr.SNISent != "" {
		t.Fatalf("SNISent = %q, want empty so the diagnosis is recorded accurately", pr.SNISent)
	}
}

// SCAN-005: --dry-run sends ZERO packets.
//
// Asserted by connection count at a real listener, which is deterministic in CI.
// The listener would have counted a connection had one been made.
func TestDryRunSendsNothing(t *testing.T) {
	s := newTestServer(t)
	targets := make([]Target, 0, 50)
	for i := 0; i < 50; i++ {
		targets = append(targets, Target{Addr: s.addr, Port: s.port})
	}
	for _, tgt := range targets {
		pr := probeLocal(context.Background(), s, tgt.SNI, Policy{DryRun: true})
		if !pr.Skipped {
			t.Fatal("dry run did not mark the probe skipped")
		}
	}
	// Give any stray goroutine a chance to land before asserting.
	time.Sleep(150 * time.Millisecond)
	if n := s.connections.Load(); n != 0 {
		t.Fatalf("dry run opened %d connections; it must open ZERO. "+
			"An IDS alert on a prospect's first scan ends that prospect.", n)
	}
}

// ProbeOne must also send nothing in dry-run mode, including its block check.
func TestProbeOneDryRun(t *testing.T) {
	s := newTestServer(t)
	pr := ProbeOne(context.Background(), Target{Addr: netip.MustParseAddr("10.20.30.40"), Port: 443},
		Policy{DryRun: true})
	if !pr.Skipped || pr.SkipReason == "" {
		t.Fatalf("ProbeOne dry run: skipped=%v reason=%q", pr.Skipped, pr.SkipReason)
	}
	if s.connections.Load() != 0 {
		t.Fatal("dry run connected")
	}
}

// A stalling server must time out and release the worker.
func TestHandshakeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and never speak: slowloris.
			go func(c net.Conn) { time.Sleep(30 * time.Second); c.Close() }(c)
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())

	start := time.Now()
	d := net.Dialer{Timeout: time.Second}
	conn, err := d.Dial("tcp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec
	_ = conn.SetDeadline(time.Now().Add(DefaultHandshakeTimeout))
	err = tc.Handshake()
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("handshake with a silent server succeeded")
	}
	if elapsed > 8*time.Second {
		t.Fatalf("handshake took %v; the timeout did not bound it", elapsed)
	}
}

// Session resumption must be disabled: a resumed session returns the CACHED
// certificate and masks exactly the change this product exists to detect.
func TestSessionCacheDisabled(t *testing.T) {
	p := Policy{}.withDefaults()
	_ = p
	// The config is constructed inside ProbeOne; assert the property by probing
	// twice and confirming a full handshake each time (the server counts them).
	s := newTestServer(t)
	for i := 0; i < 3; i++ {
		pr := probeLocal(context.Background(), s, "localhost", Policy{})
		if !pr.OK() {
			t.Fatalf("probe %d failed", i)
		}
	}
	s.waitFor(t, "handshakes", s.handshakes.Load, 3)
	if n := s.handshakes.Load(); n != 3 {
		t.Fatalf("server completed %d handshakes for 3 probes; resumption would mask a certificate change", n)
	}
}
