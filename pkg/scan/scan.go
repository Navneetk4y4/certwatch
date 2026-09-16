// Package scan performs TLS discovery: it connects, completes a handshake,
// captures the presented chain, and closes.
//
// # What it does NOT do, deliberately
//
// It is not a vulnerability scanner and must never become one. It does not
// banner-grab, does not fingerprint software versions, does not test cipher
// suites for weakness, does not probe for CVEs, does not enumerate subdomains,
// and does not attempt STARTTLS.
//
// Most importantly: it completes a TLS handshake and closes the connection. It
// sends ZERO application-layer bytes. That is a sentence a security reviewer can
// verify by reading forty lines, and it is the difference between "a certificate
// inventory tool" and "a scanner we need to think about".
//
// See project_1_full_development_plan.md §17.
package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/certwatch/certwatch/pkg/model"
	"github.com/certwatch/certwatch/pkg/x509norm"
)

// Timeouts. Short deliberately: a stalling endpoint must not hold a worker, and
// a scan of a /22 must finish in minutes, not hours.
const (
	DefaultConnectTimeout   = 3 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
	// MaxChainBytes bounds the certificates a server may present in total.
	MaxChainBytes = 512 << 10
)

// Policy is the immutable scan configuration.
type Policy struct {
	ConnectTimeout   time.Duration
	HandshakeTimeout time.Duration
	RatePerSecond    int
	Concurrency      int
	// DryRun prints targets and sends ZERO packets. Mandatory on a first scan
	// against any new range: the fastest way to lose a first customer is an IDS
	// alert on day one.
	DryRun bool
	// Offline disables the public-resolver check used for publicly_resolvable,
	// which then reports unknown rather than guessing.
	Offline bool
}

func (p Policy) withDefaults() Policy {
	if p.ConnectTimeout <= 0 {
		p.ConnectTimeout = DefaultConnectTimeout
	}
	if p.HandshakeTimeout <= 0 {
		p.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if p.RatePerSecond <= 0 {
		p.RatePerSecond = 50
	}
	if p.Concurrency <= 0 {
		p.Concurrency = 20
	}
	return p
}

// Target is one address and port to probe, with the SNI to present.
type Target struct {
	Addr netip.Addr
	Port int
	// SNI is the server name to send. Empty means send none — which is the
	// default-vhost probe and is recorded separately, never as the endpoint's
	// certificate.
	SNI string
	// Hostname is the name this address was resolved from, for reporting.
	Hostname string
}

func (t Target) String() string {
	return netip.AddrPortFrom(t.Addr, uint16(t.Port)).String()
}

// Probe is the result of one connection attempt. Exactly one of the error
// fields is set, or none when the handshake succeeded.
type Probe struct {
	Target             Target
	ObservedAt         time.Time
	Skipped            bool
	SkipReason         string
	ConnectErr         string
	HandshakeErr       string
	TLSVersion         string
	CipherSuite        string
	NegotiatedProtocol string
	Chain              *model.Chain
	// SNISent records what was actually presented, for the default-vhost
	// diagnosis: "your tool says the certificate is wrong but my browser is
	// fine" is almost always explained by this field.
	SNISent  string
	Duration time.Duration
}

// OK reports whether a leaf certificate was captured.
func (p Probe) OK() bool {
	return !p.Skipped && p.ConnectErr == "" && p.HandshakeErr == "" && p.Chain != nil && p.Chain.Leaf != nil
}

// ProbeOne connects to a single target and captures the presented chain.
//
// tls.Config notes, each load-bearing:
//
//   - InsecureSkipVerify is TRUE, and that is correct here. We are CAPTURING a
//     chain, not trusting it. Verification happens later, against a per-tenant
//     trust bundle, because a private CA is normal in the target environment and
//     the system trust store would reject most of the estate. Rejecting at the
//     dialler would make the whole internal estate invisible, which is the
//     opposite of the product.
//   - ClientSessionCache is nil: session resumption would return a CACHED
//     certificate and mask exactly the change this product exists to detect.
//   - MinVersion is TLS 1.0 because appliances in the target estate still speak
//     it, and an endpoint we refuse to talk to is an endpoint we report nothing
//     about. The negotiated version is recorded and a low one is a finding, not
//     a reason to look away.
func ProbeOne(ctx context.Context, t Target, p Policy) Probe {
	p = p.withDefaults()
	start := time.Now()
	out := Probe{Target: t, ObservedAt: start.UTC(), SNISent: t.SNI}

	if blocked, why := AddrBlocked(t.Addr); blocked {
		out.Skipped = true
		out.SkipReason = why
		return out
	}
	if p.DryRun {
		out.Skipped = true
		out.SkipReason = "dry run: no packet was sent"
		return out
	}

	connCtx, cancel := context.WithTimeout(ctx, p.ConnectTimeout)
	conn, err := dialByAddress(connCtx, t.Addr, t.Port, p.ConnectTimeout)
	cancel()
	if err != nil {
		out.ConnectErr = err.Error()
		out.Duration = time.Since(start)
		return out
	}
	defer conn.Close()

	serverName := t.SNI
	cfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // capturing a chain, not trusting it; see doc comment
		ClientSessionCache: nil,  // resumption would mask a certificate change
		MinVersion:         tls.VersionTLS10,
	}
	if serverName == "" {
		// Go requires either ServerName or InsecureSkipVerify; with no SNI we
		// still want the handshake, which is the default-vhost probe.
		cfg.ServerName = ""
	}

	tc := tls.Client(conn, cfg)
	hsCtx, hsCancel := context.WithTimeout(ctx, p.HandshakeTimeout)
	defer hsCancel()
	_ = conn.SetDeadline(time.Now().Add(p.HandshakeTimeout))

	if err := tc.HandshakeContext(hsCtx); err != nil {
		out.HandshakeErr = err.Error()
		// A handshake can fail AFTER the server presented its certificate — an
		// mTLS endpoint rejecting us at the client-auth stage is the common case.
		// The leaf is still captured, because the endpoint still told us what it
		// is serving.
		if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
			out.Chain = chainFrom(st)
		}
		out.Duration = time.Since(start)
		return out
	}

	st := tc.ConnectionState()
	out.TLSVersion = tlsVersionName(st.Version)
	out.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
	out.NegotiatedProtocol = st.NegotiatedProtocol
	out.Chain = chainFrom(st)
	out.Duration = time.Since(start)

	// The connection closes here. No application-layer byte is ever sent.
	return out
}

func chainFrom(st tls.ConnectionState) *model.Chain {
	if len(st.PeerCertificates) == 0 {
		return nil
	}
	total := 0
	ders := make([][]byte, 0, len(st.PeerCertificates))
	for _, c := range st.PeerCertificates {
		total += len(c.Raw)
		if total > MaxChainBytes {
			break
		}
		ders = append(ders, c.Raw)
	}
	if len(ders) == 0 {
		return nil
	}
	ch, err := x509norm.ParseChain(ders)
	if err != nil {
		return nil
	}
	return ch
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// IsTimeout reports whether an error string looks like a timeout, for reporting.
func IsTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}
