package scopecfg

import (
	"net/netip"
	"strings"
	"testing"
)

const valid = `
version: 1
cidrs:
  - 10.20.0.0/16
  - 192.168.5.0/24
exclude_cidrs:
  - 10.20.99.0/24
exclude_hosts:
  - 10.20.30.99
ports: [443, 8443]
certificate_directories:
  - /etc/ssl/certs
rate_limit_per_second: 25
max_concurrency: 10
`

func mustParse(t *testing.T, doc string) *Scope {
	t.Helper()
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func TestParseValid(t *testing.T) {
	s := mustParse(t, valid)
	if s.RatePerSecond() != 25 || s.Concurrency() != 10 {
		t.Fatalf("limits not honoured: rate=%d conc=%d", s.RatePerSecond(), s.Concurrency())
	}
	if len(s.Ports()) != 2 {
		t.Fatalf("ports = %v", s.Ports())
	}
	if !strings.HasPrefix(s.Digest(), "sha256:") {
		t.Fatalf("digest = %q", s.Digest())
	}
}

// SCOPE-001: a malformed or dangerous scope file is an error, never a
// best-effort interpretation.
func TestParseRejections(t *testing.T) {
	cases := []struct{ name, doc, want string }{
		{"no version", "cidrs: [10.0.0.0/8]", "unsupported version"},
		{"wrong version", "version: 2\ncidrs: [10.0.0.0/8]", "unsupported version"},
		{"unknown field", "version: 1\ncidrs: [10.0.0.0/8]\nexclude_cidr: [1.1.1.1/32]", "unknown field \"exclude_cidr\""},
		{"bad cidr", "version: 1\ncidrs: [not-a-cidr]", "is not a CIDR"},
		{"bad exclude host", "version: 1\ncidrs: [10.0.0.0/8]\nexclude_hosts: [nope]", "not an IP address"},
		{"port out of range", "version: 1\ncidrs: [10.0.0.0/8]\nports: [70000]", "out of range"},
		{"port zero", "version: 1\ncidrs: [10.0.0.0/8]\nports: [0]", "out of range"},
		{"relative directory", "version: 1\ncertificate_directories: [certs]", "not absolute"},
		{"traversal in directory", "version: 1\ncertificate_directories: [/etc/../etc/ssl]", "traversal"},
		{"proc directory", "version: 1\ncertificate_directories: [/proc/self]", "refused prefix"},
		{"dev directory", "version: 1\ncertificate_directories: [/dev]", "refused prefix"},
		{"nul byte in directory", "version: 1\ncertificate_directories: [\"/etc/\\0ssl\"]", "NUL byte"},
		{"rate too high", "version: 1\ncidrs: [10.0.0.0/8]\nrate_limit_per_second: 9999", "out of range"},
		{"concurrency too high", "version: 1\ncidrs: [10.0.0.0/8]\nmax_concurrency: 9999", "out of range"},
		{"empty scope", "version: 1", "neither cidrs nor certificate_directories"},
		{"not yaml", "\x00\x01\x02 not yaml at all {{{", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("accepted a document that should be rejected")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// An unknown field must be an ERROR. A customer who misspells `exclude_cidrs`
// must be told, not silently scanned outside their intent.
func TestUnknownFieldIsRefused(t *testing.T) {
	_, err := Parse([]byte("version: 1\ncidrs: [10.0.0.0/8]\nexcludecidrs: [10.0.1.0/24]"))
	if err == nil {
		t.Fatal("a misspelled exclusion field was silently ignored; the customer would be scanned " +
			"outside their intent and would have no way to know")
	}
}

// SCOPE-002: the intersection. This is the function a security reviewer reads.
func TestIntersect(t *testing.T) {
	s := mustParse(t, valid)

	cases := []struct {
		name    string
		target  string
		port    int
		allowed bool
		reason  string
	}{
		{"in scope", "10.20.30.40", 443, true, ""},
		{"in second cidr", "192.168.5.7", 8443, true, ""},
		{"outside every cidr", "172.16.0.1", 443, false, "not inside any declared CIDR"},
		{"undeclared port", "10.20.30.40", 22, false, "not declared"},
		{"excluded cidr", "10.20.99.5", 443, false, "excluded range"},
		{"excluded host", "10.20.30.99", 443, false, "excluded range 10.20.30.99"},
		{"boundary low", "10.20.0.0", 443, true, ""},
		{"boundary high", "10.20.255.255", 443, true, ""},
		{"just outside", "10.21.0.0", 443, false, "not inside any declared CIDR"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.target)
			allowed, violations := s.Intersect([]Target{{Addr: addr, Port: tc.port}})
			if tc.allowed {
				if len(allowed) != 1 || len(violations) != 0 {
					t.Fatalf("expected allowed, got allowed=%v violations=%v", allowed, violations)
				}
				return
			}
			if len(allowed) != 0 {
				t.Fatalf("out-of-scope target was allowed: %v", allowed)
			}
			if len(violations) != 1 {
				t.Fatalf("expected exactly one violation, got %v", violations)
			}
			if tc.reason != "" && !strings.Contains(violations[0].Reason, tc.reason) {
				t.Fatalf("violation reason %q does not mention %q", violations[0].Reason, tc.reason)
			}
		})
	}
}

// Exclusions must win over inclusions, always. An exclusion that can be
// overridden is not an exclusion.
func TestExclusionsWin(t *testing.T) {
	s := mustParse(t, `
version: 1
cidrs: [10.0.0.0/8]
exclude_cidrs: [10.0.0.0/8]
ports: [443]
`)
	allowed, violations := s.Intersect([]Target{{Addr: netip.MustParseAddr("10.1.2.3"), Port: 443}})
	if len(allowed) != 0 {
		t.Fatal("an address inside both an included and an excluded range was allowed")
	}
	if len(violations) != 1 {
		t.Fatalf("expected a reported violation, got %v", violations)
	}
}

// A violation must always be REPORTED, never silently dropped: a control plane
// asking for something out of scope is either our bug or our compromise, and
// the customer is entitled to see it (T2).
func TestViolationsAreAlwaysReported(t *testing.T) {
	s := mustParse(t, valid)
	targets := []Target{
		{netip.MustParseAddr("8.8.8.8"), 443},
		{netip.MustParseAddr("169.254.169.254"), 443},
		{netip.MustParseAddr("10.20.30.40"), 22},
		{netip.MustParseAddr("10.20.99.1"), 443},
	}
	allowed, violations := s.Intersect(targets)
	if len(allowed) != 0 {
		t.Fatalf("out-of-scope targets allowed: %v", allowed)
	}
	if len(violations) != len(targets) {
		t.Fatalf("got %d violations for %d refused targets; every refusal must be reported",
			len(violations), len(targets))
	}
	for _, v := range violations {
		if v.What == "" || v.Reason == "" {
			t.Fatalf("violation with an empty field: %+v", v)
		}
	}
}

// The control plane cannot widen scope: no field in a task changes the answer.
func TestServerCannotWidenScope(t *testing.T) {
	s := mustParse(t, valid)
	// Whatever a hostile control plane asks for, the answer for an out-of-scope
	// address is the same.
	for _, port := range []int{443, 8443, 22, 80, 65535} {
		allowed, _ := s.Intersect([]Target{{netip.MustParseAddr("203.0.113.1"), port}})
		if len(allowed) != 0 {
			t.Fatalf("port %d allowed an out-of-scope address", port)
		}
	}
}

func TestAllowsCIDR(t *testing.T) {
	s := mustParse(t, valid)
	cases := []struct {
		cidr string
		ok   bool
	}{
		{"10.20.0.0/16", true},
		{"10.20.4.0/22", true},
		{"10.20.30.40/32", true},
		{"10.0.0.0/8", false}, // wider than the declared range
		{"172.16.0.0/12", false},
	}
	for _, c := range cases {
		ok, reason := s.AllowsCIDR(netip.MustParsePrefix(c.cidr))
		if ok != c.ok {
			t.Errorf("AllowsCIDR(%s) = %v (%s), want %v", c.cidr, ok, reason, c.ok)
		}
	}
}

func TestAllowsDirectory(t *testing.T) {
	s := mustParse(t, valid)
	cases := []struct {
		path string
		ok   bool
	}{
		{"/etc/ssl/certs", true},
		{"/etc/ssl/certs/sub", true},
		{"/etc/ssl", false},
		{"/etc/ssl/certsX", false}, // prefix must be a path boundary, not a string prefix
		{"/etc/ssl/private", false},
		{"/", false},
	}
	for _, c := range cases {
		if got := s.AllowsDirectory(c.path); got != c.ok {
			t.Errorf("AllowsDirectory(%q) = %v, want %v", c.path, got, c.ok)
		}
	}
}

// Accessors must return copies: a caller mutating what it received must not be
// able to widen the scope.
func TestAccessorsReturnCopies(t *testing.T) {
	s := mustParse(t, valid)
	p := s.Ports()
	p[0] = 22
	for _, got := range s.Ports() {
		if got == 22 {
			t.Fatal("mutating the returned port slice widened the scope")
		}
	}
	d := s.Directories()
	if len(d) > 0 {
		d[0] = "/etc/ssl/private"
		if s.Directories()[0] == "/etc/ssl/private" {
			t.Fatal("mutating the returned directory slice widened the scope")
		}
	}
}

// REGRESSION: a parse error must never echo file content.
//
// gopkg.in/yaml.v3 quotes the offending text in its errors. The --scope path is
// operator-supplied and may point anywhere, so pointing it at the wrong file
// echoed that file's contents to stderr and into any log capturing it.
// Adversarial review demonstrated this with a shadow-shaped fixture: the error
// contained the password hash verbatim.
func TestParseErrorsDoNotEchoFileContent(t *testing.T) {
	secrets := []struct {
		name, doc, secret string
	}{
		{"shadow-shaped",
			"root:$6$saltsalt$VERYSECRETHASHVALUE0123456789:19000:0:99999:7::\ndaemon:*:19000:0:99999:7::\n",
			"VERYSECRETHASHVALUE0123456789"},
		{"private key PEM",
			"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQSECRETKEYBYTES\n-----END PRIVATE KEY-----\n",
			"SECRETKEYBYTES"},
		{"env file",
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\n",
			"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"},
		{"token in a map",
			"version: 1\napi_token: ghp_SUPERSECRETTOKENVALUE123456\n",
			"ghp_SUPERSECRETTOKENVALUE123456"},
	}
	for _, s := range secrets {
		t.Run(s.name, func(t *testing.T) {
			_, err := Parse([]byte(s.doc))
			if err == nil {
				t.Fatal("a non-scope document was accepted")
			}
			if strings.Contains(err.Error(), s.secret) {
				t.Fatalf("the error echoed file content: %q", err)
			}
			// A prefix of the secret is a leak too.
			if len(s.secret) > 12 && strings.Contains(err.Error(), s.secret[:12]) {
				t.Fatalf("the error echoed a prefix of file content: %q", err)
			}
		})
	}
}

// The sanitised error must still be USEFUL: a line number is what an operator
// needs to fix their file, and an error with no information at all would be
// traded for a support ticket.
func TestSanitisedErrorsStillNameTheLine(t *testing.T) {
	_, err := Parse([]byte("version: 1\ncidrs: [10.0.0.0/8]\nbogus_field: x\n"))
	if err == nil {
		t.Fatal("unknown field accepted")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Fatalf("the error does not name the offending line: %q", err)
	}
}
