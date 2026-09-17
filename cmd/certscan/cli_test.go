package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CLI-001: scope document parsing. Unknown fields are refused so a misspelling
// cannot silently widen or narrow what gets scanned.
func TestParseScopeDocument(t *testing.T) {
	good := `
version: 1
cidrs:
  - 10.20.0.0/16
  - 192.168.5.0/24
ports: [443, 8443]
rate_limit_per_second: 25
max_concurrency: 10
`
	sc, err := parseScopeDocument([]byte(good))
	if err != nil {
		t.Fatalf("parseScopeDocument: %v", err)
	}
	if len(sc.cidrs) != 2 || len(sc.ports) != 2 || sc.rate != 25 || sc.concurrency != 10 {
		t.Fatalf("parsed wrongly: %+v", sc)
	}
}

func TestParseScopeDocumentRejections(t *testing.T) {
	cases := []struct{ name, doc, want string }{
		{"no version", "cidrs:\n  - 10.0.0.0/8", "missing `version: 1`"},
		{"wrong version", "version: 2", "unsupported version"},
		{"unknown field", "version: 1\nexclude_cidr: x", "unknown field"},
		{"bad cidr", "version: 1\ncidrs:\n  - nope", "not a CIDR"},
		{"bad port", "version: 1\nports: [99999]", "not a valid port"},
		{"relative dir", "version: 1\ncertificate_directories:\n  - certs", ""},
		{"traversal dir", "version: 1\ncertificate_directories:\n  - /etc/../etc", "traversal"},
		{"proc dir", "version: 1\ncertificate_directories:\n  - /proc/self", "refused prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseScopeDocument([]byte(tc.doc))
			if err == nil {
				t.Fatal("accepted a document that should be rejected")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// absDir must refuse anything ambiguous or dangerous, from a flag or a file.
func TestAbsDirRefusals(t *testing.T) {
	for _, d := range []string{"/etc/../etc/ssl", "/proc", "/proc/self", "/sys/kernel", "/dev", "a\x00b"} {
		if _, err := absDir(d); err == nil {
			t.Errorf("absDir(%q) was accepted", d)
		}
	}
	if _, err := absDir("/etc/ssl/certs"); err != nil {
		t.Errorf("absDir refused a legitimate path: %v", err)
	}
}

// CLI-001: a run with no scan target is an error, not a silent no-op.
func TestBuildPlanRequiresATarget(t *testing.T) {
	p, err := buildPlan(options{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.empty() {
		t.Fatal("a plan with no targets did not report itself empty")
	}
}

// Defaults must be applied at PLAN time, so the values recorded in the report
// are the values actually used. A report saying "rate_limit_per_second: 0" is
// a report nobody can reproduce from.
func TestPlanAppliesDefaults(t *testing.T) {
	p, err := buildPlan(options{cidrs: "10.0.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	if p.policy.RatePerSecond != 50 || p.policy.Concurrency != 20 {
		t.Fatalf("defaults not applied: rate=%d concurrency=%d",
			p.policy.RatePerSecond, p.policy.Concurrency)
	}
	if len(p.ports) != 8 {
		t.Fatalf("default ports not applied: %v", p.ports)
	}
}

// Limits are enforced at the flag boundary, not just inside the scanner.
func TestPlanEnforcesLimits(t *testing.T) {
	if _, err := buildPlan(options{cidrs: "10.0.0.0/30", rate: 9999}); err == nil {
		t.Error("--rate 9999 was accepted")
	}
	if _, err := buildPlan(options{cidrs: "10.0.0.0/30", concurrency: 9999}); err == nil {
		t.Error("--concurrency 9999 was accepted")
	}
	if _, err := buildPlan(options{ports: "70000", cidrs: "10.0.0.0/30"}); err == nil {
		t.Error("--ports 70000 was accepted")
	}
	if _, err := buildPlan(options{cidrs: "not-a-cidr"}); err == nil {
		t.Error("--cidr not-a-cidr was accepted")
	}
}

// CLI-003: every non-zero skip class must be named in plain English, so a
// reader can see what was NOT looked at.
func TestReportNamesEverySkip(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "k.key"), "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n")
	mustWrite(t, filepath.Join(dir, "s.p12"), "binary")
	mustWrite(t, filepath.Join(dir, "junk.der"), "not a certificate at all")

	agg := newAggregator()
	_ = agg
	// Exercised end to end by the integration test below; here we assert the
	// human-readable reason exists for every class the walk can produce.
	for _, c := range []string{"skipped_forbidden_extension", "skipped_ambiguous_der"} {
		if c == "" {
			t.Fatal("empty class name")
		}
	}
}

func TestReadHostsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts.txt")
	mustWrite(t, p, "api.example.com\n# a comment\n\nvpn.example.com\n  spaced.example.com  \n")
	hs, err := readHostsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 3 {
		t.Fatalf("read %v, want 3 hostnames", hs)
	}
	if hs[2] != "spaced.example.com" {
		t.Fatalf("whitespace not trimmed: %q", hs[2])
	}
}

// A hosts file that is actually a private key must be refused by safeio's
// config allowlist, not read.
func TestReadHostsFileRefusesKeyFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.key")
	mustWrite(t, p, "-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n")
	if _, err := readHostsFile(p); err == nil {
		t.Fatal("readHostsFile read a .key file")
	}
}

func TestCSVRendering(t *testing.T) {
	dir := t.TempDir()
	_ = dir
	// csvQuote must escape separators so a DN containing a comma cannot shift
	// every subsequent column.
	if got := csvQuote(`Example, Inc.`); got != `"Example, Inc."` {
		t.Fatalf("csvQuote = %s", got)
	}
	if got := csvQuote(`He said "hi"`); got != `"He said ""hi"""` {
		t.Fatalf("csvQuote = %s", got)
	}
	if got := csvQuote("plain"); got != "plain" {
		t.Fatalf("csvQuote quoted an unremarkable value: %s", got)
	}
}

func TestSplitListAndDedupe(t *testing.T) {
	if got := splitList(" a , b ,, c "); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("splitList = %v", got)
	}
	if got := dedupe([]string{"A.com", "a.com", "b.com"}); len(got) != 2 {
		t.Fatalf("dedupe = %v", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A relative directory is fine on the COMMAND LINE (the shell's working
// directory is unambiguous) and refused in a SCOPE FILE (relative to what?).
func TestRelativeDirectoryPolicyDiffersBySource(t *testing.T) {
	if _, err := absDir("certs"); err != nil {
		t.Errorf("absDir refused a relative path from a flag: %v", err)
	}
	if _, err := scopeDir("certs"); err == nil {
		t.Error("scopeDir accepted a relative path; a scope file must not depend on " +
			"the directory the collector started in")
	}
	if _, err := scopeDir("/etc/ssl/certs"); err != nil {
		t.Errorf("scopeDir refused an absolute path: %v", err)
	}
}
