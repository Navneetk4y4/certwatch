package safeio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SAFEIO-001: the four rejection classes plus the symlinked-root case.
func TestNewPolicyRejections(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		roots   []string
		wantErr string
	}{
		{"relative root", []string{"certs"}, "not absolute"},
		{"non-existent root", []string{filepath.Join(dir, "nope")}, "cannot be resolved"},
		{"proc refused", []string{"/proc"}, "refused prefix"},
		{"proc subdir refused", []string{"/proc/self"}, "refused prefix"},
		{"sys refused", []string{"/sys"}, "refused prefix"},
		{"dev refused", []string{"/dev"}, "refused prefix"},
		{"empty", nil, "at least one root"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPolicy(tc.roots, PolicyOptions{})
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// A root that is itself a symlink must resolve to its target and stay bounded
// there. This is the case that makes containment checks meaningful later.
func TestNewPolicySymlinkedRootResolves(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p, err := NewPolicy([]string{link}, PolicyOptions{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	got := p.Roots()
	if len(got) != 1 {
		t.Fatalf("want 1 root, got %v", got)
	}
	resolved, _ := filepath.EvalSymlinks(real)
	if got[0] != resolved {
		t.Fatalf("root = %q, want resolved target %q", got[0], resolved)
	}
}

// Policy must be immutable: mutating the slice a caller received must not widen
// what the policy allows.
func TestPolicyRootsAreACopy(t *testing.T) {
	dir := t.TempDir()
	p := mustPolicy(t, dir, PolicyOptions{})
	roots := p.Roots()
	roots[0] = "/etc/ssl/private"
	if p.Roots()[0] == "/etc/ssl/private" {
		t.Fatal("mutating the returned slice changed the policy")
	}
}

func TestContainsRejectsEscape(t *testing.T) {
	cases := []struct {
		root, candidate string
		want            bool
	}{
		{"/a/b", "/a/b", true},
		{"/a/b", "/a/b/c", true},
		{"/a/b", "/a/b/c/d.pem", true},
		{"/a/b", "/a/c", false},
		{"/a/b", "/a", false},
		{"/a/b", "/a/b/../c", false},
		{"/a/b", "/a/bb", false},
	}
	for _, c := range cases {
		if got := Contains(c.root, c.candidate); got != c.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", c.root, c.candidate, got, c.want)
		}
	}
}

// SAFEIO-003: the extension gate, case-insensitively, before any open.
func TestExtensionDecision(t *testing.T) {
	cases := []struct {
		name    string
		allowed bool
	}{
		{"server.pem", true}, {"chain.crt", true}, {"c.cer", true}, {"c.der", true},
		{"SERVER.PEM", true}, {"CHAIN.CRT", true},
		{"server.key", false}, {"server.KEY", false},
		{"store.p12", false}, {"store.P12", false}, {"store.pfx", false},
		{"store.jks", false}, {"store.jceks", false}, {"store.bks", false}, {"store.keystore", false},
		{"id_rsa", false},       // extensionless
		{"cert.pem.bak", false}, // final extension only
		{"key.p8", false}, {"key.pk8", false},
		{"notes.txt", false}, {"archive.tar.gz", false},
	}
	for _, c := range cases {
		got, reason := extensionDecision(c.name)
		if got != c.allowed {
			t.Errorf("extensionDecision(%q) = %v (%s), want %v", c.name, got, reason, c.allowed)
		}
	}
}

// ReadConfigFile must refuse anything that could carry key material, and must
// refuse symlinks — it is not a general file reader.
func TestReadConfigFileRefusals(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "scope.yaml")
	writeFile(t, good, []byte("roots: []\n"))

	if b, err := ReadConfigFile(good); err != nil || len(b) == 0 {
		t.Fatalf("ReadConfigFile(good) = %v, %v", len(b), err)
	}
	if _, err := ReadConfigFile("scope.yaml"); err == nil {
		t.Error("relative path accepted")
	}
	keyFile := filepath.Join(dir, "server.key")
	writeFile(t, keyFile, []byte("-----BEGIN PRIVATE KEY-----\n"))
	if _, err := ReadConfigFile(keyFile); err == nil {
		t.Error("ReadConfigFile opened a .key file")
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(good, link); err == nil {
		if _, err := ReadConfigFile(link); err == nil {
			t.Error("ReadConfigFile followed a symlink")
		}
	}
	big := filepath.Join(dir, "big.yaml")
	writeFile(t, big, make([]byte, MaxConfigBytes+1))
	if _, err := ReadConfigFile(big); err == nil {
		t.Error("ReadConfigFile accepted an oversized file")
	}
}
