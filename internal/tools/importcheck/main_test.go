package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The exception list is the place the private-key boundary has to be re-argued.
// If it grows, this test fails and someone has to justify the growth in a diff.
func TestFileIOExceptionListHasExactlyTwoEntries(t *testing.T) {
	if len(fileIOExceptions) != 2 {
		t.Fatalf("fileIOExceptions has %d entries (%v), want exactly 2: pkg/safeio and internal/spool.\n"+
			"Every entry is a package permitted to open a file. Growing this list needs a recorded decision.",
			len(fileIOExceptions), fileIOExceptions)
	}
	want := map[string]bool{"pkg/safeio": true, "internal/spool": true}
	for _, e := range fileIOExceptions {
		if !want[e] {
			t.Fatalf("unexpected file-I/O exception %q", e)
		}
	}
}

func TestLogExceptionListHasExactlyOneEntry(t *testing.T) {
	if len(logExceptions) != 1 || logExceptions[0] != "pkg/safelog" {
		t.Fatalf("logExceptions = %v, want exactly [pkg/safelog]", logExceptions)
	}
}

// A check that has never been shown to fail is a check nobody should trust.
// Each case below is a file that MUST be rejected.
func TestCheckFileCatchesViolations(t *testing.T) {
	cases := []struct {
		name      string
		rel       string
		src       string
		wantCheck string
	}{
		{
			name: "os/exec import",
			rel:  "pkg/scan/bad.go",
			src: `package scan
import "os/exec"
func run() { _ = exec.Command }`,
			wantCheck: "CI-006",
		},
		{
			name: "os/exec in a test is still banned",
			rel:  "pkg/scan/bad_test.go",
			src: `package scan
import "os/exec"
func run() { _ = exec.Command }`,
			wantCheck: "CI-006",
		},
		{
			name: "os.Open outside safeio",
			rel:  "pkg/x509norm/bad.go",
			src: `package x509norm
import "os"
func read() { _, _ = os.Open("/etc/ssl/private/server.key") }`,
			wantCheck: "CI-007",
		},
		{
			name: "os.ReadFile outside safeio",
			rel:  "internal/scopecfg/bad.go",
			src: `package scopecfg
import "os"
func read() { _, _ = os.ReadFile("/tmp/x") }`,
			wantCheck: "CI-007",
		},
		{
			name: "os.Open under an alias is still caught",
			rel:  "pkg/scan/alias.go",
			src: `package scan
import o "os"
func read() { _, _ = o.Open("/tmp/x") }`,
			wantCheck: "CI-007",
		},
		{
			name: "io/ioutil outside safeio",
			rel:  "pkg/scan/ioutil.go",
			src: `package scan
import "io/ioutil"
func read() { _, _ = ioutil.ReadFile("/tmp/x") }`,
			wantCheck: "CI-007",
		},
		{
			name: "log/slog outside safelog",
			rel:  "pkg/scan/log.go",
			src: `package scan
import "log/slog"
func l() { slog.Info("hello") }`,
			wantCheck: "CI-008",
		},
		{
			name: "standard log outside safelog",
			rel:  "pkg/verify/log.go",
			src: `package verify
import "log"
func l() { log.Println("hello") }`,
			wantCheck: "CI-008",
		},
		{
			name: "fmt.Printf outside cmd",
			rel:  "pkg/scan/print.go",
			src: `package scan
import "fmt"
func l() { fmt.Printf("%v", 1) }`,
			wantCheck: "CI-008",
		},
		{
			name: "cmd/certscan importing internal",
			rel:  "cmd/certscan/bad.go",
			src: `package main
import "github.com/certwatch/certwatch/internal/scopecfg"
var _ = scopecfg.Config{}`,
			wantCheck: "CI-009",
		},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.rel, "/", "_"))
			if err := os.WriteFile(path, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			got := checkFile(path, tc.rel)
			found := false
			for _, f := range got {
				if f.check == tc.wantCheck {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a %s violation for %s, got %+v", tc.wantCheck, tc.rel, got)
			}
		})
	}
}

// And the converse: legitimate code must not be flagged, or the check will be
// disabled by whoever gets tired of the false positives.
func TestCheckFileAllowsLegitimateCode(t *testing.T) {
	cases := []struct{ name, rel, src string }{
		{"safeio may open files", "pkg/safeio/walk.go",
			`package safeio
import "os"
func read() { _, _ = os.Open("/x") }`},
		{"spool may open files", "internal/spool/spool.go",
			`package spool
import "os"
func read() { _, _ = os.Create("/x") }`},
		{"safelog may import slog", "pkg/safelog/safelog.go",
			`package safelog
import "log/slog"
var _ = slog.LevelInfo`},
		{"cmd may print program output", "cmd/certscan/main.go",
			`package main
import "fmt"
func main() { fmt.Println("report") }`},
		{"cmd may import pkg", "cmd/certscan/main.go",
			`package main
import "github.com/certwatch/certwatch/pkg/safeio"
var _ = safeio.DefaultMaxDepth`},
		{"fmt.Sprintf is formatting, not logging", "pkg/scan/fmt.go",
			`package scan
import "fmt"
func s() string { return fmt.Sprintf("%d", 1) }`},
		{"fmt.Errorf is error construction", "pkg/scan/err.go",
			`package scan
import "fmt"
func e() error { return fmt.Errorf("boom") }`},
		{"tests may write fixtures", "pkg/scan/scan_test.go",
			`package scan
import "os"
func t() { _ = os.WriteFile("/tmp/x", nil, 0o644) }`},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.rel, "/", "_"))
			if err := os.WriteFile(path, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := checkFile(path, tc.rel); len(got) != 0 {
				t.Fatalf("false positive on legitimate code: %+v", got)
			}
		})
	}
}
