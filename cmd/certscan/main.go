// Command certscan finds TLS certificates across a network range, a list of
// hostnames, and local certificate directories — and writes a local report.
//
// # It sends nothing anywhere
//
// There is no telemetry, no phone-home, no update check, and no account. In
// scan-only mode the only outbound connections are to the targets you name.
// With --check-public-dns it additionally queries 1.1.1.1 and 8.8.8.8 to
// determine which findings are reachable from the internet; that is the ONLY
// other outbound traffic and it is off by default.
//
// You can verify all of this by reading pkg/scan and this file. There is no
// other network code in the binary.
//
// # It never reads a private key
//
// All file access goes through pkg/safeio, which opens only .pem, .crt, .cer
// and .der files, never follows a symlink, and skips any PEM block or DER blob
// that is or might be private-key material. A CI check fails the build if any
// other package opens a file. See docs/security-model.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/certwatch/certwatch/pkg/safelog"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "0.1.0-dev"

const usage = `certscan %s — find TLS certificates across your estate.

This tool SENDS NOTHING ANYWHERE. It writes a local report and exits.

USAGE
  certscan [flags]

WHAT TO SCAN  (at least one is required)
  --cidr        CIDR range(s) to scan, comma-separated.   e.g. 10.20.0.0/22
  --hosts       Hostname(s) to check, comma-separated.    e.g. api.example.com
  --hosts-file  File containing one hostname per line.
  --dirs        Local directories to read certificates from, comma-separated.
  --scope       Path to a scope.yaml describing all of the above.

HOW TO SCAN
  --ports       Ports to probe (default 443,8443,9443,636,993,995,5671,8883).
  --rate        Max TLS handshakes per second (default 50, max 500).
  --concurrency Max simultaneous connections (default 20).
  --timeout     Overall deadline for the run (default 30m).

SAFETY
  --dry-run     Print what WOULD be scanned and send zero packets.
                Run this first against any range you have not scanned before.
  --check-public-dns
                Query public DNS resolvers to determine which findings are
                reachable from the internet. OFF by default; this is the only
                outbound traffic besides the targets themselves.

VERIFY  (the core capability)
  --verify FILE Verify each endpoint in FILE against its expected certificate,
                checking EVERY resolved IP separately. Detects partial rollout:
                some load-balancer members updated, some not.
  --propose-expectations FILE
                After a scan, write a proposed expectations file from what was
                found. Every entry starts UNCONFIRMED and cannot alert until a
                human confirms it.

OUTPUT
  --out         Write the JSON report here (default: stdout).
  --html FILE   Write a self-contained HTML report (no external assets).
  --format      json or csv (default json).
  --label       A label for this environment, recorded in the report so results
                from different environments can be compared.
  --log-level   debug, info, warn, error (default info). Logs go to stderr.

EXAMPLES
  # First run against a new range: see the targets, send nothing.
  certscan --cidr 10.20.0.0/22 --dry-run

  # Scan it for real, writing a report.
  certscan --cidr 10.20.0.0/22 --out report.json

  # Check named hosts and read a certificate directory.
  certscan --hosts api.example.com,vpn.example.com --dirs /etc/ssl/certs

  # The core loop: discover, propose expectations, confirm them, then verify.
  certscan --cidr 10.20.0.0/22 --propose-expectations expected.json
  $EDITOR expected.json                      # set "confirmed": true
  certscan --verify expected.json --html report.html

WHAT THIS TOOL DOES NOT DO
  It completes a TLS handshake and closes the connection. It sends no
  application-layer data. It does not probe for vulnerabilities, grab banners,
  test cipher suites, enumerate subdomains, or read private keys.

`

type options struct {
	cidrs       string
	hosts       string
	hostsFile   string
	dirs        string
	scopeFile   string
	ports       string
	rate        int
	concurrency int
	timeout     time.Duration
	dryRun      bool
	checkPublic bool
	out         string
	format      string
	label       string
	logLevel    string
	showVersion bool
	verifyFile  string
	htmlOut     string
	proposeOut  string
}

func main() {
	opt := parseFlags()

	if opt.showVersion {
		fmt.Printf("certscan %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	lvl, ok := safelog.ParseLevel(opt.logLevel)
	if !ok {
		fmt.Fprintf(os.Stderr, "certscan: unknown --log-level %q (want debug, info, warn or error)\n", opt.logLevel)
		os.Exit(2)
	}
	log := safelog.NewStderr(lvl)

	ctx, cancel := context.WithTimeout(context.Background(), opt.timeout)
	defer cancel()
	ctx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	runner := run
	if opt.verifyFile != "" {
		runner = runVerify
	}
	if err := runner(ctx, opt, log); err != nil {
		log.Error("scan failed", safelog.Err(err))
		fmt.Fprintf(os.Stderr, "certscan: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	var o options
	fs := flag.NewFlagSet("certscan", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, Version) }

	fs.StringVar(&o.cidrs, "cidr", "", "CIDR range(s) to scan, comma-separated")
	fs.StringVar(&o.hosts, "hosts", "", "hostname(s) to check, comma-separated")
	fs.StringVar(&o.hostsFile, "hosts-file", "", "file containing one hostname per line")
	fs.StringVar(&o.dirs, "dirs", "", "local certificate directories, comma-separated")
	fs.StringVar(&o.scopeFile, "scope", "", "path to scope.yaml")
	fs.StringVar(&o.ports, "ports", "", "ports to probe, comma-separated")
	fs.IntVar(&o.rate, "rate", 0, "max TLS handshakes per second")
	fs.IntVar(&o.concurrency, "concurrency", 0, "max simultaneous connections")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Minute, "overall deadline")
	fs.BoolVar(&o.dryRun, "dry-run", false, "print targets and send zero packets")
	fs.BoolVar(&o.checkPublic, "check-public-dns", false, "query public resolvers for reachability")
	fs.StringVar(&o.out, "out", "", "write the report here (default stdout)")
	fs.StringVar(&o.format, "format", "json", "json or csv")
	fs.StringVar(&o.label, "label", "", "environment label recorded in the report")
	fs.StringVar(&o.logLevel, "log-level", "info", "debug, info, warn or error")
	fs.BoolVar(&o.showVersion, "version", false, "print the version and exit")
	fs.StringVar(&o.verifyFile, "verify", "", "verify endpoints against an expectations file")
	fs.StringVar(&o.htmlOut, "html", "", "write a self-contained HTML report here")
	fs.StringVar(&o.proposeOut, "propose-expectations", "", "write a proposed expectations file from what was found")

	_ = fs.Parse(os.Args[1:])
	o.format = strings.ToLower(strings.TrimSpace(o.format))
	return o
}
