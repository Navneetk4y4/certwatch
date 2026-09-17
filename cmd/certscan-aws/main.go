// Command certscan-aws enumerates TLS certificates from AWS, read-only.
//
// # Why this is a separate binary from certscan
//
// The AWS SDK brings roughly thirty modules. `certscan` — the thing you run in
// the first ten minutes — has ZERO runtime dependencies, and "read the source,
// it has no dependencies" is worth a great deal in a first security review.
// Wiring the SDK into it would trade that away for a feature not everyone uses.
//
// Both binaries ship together. Run `certscan` first; run this when you want the
// scan's untracked number computed net of what AWS already knows about.
//
// # It makes no write call of any kind
//
// Eleven read-only APIs, listed in `--show-policy`. A test fails the build if
// the policy file gains an action that is not a List, Describe or Get.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/certwatch/certwatch/pkg/discover/aws"
)

var Version = "0.1.0-dev"

const usage = `certscan-aws %s — enumerate TLS certificates from AWS, read-only.

This tool makes NO write call of any kind. See --show-policy for the exact
permissions it needs and why each one.

USAGE
  certscan-aws --role-arn ARN --external-id ID [flags]

REQUIRED
  --role-arn      The read-only role to assume in the target account.
  --external-id   The external ID your trust policy requires (confused-deputy
                  defence).

OPTIONS
  --regions       Comma-separated regions (default us-east-1).
  --out           Write the JSON result here (default stdout).
  --endpoints-out Write just the endpoint list here, one per line, so it can be
                  fed to "certscan --hosts-file" and verified against reality.
  --show-policy   Print the exact IAM policy to grant, and exit.
  --timeout       Overall deadline (default 10m).

WHY YOU WANT THE ENDPOINT LIST
  Cloud configuration says what SHOULD be served. Only a TLS handshake says what
  IS. Feeding --endpoints-out into certscan checks one against the other:

      certscan-aws --role-arn ... --external-id ... --endpoints-out aws-hosts.txt
      certscan --hosts-file aws-hosts.txt --out verified.json

`

func main() {
	var (
		roleARN      = flag.String("role-arn", "", "role to assume")
		externalID   = flag.String("external-id", "", "external ID")
		regions      = flag.String("regions", "us-east-1", "comma-separated regions")
		out          = flag.String("out", "", "write JSON here")
		endpointsOut = flag.String("endpoints-out", "", "write the endpoint list here")
		showPolicy   = flag.Bool("show-policy", false, "print the IAM policy and exit")
		timeout      = flag.Duration("timeout", 10*time.Minute, "overall deadline")
		showVersion  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = func() { fmt.Fprintf(os.Stderr, usage, Version) }
	flag.Parse()

	if *showVersion {
		fmt.Printf("certscan-aws %s\n", Version)
		return
	}
	if *showPolicy {
		printPolicy()
		return
	}
	if *roleARN == "" || *externalID == "" {
		fmt.Fprintln(os.Stderr, "certscan-aws: --role-arn and --external-id are both required.")
		fmt.Fprintln(os.Stderr, "Run --show-policy to see exactly what to grant.")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	var regionList []string
	for _, r := range strings.Split(*regions, ",") {
		if t := strings.TrimSpace(r); t != "" {
			regionList = append(regionList, t)
		}
	}

	e, err := aws.New(ctx, aws.Options{
		RoleARN: *roleARN, ExternalID: *externalID, Regions: regionList,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "certscan-aws:", err)
		os.Exit(1)
	}

	res, err := e.Enumerate(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "certscan-aws:", err)
		os.Exit(1)
	}

	payload, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "certscan-aws:", err)
		os.Exit(1)
	}
	payload = append(payload, '\n')

	if *out == "" {
		_, _ = os.Stdout.Write(payload)
	} else {
		if err := os.WriteFile(*out, payload, 0o644); err != nil { //nolint:gosec // user-named output
			fmt.Fprintln(os.Stderr, "certscan-aws:", err)
			os.Exit(1)
		}
	}

	if *endpointsOut != "" {
		eps := res.KnownEndpoints()
		var b strings.Builder
		b.WriteString("# endpoints AWS says should exist, from certscan-aws\n")
		b.WriteString("# feed this to: certscan --hosts-file <this file>\n")
		for _, ep := range eps {
			host, _, _ := strings.Cut(ep, ":")
			b.WriteString(host + "\n")
		}
		if err := os.WriteFile(*endpointsOut, []byte(b.String()), 0o644); err != nil { //nolint:gosec
			fmt.Fprintln(os.Stderr, "certscan-aws:", err)
			os.Exit(1)
		}
	}

	printSummary(res, *out, *endpointsOut)
}

func printSummary(res *aws.Result, out, endpointsOut string) {
	w := os.Stderr
	bySource := map[string]int{}
	for _, f := range res.Certificates {
		bySource[f.Source]++
	}
	sources := make([]string, 0, len(bySource))
	for s := range bySource {
		sources = append(sources, s)
	}
	sort.Strings(sources)

	fmt.Fprintf(w, "\n  certscan-aws %s — regions: %s\n\n", Version, strings.Join(res.Regions, ", "))
	fmt.Fprintf(w, "  %-32s %d\n", "certificates found", len(res.Certificates))
	for _, s := range sources {
		fmt.Fprintf(w, "    %-30s %d\n", s, bySource[s])
	}
	fmt.Fprintf(w, "  %-32s %d\n", "endpoints implied", len(res.KnownEndpoints()))

	soon := res.ExpiringWithin(60*24*time.Hour, time.Now().UTC())
	fmt.Fprintf(w, "  %-32s %d\n", "expiring within 60 days", len(soon))

	if len(res.Gaps) > 0 {
		fmt.Fprintf(w, "\n  COVERAGE GAPS — these resources were NOT enumerated\n")
		for _, g := range res.Gaps {
			fmt.Fprintf(w, "  ! %s\n", g)
		}
		fmt.Fprintf(w, "\n  This enumeration is INCOMPLETE. Grant the missing permissions\n")
		fmt.Fprintf(w, "  (certscan-aws --show-policy) and re-run before relying on the count.\n")
	}
	if res.Truncated {
		fmt.Fprintf(w, "\n  ! Stopped at the per-sweep certificate cap; re-run to continue.\n")
	}
	if out != "" {
		fmt.Fprintf(w, "\n  full result written to %s\n", out)
	}
	if endpointsOut != "" {
		fmt.Fprintf(w, "  endpoint list written to %s\n", endpointsOut)
		fmt.Fprintf(w, "\n  Next: verify what is ACTUALLY served on those endpoints —\n")
		fmt.Fprintf(w, "    certscan --hosts-file %s --out verified.json\n", endpointsOut)
	}
	fmt.Fprintf(w, "\n  No write call was made. This tool cannot change anything in your account.\n\n")
}

func printPolicy() {
	fmt.Println(`{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CertwatchReadOnlyDiscovery",
    "Effect": "Allow",
    "Action": [`)
	acts := aws.RequiredActions()
	for i, a := range acts {
		comma := ","
		if i == len(acts)-1 {
			comma = ""
		}
		fmt.Printf("      %q%s\n", a, comma)
	}
	fmt.Println(`    ],
    "Resource": "*"
  }]
}`)
	fmt.Fprintln(os.Stderr, `
Every action above is a List, Describe or Get. There is no write action, and a
test fails the build if one is ever added.

Deliberately NOT requested:
  acm:GetCertificate  — it reads from a service that also stores private keys,
                        and asking for it invites the question the read-only
                        architecture exists to avoid. DescribeCertificate gives
                        us the metadata we need.

Your trust policy must also require the external ID shown to you:
  "Condition": { "StringEquals": { "sts:ExternalId": "<value>" } }

No AWS credential is ever stored by certwatch. The collector assumes this role
using its own instance credentials.`)
}
