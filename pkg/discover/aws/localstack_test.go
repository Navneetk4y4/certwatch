//go:build localstack

package aws

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// AWS-008: the LocalStack integration suite.
//
// Behind a build tag because it needs a running container. Run it with:
//
//	docker compose -f test/lab/docker-compose.aws.yml up -d
//	go test ./pkg/discover/aws/ -tags=localstack -count=1
//
// EXECUTED 2026-09-20 against localstack/localstack:3.8. All four tests pass.
//
// First run exposed something the suite could not have told us before: with an
// empty LocalStack it reported findings=0 gaps=3 and still passed, because
// community LocalStack implements neither elbv2 nor cloudfront. So the suite
// proved that GAPS are handled correctly and proved nothing whatever about
// enumeration finding a certificate.
//
// seedACM below fixes that by importing a real certificate first, and
// TestLocalStackFindsASeededCertificate asserts it comes back. Without that,
// "the AWS suite passes" was a statement about error handling wearing the
// costume of a statement about discovery.

const localstackEndpoint = "http://localhost:4566"

// Seeding is done OUTSIDE this module, by `make lab-aws-seed`, which shells
// out to the aws CLI.
//
// It is deliberately not done here. Importing a certificate is a WRITE, and
// giving the Enumerator — or even this package's test binary — a write client
// would put a write path inside the tree that policy_test.go asserts contains
// none. The read-only guarantee is worth more than the convenience of
// self-seeding tests, so the seeded ARN arrives through the environment.
func seededARN(t *testing.T) string {
	t.Helper()
	arn := os.Getenv("CERTWATCH_SEEDED_ACM_ARN")
	if arn == "" {
		t.Skip("not seeded: run `make lab-aws-seed` and re-run with " +
			"CERTWATCH_SEEDED_ACM_ARN set (it is printed by that target)")
	}
	return arn
}

func requireLocalStack(t *testing.T) {
	t.Helper()
	if os.Getenv("LOCALSTACK_ENDPOINT") != "" {
		return
	}
	c, err := net.DialTimeout("tcp", "localhost:4566", 2*time.Second)
	if err != nil {
		t.Skip("LocalStack is not running: docker compose -f test/lab/docker-compose.aws.yml up -d")
	}
	_ = c.Close()
}

func localEnumerator(t *testing.T) *Enumerator {
	t.Helper()
	requireLocalStack(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")

	e, err := New(context.Background(), Options{
		RoleARN:    "arn:aws:iam::000000000000:role/certwatch-test",
		ExternalID: "test-external-id",
		Regions:    []string{"us-east-1", "eu-west-1"},
		Endpoint:   localstackEndpoint,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// Enumeration must complete and must never return an error for a per-call
// failure: gaps are data, not errors.
func TestLocalStackEnumerationCompletes(t *testing.T) {
	e := localEnumerator(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := e.Enumerate(ctx)
	if err != nil {
		t.Fatalf("Enumerate returned an error; per-call failures must become gaps, not errors: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	t.Logf("findings=%d gaps=%d regions=%v", len(res.Certificates), len(res.Gaps), res.Regions)
	for _, g := range res.Gaps {
		t.Logf("  gap: %s", g)
	}
}

// Two consecutive sweeps must produce the same findings. A sweep that
// duplicates on every run makes the untracked number drift upward, which is the
// number the whole validation programme turns on.
func TestLocalStackEnumerationIsIdempotent(t *testing.T) {
	e := localEnumerator(t)
	ctx := context.Background()

	a, err := e.Enumerate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Enumerate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Certificates) != len(b.Certificates) {
		t.Fatalf("two sweeps found %d then %d certificates; enumeration is not idempotent",
			len(a.Certificates), len(b.Certificates))
	}
	seen := map[string]bool{}
	for _, f := range a.Certificates {
		key := f.Source + "|" + f.ARN + "|" + f.DomainName
		if seen[key] {
			t.Fatalf("duplicate finding within one sweep: %s", key)
		}
		seen[key] = true
	}
}

// A missing permission must produce a visible gap rather than a silent short
// list. LocalStack does not enforce IAM, so this is exercised by pointing at a
// service that is not enabled.
func TestLocalStackPartialFailureProducesAGap(t *testing.T) {
	requireLocalStack(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")

	e, err := New(context.Background(), Options{
		RoleARN:    "arn:aws:iam::000000000000:role/certwatch-test",
		ExternalID: "test-external-id",
		Regions:    []string{"us-east-1"},
		Endpoint:   "http://localhost:4599", // nothing listening
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := e.Enumerate(ctx)
	if err != nil {
		t.Fatalf("Enumerate returned an error instead of recording gaps: %v", err)
	}
	if len(res.Gaps) == 0 {
		t.Fatal("every call failed and NO coverage gap was recorded. " +
			"Presenting an empty enumeration as a complete one is the worst failure this product can have")
	}
	for _, g := range res.Gaps {
		if g.Reason == "" || g.Call == "" {
			t.Fatalf("a gap with no explanation: %+v", g)
		}
	}
}

// KnownEndpoints feeds the untracked-rate calculation, so it must be stable and
// deduplicated.
func TestLocalStackKnownEndpointsAreStable(t *testing.T) {
	e := localEnumerator(t)
	res, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := res.KnownEndpoints()
	b := res.KnownEndpoints()
	if len(a) != len(b) {
		t.Fatal("KnownEndpoints is not stable across calls")
	}
	seen := map[string]bool{}
	for _, ep := range a {
		if seen[ep] {
			t.Fatalf("duplicate endpoint %q", ep)
		}
		seen[ep] = true
	}
}

// The success path, not just the failure path: enumeration must actually
// return a certificate that exists.
func TestLocalStackFindsASeededCertificate(t *testing.T) {
	arn := seededARN(t)
	e := localEnumerator(t)
	t.Logf("expecting to find %s", arn)

	res, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(res.Certificates) == 0 {
		t.Fatalf("enumeration found nothing after a certificate was imported; "+
			"gaps=%d — an empty account makes every other assertion here vacuous",
			len(res.Gaps))
	}
	var found bool
	for _, f := range res.Certificates {
		if f.ARN == arn {
			found = true
		}
	}
	if !found {
		t.Errorf("the seeded certificate %s is not among the %d findings", arn, len(res.Certificates))
	}
}
