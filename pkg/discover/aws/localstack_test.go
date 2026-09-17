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
// STATUS AT THE TIME OF WRITING: this suite is WRITTEN BUT NOT EXECUTED. The
// Docker daemon was not running in the development environment, so the
// assertions below have never been observed to pass or fail. They must be run
// before the AWS enumerator is used against a real account, and the milestone
// report says so rather than implying coverage that does not exist.

const localstackEndpoint = "http://localhost:4566"

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
