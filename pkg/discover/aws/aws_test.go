package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
)

// AWS-001: the confused-deputy defence is required, not optional.
func TestNewRequiresRoleAndExternalID(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"no role", Options{ExternalID: "x", Regions: []string{"us-east-1"}}, "role ARN is required"},
		{"no external id", Options{RoleARN: "arn:aws:iam::1:role/r", Regions: []string{"us-east-1"}}, "external ID is required"},
		{"no regions", Options{RoleARN: "arn:aws:iam::1:role/r", ExternalID: "x"}, "region is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(ctx, tc.opts)
			if err == nil {
				t.Fatal("accepted incomplete options")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// AWS-006: a refused call becomes a VISIBLE coverage gap, with an explanation a
// customer can act on — not a silent short list.
func TestFailureBecomesAnActionableGap(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{"AccessDenied", "not granted"},
		{"AccessDeniedException", "not granted"},
		{"ThrottlingException", "throttled"},
		{"SignatureDoesNotMatch", "clock skew"},
		{"OptInRequired", "not enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			err := &smithy.GenericAPIError{Code: tc.code, Message: "boom"}
			gap, ok := describeFailure("eu-west-1", "acm", "ListCertificates", err)
			if !ok {
				t.Fatal("no gap produced for a failure")
			}
			if !strings.Contains(gap.Reason, tc.want) {
				t.Fatalf("reason %q does not explain the problem in terms a customer can act on (want %q)",
					gap.Reason, tc.want)
			}
			if gap.Region != "eu-west-1" || gap.Service != "acm" || gap.Call != "ListCertificates" {
				t.Fatalf("gap does not say where it happened: %+v", gap)
			}
		})
	}
	if _, ok := describeFailure("r", "s", "c", nil); ok {
		t.Error("a nil error produced a gap")
	}
	// An unmodelled error must still produce a gap, not be swallowed.
	if _, ok := describeFailure("r", "s", "c", errors.New("something odd")); !ok {
		t.Error("an unrecognised error was swallowed instead of becoming a gap")
	}
}

func TestRequiredActionsIsTheCompleteList(t *testing.T) {
	got := RequiredActions()
	if len(got) != 11 {
		t.Fatalf("RequiredActions has %d entries, want 11. If the code genuinely needs another "+
			"API, add it to the policy file and its README in the same change", len(got))
	}
	for _, a := range got {
		if !strings.Contains(a, ":") {
			t.Fatalf("malformed action %q", a)
		}
	}
}

func TestDedupeEndpoints(t *testing.T) {
	got := dedupeEndpoints([]string{"B.example:443", "b.example:443", " a.example:443 ", "", "a.example:443"})
	if len(got) != 2 || got[0] != "a.example:443" || got[1] != "b.example:443" {
		t.Fatalf("dedupeEndpoints = %v", got)
	}
}

func TestKnownEndpointsAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	r := &Result{Certificates: []Finding{
		{DomainName: "a.example", Endpoints: []string{"a.example:443"}, NotAfter: now.AddDate(0, 0, 10)},
		{DomainName: "b.example", Endpoints: []string{"b.example:443"}, NotAfter: now.AddDate(1, 0, 0)},
		{DomainName: "c.example", Endpoints: []string{"a.example:443"}},
	}}
	if eps := r.KnownEndpoints(); len(eps) != 2 {
		t.Fatalf("KnownEndpoints = %v, want 2 unique", eps)
	}
	if exp := r.ExpiringWithin(30*24*time.Hour, now); len(exp) != 1 {
		t.Fatalf("ExpiringWithin(30d) = %d, want 1", len(exp))
	}
	// A finding with no expiry must not be counted as expiring.
	if exp := r.ExpiringWithin(100*365*24*time.Hour, now); len(exp) != 2 {
		t.Fatalf("a finding with no notAfter was counted as expiring: %d", len(exp))
	}
}
