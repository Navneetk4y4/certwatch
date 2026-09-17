package aws

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// AWS-007, written BEFORE the enumerators.
//
// The policy is the artefact a security reviewer actually reads. A test that
// fails the build if it gains a write verb means the answer to "can this thing
// change anything in my account?" is checked by CI rather than by our word —
// and it means a write action cannot be added quietly alongside the code that
// would use it.
func TestIAMPolicyContainsNoWriteVerbs(t *testing.T) {
	raw, err := os.ReadFile("policy/certscan-readonly.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid      string   `json:"Sid"`
			Effect   string   `json:"Effect"`
			Action   []string `json:"Action"`
			Resource any      `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the policy is not valid JSON: %v", err)
	}
	if len(doc.Statement) == 0 {
		t.Fatal("the policy has no statements")
	}

	// Verbs that only ever read. Anything outside this set must be justified
	// here, in a diff, before it can ship.
	readOnlyPrefixes := []string{"List", "Describe", "Get", "Search", "Batch Get"}

	for _, st := range doc.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			t.Fatalf("unexpected effect %q", st.Effect)
		}
		for _, action := range st.Action {
			if action == "*" || strings.HasSuffix(action, ":*") {
				t.Fatalf("wildcard action %q: the policy must name every action it needs", action)
			}
			service, verb, ok := strings.Cut(action, ":")
			if !ok {
				t.Fatalf("malformed action %q", action)
			}

			// apigateway uses HTTP verbs rather than API names.
			if service == "apigateway" {
				if verb != "GET" && verb != "HEAD" {
					t.Fatalf("apigateway action %q is not read-only", action)
				}
				continue
			}

			readOnly := false
			for _, p := range readOnlyPrefixes {
				if strings.HasPrefix(verb, p) {
					readOnly = true
					break
				}
			}
			if !readOnly {
				t.Fatalf("action %q is not a read-only verb. The product has NO write path "+
					"(decision_register.md D2/C2); a write action here would contradict the "+
					"entire security model", action)
			}
		}
	}
}

// acm:GetCertificate is excluded deliberately. It reads from a service that
// also stores private keys, and its presence in the policy invites exactly the
// question the architecture exists to avoid.
func TestPolicyExcludesGetCertificate(t *testing.T) {
	raw, err := os.ReadFile("policy/certscan-readonly.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "acm:GetCertificate") {
		t.Fatal("acm:GetCertificate is present. It is excluded deliberately: it reads from a " +
			"service that also stores private keys, and asking for it invites the question " +
			"the read-only architecture exists to avoid. See policy/README.md")
	}
}

// Services the product has no business touching must never appear.
func TestPolicyExcludesUnrelatedServices(t *testing.T) {
	raw, err := os.ReadFile("policy/certscan-readonly.json")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, forbidden := range []string{
		"kms:", "secretsmanager:", "ssm:", "s3:", "ec2:", "lambda:", "rds:",
		"dynamodb:", "iam:Create", "iam:Put", "iam:Delete", "iam:Update",
		"sts:AssumeRole", // the trust policy grants this; the permission policy must not
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the policy mentions %q, which certwatch has no business touching", forbidden)
		}
	}
}

// Every action in the policy must be one the code actually calls, and every
// call the code makes must be in the policy. A policy asking for more than the
// code needs is a policy a reviewer is right to reject.
func TestPolicyMatchesTheCallsWeMake(t *testing.T) {
	raw, err := os.ReadFile("policy/certscan-readonly.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range RequiredActions() {
		if !strings.Contains(string(raw), `"`+action+`"`) {
			t.Fatalf("the code calls %q but the policy does not grant it; "+
				"a customer following our instructions would get AccessDenied", action)
		}
	}
	var doc struct {
		Statement []struct {
			Action []string `json:"Action"`
		} `json:"Statement"`
	}
	_ = json.Unmarshal(raw, &doc)
	required := map[string]bool{}
	for _, a := range RequiredActions() {
		required[a] = true
	}
	for _, st := range doc.Statement {
		for _, a := range st.Action {
			if !required[a] {
				t.Fatalf("the policy grants %q but no code path calls it; "+
					"asking for more than we need is what a reviewer rejects", a)
			}
		}
	}
}
