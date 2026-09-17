package aws

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A policy check that has never been shown to reject anything is a check nobody
// should trust. This runs the same validation against deliberately-bad policies
// and asserts each is rejected.
//
// Same lesson as the canary: a test that cannot fail protects nothing.
func TestPolicyCheckRejectsBadPolicies(t *testing.T) {
	bad := []struct {
		name   string
		policy string
		why    string
	}{
		{"a write verb", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["acm:ListCertificates","acm:ImportCertificate"],"Resource":"*"}]}`,
			"ImportCertificate writes"},
		{"a listener modification", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["elasticloadbalancing:ModifyListener"],"Resource":"*"}]}`,
			"ModifyListener writes"},
		{"a service wildcard", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["acm:*"],"Resource":"*"}]}`,
			"a wildcard hides whatever AWS adds later"},
		{"a total wildcard", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["*"],"Resource":"*"}]}`,
			"administrator access"},
		{"a delete", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["iam:DeleteServerCertificate"],"Resource":"*"}]}`,
			"DeleteServerCertificate destroys"},
		{"apigateway POST", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["apigateway:POST"],"Resource":"*"}]}`,
			"POST writes"},
		{"kms decrypt", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["kms:Decrypt"],"Resource":"*"}]}`,
			"kms is not ours to touch"},
	}

	dir := t.TempDir()
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "p.json")
			if err := os.WriteFile(path, []byte(tc.policy), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := validatePolicyFile(path); err == nil {
				t.Fatalf("a policy containing %s was accepted (%s)", tc.name, tc.why)
			}
		})
	}

	// And the real policy must pass the same function.
	if err := validatePolicyFile("policy/certscan-readonly.json"); err != nil {
		t.Fatalf("the shipped policy fails its own validation: %v", err)
	}
}

// validatePolicyFile is the shared validation the tests above and
// TestIAMPolicyContainsNoWriteVerbs both exercise.
func validatePolicyFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc struct {
		Statement []struct {
			Effect string   `json:"Effect"`
			Action []string `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	if len(doc.Statement) == 0 {
		return errNoStatements
	}
	readOnlyPrefixes := []string{"List", "Describe", "Get", "Search"}
	forbiddenServices := []string{"kms", "secretsmanager", "ssm", "s3", "ec2", "lambda", "rds", "dynamodb", "sts"}

	for _, st := range doc.Statement {
		for _, action := range st.Action {
			if action == "*" || strings.HasSuffix(action, ":*") {
				return errWildcard
			}
			service, verb, ok := strings.Cut(action, ":")
			if !ok {
				return errMalformed
			}
			for _, f := range forbiddenServices {
				if service == f {
					return errForbiddenService
				}
			}
			if service == "apigateway" {
				if verb != "GET" && verb != "HEAD" {
					return errWriteVerb
				}
				continue
			}
			ok = false
			for _, p := range readOnlyPrefixes {
				if strings.HasPrefix(verb, p) {
					ok = true
					break
				}
			}
			if !ok {
				return errWriteVerb
			}
		}
	}
	return nil
}

type policyError string

func (e policyError) Error() string { return string(e) }

const (
	errNoStatements     = policyError("policy has no statements")
	errWildcard         = policyError("policy contains a wildcard action")
	errMalformed        = policyError("policy contains a malformed action")
	errWriteVerb        = policyError("policy contains a non-read-only verb")
	errForbiddenService = policyError("policy names a service certwatch has no business touching")
)
