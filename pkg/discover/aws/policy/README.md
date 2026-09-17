# The AWS policy certwatch asks for

This is the complete list. There is no second policy, and no action is requested
that is not here.

## Every action, and why

| Action | Why it is needed | What it returns |
|---|---|---|
| `acm:ListCertificates` | Enumerate ACM-managed certificates | ARNs and domain names |
| `acm:DescribeCertificate` | Their metadata | Domains, SANs, issuer, validity, **which resources use them** |
| `acm:ListTagsForCertificate` | Ownership attribution | Tags you set |
| `elasticloadbalancing:DescribeLoadBalancers` | Find load balancers | ARNs, DNS names, scheme |
| `elasticloadbalancing:DescribeListeners` | Find TLS listeners | Ports and protocols |
| `elasticloadbalancing:DescribeListenerCertificates` | Which certificate each listener serves | Certificate ARNs, including SNI extras |
| `cloudfront:ListDistributions` | Find distributions | Domain names |
| `cloudfront:GetDistributionConfig` | Their viewer certificate | Certificate ARN or IAM certificate ID |
| `iam:ListServerCertificates` | Legacy uploaded certificates | **Often the oldest and least-tracked in an estate** |
| `iam:GetServerCertificate` | Their certificate body | The **public certificate only** — see below |
| `apigateway:GET` | Custom domain certificates | Domain names and certificate ARNs |

## What is deliberately NOT requested

**`acm:GetCertificate` is excluded.** It would return certificate bodies for
ACM-managed certificates, which would improve coverage slightly. It is excluded
anyway, because it reads from a service that also stores private keys, and its
presence in a policy invites exactly the question this architecture exists to
avoid. The metadata from `DescribeCertificate` is sufficient.

**`iam:GetServerCertificate` is included and is safe.** IAM does not store
retrievable private keys for server certificates; the API returns the
certificate body and chain only. This is the one place a certificate *body* is
read from an API, and it is read from a service that has no key to give.

**No write action of any kind.** No `kms:*`, `secretsmanager:*`, `s3:*`,
`ec2:*`, or `sts:*` beyond the `AssumeRole` your trust policy grants.

A test (`TestIAMPolicyContainsNoWriteVerbs`) fails the build if this file gains
an action that is not a `List`, `Describe`, or `Get`. It was written *before*
the enumerators, so a write verb cannot be added casually along with the code
that would use it.

## How to grant it

Create a role with this policy and a trust policy naming the principal your
collector runs as, plus the `ExternalId` certwatch shows you once:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "<your collector's principal>" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<the value shown to you>" } }
  }]
}
```

**No AWS credentials are ever stored by the control plane.** The collector
assumes this role using its own instance credentials; we hold the role ARN and
the external ID, and nothing else.
