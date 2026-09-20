# Dependencies — every non-stdlib import, and why

**Rule (development plan §29):** do not introduce an external library when the
standard library is sufficient. Every dependency below is recorded with what it
does, why stdlib is insufficient, and what its compromise would mean.

The collector is a static binary that runs inside customer networks. Every
dependency is a supply-chain question a security reviewer is entitled to ask,
and "we needed a token bucket" is not a good answer to it.

## Current state

| Binary | External modules | Why |
|---|---|---|
| **`certscan`** | **2** — `golang.org/x/net/idna`, `golang.org/x/text` | IDN normalisation of SANs. Both are maintained by the Go team under the same review process as the standard library |
| `certscan-aws` | ~30 (the AWS SDK) | Separate binary precisely so `certscan` does not carry them |

`make deps-check` fails the build if `certscan` gains a module outside that
allowlist. The split exists because "read the source, it has two dependencies"
is worth a great deal in a first security review, and thirty modules for an
optional feature is exactly the objection `project_1_security_model.md` §6
anticipated.

An earlier draft of the README claimed `certscan` had ZERO dependencies. That
was false — `deps-check` caught it — and the claim is corrected rather than the
check relaxed.

Things deliberately NOT taken as dependencies:

| Not used | Would have provided | Written instead | Lines |
|---|---|---|---|
| `golang.org/x/time/rate` | Token-bucket rate limiter | `pkg/scan/ratelimit.go` | ~60 |
| `golang.org/x/sys/unix` | `O_NOFOLLOW` | `syscall.O_NOFOLLOW` (stdlib) | 0 |
| `github.com/spf13/cobra` | CLI framework | `flag` (stdlib) | 0 |
| `github.com/sirupsen/logrus`, `go.uber.org/zap` | Structured logging | `pkg/safelog` over `log/slog` | ~120 |
| `github.com/stretchr/testify` | Assertions | table-driven tests with `t.Fatalf` | 0 |

`ANALYSIS` The logging case is the one worth stating. A general logging library
accepts `any`, which is exactly what INV-3 forbids: it would make "no []byte at
a log call site" a lint rule rather than a compile error. `pkg/safelog` exists so
the boundary is structural. That is worth 120 lines.

## Planned, with justification

These land at the build items shown. Each is recorded here **before** it is added
so the decision is reviewable rather than incidental.

### `gopkg.in/yaml.v3` — build item 031 (`SCOPE-001`)

| | |
|---|---|
| **Purpose** | Parse the customer-authored `scope.yaml` |
| **Why stdlib is insufficient** | Go has no YAML parser. `encoding/json` cannot read YAML |
| **Alternatives considered** | (a) Require JSON instead. Rejected: `scope.yaml` is the file a customer's platform engineer edits by hand, and a format without comments is hostile for a security-relevant config file. (b) `sigs.k8s.io/yaml`, which converts YAML→JSON: pulls in more, for less |
| **Security considerations** | Widely used, maintained by the Go YAML maintainers, no known parser-level RCE class (unlike some other languages' YAML loaders — Go's has no arbitrary type instantiation). It parses **customer-authored local config**, not remote input, so the attack surface is a customer attacking themselves |
| **Blast radius if compromised** | Would run at collector start-up with the collector's privileges. Mitigated by: pinned version in `go.sum`, `govulncheck` blocking on HIGH, SBOM diffed per release, and the file being read through `safeio.ReadConfigFile` with a 256 KiB cap |

### `golang.org/x/net/idna` — build item 026 (`X509-004`)

| | |
|---|---|
| **Purpose** | IDN → punycode normalisation of dNSName SANs |
| **Why stdlib is insufficient** | Go has no IDNA implementation in the standard library. Hand-rolling IDNA2008 + UTS-46 is a correctness minefield, and getting it wrong means either missing a certificate or matching the wrong hostname |
| **Alternatives considered** | Store SANs verbatim and never normalise. Rejected: two observations of the same certificate must produce equivalent canonical data, and `xn--` vs unicode forms would break that |
| **Security considerations** | Maintained by the Go team under `golang.org/x/`, same review process as the standard library. Parses **untrusted input** (SAN values from hostile certificates), so it is in the fuzz corpus |
| **Blast radius if compromised** | High — it processes attacker-controlled bytes. Mitigated by fuzzing `x509norm.Parse` end to end, and by the fact that a normalisation failure degrades a certificate to `parse_status=partial` rather than crashing |

### AWS SDK for Go v2 — build items 050–057

Modules: `aws-sdk-go-v2`, `config`, `credentials`, `service/acm`,
`service/elasticloadbalancingv2`, `service/elasticloadbalancing`,
`service/cloudfront`, `service/iam`, `service/apigateway`, `service/sts`.

| | |
|---|---|
| **Purpose** | Read-only enumeration of ACM, ELB, CloudFront, IAM server certificates and API Gateway custom domains |
| **Why stdlib is insufficient** | AWS SigV4 request signing, credential-chain resolution, regional endpoint resolution, pagination and adaptive retry. Reimplementing SigV4 correctly is possible and would be a mistake: a signing bug is a hard-to-diagnose auth failure in a customer's account |
| **Alternatives considered** | Hand-rolled SigV4 over `net/http`. Rejected on the above. Shelling out to the `aws` CLI. **Rejected absolutely** — it would require `os/exec`, which threat T1 and principle P5 forbid outright |
| **Security considerations** | Official AWS SDK, actively maintained, large but well-reviewed. The collector uses its **own instance credentials** to assume a customer role; the control plane stores no AWS credentials at all |
| **Blast radius if compromised** | Bounded by the IAM policy, which contains **zero write verbs** and is asserted so by a fixture test that fails the build. A compromised SDK could read what the policy allows — certificate metadata — and nothing else |
| **Size note** | `project_1_security_model.md` §6: if binary size or dependency count becomes a review objection, cloud enumeration moves to a **separate optional binary** rather than compromising the core scanner's minimalism. The package boundary (`pkg/discover/aws`) is drawn so that split costs one build-tag |

## Rules for adding a dependency

1. Record it here **before** adding it, with all five rows filled in.
2. Pin it in `go.sum`; `GOFLAGS=-mod=readonly` is set repo-wide.
3. `govulncheck` blocks on HIGH.
4. The SBOM is diffed against the previous release; an unexpected addition fails the build.
5. If it parses untrusted input, it goes in the fuzz corpus.

---

## A note on document references

Names like `decision_register.md`, `product_specification.md` and
`project_1_security_model.md` appear throughout this repository as **citations to internal
planning documents**. Those documents are not part of the open-source distribution and no
file of that name exists here — the reference records *why* a decision was made and where
the reasoning lives, not a file you can open.

Everything needed to build, test and audit this code is in the repository. The shipped
documents are `../README.md`, `../CODEMAP.md`, `security-model.md` and this file.
