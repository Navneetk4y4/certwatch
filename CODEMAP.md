# CODEMAP — every code file, where it is, and what it does

Generated 2026-09-20 from the source itself (package and declaration doc comments), not from
memory. **Code files only** — planning and product documents live in `../project_1/`.

**77 Go files · 15,258 lines** — 40 source files (8,890 L), 37 test files (6,368 L).

| Package | Source | Tests | What it is |
|---|---|---|---|
| `cmd/certscan` | 7 / 1,724 L | 3 / 743 L | The main binary |
| `cmd/certscan-aws` | 1 / 233 L | — | The AWS binary |
| `pkg/safeio` | 8 / 1,392 L | 10 / 1,245 L | The private-key boundary |
| `pkg/verify` | 2 / 990 L | 2 / 936 L | **The product**: expected vs actual, per IP |
| `pkg/x509norm` | 4 / 898 L | 7 / 883 L | Certificate parsing and normalisation |
| `pkg/scan` | 6 / 880 L | 5 / 927 L | TLS discovery and the SSRF defence |
| `pkg/discover/aws` | 2 / 665 L | 4 / 555 L | Read-only AWS enumeration |
| `test/corpus` | 2 / 497 L | 1 / 50 L | Generated certificate corpus |
| `internal/scopecfg` | 2 / 450 L | 1 / 306 L | scope.yaml — what the collector may touch |
| `test/canary` | 1 / 368 L | 2 / 314 L | The security canary |
| `internal/tools/importcheck` | 1 / 340 L | 1 / 262 L | CI-blocking structural checks |
| `pkg/model` | 2 / 251 L | — | Canonical wire types |
| `pkg/safelog` | 1 / 169 L | 1 / 147 L | The only logging path |
| `internal/tools/gencorpus` | 1 / 33 L | — | Corpus regeneration command |

---

## The four files to read first

If you only read four files, read these. They carry the architecture; everything else
serves them.

| File | Why |
|---|---|
| `pkg/verify/expectation.go` | The product's thesis, stated in the package comment: a hostname-level monitor connects once, gets whichever address answers, and reports healthy while half the traffic hits the wrong certificate |
| `pkg/safeio/doc.go` | INV-1 — the only code permitted to open a file, and why that is mechanical rather than documentary |
| `pkg/scan/scan.go` | What the scanner deliberately does **not** do: zero application-layer bytes, no banner grab, no CVE probe |
| `internal/tools/importcheck/main.go` | The four boundaries that cannot be retrofitted, enforced as build failures |

---

## `cmd/certscan` — the main binary (7 files, 1,724 L)

Zero runtime dependencies. This is the thing a prospect runs in the first ten minutes.

| File | L | Purpose |
|---|---|---|
| `main.go` | 204 | Entry point, flag definitions, help text. Package comment states the no-telemetry claim: no phone-home, no update check, no account. `--check-public-dns` is the only other outbound traffic and is off by default |
| `run.go` | 484 | Builds the scan plan and executes it. `expandTargets` turns CIDRs and hostnames into concrete targets; resolution failures become **notes, not silent drops** — an unchecked hostname is a coverage gap the reader must see |
| `verifycmd.go` | 319 | `--verify` and `--propose-expectations`. Defines `ExpectationFile` (the on-disk expected state — a file rather than a database, so a customer can read, diff and commit it), `VerifyReport`, `VerifySummary` |
| `aggregate.go` | 280 | Deduplicates certificates by fingerprint and builds the summary counts the validation programme turns on |
| `html.go` | 212 | `renderVerifyHTML` — a self-contained report. No CDN, no external font, no analytics, no script. Openable on an air-gapped laptop; a remote asset would quietly falsify the product's central promise |
| `scopedoc.go` | 182 | A minimal line-oriented `scope.yaml` reader. Deliberately duplicates `internal/scopecfg` because CI-009 forbids the OSS binary from importing `internal/` — the cost is this file, the benefit is that the published binary provably contains no commercial code |
| `hosts.go` | 43 | Reads a hostnames file through `safeio` so all file access in the binary stays inside the boundary |

**Tests (3 / 743 L)**

| File | L | Covers |
|---|---|---|
| `cli_test.go` | 203 | 12 tests — scope parsing, unknown-field refusal, plan limits, hosts-file key refusal |
| `divergence_test.go` | 322 | 4 tests — per-IP divergence across **real distinct IPs**, and `TestHostnameLevelMonitorWouldMissIt`, which proves the failure the product exists to catch |
| `verify_e2e_test.go` | 218 | 3 tests — end to end: expectation → distinct IPs → real handshakes → per-IP comparison → partial rollout → JSON → HTML |

---

## `cmd/certscan-aws` — the AWS binary (1 file, 233 L)

| File | L | Purpose |
|---|---|---|
| `main.go` | 233 | Separate binary on purpose: the AWS SDK brings ~30 modules, and *"read the source, it has no dependencies"* is worth a great deal in a first security review. Eleven read-only APIs, listed by `--show-policy` |

---

## `pkg/verify` — the product (2 files, 990 L)

Compares what an endpoint **should** serve against what **every one of its resolved IPs
actually** serves. Everything else exists to feed this comparison.

| File | L | Purpose |
|---|---|---|
| `classify.go` | 701 | `Classify` — a **pure** function of (expectation, probes, now). The ordered decision table producing MATCH / DRIFT / PARTIAL_ROLLOUT / WARNING / UNKNOWN / UNREACHABLE, per-IP evidence rows, grace windows, and the sub-reasons an operator actually acts on |
| `expectation.go` | 289 | The expected-state model: pinned and policy modes, `Validate`, `Describe`, `NormaliseFingerprint` (accepts openssl's uppercase colon form), `SANCovers`, `InferMode` |

**Tests (2 / 936 L)**

| File | L | Covers |
|---|---|---|
| `classify_test.go` | 566 | 20 tests — match, complete drift, partial rollout (including three-of-four, to catch an off-by-one that only triggers at exactly half), policy-mode compliance and divergence |
| `regression_test.go` | 370 | **14 tests, one per defect found by attacking the classifier.** Each is named for the consequence it prevents: a future `EffectiveFrom` that suppressed alerts forever, a grace window that silenced expired certificates, a SAN check whose comment claimed it existed when it did not |

---

## `pkg/safeio` — the private-key boundary (8 files, 1,392 L)

**INV-1:** the collector must never transmit bytes that parse as private-key material. The
only package permitted to open a file; `importcheck` fails the build if `os.Open` and friends
appear anywhere else.

| File | L | Purpose |
|---|---|---|
| `pem.go` | 329 | Streams PEM one line at a time. **INV-2:** on a private-key block the body is discarded to the END marker without being appended to any buffer — there is deliberately no `[]byte` accumulator on that path, so the invariant holds by construction |
| `walk.go` | 251 | `ReadCertificatesOnly` — bounded directory walk returning certificate DER only. A path outside declared scope is an **error, not a skip** |
| `der.go` | 213 | Handles `.der` / `.cer` / `.crt`, which occur as both PEM and DER in the wild: reads the head, decides, dispatches |
| `policy.go` | 185 | Limits bounding specific failures: pathological trees, hung NFS mounts, 4 GB files, symlink fork bombs |
| `counters.go` | 163 | Makes every skip visible. Guarantees `FilesSeen == sum of dispositions`; file dispositions are mutually exclusive, block counters are not |
| `classification.go` | 112 | The disposition of one file. Two values mean "certificates returned"; every other says exactly why nothing was — a skip is never silent, because an unexplained coverage gap is a lie by omission |
| `config.go` | 101 | `ReadConfigFile`, capped small so it cannot become a general file reader |
| `doc.go` | 38 | States INV-1 and how it is enforced |

**Tests (10 / 1,245 L)** — the most heavily tested package.

| File | L | Covers |
|---|---|---|
| `walk_test.go` | 401 | 13 tests — depth limit **prunes rather than aborts**, TOCTOU race, symlinks never followed, unix sockets refused |
| `pem_test.go` | 246 | 12 tests — mixed bundles, truncated blocks, enormous lines, DER classification |
| `policy_test.go` | 152 | 6 tests — rejection classes, symlinked-root resolution |
| `hardlink_test.go` | 105 | **A known limitation pinned by test**: `O_NOFOLLOW` does not stop a hardlink. The scope boundary is enforced against symlinks, not hardlinks — stated, not hidden |
| `leak_regression_test.go` | 96 | `cert \|\| key` must never return as "a certificate". Found by adversarial review, **not** by the canary — the canary planted a pure PKCS#8 key, so this leak class was outside what it planted |
| `fuzz_test.go` | 84 | `FuzzClassifyDER`, `FuzzReadPEM` — the property is not accuracy, it is that ambiguity always resolves to "refuse" |
| `config_extra_test.go` | 37 | Regression: `ReadConfigFile` needs an **allowlist**. With a denylist alone it read `/etc/shadow` happily — no extension, therefore not denied |
| `testhelp_test.go`, `fuzzhelp_test.go`, `netunix_test.go` | 124 | Shared fixtures: seeded RSA keys, cert DER, unix-socket listener |

---

## `pkg/scan` — TLS discovery and SSRF defence (6 files, 880 L)

| File | L | Purpose |
|---|---|---|
| `scan.go` | 243 | `ProbeOne` — connect, handshake, capture chain, close. Sends **zero application-layer bytes**. Not a vulnerability scanner and must never become one |
| `dial.go` | 172 | `ResolveAll`, `verifyDialAddress` (the TOCTOU closure at the syscall, distinct from the pre-dial policy check), and `StaticResolver` / `ParseResolveEntry` backing `--resolve` |
| `sweep.go` | 163 | CIDR expansion bounded by `MaxExpandedTargets` (a /8 is 16 million addresses) and concurrent sweeping |
| `ssrf.go` | 116 | `AddrBlocked` / `NameBlocked`. **The one place customer configuration does not win**: metadata endpoints hand out credentials, loopback reaches services that assume the caller is the host |
| `resolvable.go` | 107 | Tri-state public resolvability. Unknown is a real answer and must never render as false — "0% publicly resolvable" because it could not check is a lie |
| `ratelimit.go` | 79 | A 60-line token bucket, written rather than imported: every dependency in a binary running inside a customer network is a supply-chain question |

**Tests (5 / 927 L)** — `probe_test.go` (295 L, 7), `dial_test.go` (220 L, 10), `sweep_test.go`
(186 L, 8), `ssrf_test.go` (162 L, 7 — DNS rebinding, IPv4-mapped bypass, mixed answers
refused entirely), `staticresolver_test.go` (64 L, 3 — `--resolve` cannot smuggle a metadata
address past the block list).

---

## `pkg/x509norm` — parsing and normalisation (4 files, 898 L)

Two properties matter above all: **it never panics** (hostile input would DoS a whole scan
task) and **it never silently drops a certificate**.

| File | L | Purpose |
|---|---|---|
| `normalise.go` | 357 | `ParseDER`, `Fingerprint`, `NormaliseSANs` — canonical `model.Certificate` form |
| `lenient.go` | 259 | Recovers what it can from certificates `crypto/x509` rejects. Go is stricter than OpenSSL and rejects certs serving production traffic today; those are disproportionately the ancient appliance certificate nobody manages, which makes them **more** interesting to an inventory, not less |
| `dn.go` | 144 | RFC 4514 distinguished-name rendering; unlisted types become dotted OIDs |
| `chain.go` | 138 | `ParseChain`, `IdentifyLeaf` — the leaf is identified **structurally, in any presented order**, because servers get chain order wrong often enough that trusting it produces wrong answers |

**Tests (7 / 883 L)** — `normalise_test.go` (250 L, 9), `hostile_test.go` (217 L, 8 —
BMPString/UniversalString/TeletexString, wildcard survival, idempotency), `corpus_test.go`
(152 L, 5 — **the blocking gate**: <1% unparseable, zero panics), `chain_test.go` (135 L, 4),
`fuzz_test.go` (108 L, 3), plus helpers.

---

## `pkg/discover/aws` — read-only AWS enumeration (2 files, 665 L)

| File | L | Purpose |
|---|---|---|
| `enumerate.go` | 411 | Every read-only call across every configured region. **Never returns early on a per-call failure**: a customer who granted nine of eleven actions gets nine actions' worth of findings with the two gaps visible |
| `aws.go` | 254 | `Enumerator`, `RequiredActions`, `CoverageGap`, and the confused-deputy defence (role + external ID) |

**Tests (4 / 555 L)** — `localstack_test.go` (164 L, 4 — **not executed**, needs a Docker
daemon), `policy_test.go` (145 L, 4 — fails the build if the IAM policy gains a write verb),
`policy_vacuity_test.go` (132 L, 1 — *a policy check never shown to reject anything is a check
nobody should trust*), `aws_test.go` (114 L, 5).

---

## Supporting packages

| File | L | Purpose |
|---|---|---|
| `internal/scopecfg/scope.go` | 321 | Loads `scope.yaml`, the customer-authored authoritative definition of what the collector may touch. The control plane may **narrow** scope; it can never widen it |
| `internal/scopecfg/intersect.go` | 129 | Intersects a task with local scope. `Violation` records refusals — **reported, not dropped**, because a control plane asking outside scope is either our bug or our compromise, and the customer is entitled to know |
| `internal/tools/importcheck/main.go` | 340 | CI-006 no `os/exec` · CI-007 file I/O only in `safeio`/`spool` · CI-008 logging only via `safelog` · CI-009 `cmd/certscan` must not import `internal/`. Pure AST questions, so nothing is approximate |
| `internal/tools/gencorpus/main.go` | 33 | Regenerates the corpus. Run deliberately via `make corpus`, never automatically |
| `pkg/model/certificate.go` | 131 | `Certificate`, `Chain`, `ParseStatus`, `KeyAlgorithm`. Shared verbatim with the control-plane API contract so divergence is a compile error |
| `pkg/model/report.go` | 120 | The report schema — **the validation instrument**. Coverage honesty is a first-class field: a report presenting partial coverage as complete is the failure to avoid |
| `pkg/safelog/safelog.go` | 169 | The only logging path. **INV-3** is structural, not a lint rule: this API cannot accept a `[]byte`. No `Any`, no `interface{}`, no variadic `...any` |
| `test/canary/canary.go` | 368 | Plants private keys in six forms and detects any trace of them (hex, standard and URL-safe base64, PEM body lines, windows of the modulus). A library so CANARY-B can reuse one definition of "a leak" |
| `test/corpus/generate.go` | 414 | Generates the corpus — **no customer certificate ever enters this repository**. Covers cases rare in the wild but catastrophic when mishandled: `notAfter` beyond 2038, serials over 20 bytes, 1,000-entry SAN lists |
| `test/corpus/load.go` | 83 | Loads the committed corpus |
| `test/canary/canary_a_test.go` | 308 | The canary itself: runs the scan at default **and** debug verbosity, captures every artefact, fails on any trace of a planted key |

---

## What is not here

No server, no database, no HTTP handlers, no scheduler, no alerting, no auth, no UI code.
`--html` writes a static file; it is not an application. The control plane is build items
070+ and is gated behind validation that has not passed.
