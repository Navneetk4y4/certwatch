# The divergence lab — competitive test protocol

**Purpose: settle in one hour whether Project 1 has a reason to exist.**

The remaining commercial hypothesis is:

> No shipping product both **discovers endpoints the customer never registered** AND **verifies each resolved IP against a confirmed expected state** — without holding customer cloud credentials.

Two products may falsify it. This lab is how you find out.

---

## The scenario

```
lab.internal.test
     ├── 10.99.0.1:8443  →  certificate A   ("expected")
     └── 10.99.0.2:8443  →  certificate B   ("stale" — a half-completed rollout)
```

A hostname-level monitor connects once, gets whichever address answers, and reports **healthy**. That is the failure this product claims to catch.

```sh
./setup.sh              # needs sudo, only for the lo0 aliases
./setup.sh teardown
```

### If you need a true multi-A-record test

`/etc/hosts` returns one address. For a hostname that genuinely resolves to **both**, run dnsmasq:

```sh
echo "address=/lab.internal.test/10.99.0.1
address=/lab.internal.test/10.99.0.2" > /tmp/dnsmasq.conf
sudo dnsmasq -C /tmp/dnsmasq.conf -d
# then point the tool under test at 127.0.0.1 as its resolver
```

`ANALYSIS` This distinction matters for the competitive test. A product that resolves a hostname and checks **all** returned addresses passes; one that takes the first passes the `/etc/hosts` version trivially and fails the dnsmasq version. **Use dnsmasq for the real answer.**

---

## Test 1 — does Project 1 do it?  **ANSWERED: yes**

```sh
go test ./cmd/certscan/ -run 'Diverg|HostnameLevel' -v
```

**Result, 2026-09-19:**

```
DIVERGENCE DETECTED: <addr> served 02d76671b5dc42c3, <addr> served 5f5f35c937eaa718
hostname-level monitor: 1 certificates, 0 disagreements (reports healthy)
per-IP verification:    2 certificates, 1 disagreements (reports the problem)
```

**Updated 2026-09-20.** Limitations 2 and 3 below are now CLOSED. Limitation 1 stands.

```
TestDetectsPerIPCertificateDivergence
  DIVERGENCE DETECTED: 127.0.2.2 served 10005d30f1eea41b,
                       127.0.2.3 served e49d3f8560ee5055
TestHostnameLevelMonitorWouldMissIt
  hostname-level monitor: 1 certificates, 0 disagreements (reports healthy)
  per-IP verification:    2 certificates, 1 disagreements (reports the problem)
TestEndToEndPartialRolloutProducesEvidenceAndReport ... PASS
```

Two **genuinely different IP addresses**, not two ports. Expected-state verification
(`pkg/verify`) now exists: pinned and policy modes, human confirmation, grace windows, and
a classifier with 14 regression tests covering every defect adversarial testing found.

**Honest limitations of that test:**

1. It dials the listeners directly, because the production SSRF policy refuses loopback. The refusal is correct and is tested separately (`pkg/scan/ssrf_test.go`). Everything downstream of the dial — handshake, chain capture, X.509 normalisation, aggregation — is the production path.
2. Both fixture backends report the same address (they differ by port). The detection keys on *hostname + distinct fingerprints*, which is correct, but **address attribution across genuinely different IPs has not been exercised end to end.** Run `setup.sh` and point `certscan` at it to close that gap.
3. ~~This is point-in-time detection, not continuous verification against a confirmed
   expected state.~~ **Verification against a confirmed expected state now exists**
   (`pkg/verify`, `certscan --verify`). What still does NOT exist is **continuous**
   operation: scheduling, history, alert delivery, and the ability to tell a rolling
   deploy from a pool that never converged — which needs two observations separated by
   time. Claim verification. Do not claim monitoring.

```sh
# The end-to-end version, after ./setup.sh
./build/certscan --cidr 10.99.0.0/30 --ports 8443 --dry-run
./build/certscan --cidr 10.99.0.0/30 --ports 8443 --out /tmp/lab.json
jq '.summary.ip_disagreements, .summary.unique_certificates' /tmp/lab.json
```

---

## Test 2 — HostRepute   **ATTEMPTED 2026-09-20 — COULD NOT BE RUN**

`hostrepute.com` returns **HTTP 403** to every automated request (Cloudflare, Ray ID
`a3dc83e238493ed9`). Account creation is also not something I can do. Findings from public
material are in the internal `competitive_kill_test_2026_09_20.md` and are labelled
`VENDOR CLAIM, SEARCH-INDEX MEDIATED` — **not** behavioural observation. Result: A = NO
(monitors are added and metered per slot), C = YES (claimed). **NO-GO A not triggered.**

### Original protocol, for whoever can run it

`INFERRED` from public material: monitors are **defined**, not discovered — *"Active certificate monitor slots are subscription-backed. Plans limit active certificate monitor slots and schedule interval."*

**That inference is the load-bearing claim of the entire project and it is unverified.**

### Protocol

| # | Step | Records |
|---|---|---|
| 1 | Sign up for the free tier | Plan limits, monitor-slot count |
| 2 | **Without creating any monitor**, look for a discovery/scan/import feature | **A. Automatic discovery: YES / NO** |
| 3 | Add one monitor for `lab.internal.test` | How a target is specified — hostname only, or hostname+IP? |
| 4 | Install a private agent on the lab machine | What credentials it needs. **Does it ask for AWS access?** |
| 5 | Let it check | **B. Does it report ONE certificate or TWO?** |
| 6 | If two: does it name which address served which? | **C. Per-IP attribution: YES / NO** |
| 7 | Point it at `10.99.0.0/30` rather than a hostname | **D. Can it take a RANGE? If yes, discovery exists** |
| 8 | Record pricing for the tier that would cover 250 endpoints | **E. Cost per endpoint** |

### Decision

| Observation | Meaning |
|---|---|
| **A = YES and C = YES** | **NO-GO A.** HostRepute provides the whole combination. Kill Project 1 |
| A = NO, C = YES | Verification is theirs; discovery is the only gap. **Weak but alive** |
| A = NO, C = NO | Both gaps alive. The strongest surviving case |
| A = YES, C = NO | Discovery is theirs; per-IP is the gap |

---

## Test 3 — CertPulse   **PARTIALLY RUN 2026-09-20 — documentation only**

Their docs were read directly. Endpoints are added by hand (*"click **Add Endpoint**. Enter
the hostname and optional port"*); there is no CIDR scanning and no per-IP handling anywhere
in their docs, pricing or blog. **The register's `VERIFIED` "network scanning" claim was
taken from a CertPulse blog post recommending nmap and masscan — it is not their product.**
Result: A = NO for credential-free discovery, C = NO. **NO-GO B not triggered.**

Pricing, read directly: $79/mo for 250 external endpoints = **$3.79/endpoint/year**, against
Project 1's proposed $72. That gap is now the most likely killer.

### Original protocol, for whoever can run it

`VERIFIED` it does hybrid discovery: *"Network scanning, Cloud API enumeration, Kubernetes secret scanning, CT log harvesting, Filesystem scanning."*
`UNKNOWN` whether it does per-resolved-IP verification — its architecture article contains *"no discussion of load balancer split-brain scenarios or resolved IP handling."*

### Protocol

| # | Step | Records |
|---|---|---|
| 1 | Sign up for the free tier (3 certificates) | Tier limits |
| 2 | Point network discovery at `10.99.0.0/30` | **A. Does it find both backends?** |
| 3 | Check the inventory | **B. ONE certificate for the hostname, or TWO?** |
| 4 | Look for per-IP or address-level detail on the endpoint | **C. Per-IP attribution: YES / NO** |
| 5 | Connect a cloud account | **D. What AWS permissions does it demand? Does it STORE the credentials?** |
| 6 | Record pricing for 250 endpoints / 200+ certificates | **E. Cost per endpoint** |

### Decision

| Observation | Meaning |
|---|---|
| **A = YES and C = YES** | **NO-GO B.** CertPulse provides the whole combination. Kill Project 1 |
| A = YES, C = NO | Discovery is theirs; **per-IP is the only gap** |
| A = NO | Their discovery is weaker than advertised — re-test carefully before believing it |

---

## Test 4 — the credential question (Wedge F)

For **both** products, record exactly:

```
Credential          What is asked for
Permission          The scope (read-only? which services?)
Purpose             What it is used for
Required?           Mandatory for core function, or optional?
Stored?             Does the vendor hold it, or is it agent-local?
```

`VERIFIED` Project 1 holds **none** — the collector uses the customer's own instance role and the control plane stores nothing. If both competitors require vendor-held cloud credentials, that is a real and architecturally durable difference. **If either offers a credential-free mode, Wedge F is dead too.**

---

## The scoring sheet

```
                              Project 1   HostRepute   CertPulse
Automatic discovery              YES         ___          ___
Per-IP verification              YES*        ___          ___
Both in one product              YES*        ___          ___
Requires vendor cloud creds      NO          ___          ___
Cost per endpoint / year         $72(proposed) ___        ___

* expected-state verification IS built and tested; CONTINUOUS monitoring (scheduling,
  history, alert delivery) is NOT
```

**If any competitor scores YES on the first three, Project 1 has no defensible reason to exist and should be killed.**
