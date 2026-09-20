# The certwatch test laboratory — build items 058–069

Every endpoint here is broken in one specific way, because a scenario in
`project_1_testing_strategy.md` needs a system that fails in exactly that way.
Nothing reaches the public internet: static addresses on a private bridge, DNS
served by the lab's own CoreDNS.

```sh
make lab-up       # start (builds the two Go services)
make lab-verify   # assert every fixture serves what it should
make lab-down     # destroy, including volumes
```

## Run your tests INSIDE the network

On macOS a Docker bridge address is **not routable from the host**. `nc -z
10.77.0.11 8443` fails from a terminal and succeeds from a container. This is
not a workaround to be sorry about — it is closer to how the collector really
runs, inside the customer's network rather than outside it.

```sh
docker run --rm --network certwatch-lab --dns 10.77.0.53 \
  -v /tmp/labrun:/w -w /w alpine:3.20 ./certscan --verify expect.json
```

## What is in it

| Address | Service | The failure it reproduces | Item |
|---|---|---|---|
| 10.77.0.10 | `lb` | HAProxy in front of the pool: one VIP, one certificate, three backends | 059 |
| 10.77.0.11–13 | `web-a/b/c` | The healthy pool. All three serve the **same** certificate | 059 |
| **10.77.0.14** | **`web-divergent`** | **A fourth pool member serving a DIFFERENT valid certificate from the approved issuer. This is the partial rollout, and policy mode accepts both certificates — divergence across addresses is the only signal** | **064 / GAP-3** |
| 10.77.0.20 | `web-expired` | Expired a month ago | 060 |
| 10.77.0.21 | `web-badchain` | Intermediate omitted from the chain | 060 |
| 10.77.0.22 | `web-wronghost` | Valid certificate for an unrelated hostname | 060 |
| 10.77.0.23 | `web-nearexpiry` | Five days of validity left | 060 |
| 10.77.0.24 | `web-rogue` | Issued by an unapproved CA | 063 |
| 10.77.0.25 | `web-sni` | **Three hostnames on one address.** A scanner that omits SNI reports the wrong certificate | 062 |
| 10.77.0.26 | `web-mtls` | Rejects the client at the handshake — but has already sent its certificate. Must be recorded, not reported unreachable | 062 |
| 10.77.0.27 | `web-noreload` | The file on disk was replaced; the process was never reloaded, so it still serves the old certificate | 061 |
| **10.77.0.30** | **`web-draining`** | **No listener: ECONNREFUSED, not a timeout. Must be reported unreachable and excluded from the matching denominator, never counted as a mismatch** | **065 / GAP-2** |
| 10.77.0.53 | `dns` | Multi-A round robin, split horizon, and a **rebinding fixture** whose answer is a blocked address | 066 |
| 10.77.0.169 | `imds-decoy` | A metadata decoy that records every inbound connection. The test asserts the record is **empty** | 067 |
| 10.77.0.80 | `ingest` | Fake control-plane ingest capturing full bodies **and headers** — a key leaking through a header is still a leak | 069 |

LocalStack for AWS lives separately in `docker-compose.aws.yml` (item 057).

## Verified on 2026-09-20

`certscan --verify` run from inside the network, through the complete
production path including the SSRF policy:

```
endpoints verified           1 across 4 IP addresses
FAILURE  lab.internal.test:8443
  PARTIAL ROLLOUT — 3 of 4 addresses serve the expected certificate; 10.77.0.14 do not
  ✓ 10.77.0.11  a43fb78433ebc310
  ✓ 10.77.0.12  a43fb78433ebc310
  ✓ 10.77.0.13  a43fb78433ebc310
  ✗ 10.77.0.14  26dd29a8adde2cc1
```

Four genuinely different IP addresses, not four ports. This closes the
limitation the divergence README carried from the start.

**S13/S14, the SSRF scenarios.** Pointing the scanner deliberately at
`rebind.lab.internal.test` (which resolves to `169.254.169.254`) and at the
metadata address directly: both refused, `--resolve` could not smuggle either
past the block list, and the decoy recorded **zero** inbound connections.

The decoy was then touched by hand with `wget` and recorded **one** — because a
detector that has never been shown to fire proves nothing, which is the same
argument `pkg/discover/aws/policy_vacuity_test.go` makes about the IAM policy.

## Certificates

Committed, not generated at test time. `certgen` is **not** reproducible —
`ecdsa.GenerateKey` and `x509.CreateCertificate` both call
`randutil.MaybeReadByte`. See `certs/README.md`.
