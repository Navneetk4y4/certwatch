# The security canary

This directory holds the test that makes INV-1 mechanical rather than documentary:

> **Private-key material must never leave the customer environment.**

It lands in two parts, because its full design needs surfaces that do not exist
until later in the build order (`project_1_full_development_plan.md` GAP-5):

| Part | Lands after | Surfaces inspected |
|---|---|---|
| **CANARY-A** | `SAFEIO-007` (build item 021) | returned results, stdout, stderr, log output at debug level, in-process buffers |
| **CANARY-B** | build item 090 | all of A, **plus** outbound HTTP bodies and headers, the heartbeat/telemetry payload, the on-disk spool, and crash output |

`testdata/seed.bin` is a fixed 32-byte seed. The planted key is derived from it,
so it is byte-identical across runs and no historical build artefact can contain
it by coincidence. It is **not** a real key and protects nothing.

## What this test proves, and what it does not

**Proves:** across the code paths exercised, no 32-byte window of the planted
key's modulus or DER encoding, no base64 of any 48-byte window of either, and no
PEM body line of it appears in any captured artefact — while the scanner still
reported at least three real certificates and exercised all five protection paths.

**Does not prove:** that no leak is possible. It is a test over the paths it
exercises, not a proof over all executions. Specifically it cannot detect
material that has been compressed, encrypted, re-encoded in a form the search
does not model, or leaked through a channel not captured here. It is evidence,
and strong evidence, but the honest claim is "no leak was found on these paths,"
not "leakage is impossible."

Assertion 2 (at least three certificates reported) exists because a scanner that
reads nothing trivially passes a leak test. The canary must prove the scanner
works *and* does not leak, not just the second half.
