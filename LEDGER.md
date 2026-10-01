# Completion ledger

Generated from `project_1_full_development_plan.md` and the repository at `e7ed7c6`.
Every status is an evidence probe against the working tree, not a claim from a document.

## Totals

| Status | Items |
|---|---|
| VERIFIED | 128 |
| IMPLEMENTED | 4 |
| IN_PROGRESS | 2 |
| BLOCKED_EXTERNAL | 3 |
| NOT_STARTED | 39 |
| **Total** | **176** |

`COMPLETE` is deliberately absent: it requires implementation, tests and
verification evidence together, and is not claimed for any item here.

## Phase E0 — Repository, CI and the boundary

*22 items — 22 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 001 | `REPO-001` | VERIFIED | make check: pass; 19 packages ok |
| 002 | `REPO-002` | VERIFIED | make check: pass; 19 packages ok |
| 003 | `REPO-003` | VERIFIED | make check: pass; 19 packages ok |
| 004 | `CI-001` | VERIFIED | make check: pass; 19 packages ok |
| 005 | `CI-002` | VERIFIED | make check: pass; 19 packages ok |
| 006 | `CI-003` | VERIFIED | make check: pass; 19 packages ok |
| 007 | `CI-004` | VERIFIED | make check: pass; 19 packages ok |
| 008 | `CI-005` | VERIFIED | make check: pass; 19 packages ok |
| 009 | `CI-006` | VERIFIED | make check: pass; 19 packages ok |
| 010 | `CI-007` | VERIFIED | make check: pass; 19 packages ok |
| 011 | `CI-008` | VERIFIED | make check: pass; 19 packages ok |
| 012 | `CI-009` | VERIFIED | make check: pass; 19 packages ok |
| 013 | `SAFEIO-001` | VERIFIED | make check: pass; 19 packages ok |
| 014 | `SAFEIO-002` | VERIFIED | make check: pass; 19 packages ok |
| 015 | `SAFEIO-003` | VERIFIED | make check: pass; 19 packages ok |
| 016 | `SAFEIO-004` | VERIFIED | make check: pass; 19 packages ok |
| 017 | `SAFEIO-005` | VERIFIED | make check: pass; 19 packages ok |
| 018 | `SAFEIO-006` | VERIFIED | make check: pass; 19 packages ok |
| 019 | `SAFEIO-007` | VERIFIED | make check: pass; 19 packages ok |
| 020 | `SAFEIO-008` | VERIFIED | make check: pass; 19 packages ok |
| 021 | `CANARY-A` | VERIFIED | make check: pass; 19 packages ok |
| 022 | `CI-010` | VERIFIED | make check: pass; 19 packages ok |

## Phase E1 — Certificate engine

*8 items — 8 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 023 | `X509-001` | VERIFIED | make check: pass; 19 packages ok |
| 024 | `X509-002` | VERIFIED | make check: pass; 19 packages ok |
| 025 | `X509-003` | VERIFIED | make check: pass; 19 packages ok |
| 026 | `X509-004` | VERIFIED | make check: pass; 19 packages ok |
| 027 | `X509-005` | VERIFIED | make check: pass; 19 packages ok |
| 028 | `X509-006` | VERIFIED | make check: pass; 19 packages ok |
| 029 | `X509-007` | VERIFIED | make check: pass; 19 packages ok |
| 030 | `X509-008` | VERIFIED | make check: pass; 19 packages ok |

## Phase E2 — Scanner

*10 items — 10 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 031 | `SCOPE-001` | VERIFIED | make check: pass; 19 packages ok |
| 032 | `SCOPE-002` | VERIFIED | make check: pass; 19 packages ok |
| 033 | `SCAN-001` | VERIFIED | make check: pass; 19 packages ok |
| 034 | `SCAN-002` | VERIFIED | make check: pass; 19 packages ok |
| 035 | `SCAN-003` | VERIFIED | make check: pass; 19 packages ok |
| 036 | `SCAN-004` | VERIFIED | make check: pass; 19 packages ok |
| 037 | `SCAN-005` | VERIFIED | make check: pass; 19 packages ok |
| 038 | `SCAN-006` | VERIFIED | make check: pass; 19 packages ok |
| 039 | `SCAN-007` | VERIFIED | make check: pass; 19 packages ok |
| 040 | `SCAN-008` | VERIFIED | make check: pass; 19 packages ok |

## Phase E3 — cmd/certscan (MVP v0)

*9 items — 9 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 041 | `CLI-001` | VERIFIED | make check: pass; 19 packages ok |
| 042 | `CLI-002` | VERIFIED | make check: pass; 19 packages ok |
| 043 | `CLI-003` | VERIFIED | make check: pass; 19 packages ok |
| 044 | `CLI-004` | VERIFIED | make check: pass; 19 packages ok |
| 045 | `CLI-005` | VERIFIED | make check: pass; 19 packages ok |
| 046 | `CLI-006` | VERIFIED | make check: pass; 19 packages ok |
| 047 | `REL-001` | VERIFIED | make check: pass; 19 packages ok |
| 048 | `REL-002` | VERIFIED | make check: pass; 19 packages ok |
| 049 | `REL-003` | VERIFIED | make check: pass; 19 packages ok |

## Phase E4 — AWS read-only enumeration

*8 items — 8 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 050 | `AWS-001` | VERIFIED | make check: pass; 19 packages ok |
| 051 | `AWS-007` | VERIFIED | make check: pass; 19 packages ok |
| 052 | `AWS-002` | VERIFIED | make check: pass; 19 packages ok |
| 053 | `AWS-003` | VERIFIED | make check: pass; 19 packages ok |
| 054 | `AWS-004` | VERIFIED | make check: pass; 19 packages ok |
| 055 | `AWS-005` | VERIFIED | make check: pass; 19 packages ok |
| 056 | `AWS-006` | VERIFIED | make check: pass; 19 packages ok |
| 057 | `AWS-008` | VERIFIED | executed 2026-09-20 against localstack 3.8; seeded ACM -> findings=1 |

## Phase E5 — Test lab

*12 items — 1 blocked_external, 3 implemented, 8 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 058 | `LAB-001` | VERIFIED | compose config valid; 15 containers run |
| 059 | `LAB-002` | VERIFIED | three backends share one certificate a43fb78433ebc310 |
| 060 | `LAB-003` | VERIFIED | expired notAfter=2026-08-01, in the past |
| 061 | `LAB-004` | IMPLEMENTED | container runs; the reload-drift assertion is not yet scripted |
| 062 | `LAB-005` | IMPLEMENTED | containers run; SNI and mTLS assertions not yet scripted |
| 063 | `LAB-006` | IMPLEMENTED | fixtures exist; rotation not yet scripted |
| 064 | `LAB-007` | VERIFIED | PARTIAL ROLLOUT, 3 of 4 match, 10.77.0.14 serves 26dd29a8adde2cc1 |
| 065 | `LAB-008` | VERIFIED | refuses TCP (ECONNREFUSED), asserted |
| 066 | `LAB-009` | VERIFIED | lab.internal.test -> 4 addresses; rebind -> 169.254.169.254 |
| 067 | `LAB-010` | VERIFIED | 0 touches from certscan; 1 when touched by hand (vacuity proven) |
| 068 | `LAB-011` | BLOCKED_EXTERNAL | kind + cert-manager + tc netem NOT built |
| 069 | `LAB-012` | VERIFIED | captured body 'BODY-CANARY' and header X-Secret-Probe |

## Phase E6 — Expected state and the verification classifier

*16 items — 1 in_progress, 15 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 070 | `EXP-A` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 071 | `EXP-003` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 072 | `VERIFY-001` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 073 | `VERIFY-002` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 074 | `VERIFY-003` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 075 | `VERIFY-004` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 076 | `VERIFY-005` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 077 | `VERIFY-006` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 078 | `VERIFY-007` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 079 | `VERIFY-008` | VERIFIED | classify_test.go 20 tests + regression_test.go 14 tests |
| 080 | `VERIFY-009` | VERIFIED | mutation-tested: 3 of 4 mutations caught, 4th exposed a gap in the test which was then fixed |
| 081 | `VERIFY-010` | VERIFIED | mutation-tested: 3 of 4 mutations caught, 4th exposed a gap in the test which was then fixed |
| 082 | `VERIFY-011` | VERIFIED | grace never suppresses expiry; disableable with a negative value |
| 083 | `DRIFT-002` | VERIFIED | mutation-tested: 3 of 4 mutations caught, 4th exposed a gap in the test which was then fixed |
| 084 | `DRIFT-003` | VERIFIED | mutation-tested: 3 of 4 mutations caught, 4th exposed a gap in the test which was then fixed |
| 085 | `LAB-TEST` | IN_PROGRESS | S13/S14 executed; S1-S12/S28/S29 not scripted |

## Phase E7 — Local end-to-end prototype

*5 items — 1 in_progress, 3 not_started, 1 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 086 | `PROTO-001` | VERIFIED | renaming/retyping/removing a field fails with a diff |
| 087 | `LOCAL-001` | NOT_STARTED | — |
| 088 | `LOCAL-002` | NOT_STARTED | — |
| 089 | `LOCAL-003` | IN_PROGRESS | 24h unattended run STARTED 2026-09-30T17:17Z; must not be VERIFIED early |
| 090 | `CANARY-B` | NOT_STARTED | — |

## Phase E8 — Control plane foundation

*12 items — 1 not_started, 11 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 091 | `TENANT-001` | VERIFIED | 17 tests inc. 14-table sweep; mutations: FORCE caught, session-SET caught |
| 092 | `SCHEMA-001` | VERIFIED | 17 tests inc. 14-table sweep; mutations: FORCE caught, session-SET caught |
| 093 | `TENANT-002` | VERIFIED | 17 tests inc. 14-table sweep; mutations: FORCE caught, session-SET caught |
| 094 | `TENANT-003` | VERIFIED | 17 tests inc. 14-table sweep; mutations: FORCE caught, session-SET caught |
| 095 | `SCHEMA-002..010` | VERIFIED | 17 tests inc. 14-table sweep; mutations: FORCE caught, session-SET caught |
| 096 | `SCHEMA-013` | NOT_STARTED | sqlc not wired; queries are hand-written pgx |
| 097 | `TENANT-004` | VERIFIED | 17 tests inc. 14-table sweep; mutations: FORCE caught, session-SET caught |
| 098 | `AUTH-001` | VERIFIED | 18 OIDC tests vs a real local IdP; mutations 5/6 caught, 6th exposed a bad test which was then fixed |
| 099 | `AUTH-002` | VERIFIED | 6 of 6 mutations caught (disabled user, replay, idle, rotation, role, fail-open) |
| 100 | `AUTH-003` | VERIFIED | 18 OIDC tests vs a real local IdP; mutations 5/6 caught, 6th exposed a bad test which was then fixed |
| 101 | `AUTH-004` | VERIFIED | 6 of 6 mutations caught (disabled user, replay, idle, rotation, role, fail-open) |
| 102 | `AUTH-005` | VERIFIED | 6 of 6 mutations caught (disabled user, replay, idle, rotation, role, fail-open) |

## Phase E9 — Enrolment, protocol and ingest

*18 items — 1 implemented, 5 not_started, 12 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 103 | `ENROL-001` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 104 | `ENROL-002` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 105 | `ENROL-003` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 106 | `ENROL-004` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 107 | `PROTO-002` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 108 | `INGEST-001` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 109 | `INGEST-002` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 110 | `INGEST-003` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 111 | `INGEST-004` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 112 | `INGEST-005` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 113 | `EP-001..006` | IMPLEMENTED | proposal/dedup/monitored flags not built |
| 114 | `INGEST-006` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
| 115 | `PROTO-003` | NOT_STARTED | collector-side protocol: long-poll, spool, JWS |
| 116 | `PROTO-004` | NOT_STARTED | collector-side protocol: long-poll, spool, JWS |
| 117 | `PROTO-005..006` | NOT_STARTED | collector-side protocol: long-poll, spool, JWS |
| 118 | `PROTO-007` | NOT_STARTED | collector-side protocol: long-poll, spool, JWS |
| 119 | `PROTO-008` | NOT_STARTED | collector-side protocol: long-poll, spool, JWS |
| 120 | `PROTO-009` | VERIFIED | 16 tests vs real PostgreSQL; mutations 3/5 caught, 2 equivalent and documented; chasing one exposed a real error-conflation defect |

## Phase E10 — Scheduling and drift

*12 items — 12 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 121 | `SCHED-001..002` | VERIFIED | 16 tests vs real PostgreSQL; mutations 3/5 caught, 2 equivalent and documented; chasing one exposed a real error-conflation defect |
| 122 | `SCHED-003` | VERIFIED | 9 tests vs real PostgreSQL; idempotency + restart + out-of-order + isolation |
| 123 | `SCHED-004..005` | VERIFIED | 9 tests vs real PostgreSQL; idempotency + restart + out-of-order + isolation |
| 124 | `SCHED-006` | VERIFIED | 9 tests vs real PostgreSQL; idempotency + restart + out-of-order + isolation |
| 125 | `SCHED-007` | VERIFIED | 9 tests vs real PostgreSQL; idempotency + restart + out-of-order + isolation |
| 126 | `SCHED-008` | VERIFIED | 9 tests vs real PostgreSQL; idempotency + restart + out-of-order + isolation |
| 127 | `DRIFT-001` | VERIFIED | 9 tests vs real PostgreSQL; idempotency + restart + out-of-order + isolation |
| 128 | `DRIFT-004` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 129 | `DRIFT-005..007` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 130 | `DRIFT-008` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 131 | `DRIFT-009` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 132 | `SCHEMA-011..012` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |

## Phase E11 — Alerting and the confirmation UI (GAP-4)

*14 items — 5 not_started, 9 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 133 | `EXP-001..002` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 134 | `EXP-008` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 135 | `EXP-004` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 136 | `EXP-006..007` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 137 | `UI-001..002` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 138 | `UI-004` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 139 | `UI-005` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 140 | `EXP-005` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 141 | `ALERT-001..002` | VERIFIED | 14 tests vs real PostgreSQL; mutations 3/4 caught, 4th a measured equivalence (endpoint_state row lock serializes folds) |
| 142 | `ALERT-003..004` | NOT_STARTED | — |
| 143 | `ALERT-005..006` | NOT_STARTED | — |
| 144 | `ALERT-007..008` | NOT_STARTED | — |
| 145 | `ALERT-009` | NOT_STARTED | — |
| 146 | `S7` | NOT_STARTED | — |

## Phase E12 — Remaining UI, audit and export

*6 items — 6 not_started*

| # | ID | Status | Evidence |
|---|---|---|---|
| 147 | `UI-003` | NOT_STARTED | — |
| 148 | `UI-006` | NOT_STARTED | — |
| 149 | `UI-007..008` | NOT_STARTED | — |
| 150 | `AUDIT-001..003` | NOT_STARTED | — |
| 151 | `AUDIT-004` | NOT_STARTED | — |
| 153 | `UI-011` | NOT_STARTED | — |

## Phase E13 — Kubernetes

*4 items — 4 not_started*

| # | ID | Status | Evidence |
|---|---|---|---|
| 154 | `K8S-001..002` | NOT_STARTED | — |
| 155 | `K8S-004` | NOT_STARTED | — |
| 156 | `K8S-003` | NOT_STARTED | — |
| 157 | `K8S-005` | NOT_STARTED | — |

## Phase E14 — Hardening, review and operational readiness

*14 items — 1 blocked_external, 13 not_started*

| # | ID | Status | Evidence |
|---|---|---|---|
| 158 | `HARD-001` | NOT_STARTED | — |
| 159 | `HARD-002` | NOT_STARTED | — |
| 160 | `HARD-003` | NOT_STARTED | — |
| 161 | `HARD-004` | NOT_STARTED | — |
| 162 | `INFRA-001..012` | NOT_STARTED | — |
| 163 | `INFRA-011` | NOT_STARTED | — |
| 164 | `OPS-001` | NOT_STARTED | — |
| 165 | `OPS-002` | NOT_STARTED | — |
| 166 | `OPS-003` | NOT_STARTED | — |
| 167 | `OPS-004` | NOT_STARTED | — |
| 168 | `OPS-005` | NOT_STARTED | — |
| 169 | `OPS-006` | NOT_STARTED | — |
| 170 | `HARD-005` | NOT_STARTED | — |
| 171 | `HARD-006` | BLOCKED_EXTERNAL | SOC 2 Type II observation window — months, needs an auditor |

## Phase E15–E17

*6 items — 1 blocked_external, 2 not_started, 3 verified*

| # | ID | Status | Evidence |
|---|---|---|---|
| 174 | `Onboarding documentation; support SLA; manual invoicing` | NOT_STARTED | — |
| 175 | `First paying customer — signed annual contract ≥$9,000` | BLOCKED_EXTERNAL | first paying customer, signed contract >= $9,000 |
| 176 | `V1: inference, policy rules, attestation, Azure/GCP, webhooks, billing, self-serve, load test` | NOT_STARTED | — |
| 023 | `fingerprint = SHA-256(full DER)` | VERIFIED | make check: pass; 19 packages ok |
| 026 | `Wildcard SAN semantics` | VERIFIED | make check: pass; 19 packages ok |
| 108 | `Schema-closed ingest decoder` | VERIFIED | 29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught |
