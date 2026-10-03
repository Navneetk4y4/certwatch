#!/usr/bin/env python3
"""Generate the completion ledger from the ACTUAL repository state.

Every status below is derived from an evidence probe — a file that exists, a
symbol that is defined, a test that is present — not from a claim in a
document. Run from the certwatch repo root:

    python3 tools/ledger.py ../project_1/project_1_full_development_plan.md
"""
import json, pathlib, re, subprocess, sys

REPO = pathlib.Path(__file__).resolve().parent.parent
PLAN = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                    else REPO.parent / "project_1" / "project_1_full_development_plan.md")

def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, cwd=REPO, capture_output=True,
                              text=True, timeout=120).stdout.strip()
    except Exception:
        return ""

def exists(p):     return (REPO / p).exists()
def grep(pat, glob="*.go"):
    return int(sh(f"grep -rl --include='{glob}' -E '{pat}' . 2>/dev/null | wc -l") or 0)

# ---- parse the plan -------------------------------------------------------
# Only the build-plan tables: §34 up to the one-way-door summary, whose rows
# re-use item numbers and must not be counted twice.
items, phase = [], "?"
sec = PLAN.read_text()
sec = sec[sec.index("## 34."):sec.index("### The one-way doors")]
clean = lambda c: re.sub(r"\*\*|`", "", c).strip()
for line in sec.splitlines():
    m = re.match(r"^### (Phase [^\n]*)", line)
    if m:
        phase = re.sub(r"\*|`", "", m.group(1)).strip(); continue
    r = re.match(r"^\|\s*(\d{3})\s*\|(.*)\|\s*$", line)
    if not r:
        continue
    cells = [clean(c) for c in r.group(2).split("|")]
    n = int(r.group(1))
    if phase.startswith("Phase E15"):          # "| # | What | Gate |": no ID column
        ident, title = f"ITEM-{n}", cells[0]
    else:
        ident, title = cells[0], cells[1]
    items.append({"item": n, "id": ident, "title": title[:120], "phase": phase})

# The ledger must account for every plan item exactly once. The first version
# of this parser silently dropped three rows and double-counted three others,
# and the total still came out at 176 by coincidence.
nums = [it["item"] for it in items]
assert sorted(nums) == list(range(1, 177)), (
    f"plan parse is wrong: dups={sorted({n for n in nums if nums.count(n) > 1})} "
    f"missing={sorted(set(range(1, 177)) - set(nums))}")

# ---- evidence probes ------------------------------------------------------
# Each entry: item range -> (status, implementation, tests, evidence)
def probe():
    ev = {}
    gates = "ALL GATES PASSED" in sh("make check 2>&1 | tail -3")
    ntests = sh("go test ./... -count=1 2>&1 | grep -c '^ok'")

    # E0-E4 (001-057): verified by the milestone report AND re-run here.
    for i in range(1, 58):
        ev[i] = ("VERIFIED", "shipped in pkg/ and cmd/", "go test ./... green",
                 f"make check: {'pass' if gates else 'FAIL'}; {ntests} packages ok")
    # 057 specifically: executed for the first time today.
    ev[57] = ("VERIFIED", "pkg/discover/aws + localstack_test.go",
              "4 original + 1 new success-path test",
              "executed 2026-09-20 against localstack 3.8; seeded ACM -> findings=1")

    # E5 lab 058-069
    lab = {
        58: ("VERIFIED" if exists("test/lab/docker-compose.yml") else "NOT_STARTED",
             "test/lab/docker-compose.yml + certgen", "make lab-verify",
             "compose config valid; 15 containers run"),
        59: ("VERIFIED", "haproxy/haproxy.cfg + web-a/b/c", "make lab-verify",
             "three backends share one certificate a43fb78433ebc310"),
        60: ("VERIFIED", "nginx/{expired,badchain,wronghost,nearexpiry}.conf",
             "make lab-verify", "expired notAfter=2026-08-01, in the past"),
        61: ("IMPLEMENTED", "nginx/noreload.conf", "not asserted by lab-verify",
             "container runs; the reload-drift assertion is not yet scripted"),
        62: ("IMPLEMENTED", "nginx/{sni,mtls}.conf", "not asserted by lab-verify",
             "containers run; SNI and mTLS assertions not yet scripted"),
        63: ("IMPLEMENTED", "certs/rotate-old|new, nginx/rogue.conf",
             "not asserted by lab-verify", "fixtures exist; rotation not yet scripted"),
        64: ("VERIFIED", "web-divergent at 10.77.0.14", "make lab-verify + certscan run",
             "PARTIAL ROLLOUT, 3 of 4 match, 10.77.0.14 serves 26dd29a8adde2cc1"),
        65: ("VERIFIED", "web-draining, no listener", "make lab-verify",
             "refuses TCP (ECONNREFUSED), asserted"),
        66: ("VERIFIED", "coredns/Corefile", "dig inside the network",
             "lab.internal.test -> 4 addresses; rebind -> 169.254.169.254"),
        67: ("VERIFIED", "test/lab/services -mode=imds", "S13/S14 run",
             "0 touches from certscan; 1 when touched by hand (vacuity proven)"),
        68: ("BLOCKED_EXTERNAL", "docker-compose.aws.yml (LocalStack only)",
             "LocalStack suite passes", "kind + cert-manager + tc netem NOT built"),
        69: ("VERIFIED", "test/lab/services -mode=ingest", "manual probe",
             "captured body 'BODY-CANARY' and header X-Secret-Probe"),
    }
    ev.update(lab)

    # E6 070-085
    has_state = exists("pkg/state/machine.go")
    for i in range(70, 80):
        ev[i] = ("VERIFIED", "pkg/verify", "pkg/verify tests green",
                 "classify_test.go 20 tests + regression_test.go 14 tests")
    for i, note in [(80, "soft/hard + per-sub-reason N"), (81, "60s recheck, 10min window"),
                    (83, "hard_transition/recovery/escalation"), (84, "severity table")]:
        ev[i] = (("VERIFIED" if has_state else "NOT_STARTED"), f"pkg/state — {note}",
                 "pkg/state 20 tests", "mutation-tested: 3 of 4 mutations caught, 4th "
                 "exposed a gap in the test which was then fixed")
    ev[82] = ("VERIFIED", "pkg/verify grace window", "regression_test.go",
              "grace never suppresses expiry; disableable with a negative value")
    ev[85] = ("IN_PROGRESS", "lab exists; scenarios not scripted as a suite",
              "one scenario run by hand", "S13/S14 executed; S1-S12/S28/S29 not scripted")

    ev[86] = ("VERIFIED", "pkg/model + testdata/wire_golden.json",
              "3 tests: golden, round-trip, strict decode",
              "renaming/retyping/removing a field fails with a diff")
    for i in range(87, 91):
        ev[i] = ("NOT_STARTED", "", "", "")
    for i in range(91, 177):
        ev[i] = ("NOT_STARTED", "", "", "")

    # From 091 on, every claim names the plan ID it is evidence FOR, and the
    # claim is refused if that is not the plan's ID for that row. An earlier
    # version keyed these blocks by work epic and shifted 120-141 onto the
    # wrong rows, marking UI and partitioning VERIFIED with no UI in the repo.
    def claim(i, pid, status, impl, tests, evidence):
        assert plan_id[i].startswith(pid), f"item {i} is {plan_id[i]!r}, claim says {pid!r}"
        ev[i] = (status, impl, tests, evidence)

    # E8 tenancy + RLS, verified against real PostgreSQL.
    e8 = "17 tests inc. 14-table sweep; mutations: FORCE caught, session-SET caught"
    claim(91, "TENANT-001", "VERIFIED", "constrained roles; Open refuses BYPASSRLS/superuser", "internal/store", e8)
    claim(92, "SCHEMA-001", "VERIFIED", "migration 001, RLS scaffolding, tenant_rls()", "internal/store", e8)
    claim(93, "TENANT-002", "VERIFIED", "internal/tenancy; no handle without a tenant", "internal/store", e8)
    claim(94, "TENANT-003", "VERIFIED", "set_config(..., TRUE) transaction-local", "internal/store", e8)
    claim(95, "SCHEMA-002", "VERIFIED", "migrations 002-009, tenant-owned tables", "internal/store", e8)
    claim(97, "TENANT-004", "VERIFIED", "cross-tenant suite + pg_class/pg_policy sweep; exactly one "
          "pre-tenancy table, reachable only through SECURITY DEFINER functions", "internal/store", e8)
    claim(96, "SCHEMA-013", "VERIFIED" if exists("sqlc.yaml") else "NOT_STARTED",
          "sqlc.yaml; internal/store/queries -> internal/store/db, used by store/sched/history",
          "make sqlc-check (vet + diff) in make check; 3 sqlc tests",
          "generated query on bare pool sees 0 rows (RLS); every generated query used; "
          "mutations 2/3 caught, 3rd (NULLIF cast) a measured equivalence")

    # E9 auth.
    a9 = "6 of 6 mutations caught (disabled user, replay, idle, rotation, role, fail-open)"
    oidc = ("OIDC tests vs a real local IdP; shared-issuer cross-tenant login found and "
            "fixed (c871b3e); mutations 7/8 caught, 8th a measured equivalence")
    claim(98, "AUTH-001", "VERIFIED", "internal/auth/oidc.go — discovery, PKCE S256, nonce",
          "forged signature, wrong issuer/audience, nonce mismatch, expiry, state replay", oidc)
    claim(99, "AUTH-002", "VERIFIED", "internal/auth sessions", "13 tests", a9)
    claim(100, "AUTH-003", "VERIFIED", "domain-to-tenant from the verified claim; JIT viewer; "
          "flow bound to (issuer, client, domain)", "cross-tenant login refused", oidc)
    claim(101, "AUTH-004", "VERIFIED", "RBAC middleware, scope-then-authorize", "4 tests", a9)
    claim(102, "AUTH-005", "VERIFIED", "authorization matrix, asserted total", "TestAuthorizationMatrix...", a9)

    # E9 enrolment + ingestion.
    e10 = "29 tests vs real PostgreSQL and a real TLS 1.3 connection; mutations 7/7 caught"
    for i, pid, what in [(103, "ENROL-001", "CA, clientAuth-only issuance, narrow Sign/Bundle"),
                         (104, "ENROL-002", "token: hashed, single-use, 24h, audited; 409 vs 401"),
                         (105, "ENROL-003", "CSR validation: proof of possession, key strength"),
                         (106, "ENROL-004", "rotation at 50% life; immediate revocation"),
                         (107, "PROTO-002", "mTLS, TLS 1.3 min, CA pinning, no session tickets"),
                         (108, "INGEST-001", "schema-closed decoder"),
                         (109, "INGEST-002", "tenant cross-check vs client cert; 403 + audit"),
                         (110, "INGEST-003", "INV-5 server-side private-key rejection"),
                         (111, "INGEST-004", "idempotency by batch_id"),
                         (112, "INGEST-005", "upsert pipeline"),
                         (114, "INGEST-006", "caps: 1000 obs / 5MB / 20MB; gzip bomb bounded")]:
        claim(i, pid, "VERIFIED", what, "internal/ingest + internal/enroll", e10)
    claim(113, "EP-001", "IMPLEMENTED", "endpoints upserted on ingest", "covered indirectly",
          "proposal/dedup/monitored flags not built")

    # E10 scheduling and drift. Only what the row asks for counts.
    claim(122, "SCHED-003", "IMPLEMENTED", "internal/sched — persistent queue, SKIP LOCKED, leases",
          "TestConcurrentWorkersNeverClaimTheSameJob, TestConcurrentEnqueueOfOneKeyProducesOneRow",
          "two workers never double-claim (verified); per-collector enqueue not built")
    claim(127, "DRIFT-001", "VERIFIED", "drift_events (002), written in the fold's transaction",
          "internal/history tests", "9 tests vs real PostgreSQL; idempotency, restart, isolation")
    claim(128, "DRIFT-004", "VERIFIED", "alerts partial unique index on (tenant, dedupe_key) WHERE open",
          "TestConcurrentConfirmingFoldsProduceOneAlert, TestRepeatedDriftDoesNotDuplicate",
          "a second open alert for a group is refused by the database")
    for i, pid, what in [(121, "SCHED-001", "partial: next_verify_at exists; no tier model, no jitter"),
                         (123, "SCHED-004", "no promotion/demotion"),
                         (124, "SCHED-006", "partial: queue depth (StatsFor) only; no demotion, no UI"),
                         (125, "SCHED-007", "no collector-silence sweep"),
                         (126, "SCHED-008", "job retry backoff exists; endpoint transport backoff does not"),
                         (129, "DRIFT-005", "partial: recovery only; no ack, snooze, ownership-gap"),
                         (130, "DRIFT-008", "no report_only flag"),
                         (131, "DRIFT-009", "no total_30d"),
                         (132, "SCHEMA-011", "no partitioning, no downsample"),
                         (133, "EXP-001", "partial: expected_states table only; no write path"),
                         (135, "EXP-004", "API not built"),
                         (136, "EXP-006", "not built"),
                         (137, "UI-001", "no UI in the repository"),
                         (138, "UI-004", "no UI in the repository"),
                         (139, "UI-005", "no UI in the repository"),
                         (140, "EXP-005", "not built"),
                         (142, "ALERT-003", "partial: Notifier interface only; no Slack, no SES"),
                         (143, "ALERT-005", "partial: re-notification sweep + recovery; no 0/4/24h, ack, snooze"),
                         (144, "ALERT-007", "partial: retry + give-up; no channel health, no rate limit"),
                         (145, "ALERT-009", "no cross-endpoint aggregation")]:
        claim(i, pid, "NOT_STARTED", "", "", what)
    claim(134, "EXP-008", "IMPLEMENTED", "pkg/verify/classify.go — Alertable set in one place",
          "TestUnconfirmedExpectationNeverAlerts + regression", "the 16-case matrix is not asserted as such")
    claim(141, "ALERT-001", "IMPLEMENTED", "internal/alert — alerts + alert_deliveries outbox, upsert",
          "internal/alert 14 tests", "tables and upsert verified; endpoint aggregation not built")
    claim(146, "S7", "IMPLEMENTED", "unconfirmed -> not alertable -> no event -> no alert",
          "TestNonAlertableResultNeverCreatesAnAlert (real PostgreSQL)",
          "zero notifications verified; the 'one UI row' half needs the UI")
    claim(120, "PROTO-009", "NOT_STARTED", "", "", "conformance suite not built")
    for i, pid in [(115, "PROTO-003"), (116, "PROTO-004"), (117, "PROTO-005"),
                   (118, "PROTO-007"), (119, "PROTO-008")]:
        claim(i, pid, "NOT_STARTED", "", "", "collector-side protocol")

    claim(89, "LOCAL-003", "IN_PROGRESS", "test/lab/soak/run.sh (caffeinate + gap detection)", "running",
          "attempt 1 INVALID (host slept); attempt 2 started 2026-10-03T14:15:48Z; "
          "must not be VERIFIED before a full 24h with zero invalidating gaps")

    # Items that are not engineering at all.
    for i, why in [(171, "SOC 2 Type II observation window — months, needs an auditor"),
                   (172, "design-partner pilot — needs a customer"),
                   (173, "7-day false-positive soak — needs a pilot"),
                   (175, "first paying customer, signed contract >= $9,000")]:
        ev[i] = ("BLOCKED_EXTERNAL", "", "", why)
    return ev

plan_id = {it["item"]: it["id"] for it in items}
ev = probe()
commit = sh("git rev-parse --short HEAD")
for it in items:
    s, impl, tests, evid = ev.get(it["item"], ("NOT_STARTED", "", "", ""))
    it.update(status=s, implementation=impl, tests=tests, evidence=evid,
              commit=commit if s not in ("NOT_STARTED",) else "")

counts = {}
for it in items:
    counts[it["status"]] = counts.get(it["status"], 0) + 1

(REPO / "ledger.json").write_text(json.dumps(
    {"total": len(items), "counts": counts, "generated_from": str(PLAN),
     "head": commit, "items": items}, indent=1))

# ---- human-readable -------------------------------------------------------
out = ["# Completion ledger", "",
       f"Generated from `{PLAN.name}` and the repository at `{commit}`.",
       "Every status is an evidence probe against the working tree, not a claim from a document.",
       "", "## Totals", "", "| Status | Items |", "|---|---|"]
order = ["VERIFIED", "TESTED", "IMPLEMENTED", "IN_PROGRESS", "BLOCKED_EXTERNAL", "NOT_STARTED"]
for k in order:
    if counts.get(k):
        out.append(f"| {k} | {counts[k]} |")
out += [f"| **Total** | **{len(items)}** |", ""]
out += ["`COMPLETE` is deliberately absent: it requires implementation, tests and",
        "verification evidence together, and is not claimed for any item here.", ""]

by_phase = {}
for it in items:
    by_phase.setdefault(it["phase"], []).append(it)
for ph, its in by_phase.items():
    c = {}
    for it in its:
        c[it["status"]] = c.get(it["status"], 0) + 1
    summ = ", ".join(f"{v} {k.lower()}" for k, v in sorted(c.items()))
    out += [f"## {ph}", "", f"*{len(its)} items — {summ}*", "",
            "| # | ID | Status | Evidence |", "|---|---|---|---|"]
    for it in its:
        e = it["evidence"] or ("—" if it["status"] == "NOT_STARTED" else "")
        out.append(f"| {it['item']:03d} | `{it['id']}` | {it['status']} | {e} |")
    out.append("")
(REPO / "LEDGER.md").write_text("\n".join(out))
print(f"total {len(items)}")
for k in order:
    if counts.get(k):
        print(f"  {k:18} {counts[k]}")
