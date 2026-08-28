# Pico — Sprint 024: Finding-Set Diff over COMPLETE Scans (v0.4 start)

**Status:** DONE

**Sprint:** 024
**Phase:** v0.4 — Security Memory and Change Detection
**Type:** Implementation (first slice)
**Baseline:** `fac8406` (post-Sprint-023 main HEAD, origin/main)
**Depends on:** Sprint 015 (finding fingerprints), Sprint 010 (COMPLETE-scan query), Sprint 019 (incomplete-evidence freshness)

---

# 1. Purpose

v0.4's central claim is:

> **Pico can tell a developer what dangerous path appeared, disappeared,
> weakened, strengthened, or became uncertain—and what observed change
> caused it.**

S015 already made finding fingerprints a pure function of security-significant
content. Scans are already append-only. What is missing is a **comparison
product**: two COMPLETE snapshots, compared by fingerprint, without treating
collection failure as remediation.

Sprint 024 is the first v0.4 slice. It proves **finding-set memory**, not the
whole phase.

> **`pico diff` compares Findings from the last two COMPLETE scans by
> fingerprint: unchanged, appeared, disappeared. A newer PARTIAL/FAILED
> attempt is a freshness warning, never a disappearance.**

---

# 2. Scope

- **Application service** `DiffService::latest`: load the two newest COMPLETE
  scans (same ordering as `ScanRepo::newest_complete`), list Findings for each
  via existing persistence, join on `fingerprint`.
- **CLI** `pico diff`: render the comparison. No scan ids in this sprint
  (always last two COMPLETE).
- **Freshness**: reuse S019 semantics. If a newer RUNNING/PARTIAL/FAILED
  attempt exists, warn and still compare COMPLETE snapshots. Collection
  failure is never presented as a disappeared Finding.
- **Empty states**: 0 COMPLETE scans and 1 COMPLETE scan have distinct
  guidance; neither is an all-clear.
- **Golden-path regression**: `pico findings` / `pico finding` / scan summary
  unchanged.
- **MCP**: no `diff` tool this sprint. Record N/A; same application service
  can grow an MCP surface later.

---

# 3. Non-goals

- Resource/relationship first-seen / last-seen / reappeared (later v0.4).
- Causal explanation ("Bash went from ALLOW to DENY caused this") — later
  slice using evidence from both sides.
- Weakened / strengthened / uncertain as first-class lifecycle states.
  Fingerprint identity already includes severity and confidence, so those
  changes appear as disappeared + appeared. Do not invent a coarser identity
  in this sprint.
- Retention, pruning, database-health controls.
- Machine-readable / CI export as a public API (CLI text only).
- Runtime monitoring, alerts, notifications (v0.5).
- A third agent, new adapters, or new finding rules.
- Independent-developer v0.3 comprehension gate (still a human process).

---

# 4. Validation Matrix

```text
R1  Unchanged environment => no security-significant finding diff
    → NEW-FIXTURE (unchanged_complete_scans_have_empty_finding_diff)

R2  Finding disappearance is reported when a later COMPLETE scan no longer
    contains the fingerprint (e.g. Bash deny / blocked path)
    → NEW-FIXTURE (complete_scan_without_finding_reports_disappeared)

R3  Security-significant change that still yields a Finding flips the
    fingerprint: one disappeared, one appeared (S015 identity)
    → NEW-FIXTURE (fingerprint_flip_is_disappeared_and_appeared)

R4  Newer PARTIAL/FAILED attempt never counts as disappearance; diff uses
    last two COMPLETE scans and surfaces the S019 freshness warning
    → NEW-FIXTURE (partial_attempt_does_not_fabricate_disappearance)

R5  0 or 1 COMPLETE scan: distinct guidance, not an all-clear
    → NEW-FIXTURE (diff_empty_states_are_scoped)

R6  Determinism: identical pair => identical rendered diff (ids/timestamps
    aside, structure and fingerprint sets match)
    → NEW-FIXTURE (diff_fingerprint_sets_stable_across_identical_pairs)

R7  Secret sweep: synthetic tokens never appear in the diff
    → NEW-FIXTURE (secret_sweep_never_leaks_token_in_diff)

R8  MCP parity: no diff tool => N/A (justify; do not add a tool)
    → NOT-APPLICABLE
```

---

# 5. Controlled Environment

Fixture-only. Reuse the Sprint 010 golden provider-injected OpenCode path
(no live tokens, no new dogfood). PARTIAL is produced with the existing
malformed OpenCode fixture after two COMPLETE scans.

---

# 6. Design Notes

## 6.1 Comparison set (R1–R4)
`ScanRepo` gains `list_complete` (COMPLETE only, same order as
`newest_complete`: `completed_at DESC, started_at DESC, id DESC`). Diff takes
the first two, then compares **older → newer**.

Join key is `findings.fingerprint` (S015). Row `id` is not the identity.

## 6.2 CLI (R1, R5)
```text
Pico diff

From: <older-id> (COMPLETE)
To:   <newer-id> (COMPLETE)
Compared: LAST TWO COMPLETE SCANS
Freshness: LATEST COMPLETE | NEWER INCOMPLETE ATTEMPT

Findings
  Unchanged: N
  Appeared:  N
  Disappeared: N
```

Zero appeared and zero disappeared: `No security-significant finding change.`
Zero findings on both sides: that sentence plus `This is not an all-clear.`

Appeared/disappeared entries show severity, confidence, title, fingerprint,
and finding id, through `terminal_safe`.

## 6.3 Incomplete evidence (R4)
Do not select PARTIAL scans as `from`/`to`. If `newest_attempt` is newer and
incomplete, copy the S019 warning used by `pico findings`.

## 6.4 Tests (R1–R7)
`tests/integration/sprint024_cli_test.rs` through `DiffService` +
`render_finding_diff`. Do not require spawning the process unless that is
already the local convention.

---

# 7. Commit Policy

Authoring commit:

```text
docs(sprints): define Sprint 024 finding-set diff over COMPLETE scans
```

Implementation commits conventional, each with its regression test. Do not
amend previous commits. Do not claim v0.4 complete.

---

# 8. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-08-27
  Baseline: fac8406 (post-S023 origin/main)
  Verified by: cargo test --lib (144 passed); sprint024_cli_test (7);
               sprint010_cli_test (14); persistence (39)

commits
  authored + impl: feat(cli) pico diff; docs(sprints) SPRINT-024

repository state
  A  src/application/diff.rs
  M  src/application/mod.rs
  M  src/persistence/repos.rs     (ScanRepo::list_complete)
  M  src/cli/mod.rs / render.rs
  A  tests/integration/sprint024_cli_test.rs
  M  tests/integration.rs
  A  docs/internal/sprints/SPRINT-024.md
  M  docs/internal/ROADMAP.md     (§18 v0.4 IN PROGRESS)

new fixtures (R1–R8)
  R1 unchanged_complete_scans_have_empty_finding_diff
  R2 complete_scan_without_finding_reports_disappeared
  R3 fingerprint_flip_is_disappeared_and_appeared
  R4 partial_attempt_does_not_fabricate_disappearance
  R5 diff_empty_states_are_scoped
  R6 diff_fingerprint_sets_stable_across_identical_pairs
  R7 secret_sweep_never_leaks_token_in_diff
  R8 MCP N/A

MCP N/A justification
  MCP tools remain list_findings / get_finding. No scan/diff tool.
  DiffService is application-layer and can be exposed later.

determinism + secret-sweep
  R6 PASS; R7 PASS (TEST_SECRET_SHOULD_NOT_PERSIST / synthetic-token absent)

roadmap note (v0.4 in progress; v0.3 independent gate still open)
  ROADMAP §18: v0.4 IN PROGRESS (S024); independent comprehension still PENDING
```

---

# 9. Final Report Contract

```text
Sprint: SPRINT-024 — Finding-Set Diff over COMPLETE Scans
Status: DONE
Baseline: fac8406

Memory:
  last-two COMPLETE comparison: PASS
  unchanged empty diff: PASS
  fingerprint flip appeared+disappeared: PASS
  PARTIAL is not disappearance: PASS
  empty states scoped: PASS
  MCP: N/A (justified)

Golden path: intact
```
