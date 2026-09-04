# Pico — Sprint 025: Scan History and Explicit Diff by ID (v0.4 slice 2)

**Status:** DONE

**Sprint:** 025
**Phase:** v0.4 — Security Memory and Change Detection
**Type:** Implementation (second slice)
**Baseline:** TBD (post-Sprint-024 main HEAD)
**Depends on:** Sprint 024 (finding-set diff), Sprint 015 (fingerprints), Sprint 010 (COMPLETE-scan query)

---

# 1. Purpose

Sprint 024 proved finding-set memory over the last two COMPLETE scans. Two
gaps remain in the comparison UX:

1. **No scan catalog.** Users cannot see what scans exist, which are COMPLETE,
   or which pair `pico diff` would compare.
2. **No explicit pair.** `pico diff` always compares the last two COMPLETE
   scans. Users cannot compare an older pair to investigate when a path
   appeared or to verify a specific change window.

Sprint 025 closes both gaps:

> **`pico history` lists all scans with status, finding count, and timestamps.
> `pico diff <from> <to>` compares Findings between two explicit COMPLETE
> scans by id.**

---

# 2. Scope

- **Application service** `HistoryService::list`: load all scans via
  `ScanRepo::list()`, attach finding counts via `FindingRepo::count_for_scan`,
  return a `ScanHistory` vec ordered chronologically.
- **Application service** `DiffService::compare`: given two scan ids, validate
  both are COMPLETE, load findings for each, and produce a `FindingDiff`
  (same type as `DiffService::latest`). Reuse the existing `compare()` logic.
- **CLI** `pico history`: render the scan catalog.
- **CLI** `pico diff <from> <to>`: compare two explicit scans by id.
  `pico diff` (no args) continues to delegate to `DiffService::latest`.
- **Golden-path regression**: `pico scan`, `pico findings`, `pico finding`,
  `pico diff` (no args) unchanged.

---

# 3. Non-goals

- Resource / relationship first-seen / last-seen / changed / disappeared
  (Sprint 026).
- Causal explanation from evidence on both sides.
- Weakened / strengthened / uncertain as first-class lifecycle states.
- Retention, pruning, database-health controls.
- Machine-readable / CI export as a public API.
- MCP diff or history tools (CLI only this slice).
- Independent-developer v0.3 comprehension gate (still a human process).

---

# 4. Validation Matrix

```text
R1  `pico history` lists all scans in chronological order with status,
    finding count, and completed-at timestamp
    → NEW-FIXTURE (history_lists_all_scans_chronologically)

R2  `pico history` with zero scans shows a scoped empty state, not an
    all-clear
    → NEW-FIXTURE (history_empty_state_is_scoped)

R3  `pico diff <from> <to>` compares two COMPLETE scans and produces the
    same FindingDiff structure as `pico diff` (no args) for the same pair
    → NEW-FIXTURE (explicit_diff_matches_latest_for_same_pair)

R4  `pico diff <from> <to>` with a non-existent scan id returns a clear
    error
    → NEW-FIXTURE (explicit_diff_nonexistent_scan_is_error)

R5  `pico diff <from> <to>` with a PARTIAL or FAILED scan id returns a
    clear error (COMPLETE-only comparison)
    → NEW-FIXTURE (explicit_diff_partial_scan_is_error)

R6  `pico diff <from> <to>` with from = to returns a clear error
    → NEW-FIXTURE (explicit_diff_same_scan_is_error)

R7  Determinism: identical id pair => identical rendered diff
    → NEW-FIXTURE (explicit_diff_deterministic_across_runs)

R8  Secret sweep: synthetic tokens never appear in history or diff output
    → NEW-FIXTURE (secret_sweep_never_leaks_in_history_or_explicit_diff)

R9  `pico diff` (no args) behavior unchanged from Sprint 024
    → EXISTING-FIXTURE (sprint024 R1–R7 still pass)

R10 MCP parity: no history/diff tool => N/A
    → NOT-APPLICABLE
```

---

# 5. Controlled Environment

Fixture-only. Reuse the Sprint 010 / Sprint 024 golden provider-injected
OpenCode path (no live tokens, no new dogfood).

---

# 6. Design Notes

## 6.1 History service

```rust
pub struct ScanSummary {
    pub id: String,
    pub status: String,           // "COMPLETE" | "PARTIAL" | "FAILED" | "RUNNING"
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub finding_count: u64,
}

pub struct ScanHistory {
    pub scans: Vec<ScanSummary>,
}
```

`HistoryService::list(workspace)` opens a read-only snapshot, calls
`ScanRepo::list()` (chronological), and for each scan calls
`FindingRepo::count_for_scan(scan_id)`. Returns `ScanHistory`.

Note: `FindingRepo::count_for_scan` does not exist yet; add it as
`SELECT COUNT(*) FROM findings WHERE scan_id = ?1`.

## 6.2 Explicit diff

`DiffService::compare(workspace, from_id, to_id)` opens a read-only snapshot,
loads both scans via `ScanRepo::get(id)`, validates:

- Both exist => error `PicoError::usage("scan {id} not found")`
- Both COMPLETE => error `PicoError::usage("scan {id} is {status}; diff requires COMPLETE")`
- from != to => error `PicoError::usage("cannot diff a scan with itself")`

Then loads findings for both, calls the existing `compare()` function, and
returns `FindingDiffResult::Ready(FindingDiff)`.

The `freshness` field is `LatestComplete` (explicit pair is intentional;
freshness warnings apply to the implicit "last two" path only). The
`newest_attempt` field is `None` for explicit diffs.

## 6.3 CLI

```text
pico history

  Scan History

  ID                    Status    Findings  Completed
  scan_abc123           COMPLETE       1     2026-08-27T14:30:00Z
  scan_def456           COMPLETE       0     2026-08-26T10:15:00Z
  scan_ghi789           PARTIAL       —     —

  Newest COMPLETE: scan_abc123
```

```text
pico diff <from> <to>

Pico diff

From: <from-id> (COMPLETE)
To:   <to-id> (COMPLETE)
Compared: EXPLICIT PAIR

Findings
  Unchanged: N
  Appeared:  N
  Disappeared: N
```

`pico diff` (no args) output unchanged from Sprint 024 except the
`Compared:` line now reads `LAST TWO COMPLETE SCANS` (already the case).

## 6.4 Error rendering

Errors from explicit diff are rendered to stderr with the `PicoError::Usage`
pattern already used by `pico finding <empty-id>`.

## 6.5 Tests

`tests/integration/sprint025_cli_test.rs` through `HistoryService` +
`DiffService::compare` + render functions. Follow the Sprint 024 test
pattern (tempdir workspace, provider injection, InitService, ScanService).

---

# 7. Commit Policy

Authoring commit:

```text
docs(sprints): define Sprint 025 scan history and explicit diff by ID
```

Implementation commits conventional, each with its regression test. Do not
amend previous commits. Do not claim v0.4 complete.

---

# 8. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-09-03
  Baseline: TBD (post-S024 main HEAD)
  Verified by: cargo test --lib (150 passed); sprint025_cli_test (9);
               sprint024_cli_test (7+1 regression); persistence (39)

commits
  authored + impl: feat(cli) pico history + pico diff <from> <to>;
                   docs(sprints) SPRINT-025

repository state
  A  src/application/history.rs
  M  src/application/mod.rs          (HistoryService, ScanHistory, ScanSummary, ComparedVia)
  M  src/application/diff.rs         (DiffService::compare, ComparedVia)
  M  src/persistence/findings.rs     (FindingRepo::count_for_scan)
  M  src/cli/mod.rs                  (History command, Diff with optional args)
  M  src/cli/render.rs               (render_scan_history, render_ready_diff compared_via)
  A  tests/integration/sprint025_cli_test.rs
  M  tests/integration.rs            (sprint025_cli_test registration)
  A  docs/internal/sprints/SPRINT-025.md

new fixtures (R1–R10)
  R1 history_lists_all_scans_chronologically
  R2 history_empty_state_is_scoped
  R3 explicit_diff_matches_latest_for_same_pair
  R4 explicit_diff_nonexistent_scan_is_error
  R5 explicit_diff_partial_scan_is_error
  R6 explicit_diff_same_scan_is_error
  R7 explicit_diff_deterministic_across_runs
  R8 secret_sweep_never_leaks_in_history_or_explicit_diff
  R9 existing sprint024 regression (sprint024_latest_diff_unchanged)
  R10 MCP N/A

MCP N/A justification
  MCP tools remain list_findings / get_finding. No history/diff tool.
  HistoryService and DiffService::compare are application-layer and can
  be exposed later without a second comparison engine.

determinism + secret-sweep
  R7 PASS; R8 PASS (SECRET_SENTINEL / synthetic-token absent)

roadmap note (v0.4 in progress; v0.3 independent gate still open)
  ROADMAP §18: v0.4 IN PROGRESS (S024+S025); independent comprehension
  still PENDING
```

---

# 9. Final Report Contract

```text
Sprint: SPRINT-025 — Scan History and Explicit Diff by ID
Status: DONE
Baseline: TBD

History:
  lists all scans chronologically: PASS
  empty state scoped: PASS

Explicit diff:
  matches latest for same pair: PASS
  nonexistent scan error: PASS
  partial scan error: PASS
  same-scan error: PASS
  deterministic: PASS

Regression: Sprint 024 R1–R7 intact
Golden path: intact
```
