# Pico — Sprint 030: Retention, Pruning, and Database Health (v0.4 slice 7)

**Status:** DONE

**Sprint:** 030
**Phase:** v0.4 — Security Memory and Change Detection
**Type:** Implementation (seventh slice)
**Baseline:** `1f7824b` (post-Sprint-029 comparison contract guard)
**Depends on:** Sprint 008 (persisted analysis), Sprint 024/025 (diff pair selection and history), Sprint 028 (finding lifecycle), Sprint 029 (comparison contract guard)

---

# 1. Purpose

S024–S029 built append-oriented security memory over locally persisted scans.
Nothing in Pico deletes state: every scan adds observations, evidence,
findings, analysis, and diagnostics rows forever. ROADMAP §8 requires local
retention, pruning, and database-health controls that preserve provenance
safely, and its exit criteria require history to remain usable under a
defined retention window without exposing secrets.

Today the risks of unbounded growth are concrete:

- the database grows without bound (append-oriented by design);
- no tooling exists to inspect or restore database health;
- deleting anything is currently unsafe: no foreign key cascades from
  `scans(id)`, three join tables reference `evidence(id)` without cascades,
  and `relationship_evidence` links global relationships to per-scan
  evidence rows.

Sprint 030 proves a **bounded, whole-unit retention contract**:

> **`pico prune` deletes whole, coherent scan units beyond a defined
> retention window — never partial rows, never a live scan — reports exactly
> what it removed, re-verifies database health afterwards, and is idempotent.
> `pico doctor` reports database health read-only: schema version,
> `integrity_check`, `foreign_key_check`, and detectable dangling
> cross-references. Pruning never fabricates finding or graph disappearance:
> a pruned scan leaves history the way a scan that was never run would, and
> S024–S029 semantics over the retained window are unchanged.**

Pruning changes how deep history reaches; it does not reinterpret anything.
A `pico diff` pair that references a pruned scan fails with the existing
explicit "not found" behavior. Graph `first_seen`/`reappeared` attribution
was already window-relative over COMPLETE history; after pruning it is
simply shallower, and Pico must not claim otherwise.

This is not v0.4 complete. Environment-versus-evidence attribution, MCP
diff/history, stable public machine output, and the independent
comprehension gate remain later work.

---

# 2. Scope

- New CLI command `pico prune` (write path): applies the retention policy,
  deletes whole scan units oldest-first beyond the window, reports exactly
  what was deleted, and re-runs the health check after deletion.
- New CLI command `pico doctor` (read path): reports schema version,
  `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, dangling JSON
  reference detection over retained rows, scan-unit coherence, and the
  current retention state. `pico doctor` never mutates state.
- Frozen default retention policy: keep the newest 10 COMPLETE scans plus
  every incomplete attempt (RUNNING/PARTIAL/FAILED) that is newer than the
  newest COMPLETE scan; prune PARTIAL/FAILED attempts older than the newest
  COMPLETE scan; never prune RUNNING scans.
- `--keep N` flag on `pico prune` (integer, `N >= 2`, default 10). Values
  below 2 are a usage error with a fixed message.
- Whole-unit deletion order (frozen, FK-safe under `foreign_keys = true`):
  `scan_diagnostics` → `scan_analyses` → `findings` (link tables cascade) →
  `attack_paths` (link tables cascade) → `observations` →
  `relationship_evidence` rows targeting the scan's evidence ids → the
  scan's `evidence` rows → the `scans` row.
- Deletion is transactional per prune run: all-or-nothing; a failure leaves
  the database exactly as it was.
- Global identity surfaces are never pruned: `resources`, `relationships`,
  and `relationship_evidence` rows whose evidence is retained stay.
- Refuse to prune while any RUNNING scan exists (fail-closed, nothing
  deleted, fixed message).
- Health check function shared by both commands: schema version,
  `integrity_check` = ok, `foreign_key_check` empty, dangling JSON id
  reference detection for `finding_reasons` / `finding_remediations` over
  retained rows, and orphan-scan checks (every scan-scoped row references an
  existing scan; every scan has at most one analysis summary and at most one
  diagnostics row).
- Deterministic report rendering through `terminal_safe`, including pruned
  scan ids and counts; no claim of space reclaimed; no claim that pruning
  improved security.
- Explicitly report when nothing was pruned (no-op is a success, not an
  error).
- Schema remains v6. No data migration. MCP remains exactly `list_findings`
  and `get_finding`; no MCP surface for prune/doctor.
- Automatic post-scan pruning, config files, WAL mode, VACUUM, and orphaned
  global-resource garbage collection remain out of scope (§3).

---

# 3. Non-goals

- Automatic or background retention (post-scan auto-prune is later work;
  retention applies only when `pico prune` runs).
- A configuration file or settings surface. The window is a flag with a
  frozen default; no persistence of the choice.
- VACUUM, `ANALYZE`, page-size tuning, or any disk-space reclamation. Prune
  reports row counts, never bytes reclaimed; free pages remain until a later
  slice.
- WAL journal mode, `-wal`/`-shm` sidecar files, or changed permission
  handling.
- Pruning, rewriting, or re-timestamping `resources`, `relationships`, or
  their join rows (global identity and cross-scan lifecycle stay append-
  oriented).
- Repairing, rewriting, or backfilling any persisted row. `pico doctor`
  reports; it does not fix.
- Re-purposing pruning as environment-change attribution: a pruned scan
  never becomes evidence of remediation, disappearance, or an all-clear.
- MCP tools for prune, doctor, diff, or history; `--json` output.
- Claiming v0.4 complete or advancing to v0.5.

---

# 4. Validation Matrix

```text
R1  Below-window workspace: pico prune deletes nothing, reports "nothing
    pruned", and the database content digest is byte-identical.
    → NEW-FIXTURE (below_window_prune_is_a_no_op)

R2  Window exceeded: with 12 COMPLETE scans and --keep 10, exactly the 2
    oldest COMPLETE scan units are deleted; every newer COMPLETE scan, the
    newest PARTIAL/FAILED attempts, and all their rows are byte-identical
    to before (retained-row digest). Re-running prune is a no-op.
    Default policy (no flag) behaves as --keep 10.
    → NEW-FIXTURE (window_exceeded_prunes_oldest_units_idempotently)

R3  Workspace with any RUNNING scan: prune refuses with a fixed message and
    deletes nothing (digest unchanged). PARTIAL/FAILED older than the
    newest COMPLETE are pruned by the same rule set in one run.
    → NEW-FIXTURE (running_scan_blocks_prune)

R4  Whole-unit atomicity: for every pruned scan id, zero rows remain in any
    scan-scoped table; no retained row gains or loses rows; an injected
    deletion failure mid-run (fixture) rolls back the entire prune.
    → NEW-FIXTURE (pruned_units_leave_no_residual_rows)

R5  History honesty after pruning: `pico history` lists only retained
    scans; `pico diff <pruned_id> <retained_id>` and the reverse fail with
    the existing "scan {id} not found" usage error; the latest diff over
    the retained pair is Ready with intact S029 provenance lines.
    → NEW-FIXTURE (pruned_history_is_explicit_not_fabricated)

R6  Healthy workspace: `pico doctor` reports ok on all checks with counts
    and the retention state, performs no writes (content digest unchanged),
    and exits successfully.
    → NEW-FIXTURE (doctor_reports_ok_without_writing)

R7  Injected inconsistency: a fixture with a foreign-key violation or a
    dangling finding_reasons JSON evidence id is reported by `pico doctor`
    with a deterministic, terminal-safe message; it is never silently
    ignored and never auto-repaired.
    → NEW-FIXTURE (doctor_reports_injected_inconsistency_fail_closed)

R8  `--keep` validation: 0, 1, negative, non-numeric, and missing-value
    forms are usage errors with a fixed message; nothing is deleted.
    → NEW-FIXTURE (keep_flag_is_validated_before_any_deletion)

R9  Secret sweep: a sentinel seeded into a pruned scan's evidence,
    diagnostics, and metadata rows is absent from the whole database after
    prune (retention reduces retained secrets, never leaks them); prune and
    doctor output never contain the sentinel or control bytes.
    → NEW-FIXTURE (pruning_removes_secrets_and_reports_stay_clean)

R10 S024–S029 suites stay green; schema stays v6; MCP descriptors and
    golden payloads stay byte-compatible and expose no new tool.
```

---

# 5. Design Notes

## 5.1 Frozen retention policy

```text
KEEP_COMPLETE_DEFAULT = 10          // --keep N, N >= 2, integer
keep_set(N):
  the newest N COMPLETE scans by (completed_at, started_at, id) — the
  list_complete ordering, kept ascending for windowing
prune_set(N):
  COMPLETE scans outside keep_set(N), oldest-first
  + PARTIAL/FAILED attempts S where (S.started_at, S.id) is strictly older
    than (newest COMPLETE.started_at, newest COMPLETE.id)
never pruned:
  RUNNING scans (prune refuses entirely if any exists)
  the newest PARTIAL/FAILED attempt relative to the newest COMPLETE
  resources, relationships, relationship_evidence (global surfaces)
```

Rationale frozen into the design: an incomplete attempt is only security-
memory-significant while it is newer than the newest COMPLETE scan
(`attempt_is_newer` in S019/S024 freshness semantics). Once a COMPLETE scan
is newer, an older PARTIAL/FAILED attempt cannot produce a freshness
warning, so deleting it cannot change any Pico conclusion — it only shrinks
history. RUNNING scans are never touched because a live scan may still
write; prune refuses instead of racing.

`N >= 2` is required so the latest-two diff contract (S024) always remains
meaningful under any accepted flag value; the default 10 is the frozen
small-team window. The chosen `N` is reported by both `pico prune` and
`pico doctor` but never persisted.

## 5.2 Frozen deletion unit and order

One scan unit is exactly: the `scans` row, its `observations`, `evidence`,
`findings` (+ all four link tables), `attack_paths` (+ both link tables),
`scan_analyses`, `scan_diagnostics`, and the `relationship_evidence` rows
whose `evidence_id` belongs to the unit.

Order (required, FK-safe with `foreign_keys = true`, verified by the
schema inventory in §6 task 2):

```text
BEGIN
  for each pruned scan, oldest-first:
    DELETE FROM scan_diagnostics WHERE scan_id = ?
    DELETE FROM scan_analyses    WHERE scan_id = ?
    DELETE FROM findings         WHERE scan_id = ?   -- cascades 4 link tables
    DELETE FROM attack_paths     WHERE scan_id = ?   -- cascades 2 link tables
    DELETE FROM observations     WHERE scan_id = ?
    DELETE FROM relationship_evidence
      WHERE evidence_id IN (SELECT id FROM evidence WHERE scan_id = ?)
    DELETE FROM evidence         WHERE scan_id = ?
    DELETE FROM scans            WHERE id = ?
COMMIT
```

Rules:

- Cascades are the ONLY permitted cascade use; the prune code must not rely
  on any cascade from `scans(id)` (none exists).
- Every pruned scan's `relationship_evidence` rows are removed explicitly by
  `evidence_id` membership before the unit's `evidence` rows.
- The whole prune run is one transaction. Any error → rollback → database
  byte-identical to the pre-prune digest.
- JSON id columns (`finding_reasons.*_ids`, `finding_remediations.target_*_ids`)
  cannot dangle: retained findings keep their whole same-scan unit, and
  global `resources`/`relationships` are never deleted. `pico doctor` still
  detects any pre-existing dangling reference and reports it rather than
  assuming coherence (R7).

## 5.3 Frozen health check

One shared function, two consumers (`pico doctor` renders it; `pico prune`
runs it before and after deletion):

```text
HealthReport {
  schema_version: i64,                     // must equal SUPPORTED_SCHEMA_VERSION
  integrity: Result<(), String>,           // PRAGMA integrity_check
  foreign_keys: Result<(), String>,        // PRAGMA foreign_key_check
  dangling_json_refs: Vec<DanglingRef>,    // finding_reasons/finding_remediations
  orphan_scan_rows: u64,                   // scan-scoped rows w/o scans row
  summary_rows: u64,                       // scans with >1 scan_analyses or
                                           // >1 scan_diagnostics row
  counts: RetentionCounts,                 // COMPLETE / PARTIAL / FAILED /
                                           // RUNNING + window state
}
```

- Read-only consumer opens `SQLITE_OPEN_READ_ONLY` + `require_schema_version`.
  The prune consumer may open read-write, but the health check itself only
  runs PRAGMAs and SELECTs.
- Dangling JSON detection parses the JSON text columns of `finding_reasons`
  and `finding_remediations` and reports ids that do not resolve to existing
  rows, deterministically ordered and bounded (a cap on reported items, e.g.
  first 20, with a "... and N more" line).
- A failing check is a report item, not necessarily a process failure:
  `pico doctor` exits non-zero when any check fails (fail-closed signal for
  scripts) but still renders the full report. `pico prune` aborts before any
  deletion when a pre-check fails.
- `pico_version`-style hygiene: all rendered values pass `terminal_safe`.

## 5.4 CLI contracts (semantics frozen; exact copy finalized at implementation review)

- `pico prune [--keep N]`: prints a deterministic report — policy line,
  per-deleted-scan lines (id, status, row counts by table), totals,
  post-prune health result, and retained-state summary. Nothing pruned →
  explicit "nothing pruned" sentence, success exit.
- `pico doctor`: prints the health report and retention state; success exit
  only when all checks pass.
- Both commands follow existing render conventions: `terminal_safe` on all
  persisted text, no secrets, no fabricated claims (never "space reclaimed",
  never "environment changed", never "findings fixed").
- CLI shape note (ARCHITECTURE §23.1) gains `pico prune` and `pico doctor`
  in the implemented list.

## 5.5 Test and evidence shape

- Primary integration file: `tests/integration/sprint030_cli_test.rs`,
  registered in `tests/integration.rs`.
- Unit coverage: policy windowing (keep-set/prune-set boundaries, tie-breaks
  by (started_at, id)), deletion-order function against an FK-violation
  fixture, health-check parsers, `--keep` validation.
- Fixtures build scan units through the real services where possible
  (ScanService produces units with real row shapes) and hand-seeded
  persistence where the case needs controlled timestamps or injected
  inconsistencies (R7), following the S028/S029 helper pattern with valid
  S029 comparison declarations.
- R4's injected failure: trigger a mid-unit failure via a fixture that
  violates an FK (e.g., seed a stray `relationship_evidence` row whose
  relationship was deleted) and prove rollback leaves every count and the
  digest unchanged. The stray row itself is reported by `foreign_key_check`
  (documented interplay, not a contradiction).
- R9 reuses and extends the secret-sweep pattern: a `persisted_occurrences`
  helper that covers ALL tables including the migrations-3–6 surfaces
  (the sprint006 helper predates them and must be extended locally in the
  S030 file, not changed in place).
- Zero-write proofs reuse the S029 `content_digest` pattern for `pico
  doctor`, R1, and R3.

## 5.6 Review checkpoints (frozen)

1. Review after policy + unit tests: keep-set/prune-set boundaries and
   `--keep` validation are green before any deletion code runs.
2. Review after deletion implementation: R1–R5 green (atomicity, residual,
   honesty) before `pico doctor` work.
3. Review after health checks: R6–R9 green, including exact fail-closed
   messages.
4. Confirm schema remains v6 and `src/mcp/tools.rs` plus MCP golden fixtures
   are byte-unchanged.
5. Confirm prune never touches `resources`/`relationships`, never deletes a
   RUNNING scan, and never claims reclamation.
6. Confirm docs say "pruned", never "remediated", "disappeared", or
   "environment changed".

---

# 6. Task Breakdown

1. **Spec freeze** — approve this document, especially the default window,
   the `N >= 2` floor, the incomplete-attempt rule, the RUNNING refusal, the
   deletion order, and the two-command shape. No implementation before
   approval.
2. **Policy and deletion engine** — retention policy function, frozen
   deletion order, transactional wrapper, refusal rules; unit tests.
3. **`pico prune` CLI** — dispatch, render, report copy, post-prune health
   re-check.
4. **`pico doctor` CLI** — shared health check, render, fail-closed exit.
5. **Evidence** — R1–R9 fixtures, extended secret sweep, zero-write digests,
   idempotency, rollback fixture.
6. **Documentation and gates** — update architecture only after behavior
   lands; fill §8 evidence; run fmt, clippy, all targets, and diff check.

---

# 7. Commit Policy

```text
docs(sprints): define Sprint 030 retention and database health
```

Implementation conventional. Do not amend. Do not claim v0.4 complete.

---

# 8. Completion Evidence (filled at execution)

```text
Date: 2026-09-04
Baseline: 1f7824b (post-Sprint-029 implementation); spec: 4fc6b06
Verified by: three staged review checkpoints (engine → prune CLI → doctor),
full cargo test --all-targets after each stage

fixtures (R1–R9) — tests/integration/sprint030_cli_test.rs
  R1  below_window_prune_is_a_no_op
  R2  window_exceeded_prunes_oldest_units_idempotently
  R3  running_scan_blocks_prune
  R4  pruned_units_leave_no_residual_rows
  R5  pruned_history_is_explicit_not_fabricated
  R6  doctor_reports_ok_without_writing
  R7  doctor_reports_injected_inconsistency_fail_closed
  R8  keep_flag_is_validated_before_any_deletion
  R9  pruning_removes_secrets_and_reports_stay_clean
  R10 doctor_requires_initialized_state + full-suite regression run
  (plus 28 engine/service unit tests: 20 in-module in
  src/application/retention.rs and 8 in
  tests/persistence/sprint030_retention_test.rs, covering policy windows,
  tie-breaks, deletion order, rollback-on-inconsistency, refusal rules,
  dangling/orphan detection, and doctor no-write)

schema evidence:
  SUPPORTED_SCHEMA_VERSION = 6
  migration: none

MCP evidence:
  descriptors: list_findings, get_finding (unchanged)
  golden payloads: unchanged (git diff --stat -- src/mcp/ empty)

security/read-only evidence:
  doctor/no-op content digest before/after: byte-identical (R1, R6;
  sha256 over sqlite_master rows, user_version, and full table row
  content); retained-row digest byte-identical across real prunes
  (R2, R4)
  pruned-scan secret sweep after deletion: sentinel absent from all 16
  tables after prune (R9); retained sentinel intentionally remains
  prune/doctor output terminal-safe sweep: no control bytes (R7, R9)

gates:
  cargo fmt --all -- --check            PASS
  cargo clippy --all-targets -- -D warnings PASS
  cargo test --all-targets              PASS (520: 222 lib, 30 domain,
                                        218 integration, 50 persistence)
  git diff --check                      PASS
```

---

# 9. Final Report Contract

When Sprint 030 is implemented, report:

- files changed and why;
- exact policy, deletion-order, health-check, and CLI contracts delivered;
- R1–R10 results plus total test counts;
- schema and MCP non-change evidence;
- rollback, idempotency, and secret-removal evidence;
- remaining v0.4 caveats (attribution, MCP diff, machine output,
  comprehension gate);
- `Sprint 030: DONE` only if every checkpoint passes;
- `v0.4: not complete` and the remaining blockers.

---

# 10. Corrective Follow-up Addendum (Sprint 031)

Post-S030 sign-off review (V0.4-CLOSEOUT-PLAN.md) reproduced two P1 defects
and one P2 gap in this slice's delivery at `4c0c49f`: post-health
validation ran after the deletion committed; doctor diagnostics echoed raw
malformed JSON and unresolved id contents; and the RUNNING refusal raced
concurrent writers. Sprint 031
(`docs/internal/sprints/SPRINT-031.md`) corrects all three: one immediate
write transaction covers the whole prune decision and mutation (schema
validated without migrating, post-health validated before commit,
rollback leaves every row unchanged), and diagnostics now report bounded
structural locations with stable reason codes (`unresolved` /
`unparseable`) and never echo contents. Failing regressions were added
first and proven to fail on `4c0c49f`; S030's byte-frozen doctor renders
(R6/R7) were re-pinned to the clarified window line and redacted dangling
shape. S030's policy semantics (keep-10, `--keep >= 2`, whole-unit order,
no-op success, global identity retention) are unchanged.
