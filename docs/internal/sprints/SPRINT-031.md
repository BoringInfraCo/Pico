# Pico — Sprint 031: Retention Correctness Follow-up (v0.4 slice 8)

**Status:** DONE

**Sprint:** 031
**Phase:** v0.4 — Security Memory and Change Detection (closeout)
**Type:** Correction (small)
**Baseline:** `4c0c49f` (post-Sprint-030 retention controls)
**Depends on:** Sprint 030
**Authority:** `docs/internal/sprints/V0.4-CLOSEOUT-PLAN.md` (review verdict
and bounded cleanup; reproduced probes `/tmp/pico-s030-review-probes.{rs,log}`)

---

# 1. Purpose

The S030 sign-off review reproduced two P1 defects and identified one P2
gap. Sprint 031 corrects them and freezes the regressions that fail on the
`4c0c49f` baseline:

> **P1 — deletion committed before post-health validation.**
> `PruneService::run` commits the deletion transaction and only then runs
> `check_health`; a failing post-health check returns an error while the
> deletion has already persisted. Reproduced with a retained finding whose
> JSON `evidence_ids` point at the oldest unit's evidence: doctor passes,
> `pico prune --keep 2` errors, and the oldest scan is gone.
>
> **P1 — doctor echoes raw malformed JSON and untrusted unresolved ids.**
> Unparseable JSON text and arbitrary unresolved id strings travel in
> `DanglingRef` and are rendered by `render_doctor_report`. `terminal_safe`
> escapes control bytes but does not redact secret-looking content; a
> sentinel placed in malformed `finding_reasons.evidence_ids` reaches
> stdout.
>
> **P2 — RUNNING refusal and planning race concurrent writers.** Scans,
> the refusal check, the plan, and pre-health are read before any write
> transaction exists; a scan can start in that interval, violating the
> refusal contract, and the report can be stale.

Sprint 031 proves:

> **`pico prune` holds one immediate write transaction for its entire
> decision and mutation: schema is validated without migrating, scans are
> loaded, RUNNING is refused, retention is planned, pre-health gates, units
> are deleted, and post-health validates — all inside that snapshot. A
> failed health gate rolls back and leaves every row unchanged. Doctor
> diagnostics report bounded structural locations and stable reason codes
> and never echo raw JSON text or unresolved id contents.**

S030's policy semantics are preserved exactly: keep-10 default, `--keep`
floor of 2, whole-unit deletion order, no-op success, global identity
retention, and the two-tool MCP surface.

---

# 2. Scope

- Restructure `PruneService::run` into one immediate write transaction
  (`BEGIN IMMEDIATE`) covering: scan load, RUNNING refusal, retention
  plan, pre-health gate, unit deletion, and post-health validation before
  commit; any failure rolls back and changes nothing.
- Replace `db.migrate()` in prune with `require_schema_version`: an
  unsupported schema fails closed without migrating (remedy stays "run
  `pico init` to upgrade" / the existing downgrade message).
- Redact diagnostics: `DanglingRef` no longer carries the unresolved id or
  raw stored text; it carries table, column, referenced table, stable
  reason category (`unresolved` / `unparseable`), and a bounded structural
  location (finding_id + position) with a per-cell unresolved count.
- Cap diagnostics during collection, not only at render: stop storing
  locations after the frozen cap while still counting the remainder;
  document that reference-target id sets are still loaded (this is not
  bounded total memory).
- Update `render_doctor_report`: new dangling line shape (no contents) and
  a clarified retention-window line that separates the policy window from
  the scans actually present.
- Clarify count semantics: `UnitCounts` covers the seven directly deleted
  tables; cascade-deleted link rows and the `scans` row are not counted.
- Update the S030 byte-frozen renders (R6 healthy window line; R7 dangling
  line shape) as fixture maintenance with pinned regressions.
- Add an S030 completion addendum recording the corrective follow-up.
- Schema stays v6. MCP stays exactly `list_findings` and `get_finding`.

---

# 3. Non-goals

- The S032+ attribution, JSON-output, MCP diff/history, and comprehension
  slices (closeout §4–§7).
- Changing the retention policy, window defaults, deletion order, or the
  no-op/refusal/health-abort error copy beyond what the fixes require.
- Repairing detected inconsistencies (doctor still reports; it never
  fixes).
- Bounded total database memory during health checks (target-id sets
  still load; documented, not fixed).
- Automatic retention, VACUUM, WAL, config files, or global-row GC.
- Backfilling, rewriting, or re-analyzing any persisted row.

---

# 4. Validation Matrix

```text
R1  A retained finding's JSON evidence_ids reference the OLDEST unit's
    existing evidence (so pre-health passes). prune --keep 2 fails with
    "database health check failed after prune", the whole-DB content
    digest is byte-identical, every pruned unit still exists with all
    rows, and doctor afterwards reports the dangling reference.
    → NEW-FIXTURE, fails on 4c0c49f
    (post_health_failure_rolls_back_and_deletes_nothing)

R2  Sentinel inside malformed finding_reasons.evidence_ids: the doctor
    render contains the table, column, structural location, and
    unparseable category — never the sentinel, never the raw JSON text.
    → NEW-FIXTURE, fails on 4c0c49f
    (doctor_redacts_malformed_json_sentinel)

R3  Valid JSON ids containing sentinels that resolve to nothing: the
    doctor render shows the per-cell unresolved count and structural
    location — never any sentinel id.
    → NEW-FIXTURE, fails on 4c0c49f
    (doctor_redacts_unresolved_id_contents)

R4  Schema-v5 database (migration-6 rewind fixture): prune fails with the
    existing require_schema_version remedy, PRAGMA user_version stays 5,
    no row changes; doctor on the same state reports the unsupported
    schema without writing.
    → NEW-FIXTURE, fails on 4c0c49f (baseline migrates then proceeds)
    (prune_rejects_unsupported_schema_without_migrating)

R5  Two-connection exclusion: connection A holds the immediate write
    transaction the service uses; connection B (busy_timeout 0) cannot
    write until A commits; after commit B succeeds. A RUNNING scan
    committed by B before prune starts is still refused. No sleeps.
    → NEW-FIXTURE (immediate_transaction_excludes_concurrent_writer)

R6  Zero-write proofs stay green under the new sequence: below-window
    no-op and RUNNING refusal change nothing (whole-DB digest); repeat
    pruning stays idempotent with retained-row digests.
    → REGRESSION (prune_noop_and_refusal_stay_zero_write,
      prune_repeat_stays_idempotent)

R7  Secret sweep: sentinel-bearing rows produce no sentinel content in
    prune or doctor output under the new diagnostics shape; every output
    byte is terminal-safe.
    → NEW-FIXTURE (prune_and_doctor_output_stay_secret_safe)

R8  S024–S030 suites stay green (updated S030 R6/R7 byte fixtures
    included); schema stays v6; MCP descriptors and golden payloads
    byte-unchanged.
```

---

# 5. Design Notes

## 5.1 Frozen PruneService::run sequence

```text
1. RetentionWindow::resolve(keep)?            // unchanged, before any DB work
2. Database::open_existing(.pico/pico.db)?    // NO migrate
3. require_schema_version(conn)?              // unsupported schema fails closed
4. tx = conn.transaction_with_behavior(Immediate)   // one write transaction
5. inside tx:
     scans = ScanRepo::list()
     RUNNING present → rollback + Err(usage, frozen refusal message)
     plan = plan_retention(window, scans)
     pre = check_health(tx, window); !ok → rollback + Err(database, frozen abort)
     no-op → rollback + Ok(report from this snapshot)
     pruned = delete_scan_units(tx, planned order)   // frozen order
     post = check_health(tx, window); !ok → rollback + Err(database,
            "database health check failed after prune")
     commit
6. report built from this same snapshot
```

Lock behavior: `BEGIN IMMEDIATE` excludes other writers for the whole
operation; a competing writer either already holds the write lock (prune
fails with a database error and deletes nothing) or is excluded until
prune finishes. A RUNNING scan that commits before prune acquires the lock
is refused; one that commits after is not visible to the snapshot and
cannot race the decision. `check_health` runs only PRAGMAs and SELECTs, so
it is valid inside the write transaction. `Transaction` derefs to
`Connection`, so `delete_scan_units` and `check_health` signatures are
unchanged.

## 5.2 Frozen redacted diagnostics

```rust
pub struct DanglingRef {
    pub table: String,             // "finding_reasons" | "finding_remediations"
    pub column: String,            // frozen column name, schema order
    pub referenced_table: String,  // target table; "-" when unparseable
    pub category: String,          // "unresolved" | "unparseable" (stable reason codes)
    pub finding_id: String,        // structural row location (rendered terminal_safe)
    pub position: u32,
    pub unresolved_count: u64,     // distinct unresolved ids in this cell; 0 when unparseable
}
```

No raw JSON text and no unresolved id contents exist anywhere in the DTO
or the renderer. One diagnostic item per (row, column) cell that has a
problem; per-cell unresolved ids are counted, never listed. Collection
stops STORING after the frozen cap of 20 items but continues COUNTING
locations so the report stays exact; `dangling_more` counts locations
beyond the cap. Doc note: reference-target id sets still load in full —
this is diagnostic-shape bounding, not bounded total database memory use.

Renderer (exact copy):

```text
Dangling references: {total location count}      // or "none"
  {table}/{column}: {unresolved_count} unresolved {referenced_table} id(s) at finding_id={finding_id} position={position}
  {table}/{column}: unparseable JSON at finding_id={finding_id} position={position}
  ... and {dangling_more} more                   // only when dangling_more > 0
```

Deterministic order unchanged: finding_reasons before finding_remediations,
rows by (finding_id, position), columns in schema order. `finding_id` is
the only persisted value rendered; it passes `terminal_safe`.

## 5.3 Frozen doctor window line

```text
Retention window: policy keep {window_keep} COMPLETE scans; workspace has {counts.complete} COMPLETE scans; oldest retained {oldest_retained_complete|none}; newest {newest_complete|none}
```

This separates the policy window from the scans actually present (the S030
line conflated them when the workspace holds fewer COMPLETE scans than the
policy keeps).

## 5.4 Counts clarification (documentation)

`UnitCounts` (and its render) cover exactly the seven directly deleted
tables — observations, evidence, findings, attack_paths, scan_analyses,
scan_diagnostics, relationship_evidence. Cascade-deleted link-table rows
and the `scans` row itself are not counted and are not claimed.

## 5.5 S030 fixture maintenance

S030 R6 (healthy doctor) and R7 (dangling doctor) byte-frozen renders are
updated to the §5.2/§5.3 shapes and re-pinned. All other S030/S024–S029
behavior is untouched. An addendum note is appended to
`docs/internal/sprints/SPRINT-030.md` recording the corrective follow-up
and its evidence pointer.

## 5.6 Review checkpoints (frozen)

1. Stage A complete when R1–R5 exist and R1–R4 demonstrably fail on
   `4c0c49f`; no production code changed yet.
2. Stage B: transaction restructure green (R1, R4, R6) before the
   redaction work.
3. Redaction green (R2, R3, R7) before renderer/S030 fixture updates.
4. Confirm schema stays v6 and MCP surfaces are byte-unchanged.
5. Confirm the whole prune operation is one immediate transaction and the
   report comes from its snapshot.
6. Confirm no output line can contain raw JSON text or unresolved id
   contents.

---

# 6. Task Breakdown

1. **Stage A — failing regressions:** add R1–R5 fixtures proving the safe
   contracts; verify R1–R4 fail on `4c0c49f` (and R5 passes as a mechanism
   pin); no production changes.
2. **Stage B — corrections:** transaction restructure, schema rejection,
   redacted DTO + capped collection, renderer updates, S030 fixture
   re-pins, doc clarifications; all gates green.
3. **Documentation and gates:** S030 addendum, SPRINT-031 §8 evidence,
   ROADMAP closeout paragraph update, fmt/clippy/all-targets/diff-check.

---

# 7. Commit Policy

```text
docs(sprints): add v0.4 closeout plan
docs(sprints): define Sprint 031 retention correctness follow-up
fix(retention): fail prune health gates closed and redact diagnostics
```

Implementation conventional. Do not amend. Do not claim v0.4 complete.

---

# 8. Completion Evidence (filled at execution)

```text
Date: 2026-09-04
Baseline: 4c0c49f (post-Sprint-030); plan: 47ae405; spec: 9062baf
Verified by: staged review (failing regressions → transaction restructure →
redaction → renderer/S030 re-pins), full cargo test --all-targets after
each stage

fixtures (R1–R8) — tests/integration/sprint031_cli_test.rs
  R1  post_health_failure_rolls_back_and_deletes_nothing
  R2  doctor_redacts_malformed_json_sentinel
  R3  doctor_redacts_unresolved_id_contents
  R4  prune_rejects_unsupported_schema_without_migrating
  R5  immediate_transaction_excludes_concurrent_writer
  R6  prune_noop_and_refusal_stay_zero_write + prune_repeat_stays_idempotent
  R7  prune_and_doctor_output_stay_secret_safe
  R8  full-suite regression run (S024–S030 green, re-pinned S030 R6/R7)

stage-A proof (fails on 4c0c49f):
  R1 R2 R3 R4 failing at baseline: recorded before fixes (digest mismatch;
  sentinel echoed verbatim; per-id items instead of per-cell counts;
  v5 database migrated then no-op'd instead of refusing)

schema evidence:
  SUPPORTED_SCHEMA_VERSION = 6
  migration: none (prune no longer migrates)

MCP evidence:
  descriptors: list_findings, get_finding (unchanged)
  golden payloads: unchanged (git diff --stat -- src/mcp/ empty)

security/read-only evidence:
  rollback digest on failed post-health: whole-DB content digest
  byte-identical (R1); pruned unit fully intact after rollback
  sentinel sweep over prune/doctor output: clean (R7); doctor dangling
  lines carry no raw JSON text or unresolved id contents (R2, R3)
  unsupported-schema zero-write proof: user_version stays 5, no row
  changes (R4)

gates:
  cargo fmt --all -- --check            PASS
  cargo clippy --all-targets -- -D warnings PASS
  cargo test --all-targets              PASS (528: 222 lib, 30 domain,
                                        226 integration, 50 persistence)
  git diff --check                      PASS
```

---

# 9. Final Report Contract

When Sprint 031 is implemented, report:

- files changed and why;
- the frozen transaction sequence, redacted DTO, and renderer contracts
  delivered;
- R1–R8 results plus stage-A fail-on-baseline proof and total test counts;
- schema and MCP non-change evidence;
- rollback, redaction, and concurrency evidence;
- remaining v0.4 caveats (S032–S035 slices, comprehension gate);
- `Sprint 031: DONE` only if every checkpoint passes;
- `v0.4: not complete` and the remaining blockers.
