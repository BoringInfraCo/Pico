# Pico — Sprint 028: Finding Lifecycle on COMPLETE Diffs (v0.4 slice 5)

**Status:** DONE

**Sprint:** 028
**Phase:** v0.4 — Security Memory and Change Detection
**Type:** Implementation (fifth slice)
**Baseline:** `89d93c5` (post-Sprint-027 causal explanation)
**Depends on:** Sprint 015 (fingerprints), Sprint 024 (finding-set diff), Sprint 027 (causes)

---

# 1. Purpose

S015 fingerprints include severity and confidence, so a severity-only
change is a **fingerprint flip** (disappeared + appeared). S024 deferred
a coarser identity on purpose.

Sprint 028 proves **finding lifecycle**:

> **`pico diff` classifies Findings as unchanged, appeared, disappeared,
> weakened, strengthened, or uncertain. Weakened/strengthened require the
> same family identity (S015 hash minus severity and confidence). Distinct
> sinks or boundaries remain appeared/disappeared. Row status stays OPEN.**

This is not v0.4 complete (retention, MCP diff, analysis-version vs
environment as a first-class product fact remain).

---

# 2. Scope

- **Family fingerprint:** same length-prefixed hash as S015 except
  `severity` and `confidence` are omitted. Path fingerprints (including
  boundaries) and sink identities stay in the family, so worker churn and
  boundary changes do **not** become weakened.
- Persist `family_fingerprint` on `findings` (schema v6). Row `status`
  remains `OPEN` only. Lifecycle is a **comparison** fact, not a row
  rewrite.
- `pico diff` Findings counts: Unchanged, Appeared, Disappeared,
  Weakened, Strengthened, Uncertain.
- Weakened: family match, fingerprint differs, severity and/or confidence
  did not increase, and at least one decreased.
- Strengthened: family match, fingerprint differs, severity and/or
  confidence did not decrease, and at least one increased.
- Uncertain: family match, fingerprint differs, mixed severity/confidence
  directions (or equal sev+conf, which should not occur).
- Cause on weakened/strengthened/uncertain: `Severity X → Y` and/or
  `Confidence X → Y`. Appeared/disappeared keep S027 graph causes.
- MCP: no lifecycle tool. N/A.
- Empty-change sentence: no appeared, disappeared, weakened,
  strengthened, or uncertain.

---

# 3. Non-goals

- Expanding persisted `findings.status` beyond `OPEN`.
- Merging distinct sinks or boundaries into one family.
- Retention, MCP diff, `--json` API.
- Treating `pico_version` / analysis-version as Uncertain by itself.
- Independent-developer comprehension gate.
- Claiming v0.4 complete.

---

# 4. Validation Matrix

```text
R1  Unchanged COMPLETE pair: Weakened/Strengthened/Uncertain = 0;
    "No security-significant finding change." intact.
    → NEW-FIXTURE (unchanged_pair_has_no_lifecycle_movement)

R2  ALLOW → DENY: disappeared, not weakened.
    → NEW-FIXTURE (bash_deny_is_disappeared_not_weakened)

R3  Worker checkout → billing: appeared + disappeared, not weakened.
    → NEW-FIXTURE (worker_churn_is_not_weakened)

R4  Engine: family fingerprint stable when only severity/confidence
    change; flips when sink or path fingerprint changes.
    → NEW-FIXTURE (engine unit in findings/engine.rs)

R5  Diff classify: same family + lower severity => weakened; higher =>
    strengthened; mixed sev/conf => uncertain.
    → NEW-FIXTURE (application unit)

R6  PARTIAL after two COMPLETE: no fabricated lifecycle movement.
    → NEW-FIXTURE (partial_does_not_fabricate_lifecycle)

R7  Secret sweep on render including new headings.
    → NEW-FIXTURE (secret_sweep_never_leaks_in_lifecycle)

R8  S024/S025/S026/S027 still green.

R9  MCP N/A — no new tool.
```

---

# 5. Design Notes

## 5.1 Family hash

Reuse `finding_fingerprint` field encoding without the severity and
confidence fields. Prefix `sha256:`.

Family covers: finding version, finding class, source/actor/sink identities,
path fingerprints (including boundaries), and remediation rule ids. Path
fingerprints (including boundaries) and sink identities stay in the family,
so worker churn and boundary changes do **not** become weakened — they stay
disappeared + appeared (R2/R3).

### Effective family rule (frozen)

```text
effective_family(row) =
  if row.family_fingerprint != '' then row.family_fingerprint
  else row.fingerprint
```

- New (schema v6) rows always carry a non-empty `family_fingerprint`.
- Legacy rows with `family_fingerprint = ''` fall back to the full
  `fingerprint`. Consequence: a legacy row can only exact-match; it never
  joins across fingerprints (no cross-fingerprint family join on `''`).
  This is the `''` semantics: `''` means "no family fact recorded", not
  "all legacy rows share one family".

## 5.2 Schema v6

```sql
ALTER TABLE findings ADD COLUMN family_fingerprint TEXT NOT NULL DEFAULT '';
```

`SUPPORTED_SCHEMA_VERSION = 6`.

### Schema integrity rules (frozen)

1. Partial unique index — one live family per scan, legacy `''` excluded:

   ```sql
   CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_family
     ON findings(scan_id, family_fingerprint)
     WHERE family_fingerprint <> '';
   ```

   Rationale: the same family must not appear twice in one scan (that
   would be a collision, see §5.3). Legacy `''` rows are excluded so
   pre-v6 backfills never violate the index.

2. Insert trigger — new rows must carry a family:

   ```sql
   CREATE TRIGGER IF NOT EXISTS findings_family_nonempty_insert
   BEFORE INSERT ON findings
   FOR EACH ROW
   WHEN NEW.family_fingerprint = ''
   BEGIN
     SELECT RAISE(ABORT, 'family_fingerprint must be non-empty');
   END;
   ```

   Legacy `''` rows exist only because they were written before v6 (or
   backfilled with the `DEFAULT ''`). All v6 writers compute
   `finding_family_fingerprint` in the findings engine.

3. `migrate()` rejects future versions:

   ```text
   let current = PRAGMA user_version;
   if current > SUPPORTED_SCHEMA_VERSION (6) {
     return Err(migration("unsupported future schema version {current}"));
   }
   ```

   Never silently downgrade or ignore a newer schema. Query commands
   (`pico diff`, `pico findings`, `pico finding`) use
   `require_schema_version` and never migrate.

### Legacy rows `''` semantics (frozen)

- `family_fingerprint = ''` ≡ "no family fact recorded".
- Read path applies the effective-family rule (§5.1): `''` → full
  `fingerprint`, so a legacy row exact-matches only.
- Two legacy `''` rows never family-match each other via `''`.
- A legacy `''` row never forms weakened/strengthened/uncertain with a
  v6 row: different effective families (full fingerprint vs real family)
  unless the full fingerprints are exactly equal (then it is unchanged).

## 5.3 Matching — two-phase, exact-first, family-second (frozen)

Phase 1 (exact): join from-scan and to-scan findings on full `fingerprint`.
Matches become `unchanged`. Exact matches are removed from both sides and
never reconsidered for lifecycle.

Phase 2 (family): on the remainders, join on `effective_family`:

- Group remaining from-rows by effective family; group remaining to-rows
  by effective family.
- For each family present on both sides with cardinalities
  `(from_n, to_n)`:
  - If `from_n == 1 && to_n == 1` → exactly one lifecycle movement.
    Classify the single `(from, to)` pair by §5.4 (weakened /
    strengthened / uncertain). `uncertain` is reserved for this 1:1 case
    with mixed directions (or equal sev+conf, which should not occur —
    a fingerprint flip without a rating change indicates a hash-contract
    violation to investigate, never silent weakened/strengthened).
  - Else (collision: either side cardinality != 1) → **no lifecycle**.
    All rows in that family on both sides stay `disappeared` +
    `appeared` with S027 graph causes. Never fabricate 1:N, N:1, or N:M
    lifecycle pairs; never pick a "best" pair.
- Families present on one side only → `appeared` / `disappeared` as in
  S024, with S027 causes attached.

Only COMPLETE scans participate as comparison sides (S024 invariant).
A newer PARTIAL/FAILED/RUNNING attempt never fabricates lifecycle (R6);
it only sets freshness context.

### Structured DTOs (frozen names)

```text
FindingRatingDelta {
  field: String,        // "severity" | "confidence"
  from_value: String,   // e.g. "CRITICAL"
  to_value: String,     // e.g. "HIGH"
}

FindingLifecycleChange {
  from: DiffFinding,              // from-scan side (includes family_fingerprint)
  to: DiffFinding,                // to-scan side (includes family_fingerprint)
  deltas: Vec<FindingRatingDelta> // severity-first; only changed dims
}

FindingDiff {
  ...
  weakened: Vec<FindingLifecycleChange>,
  strengthened: Vec<FindingLifecycleChange>,
  uncertain: Vec<FindingLifecycleChange>,
}

DiffFinding {
  ...
  family_fingerprint: String,
}
```

`DiffFinding.cause` stays `None` on lifecycle rows; the render `Cause:`
is the rating sentence (§5.5), not a graph cause. Appeared/disappeared
keep S027 graph causes via `attach_causes` (unchanged behavior).

### Conservation invariants (frozen formulas)

Let `F` = from-scan finding count, `T` = to-scan finding count,
`U` = unchanged, `A` = appeared, `D` = disappeared,
`W/S/N` = weakened/strengthened/uncertain counts,
`L = W + S + N` (lifecycle movements; each consumes exactly one
from-row and produces exactly one to-row):

```text
F = U + D + L
T = U + A + L
```

Additional invariants:

- No double-count: an exact match is never also family-matched; each
  fingerprint participates at most once (exact-first removal).
- No fabrication: `L` only grows from 1:1 family pairs with differing
  full fingerprints. Collisions contribute to `A`/`D`, never to `L`.
- Unchanged COMPLETE pair ⇒ `A = D = W = S = N = 0`, `F = T = U` (R1).
- PARTIAL after two COMPLETE ⇒ same `L` as before the PARTIAL (R6).

## 5.4 Severity / confidence ordering matrix (frozen)

Ranks (derive `Ord` order in `src/findings/model.rs`):

```text
severity rank:    INFO = 0 < LOW = 1 < MEDIUM = 2 < HIGH = 3 < CRITICAL = 4
confidence rank:  LOW = 0 < MEDIUM = 1 < HIGH = 2
```

Let `sev = rank(to.severity) - rank(from.severity)`,
`conf = rank(to.confidence) - rank(from.confidence)`.
Applies only when effective families match and full fingerprints differ.

| sev direction | conf direction | classification | example |
|---|---|---|---|
| down (`< 0`) | down (`< 0`) | weakened | CRITICAL→HIGH, HIGH→MEDIUM |
| down | same (`== 0`) | weakened | CRITICAL→HIGH, HIGH→HIGH |
| same | down | weakened | HIGH→HIGH, HIGH→MEDIUM |
| up (`> 0`) | up | strengthened | HIGH→CRITICAL, MEDIUM→HIGH |
| up | same | strengthened | HIGH→CRITICAL, HIGH→HIGH |
| same | up | strengthened | HIGH→HIGH, MEDIUM→HIGH |
| down | up | uncertain | CRITICAL→HIGH, LOW→HIGH |
| up | down | uncertain | HIGH→CRITICAL, HIGH→LOW |
| same | same | uncertain (should not occur) | ratings equal but fingerprint flipped |

Formal rules:

```text
weakened     ⇔ (sev <= 0 && conf <= 0) && (sev < 0 || conf < 0)
strengthened ⇔ (sev >= 0 && conf >= 0) && (sev > 0 || conf > 0)
uncertain    ⇔ otherwise (mixed directions, or equal sev+conf)
```

- Weakened: severity and/or confidence did not increase, at least one
  decreased.
- Strengthened: severity and/or confidence did not decrease, at least one
  increased.
- Uncertain: mixed severity/confidence directions (or equal sev+conf,
  which should not occur given the S015 hash contract — treat as
  uncertain and investigate, never as weakened/strengthened).
- `pico_version` / analysis-version changes never create lifecycle
  movement (non-goal): the family identity is the S015 hash minus
  severity and confidence only, so a finding-version change stays
  inside the family hash and an analysis-version change surfaces
  through path fingerprints. Such changes remain appeared/disappeared,
  never weakened/strengthened/uncertain.

Deltas recorded severity-first, only changed dims:
`deltas = [severity?] + [confidence?]`; an unchanged dim is omitted.
Empty `deltas` with differing fingerprints renders the fallback
`Ratings unchanged; fingerprint changed` (§5.5).

## 5.5 CLI (frozen render contract)

Header counts block, byte-exact (note `Appeared:` carries two spaces to
align with S024; new rows use a single space like `Disappeared:`):

```text
Findings
  Unchanged: N
  Appeared:  N
  Disappeared: N
  Weakened: N
  Strengthened: N
  Uncertain: N
```

Order is Unchanged, Appeared, Disappeared, Weakened, Strengthened,
Uncertain. Existing Unchanged/Appeared/Disappeared lines keep S024
byte-compat.

Sections after the counts, in order: Appeared, Disappeared, Weakened,
Strengthened, Uncertain. Each bucket heading is `\nWeakened\n` etc.
(only rendered when non-empty). Appeared/disappeared entries keep the
S027 `push_diff_finding` layout unchanged.

Each lifecycle entry (`FindingLifecycleChange`) renders the to-side
identity plus the from-side provenance:

```text
  {to.severity} · {to.confidence} confidence
  {to.title}
  Fingerprint: {to.fingerprint}
  ID: {to.id}
  From fingerprint: {from.fingerprint}
  From: {from.severity} · {from.confidence} confidence
  Cause: {rating sentence}
```

Rating sentence from `deltas`, severity-first, only changed dims joined
with `"; "`:

```text
Cause: Severity CRITICAL → HIGH; Confidence HIGH → MEDIUM
```

- One changed dim → single clause (`Cause: Severity HIGH → CRITICAL`).
- `deltas` empty (or no changed dims) →
  `Cause: Ratings unchanged; fingerprint changed`.
- Arrow is the literal `→` (U+2192, passes `terminal_safe`).
- Every persisted value (`severity`, `confidence`, `title`,
  `fingerprint`, `id`, delta `from_value`/`to_value`) goes through
  `terminal_safe`. No new raw fields; no secret-bearing fields are
  rendered.

Empty-change sentence: rendered only when appeared + disappeared +
weakened + strengthened + uncertain are ALL empty. Sentence text stays
byte-identical to S024:

```text
No security-significant finding change.
```

plus `This is not an all-clear.` when `unchanged` is also empty.

Anchors `"\nFindings\n"` and `"\nResources\n"` stay intact so
`findings_section`-style test helpers keep working.

## 5.6 Tests

`tests/integration/sprint028_cli_test.rs` plus engine/application units.
Keep S024 R3 byte-semantics: worker churn is still disappeared+appeared.

## 5.7 Review checkpoints (frozen)

1. R1–R9 validation matrix (§4) green, including unchanged-pair L=0,
   ALLOW→DENY disappeared-not-weakened, worker-churn
   disappeared+appeared, PARTIAL-no-fabrication, secret sweep over new
   headings/cause lines.
2. Conservation formulas (§5.3) asserted on fixtures:
   `F = U + D + L`, `T = U + A + L`.
3. Collision fixture: one family with 2 from × 1 to (and 1 × 2) yields
   `L = 0`, all rows in `A`/`D` with graph causes.
4. Mixed-direction 1:1 fixture yields exactly one `uncertain`, never
   weakened/strengthened.
5. Header byte-check: `Appeared:  N` (two spaces) preserved;
   `Weakened:`/`Strengthened:`/`Uncertain:` single-space lines present
   in order.
6. Secret sweep: rendered diff contains no token material, no
   `source_locator` values, no raw metadata — only whitelisted
   classification facts through `terminal_safe`.
7. S024/S025/S026/S027 suites still green; MCP surface unchanged
   (no new tool).

---

# 6. Commit Policy

```text
docs(sprints): define Sprint 028 finding lifecycle on COMPLETE diffs
```

Implementation conventional. Do not amend. Do not claim v0.4 complete.

---

# 7. Completion Evidence (filled at execution)

```text
Date: 2026-09-04
Baseline: 89d93c5 (post-Sprint-027 implementation); spec: 619154c
Verified by: cargo test --all-targets (168 lib + 30 domain + 199
             integration + 1 ignored + 39 persistence, 0 failed);
             sprint028_cli_test (20); S024–S027 green; clippy clean;
             fmt clean
P2 follow-up: migrate_to_version made private (in-crate helper; partial
             migrations are NOT a supported public surface) and the REAL
             v5→v6 migration test moved from
             tests/integration/sprint028_cli_test.rs into the db.rs
             #[cfg(test)] module (file now 869 lines; 20 integration
             tests remain)

fixtures (R1–R9) — tests/integration/sprint028_cli_test.rs
  R1 unchanged_pair_has_no_lifecycle_movement
  R2 bash_deny_is_disappeared_not_weakened
  R3 worker_churn_is_not_weakened
  R4 engine unit (findings/engine.rs: family flips on sink/path change,
     stable on sev/conf change) + severity_confidence_independence_stable
     + partial_does_not_fabricate_lifecycle (R6)
  R5 application unit (diff.rs: classification matrix) persisted through
     fixtures:
        engine_generated_severity_change_is_weakened (END-TO-END SEAM, no
          fabricated identities: both sides are generated by the findings
          engine itself via severity_change_fixture + generate —
          PUBLIC_EXTERNAL → AUTHENTICATED_EXTERNAL flips the full
          fingerprint while the engine keeps family_fingerprint identical,
          CRITICAL/HIGH vs HIGH/HIGH. Engine Findings are persisted via
          FindingRepo::insert mapped to FindingRecord, then
          DiffService::compare classifies weakened=1 with deltas
          [Severity CRITICAL → HIGH] and conservation F = U + D + W + S + X,
          T = U + A + W + S + X. Crux assertions equate the diff's
          from/to fingerprints AND family fingerprints against the actual
          engine-generated values (sha256:..., proven not the old fixture
          literals), and the rendered Weakened section contains both engine
          fingerprints verbatim plus "Cause: Severity CRITICAL → HIGH")
        severity_down_is_weakened (CRITICAL/HIGH → HIGH/HIGH; deltas
          [Severity CRITICAL → HIGH]; "Cause: Severity CRITICAL → HIGH"
          in Weakened section)
        strengthened_direction (HIGH/MEDIUM → HIGH/HIGH)
        mixed_direction_is_uncertain (HIGH/MEDIUM → MEDIUM/HIGH;
          "Cause: Severity HIGH → MEDIUM; Confidence MEDIUM → HIGH")
        reverse_pair_swaps_weakened_strengthened (falling vs rising across
          three chronological scans; out-of-order pair refused by the
          temporal guard "not at or before")
        collision_is_conservative (2×1 same family → lifecycle 0,
          disappeared 2 + appeared 1; index dropped to simulate the
          defensive path the partial unique index forbids)
        legacy_empty_family_never_joins ('' effective family = full
          fingerprint; appeared 1 + disappeared 1)
  R6 partial_does_not_fabricate_lifecycle (NewerIncomplete; lifecycle 0)
  R7 secret_sweep_never_leaks_in_lifecycle
  R8 S024/S025/S026/S027 suites green
  R9 MCP N/A — no lifecycle tool; header byte-contract covered by
     counts_contract ("Appeared:  0" two spaces) and
     unchanged_pair_has_no_lifecycle_movement

schema v6 integrity (migration/integrity tests)
  fresh_db_initializes_at_schema_v6 (SUPPORTED_SCHEMA_VERSION == 6)
  REAL v5→v6 migration — migration6_from_v5_preserves_rows_and_links
    (now in src/persistence/db.rs #[cfg(test)]): a true v5 database is
    built via the private migrate_to_version helper
    (user_version == 5) and seeded with a complete scan, three resources,
    a scan_analysis + attack_path, an evidence row, and a v5 findings row
    (no family column) with ALL FOUR link types seeded and proven to
    survive: finding_paths, finding_evidence, finding_reasons, and
    finding_remediations. Full migrate() reaches v6 with every seeded
    row preserved (counts + key values identical), family_fingerprint
    stays '' (no backfill), FindingRepo get/list + validate() pass,
    integrity objects exist (idx_findings_scan_family,
    findings_family_nonempty_insert), PRAGMA foreign_key_check empty and
    PRAGMA integrity_check == 'ok'. A second migrate() is idempotent
    (still v6, data intact). Rollback safety: a pre-created object
    clashing with a migration-6 name makes migrate() fail closed with
    user_version still 5; dropping the clash re-migrates cleanly to v6.
  migration6_integrity_objects (idx_findings_scan_family partial unique
    index + findings_family_nonempty_insert trigger; duplicate (scan_id,
    family) and empty-family raw inserts fail; repo rejects empty family)
  legacy read semantics are asserted inside the migration test ('' row
    validates and lists); db.rs migrate_to_version unit test covers
    rejecting out-of-range and below-current targets (clamped-target
    helper fails closed)
  future_schema_version_fails_before_writes (user_version 99 rejected by
    require_schema_version + migrate(); no writes; content unchanged)
  null_family_fails_closed (NULL family_fingerprint is corruption: the
    diff read returns a family_fingerprint integrity error instead of
    masquerading as legacy ''; user_version untouched)

read-only + determinism
  read_only_diff_performs_zero_writes (user_version + finding/scan counts
    identical around DiffService::latest)
  comparison_is_byte_identical (same pair renders equal twice)
  conservation_invariant (F = U + D + L; T = U + A + L on the unambiguous
    weakened fixture)

review caveats
  Production findings are fixed at HIGH confidence, but source-trust
  changes (PUBLIC_EXTERNAL → AUTHENTICATED_EXTERNAL) change severity
  without changing family, so real CRITICAL→HIGH weakened movement is
  producible by live scans — and the end-to-end seam is now proven with
  engine-generated identities: engine hashes traverse engine →
  persistence (FindingRepo) → DiffService::compare → render with no
  fabricated identities anywhere on the path. The confidence-only and
  mixed-direction lifecycle cases are proven with persistence fixtures
  (crafted FindingRecord rows). The collision fixture drops
  idx_findings_scan_family because the schema makes same-family
  duplicates within one scan impossible; the comparison path never pairs.
  Upgrade guidance: upgrade Pico or use a compatible build; database
  downgrade is unsupported.

Status: DONE — v0.4: not complete (retention, MCP diff,
  analysis-version vs environment remain)
```

---

# 8. Final Report Contract

```text
Sprint: SPRINT-028 — Finding Lifecycle
Status: DONE
v0.4: not complete
```
