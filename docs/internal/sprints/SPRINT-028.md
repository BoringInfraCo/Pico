# Pico — Sprint 028: Finding Lifecycle on COMPLETE Diffs (v0.4 slice 5)

**Status:** IN PROGRESS

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

## 5.2 Schema v6

```sql
ALTER TABLE findings ADD COLUMN family_fingerprint TEXT NOT NULL DEFAULT '';
```

`SUPPORTED_SCHEMA_VERSION = 6`. Empty family on a row is treated as
equal to `fingerprint` (no cross-fingerprint join).

## 5.3 CLI

```text
Findings
  Unchanged: N
  Appeared:  N
  Disappeared: N
  Weakened: N
  Strengthened: N
  Uncertain: N
```

List Weakened / Strengthened / Uncertain after Disappeared entries.
`Cause:` on those rows is the severity/confidence sentence.

## 5.4 Tests

`tests/integration/sprint028_cli_test.rs` plus engine/application units.
Keep S024 R3 byte-semantics: worker churn is still disappeared+appeared.

---

# 6. Commit Policy

```text
docs(sprints): define Sprint 028 finding lifecycle on COMPLETE diffs
```

Implementation conventional. Do not amend. Do not claim v0.4 complete.

---

# 7. Completion Evidence (filled at execution)

```text
Date: TBD
Baseline: 89d93c5
```

---

# 8. Final Report Contract

```text
Sprint: SPRINT-028 — Finding Lifecycle
Status: IN PROGRESS
v0.4: not complete
```
