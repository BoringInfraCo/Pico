# Pico — v0.4 Slice 3: Graph Memory (Sprint 026)

**Status:** reference note, not a sprint spec.
**Phase:** v0.4 — Security Memory and Change Detection
**Sprint:** 026 (`docs/internal/sprints/SPRINT-026.md`)
**Audience:** operator / reviewer.

This is the scope statement for **graph memory**. It does not close v0.4.
Causal explanation, finding lifecycle beyond `OPEN`, retention, and MCP
diff remain later slices.

---

## 1. What this slice supports

`pico diff` and `pico diff <from> <to>` compare **resources and
relationships** from two COMPLETE scans by observation-snapshot
`canonical_key`.

Buckets (per subject type):

| Bucket | Meaning |
|---|---|
| Unchanged | Present on both sides; security-significant snapshot equal (counted, not listed) |
| First seen | Present in `to`, absent in `from`, never in an older COMPLETE scan |
| Reappeared | Present in `to`, absent in `from`, present in some older COMPLETE scan |
| Changed | Present on both sides; allowlisted snapshot fields differ |
| Disappeared | Present in `from`, absent in `to` |

First-seen / last-seen scan ids are the oldest / newest **COMPLETE** scan
whose observation set contains the key.

---

## 2. What this slice reuses (do not rebuild)

- S024/S025 COMPLETE pair selection and S019 freshness.
- Scan-scoped graph snapshots (`GRAPH_SNAPSHOT_VERSION`,
  `resource_snapshot_metadata` / `relationship_snapshot_metadata`).
- Canonical keys as identity (S015-style). Credential fingerprints and
  worker tags that change are **new keys**, not `changed`.

---

## 3. Honesty limits

- Stable-row `first_observed_at` / `last_observed_at` never record
  absence and are **not** product first-seen / last-seen.
- PARTIAL/FAILED/RUNNING observation sets are never comparison sides and
  never first-seen / last-seen / reappeared history.
- `No security-significant finding change` is still a **Finding-set**
  sentence. Graph change does not suppress it.
- Effective Bash is the `can_execute` edge, not the shared `shell:bash`
  resource.
- GitHub `can_access` vs `can_mutate` are two relationship keys.
- This slice does not explain *why* a Finding appeared.

---

## 4. Surfaces

- **CLI:** Resources / Relationships sections after Findings on a Ready
  diff.
- **MCP:** no graph/diff tool.
- **Schema:** no new tables.

v0.4 remains in progress.
