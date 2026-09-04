# Pico — Sprint 026: Graph Memory over COMPLETE Observation Sets (v0.4 slice 3)

**Status:** DONE

**Sprint:** 026
**Phase:** v0.4 — Security Memory and Change Detection
**Type:** Implementation (third slice)
**Baseline:** `f044a0e` (post-Sprint-025 explicit-pair freshness fix)
**Depends on:** Sprint 024 (finding-set diff), Sprint 025 (history + explicit pair), Sprint 007 (scan-scoped graph snapshots)

---

# 1. Purpose

S024/S025 proved finding-set memory. That is silent when Findings stay at 0 —
the live-environment case — and silent when Bash, MCP, or authority moves
without flipping a Finding fingerprint.

Sprint 026 proves **graph memory**:

> **`pico diff` compares resources and relationships from two COMPLETE scans
> by observation-snapshot `canonical_key`. First seen, reappeared, changed,
> and disappeared are derived from COMPLETE observation sets. A newer
> PARTIAL/FAILED attempt is a freshness warning, never graph disappearance.
> Stable-row `first_observed_at` / `last_observed_at` are not product
> first-seen / last-seen.**

This is not v0.4 complete. Causal “Bash went from ALLOW to DENY caused this
Finding” remains a later slice.

---

# 2. Scope

- **Observation-set compare** on the same COMPLETE pair S024/S025 already
  select (`DiffService::latest` and `DiffService::compare`).
- Join key: snapshot `canonical_key` (resource or relationship). Do not join
  on `observations.subject_id`. Do not use `resources.first_observed_at` /
  `last_observed_at`.
- Presence in a COMPLETE scan ⇔ a parsed graph snapshot for that key exists
  in that scan’s observations. Infer absence by set difference. Do **not**
  write `observation_type: "absent"` at scan time.
- Lifecycle buckets per subject type (resources, relationships):
  `unchanged`, `first_seen`, `reappeared`, `changed`, `disappeared`.
- First-seen / last-seen scan ids: oldest / newest **COMPLETE** scan whose
  observation set contains the key. Reappeared requires walking COMPLETE
  history older than `from`.
- **CLI:** append Resources / Relationships sections **after** the Findings
  block. Findings subsection stays byte-stable (S024/S025 contract).
- **Freshness:** reuse S019/S024. Explicit pair still omits Freshness lines.
- **MCP:** no graph/diff tool. Record N/A.

---

# 3. Non-goals

- Causal explanation tying a graph delta to a Finding.
- Weakened / strengthened / uncertain as Finding lifecycle states.
- Writing `absent` observations during scan.
- Mutating stable-row timestamps as product memory.
- Retention, pruning, database-health controls.
- Machine-readable / CI export as a public API.
- MCP history/diff tools.
- A third agent, new adapters, or new finding rules.
- Independent-developer comprehension gate.

---

# 4. Validation Matrix

```text
R1  Unchanged COMPLETE pair => empty graph first_seen/reappeared/changed/
    disappeared. Findings empty-change sentence unchanged.
    → NEW-FIXTURE (unchanged_complete_scans_have_empty_graph_diff)

R2  Bash ALLOW → DENY: `agent:opencode|can_execute|shell:bash` is changed
    (state / effective_state). `shell:bash` is not disappeared.
    → NEW-FIXTURE (bash_deny_changes_can_execute_not_disappearing_bash)

R3  Worker identity churn (checkout → billing) is disappeared + first_seen,
    not changed.
    → NEW-FIXTURE (worker_identity_churn_is_disappeared_and_first_seen)

R4  Newer PARTIAL never fabricates graph disappearance. Same S024 malformed
    fixture after two COMPLETE scans.
    → NEW-FIXTURE (partial_attempt_does_not_fabricate_graph_disappearance)

R5  Three COMPLETE scans (MCP present → absent → present): MCP keys
    reappeared; first_seen is scan 1; last_seen is scan 3.
    → NEW-FIXTURE (reappeared_requires_older_complete_history)

R6  Same worker key, authority tier EXACT → UNKNOWN/SCOPED: relationship
    changed, not identity churn.
    → NEW-FIXTURE (authority_tier_change_is_changed_same_key)

R7  GitHub `can_access` vs `can_mutate` is two keys (disappeared +
    first_seen), not changed.
    → NEW-FIXTURE (github_kind_flip_is_not_changed)

R8  Mixed OpenCode + Claude: two `can_execute` keys; one `shell:bash`.
    → NEW-FIXTURE (mixed_agents_do_not_collapse_bash_edges)

R9  Credential fingerprint rotation is identity churn (old disappeared,
    new first_seen).
    → NEW-FIXTURE (credential_fingerprint_rotation_is_identity_churn)

R10 0 or 1 COMPLETE: existing S024 empty-state strings; no graph section
    claiming safety.
    → NEW-FIXTURE (graph_empty_states_are_scoped)

R11 Secret sweep: TEST_SECRET_SHOULD_NOT_PERSIST / synthetic-token / ghp_
    never appear in the rendered graph section.
    → NEW-FIXTURE (secret_sweep_never_leaks_in_graph_diff)

R12 Findings subsection (from "\nFindings\n" through the finding
    empty-state lines) matches S024/S025. compared_via unchanged.
    → NEW-FIXTURE (findings_section_byte_contract_from_s024_s025)

R13 MCP parity: no graph/diff tool => N/A
    → NOT-APPLICABLE
```

---

# 5. Controlled Environment

Fixture-only. Reuse Sprint 010/024 golden provider-injected OpenCode path.
R5 uses ALLOW then DENY (`tests/fixtures/opencode/deny/opencode.json`, no
MCP) then ALLOW. R8 uses `tests/fixtures/mixed/`. R7 uses
`ScanService::run_with_home_and_environment_and_github` / `_and_providers`
(Sprint 021 seams). No live tokens, no new dogfood.

---

# 6. Design Notes

## 6.1 Presence (R1, R4)

`ObservationRepo::list_for_scan`. Parse snapshots with the existing
`parse_resource_snapshot` / `parse_relationship_snapshot` in
`src/graph/projection.rs` (export them). Ignore `observation_type`
(`present` / `observed` / `effective_permission`). Duplicate keys in one
scan: first-wins in observation-id order, same as projection.

Missing/invalid snapshot on a COMPLETE scan: fail closed (error), never
fall back to live `resources` / `relationships` rows.

PARTIAL/FAILED/RUNNING scans are never comparison sides and never
contribute to first-seen / last-seen / reappeared history.

## 6.2 Changed (R2, R6)

A key present on both sides is **changed** when security-significant
snapshot fields differ; otherwise **unchanged** (count only).

Compare:

- Resource: `kind`, `provider`, `name`, plus allowlisted `safe_metadata`
  keys present on either side.
- Relationship: `kind`, `state`, plus allowlisted `safe_metadata` keys
  present on either side.

Allowlisted `safe_metadata` keys:

```text
effective_state
effective_permission
scope
runtime_mode
boundary_kind
enabled
transport
permission
permission_pattern
influence_strength
trust
content_class
consequential_sink
authority_resolution
permission_state
credential_status
account_scope_state
sink_impact
unknown_reasons
granted_permissions
zone_scoped
credential_type
validity
environment_reachability
presence
identity_precision
```

Do **not** treat as changed: `source_locator`, `discovery`, timestamps,
internal resource ids, observation ids, or the extra root `capability`
patched onto the Bash *resource* snapshot. Effective Bash lives on the
`can_execute` relationship.

Render deltas as `field: OLD → NEW` through `terminal_safe`. Never dump
raw `safe_metadata`.

Canonical-key identity churn (credential fingerprint, worker tag/name,
GitHub `can_access` vs `can_mutate`) is disappeared + first_seen, not
changed.

## 6.3 Reappeared / first-seen / last-seen (R5)

After pairwise classification against `(from, to)`:

- For each key in `to \ from`, look at COMPLETE scans older than `from`
  (`ScanRepo::list_complete` after the pair). Any hit → **reappeared**;
  else **first_seen**.
- `first_seen_scan_id` = oldest COMPLETE containing the key.
- `last_seen_scan_id` = newest COMPLETE containing the key.

Explicit `pico diff <from> <to>` uses the same workspace COMPLETE
history. Freshness still applies only to `ComparedVia::LatestTwo`.

## 6.4 DTO (R12)

Add a sibling `graph` field on `FindingDiff`. Do not change finding vec
fields or `compare()` fingerprint join.

```rust
pub struct GraphDiff {
    pub resources: GraphSubjectDiff,
    pub relationships: GraphSubjectDiff,
}

pub struct GraphSubjectDiff {
    pub unchanged: Vec<GraphSubject>,
    pub first_seen: Vec<GraphSubject>,
    pub reappeared: Vec<GraphSubject>,
    pub changed: Vec<GraphSubject>,
    pub disappeared: Vec<GraphSubject>,
}
```

Sort each vec by `canonical_key`. Place comparison logic in
`src/application/graph_diff.rs`. `DiffService::latest` / `compare` attach
the graph after the finding compare. No schema migration.

## 6.5 CLI

Findings block **unchanged**, including:

- `No security-significant finding change.` iff finding appeared =
  disappeared = 0
- `This is not an all-clear.` iff those are 0 **and** finding unchanged
  is empty

Those sentences are gated on **finding** vecs only.

Then append:

```text
Resources
  Unchanged: N
  First seen: N
  Reappeared: N
  Changed: N
  Disappeared: N

[First seen / Reappeared / Changed / Disappeared entries]
  kind · provider · canonical_key
  First seen: <scan-id>
  Last seen:  <scan-id>
  field: OLD → NEW     # changed only

Relationships
  … same buckets …
  canonical_key
  state: DERIVED → BLOCKED
```

Unchanged subjects: count only. 0/1 COMPLETE: keep S024 empty-state
strings; do not add a graph section that reads as safety.

`pico history` is unchanged.

## 6.6 Tests

`tests/integration/sprint026_cli_test.rs` through `DiffService` +
`render_finding_diff`. Follow Sprint 024/025 (tempdir, provider injection,
InitService, ScanService). Do not require spawning the process.

---

# 7. Commit Policy

Authoring commit:

```text
docs(sprints): define Sprint 026 graph memory over COMPLETE observation sets
```

Implementation commits conventional, each with its regression test. Do not
amend previous commits. Do not claim v0.4 complete.

---

# 8. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-09-04
  Baseline: f044a0e (post-S025 freshness fix); spec 0524e7a
  Verified by: cargo test --lib (150 passed); sprint026_cli_test (12);
               sprint024_cli_test (7+1 regression); sprint025_cli_test (9);
               cargo clippy --all-targets -- -D warnings

commits
  authored: 0524e7a docs(sprints): define Sprint 026 graph memory …
  impl:     feat(cli): add graph memory to pico diff

repository state
  A  src/application/graph_diff.rs
  M  src/application/diff.rs          (FindingDiff.graph; DiffService wires compare_graph)
  M  src/application/mod.rs
  M  src/graph/mod.rs / projection.rs (export snapshot parsers)
  M  src/cli/render.rs                (Resources / Relationships after Findings)
  A  tests/integration/sprint026_cli_test.rs
  M  tests/integration.rs
  A  docs/internal/sprints/SPRINT-026-support-note.md
  M  docs/internal/sprints/SPRINT-026.md
  M  docs/internal/ARCHITECTURE.md    (§28.5 S025+S026)

new fixtures (R1–R13)
  R1 unchanged_complete_scans_have_empty_graph_diff
  R2 bash_deny_changes_can_execute_not_disappearing_bash
  R3 worker_identity_churn_is_disappeared_and_first_seen
  R4 partial_attempt_does_not_fabricate_graph_disappearance
  R5 reappeared_requires_older_complete_history
  R6 authority_tier_change_is_changed_same_key
  R7 github_kind_flip_is_not_changed
  R8 mixed_agents_do_not_collapse_bash_edges
  R9 credential_fingerprint_rotation_is_identity_churn
  R10 graph_empty_states_are_scoped
  R11 secret_sweep_never_leaks_in_graph_diff
  R12 findings_section_byte_contract_from_s024_s025
  R13 MCP N/A

MCP N/A justification
  MCP tools remain list_findings / get_finding. GraphDiff is
  application-layer and can be exposed later without a second
  comparison engine.

determinism + secret-sweep
  R1/R4/R8/R12 PASS; R11 PASS (SECRET_SENTINEL / synthetic-token / ghp_ absent)

roadmap note (v0.4 in progress; v0.3 independent gate still open)
  ROADMAP §18: v0.4 IN PROGRESS (S024+S025+S026); independent comprehension
  still PENDING
```

---

# 9. Final Report Contract

```text
Sprint: SPRINT-026 — Graph Memory over COMPLETE Observation Sets
Status: DONE
Baseline: f044a0e

Graph:
  observation-set compare by canonical_key: PASS
  first seen / reappeared / changed / disappeared: PASS
  PARTIAL is not disappearance: PASS
  Findings section byte-stable: PASS
  MCP: N/A

Golden path: intact
v0.4: not complete
```
