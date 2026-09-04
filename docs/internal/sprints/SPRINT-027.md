# Pico — Sprint 027: Causal Explanation of Finding Diffs (v0.4 slice 4)

**Status:** DONE

**Sprint:** 027
**Phase:** v0.4 — Security Memory and Change Detection
**Type:** Implementation (fourth slice)
**Baseline:** `a5470f2` (post-Sprint-026 graph memory)
**Depends on:** Sprint 024 (finding-set diff), Sprint 026 (graph memory), Sprint 015 (fingerprints)

---

# 1. Purpose

S024 reports that a Finding appeared or disappeared. S026 reports which
graph keys moved. Neither answers the phase claim's second half:

> **…and what observed change caused it.**

Sprint 027 proves **causal explanation**:

> **When a Finding appears, disappears, or fingerprint-flips across two
> COMPLETE scans, `pico diff` names the smallest observed
> security-significant graph change on that Finding's path, using
> observation snapshots and Evidence from both sides. It does not
> re-run discovery or invent a cause from a PARTIAL attempt.**

This is not v0.4 complete. Finding lifecycle beyond `OPEN`, retention,
and MCP remain later slices.

---

# 2. Scope

- Attach one primary `Cause` to each appeared and disappeared Finding on
  a Ready `pico diff` (implicit latest and explicit pair).
- Join the Finding's persisted attack-path endpoints and edges to S026
  `GraphDiff` keys (`canonical_key`).
- Prefer the smallest path cut that actually moved, in this order:
  1. `can_execute` (Bash effective state / relationship state)
  2. influence (`can_retrieve` / `can_call` / `configured_with` / MCP
     resource presence)
  3. credential reachability (`can_access` / credential resource)
  4. mutation authority (`can_mutate` / `authority_resolution`)
  5. sink identity (worker resource first-seen / disappeared)
- Fingerprint flip (same source+actor, different sink): one sink-identity
  cause on **both** the disappeared and appeared entries, not two
  unrelated stories.
- Evidence: record supporting Evidence `id` + `source_type` from both
  scans when the chosen graph key has same-scan Evidence. Do not print
  raw observation bodies.
- CLI: append a `Cause:` line under appeared/disappeared Finding
  listings. Unchanged Findings stay unlisted. The
  `No security-significant finding change.` sentence is unchanged.
- MCP: no new tool. N/A.

---

# 3. Non-goals

- Weakened / strengthened / uncertain Finding lifecycle states.
- Explaining graph-only changes when Findings did not move.
- Writing `absent` observations.
- Retention, pruning, `--json` public API.
- MCP diff / cause tools.
- Production-classification (`sink_impact`) work.
- Independent-developer comprehension gate.

---

# 4. Validation Matrix

```text
R1  Unchanged COMPLETE pair: no Cause lines; S024/S026 finding empty-change
    sentence intact.
    → NEW-FIXTURE (unchanged_diff_has_no_cause_lines)

R2  ALLOW → DENY: disappeared Finding Cause names Bash effective state
    (AUTO_ALLOW → DENIED or equivalent state BLOCKED), not MCP absence,
    even though the deny fixture also drops GitHub MCP.
    → NEW-FIXTURE (bash_deny_cause_is_effective_state_not_mcp)

R3  Worker checkout → billing: fingerprint flip; both Finding entries
    share a sink-identity Cause (old worker key → new worker key).
    → NEW-FIXTURE (worker_churn_cause_is_sink_identity_on_both_sides)

R4  Newer PARTIAL after two COMPLETE: no fabricated Cause; finding set
    unchanged; freshness warning intact.
    → NEW-FIXTURE (partial_attempt_does_not_invent_cause)

R5  Graph-only change that does not flip Findings (e.g. identical
    golden pair): still "No security-significant finding change."
    → covered by R1

R6  When no intersecting graph delta exists for a Finding change:
    Cause is an explicit unknown sentence, not silence.
    → NEW-FIXTURE (unknown_cause_is_explicit) — construct via
    fingerprint flip of a field that is not a graph key if needed;
    otherwise document N/A if every golden Finding change intersects
    the graph. Prefer a fixture if practical.

R7  Determinism: identical pair => identical Cause summaries.
    → NEW-FIXTURE (cause_summaries_stable_across_identical_pairs)

R8  Secret sweep: TEST_SECRET_SHOULD_NOT_PERSIST / synthetic-token /
    ghp_ absent from Cause lines and full render.
    → NEW-FIXTURE (secret_sweep_never_leaks_in_cause)

R9  Findings subsection counts/empty-state sentences from S024/S026
    remain; Cause lines appear only under Appeared/Disappeared entries.
    → NEW-FIXTURE (findings_counts_contract_with_optional_cause_lines)

R10 MCP: no cause/diff tool => N/A
    → NOT-APPLICABLE
```

---

# 5. Controlled Environment

Fixture-only. Reuse Sprint 024/026 golden provider-injected OpenCode
path (`ALLOW`, `DENY`, checkout/billing workers, malformed PARTIAL).
No live tokens.

---

# 6. Design Notes

## 6.1 Finding keys (do not use live timestamps)

For each appeared/disappeared Finding, load `FindingRepo::list_paths` →
`AttackPathRepo::get` / `list_edges`. Resolve resource and relationship
ids to `canonical_key` via `ResourceRepo::get` / `RelationshipRepo::get`.
Those rows keep identity after a later scan; membership/state for the
comparison already lives in S026 snapshots.

## 6.2 Smallest cause

Intersect the Finding's keys with `GraphDiff` first_seen / reappeared /
changed / disappeared. Rank hits with the §2 order. First hit wins.
Changed `can_execute` outranks disappeared MCP when both exist (deny
fixture).

Sink-identity pairing: if a disappeared Finding and an appeared Finding
share source+actor keys and differ on sink, emit the sink-identity cause
on both and skip the ranked walk.

## 6.3 DTO

```rust
pub struct FindingCause {
    pub summary: String,
    pub graph_key: Option<String>,
    pub field: Option<String>,
    pub from_value: Option<String>,
    pub to_value: Option<String>,
    pub evidence_source_types: Vec<String>,
}

pub struct DiffFinding {
    // existing fields
    pub cause: Option<FindingCause>,
}
```

Unchanged Findings: `cause = None`.

## 6.4 CLI

`push_diff_finding` appends, when `cause` is Some:

```text
  Cause: Bash effective state AUTO_ALLOW → DENIED
```

Use `terminal_safe` on every cause string. Do not dump Evidence
observation bodies or `safe_metadata`.

0/1 COMPLETE empty states: unchanged (no Ready graph, no Cause).

## 6.5 Tests

`tests/integration/sprint027_cli_test.rs`. Copy 026 helpers. Register in
`tests/integration.rs`. Keep sprint024/025/026 green.

---

# 7. Commit Policy

Authoring commit:

```text
docs(sprints): define Sprint 027 causal explanation of finding diffs
```

Implementation commits conventional. Do not amend. Do not claim v0.4
complete.

---

# 8. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-09-04
  Baseline: a5470f2 (post-S026); spec 5b8664a
  Verified by: cargo test --lib (151 passed); sprint027_cli_test (7);
               sprint024/025/026 green; cargo clippy --all-targets -- -D warnings

commits
  authored: 5b8664a docs(sprints): define Sprint 027 causal explanation …
  impl:     feat(cli): explain finding diffs from graph causes

repository state
  A  src/application/cause.rs
  M  src/application/diff.rs          (DiffFinding.cause; attach_causes)
  M  src/application/mod.rs
  M  src/cli/render.rs                (Cause: line under appeared/disappeared)
  A  tests/integration/sprint027_cli_test.rs
  M  tests/integration.rs
  M  docs/internal/sprints/SPRINT-027.md
  M  docs/internal/ARCHITECTURE.md

new fixtures (R1–R10)
  R1 unchanged_diff_has_no_cause_lines
  R2 bash_deny_cause_is_effective_state_not_mcp
  R3 worker_churn_cause_is_sink_identity_on_both_sides
  R4 partial_attempt_does_not_invent_cause
  R5 covered by R1
  R6 unknown_cause_sentence_is_explicit (unit)
  R7 cause_summaries_stable_across_identical_pairs
  R8 secret_sweep_never_leaks_in_cause
  R9 findings_counts_contract_with_optional_cause_lines
  R10 MCP N/A

MCP N/A justification
  MCP tools remain list_findings / get_finding.

roadmap note
  ROADMAP §18: v0.4 IN PROGRESS (S024–S027); independent comprehension PENDING
```

---

# 9. Final Report Contract

```text
Sprint: SPRINT-027 — Causal Explanation of Finding Diffs
Status: DONE
Baseline: a5470f2

Cause:
  Bash deny names effective state, not MCP: PASS
  Worker churn is one sink-identity story: PASS
  PARTIAL does not invent a cause: PASS
  Unchanged pair has no Cause lines: PASS
  MCP: N/A

Golden path: intact
v0.4: not complete
```
