# Pico — Sprint 042: Observation Basis on Finding Summaries (v0.5 slice 6)

**Status:** SPEC — frozen for implementation.
**Sprint:** 042
**Phase:** v0.5 — Continuous and Runtime Observation (slice 6)
**Type:** Vertical slice (small)
**Baseline:** `f29de82`
**Depends on:** S041 (`ObservedExecutionView`, `observed_execution_views`)
**Authority:** `docs/internal/ROADMAP.md` §9; `SPRINT-041.md` §1.2/§1.5 and its
§4 documented omission ("`list_findings` summaries do not carry the observation
basis").

---

# 1. Purpose

Close S041's recorded omission: an agent or developer reading the finding *list*
should see which findings rest on observed execution, without fetching each
detail.

> **`pico findings` and the MCP `list_findings` payload show the same observation
> basis the detail already shows, derived by the same rule, with no second
> interpretation of evidence.**

---

# 2. Scope

## 2.1 Frozen interface (reuse, do not re-derive)

```rust
// src/application/findings.rs
pub struct FindingSummary {
    /* existing 9 fields unchanged */
    /// SAME rule and SAME type as FindingDetail.observed_execution (S041 §1.2).
    /// Always present (no skip_serializing_if); empty when nothing was observed.
    pub observed_execution: Vec<ObservedExecutionView>,
}
```

Population MUST call the existing `observed_execution_views(...)` helper (S041)
over the finding's linked evidence. A second classification rule is forbidden.

Evidence access: `summarize_scan` has no evidence today. Resolve scan evidence
once with the existing bulk query (`EvidenceRepo::get_for_scan`) into an id map,
then the existing per-finding `FindingRepo::list_evidence` (indexed). N is
bounded by the existing `MAX_FINDINGS_PER_SCAN`; no new query type, no schema
change.

## 2.2 CLI list rendering (frozen wording family)

In `render_findings_list` / `push_summary` (`src/cli/render.rs`), when a
summary's `observed_execution` is non-empty, append ONE line per entry, reusing
`render_observation_basis`' existing label logic (do not duplicate the label):

```text
Observed execution: can_execute via runtime evidence (FRESH)
```

Omitted entirely when the list is empty (no noise on findings that do not rest
on runtime evidence).

## 2.3 MCP parity (Invariant 8)

`SafeFindingSummary` (`src/mcp/tools.rs`) gains:

```rust
observed_execution: Vec<SafeObservedExecution>,   // always present, terminal_safe
```

mirroring the application DTO 1:1 (same type already used by `SafeDetail`). Both
sides must add the field with **no** `skip_serializing_if`, so
`tests/integration/sprint011_mcp_golden_test.rs` keeps passing **without edits to
its assertions**.

---

# 3. Non-goals

- No change to the S041 detail derivation, wording, or `Observation basis`
  section; no new DTO, no new rule.
- No fingerprint / `FINDING_VERSION` / comparison-contract change; no change to
  titles, reasons, severity, confidence.
- No `--json` surface for `pico findings`; no new CLI flags; no new MCP tools.
- No linking of attempted/stale evidence (the list will realistically surface
  only `OBSERVED_EXECUTION`; that is a documented consequence, not a gap).
- No schema change, no new dependencies, no daemon/enforcement.

---

# 4. Acceptance

- [ ] `pico findings` prints one `Observed execution: …` line for a finding whose
      linked evidence includes `DIRECT` `opencode_runtime_observer` evidence, and
      prints nothing for findings without it.
- [ ] MCP `list_findings` payload carries `observed_execution`, terminal-safe,
      and `sprint011_mcp_golden_test.rs` passes unmodified.
- [ ] The list and detail agree for the same finding (same basis, freshness,
      relationship key) — asserted, not assumed.
- [ ] `pico findings` output for a workspace with no runtime evidence is
      unchanged in substance (no marker lines).
- [ ] S041 detail output, fingerprints, and contracts untouched
      (`git diff src/findings/engine.rs src/findings/model.rs
      src/application/compare_contract.rs` empty); `git diff Cargo.toml
      Cargo.lock` empty.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
      `cargo test --all-targets`, `git diff --check` green.
- [ ] Manual verification with a synthetic store: observed finding shows the line
      in `pico findings`; a finding without runtime evidence does not.

# 5. Completion notes (2026-09-16, HEAD `f29de82` + working tree)

## Implemented

Two parallel subagents, file ownership respected.
- **Application + CLI** (`src/application/findings.rs`, `src/cli/render.rs`):
  `FindingSummary.observed_execution` (always present, no `skip_serializing_if`),
  populated by the existing S041 `observed_execution_views` rule — no second
  classification rule. Evidence resolved once per scan via
  `EvidenceRepo::get_for_scan` into a map, then the existing indexed per-finding
  `FindingRepo::list_evidence` (N bounded by `MAX_FINDINGS_PER_SCAN`). The label
  logic was refactored into shared helpers so `Observed execution:` /
  `Attempted (not executed):` exist in exactly one place; the detail bytes are
  unchanged.
- **MCP** (`src/mcp/tools.rs`): `SafeFindingSummary.observed_execution:
  Vec<SafeObservedExecution>` mirrored 1:1 with `terminal_safe`.

## Deviations

1. `FindingSummary` derive relaxed `PartialEq, Eq` → `PartialEq` because it now
   holds `Vec<ObservedExecutionView>` (frozen `PartialEq`-only in S041). Nothing
   relied on `Eq`.
2. The integration test seeds the finding through the in-process provider seam
   and then drives the compiled binary (the binary exposes no provider seam — the
   same limitation S041 recorded). The store is synthetic; the real store is
   never used.

## Validation

- New: 2 application unit + 6 render unit + 3 MCP unit + 5 CLI binary-driven +
  2 MCP integration (S042) — all PASS.
- Full suite: **720 passed, 1 ignored, 0 failed**; `fmt`, `clippy -D warnings`,
  `git diff --check` clean; `git diff Cargo.toml Cargo.lock` empty.
- Identity untouched: `src/findings/engine.rs`, `src/findings/model.rs`,
  `src/application/compare_contract.rs` unchanged.
- `tests/integration/sprint011_mcp_golden_test.rs` passed **unmodified**
  (whole-payload equality holds because both DTOs add the field identically and
  always).
- List and detail agree for the same finding (asserted); list label follows the
  basis (proving the S041 hardcoded-label bug class cannot recur here);
  byte-identical repeats; sentinel sweep clean.

## Learnings

Reusing the existing derivation and label helpers (rather than a parallel rule)
made the parity story trivial: the only real work was bounded evidence access for
a list, and keeping the field always-present so a whole-payload golden needs no
edit.

## Canon Changes

None; closes S041 §4's recorded omission.
