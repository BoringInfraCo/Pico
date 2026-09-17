# Pico — Sprint 041: Observed-Execution Explanation (v0.5 slice 5)

**Status:** SPEC — frozen for implementation.
**Sprint:** 041
**Phase:** v0.5 — Continuous and Runtime Observation (slice 5)
**Type:** Vertical slice (small)
**Baseline:** `4e63afd`
**Depends on:** S040 (runtime evidence ingestion)
**Authority:** `docs/internal/ROADMAP.md` §9 exit criterion ("Pico clearly
distinguishes observed execution from inferred capability"); `SPRINT-040.md`
§1.6/§1.8 and its recorded limitation ("the finding narrative does not name
runtime observation").

---

# 0. Purpose

S040 made Pico able to *observe* execution; S041 makes Pico *say so*.

> **When a finding rests on runtime evidence, Pico states plainly that the
> capability was observed rather than merely configured — in `pico scan`,
> `pico finding <id>`, and the MCP finding payload — without changing the
> finding's identity, summary text, or any contract.**

## 0.1 What this slice may and may not say

Allowed: *"Observed execution: can_execute via runtime evidence (FRESH)"* and
*"Attempted (not executed): …"* — derived deterministically from the finding's
own linked evidence.

Forbidden (unchanged canon): compromise, exploitation, propagation, malicious
intent, approval/denial, and any "observed" label not backed by `DIRECT`
`opencode_runtime_observer` evidence.

---

# 1. Scope

## 1.1 Derivation (deterministic, from persisted evidence only)

A finding has an observation basis entry for each linked evidence item where:

```text
class        == DIRECT
source_type  == "opencode_runtime_observer"
```

Basis label comes from the **evidence's own persisted observation** (never
recomputed): `observed_execution` → `OBSERVED_EXECUTION`; `attempted_not_executed`
→ `ATTEMPTED_NOT_EXECUTED`; any other value → skip the entry (do not guess).
Freshness is the **persisted** freshness (never recomputed). No other evidence
class or source may produce this label.

## 1.2 Frozen interface

```rust
// src/application/findings.rs (owner: interface agent A) — single source of truth
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservedExecutionView {
    /// Canonical key of the capability relationship, e.g.
    /// `agent:opencode|can_execute|shell:bash`.
    pub relationship_key: String,
    /// `OBSERVED_EXECUTION` | `ATTEMPTED_NOT_EXECUTED` (from persisted evidence).
    pub basis: String,
    /// Persisted freshness (`FRESH`/`AGING`/`STALE`/`UNKNOWN`).
    pub freshness: String,
    /// Supporting evidence id.
    pub evidence_id: String,
}

// FindingDetail gains (ALWAYS present; empty vec when nothing observed):
pub observed_execution: Vec<ObservedExecutionView>,
```

Field additions must be **always present** (no `skip_serializing_if`) so the MCP
whole-payload golden equality (`tests/integration/sprint011_mcp_golden_test.rs`)
continues to hold once the MCP mirror is added.

## 1.3 CLI rendering (frozen wording family)

In `render_finding_detail` (`src/cli/render.rs`), when `observed_execution` is
non-empty, add a section (after `Weakest evidence`, before `Evidence`):

```text
Observation basis
  Observed execution: can_execute via runtime evidence (FRESH)
  Evidence: <evidence_id>
```

or, for a pending-only observation:

```text
Observation basis
  Attempted (not executed): can_execute via runtime evidence (FRESH)
  Evidence: <evidence_id>
```

- `can_execute` is the middle segment of the canonical key when it is
  `a|b|c` shape; otherwise print the full key. Never fabricate a segment.
- The section is omitted entirely when the list is empty (no noise on the
  golden path without runtime evidence).

In the `pico scan` summary (`src/cli/mod.rs` `run_scan`), when the scan
observed execution, append ONE line after the existing summary block:

```text
Observed execution: can_execute via runtime evidence (FRESH)
```

**Do NOT touch `render_scan_effective_bash`** — `tests/integration/sprint023_cli_test.rs:104,143`
asserts the exact string `"Effective Bash: ALLOW\n"`.

## 1.4 ScanResult additive field

`ScanResult` (`src/application/scan.rs`) gains:

```rust
/// Populated only when the opt-in runtime step observed execution.
pub runtime_observation: Option<ObservedExecutionView>,
```

Set it only when the runtime promotion actually happened (the same condition
that already sets `plan.promote == true`). Runtime-disabled scans keep it
`None` and must remain byte-identical in behavior.

## 1.5 MCP parity (required by Invariant 8)

`SafeDetail` (`src/mcp/tools.rs:461-491`) gains an identical-shape mirror:

```rust
struct SafeObservedExecution { relationship_key: String, basis: String,
                               freshness: String, evidence_id: String }
// SafeDetail gains: observed_execution: Vec<SafeObservedExecution>  (always present)
```

All four strings pass through `terminal_safe`. The MCP payload must remain
field-for-field equal to `serde_json::to_value(FindingQueryService::get(..))`
modulo the existing `Safe*` transforms, so `sprint011_mcp_golden_test.rs` stays
green without edits to its assertions.

---

# 2. Non-goals

- No change to finding `title`, `summary`, `ReasonCode`, reason text,
  severity, confidence, or remediation.
- No change to `FINDING_VERSION`, `fingerprint_input`, `family_fingerprint`, or
  `COMPARISON_CONTRACT_VERSION`; no finding-identity change of any kind.
- No new evidence/observation semantics, no recomputation of freshness, no
  authority/approval claims, no LLM involvement.
- No new MCP tools, arguments, or protocol change; no `list_findings` summary
  change (documented omission, see §4).
- No new CLI flags or JSON surfaces for findings; no SQLite schema change; no
  new dependencies; no daemon/enforcement.

---

# 3. Acceptance

- [ ] With S040 runtime evidence + a production finding, `pico finding <id>`
      renders the `Observation basis` section naming observed execution,
      freshness, and the evidence id.
- [ ] A pending-only observation renders `Attempted (not executed)`, never
      `Observed execution`. **Scope of this criterion:** verified end-to-end at
      the **scan-summary** level. At the **finding-detail** level it is
      implemented and unit-tested but unreachable by design, because S040 keeps
      attempted/stale runtime evidence unlinked so it cannot weaken the finding's
      freshness gate (see §4).
- [ ] A stale observation of a real execution is surfaced nowhere as a current
      claim (silent in the scan summary; not linked to any finding).
- [ ] Without runtime evidence, no `Observation basis` section appears anywhere
      (no noise, no false observation claim).
- [ ] `pico scan --runtime` prints exactly one `Observed execution: …` line when
      promotion happened, and nothing when it did not; the
      `Effective Bash: ALLOW\n` line is byte-identical to before.
- [ ] MCP `get_finding` payload contains the mirrored `observed_execution`
      array, terminal-safe, and
      `tests/integration/sprint011_mcp_golden_test.rs` passes unmodified.
- [ ] Fingerprint/contract stability: `src/findings/engine.rs` `fingerprint_input`,
      `FINDING_VERSION`, and `compare_contract.rs` are untouched, and the S025/
      S028/S029/S033 suites pass unchanged.
- [ ] No `compromised`/`exploited`/`exfiltrat` (case-insensitive) anywhere in the
      new output; sentinel content from forbidden store fields never surfaces;
      repeated runs are byte-identical.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
      `cargo test --all-targets`, `git diff --check` green; `git diff Cargo.toml
      Cargo.lock` empty.

# 4. Documented omissions

- `list_findings` summaries do not carry the observation basis (detail-only in
  this slice). Recorded here so the omission is explicit rather than implied.
- Evidence `subject`/tool name is only displayed if it is already persisted on
  the runtime evidence; it must never be fabricated or reverse-engineered.
- **Findings-level "attempted" basis is unreachable end-to-end.** S040 persists
  attempted/stale runtime evidence *unlinked* (deliberately, so it can never
  weaken or inflate the configured-capability finding's freshness gate), and the
  finding engine draws evidence only from path edges. The `ATTEMPTED_NOT_EXECUTED`
  mapping is therefore implemented and unit-tested as a correct forward
  behaviour — e.g. if such evidence is ever linked — and surfaced end-to-end
  today at the **scan-summary** level. Linking attempted evidence to findings
  would change confidence/fingerprints and is explicitly out of scope.

# 5. Completion notes (2026-09-16, HEAD `4e63afd` + working tree)

## Implemented

Two parallel subagents (detail derivation/render; scan summary + MCP parity),
file ownership respected, plus a coordinator correction and gap-close.

- **Detail derivation** (`src/application/findings.rs`): `ObservedExecutionView`
  (4 fields, always serialized), `FindingDetail.observed_execution` (always
  present, empty when nothing observed), derived strictly from already-linked
  evidence where `class == DIRECT` and `source_type == opencode_runtime_observer`,
  reading the persisted `metadata.classification` (`observed_execution` /
  `attempted_not_executed`; any other value is skipped, never guessed) and the
  persisted freshness.
- **Finding-detail rendering** (`src/cli/render.rs`): `Observation basis` section
  placed after `Weakest evidence` and before `Evidence`, omitted entirely when
  empty; `a|b|c` middle-segment extraction with full-key fallback.
- **Scan summary** (`src/application/scan.rs`, `src/cli/mod.rs`):
  `ScanResult.runtime_observation` populated only from persisted evidence;
  exactly one summary line — `Observed execution: …` when promoted, and
  `Attempted (not executed): …` when the agent attempted Bash without an observed
  execution; stale observations stay silent (never laundered into a current
  claim). `render_scan_effective_bash` untouched.
- **MCP parity** (`src/mcp/tools.rs`): `SafeObservedExecution` mirrored 1:1 onto
  `SafeDetail.observed_execution` (always present, `terminal_safe`), so the
  whole-payload golden equality in `sprint011_mcp_golden_test.rs` passes with no
  assertion edits.
- **Coordinator correction:** the scan renderer initially hardcoded the
  `Observed execution:` label and ignored `basis`, which mislabelled an attempt;
  fixed to derive the label from the persisted basis, with a unit case added.

## Deviations

1. **Coordinator gap-close (scan level):** the spec's attempted-basis acceptance
   was originally satisfiable only in unit tests, because S040 keeps attempted
   evidence unlinked. Rather than leave a criterion that cannot be met
   end-to-end, the scan summary now surfaces the attempt (no promotion, no
   execution claim, no finding change).
2. Four pre-existing `FindingDetail` literals in `tests/integration/sprint016|017|018_cli_test.rs`
   needed the new field (mechanical `observed_execution: vec![]`); no assertions
   changed. `src/application/mod.rs` gained the DTO re-export so `scan.rs`/MCP can
   name the frozen public type.
3. A hermetic production finding requires the injected provider seam, which the
   binary does not expose, so the finding-detail wording is proven by unit tests
   and the scan line by binary-driven integration tests.

## Validation

- New: 8 findings-derivation unit + 7 render unit + 7 scan-line unit (incl. the
  attempted label) + 2 MCP unit + 2 scan-integration + 5 binary-driven
  integration (S041) — all PASS.
- Full suite: **689 passed, 1 ignored, 0 failed**; `fmt`, `clippy -D warnings`,
  `git diff --check` clean; `git diff Cargo.toml Cargo.lock` **empty**.
- Identity preserved: `git diff src/findings/engine.rs src/findings/model.rs
  src/application/compare_contract.rs` **empty** (no fingerprint, finding-version,
  or comparison-contract change); S025/S028/S029/S033 suites unchanged and green.
- Manual (synthetic stores, never the real one) — all four postures correct:
  fresh completed → `Observed execution: can_execute via runtime evidence (FRESH)`;
  pending-only → `Attempted (not executed): can_execute via runtime evidence (FRESH)`;
  stale completed → no line; default scan → no line, with `Effective Bash: ALLOW`
  byte-identical throughout.

## Learnings

Rendering-only enrichment is the safe way to close an explanation gap: because
`fingerprint_input` excludes reasons and rendered text, Pico can say more without
changing finding identity or the S029 contract. The attempted/executed distinction
also showed that surfacing a fact and *acting* on it are separable — the scan can
report an attempt without linking evidence or touching the finding.

## Canon Changes

None; the v0.5 §9 exit criterion ("clearly distinguishes observed execution from
inferred capability") is now met at the scan-summary and finding-detail levels,
with the finding-detail attempted case documented as out of reach by design.
