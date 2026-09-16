# Pico — Sprint 038: Local Change Notices (v0.5 slice 2)

**Status:** SPEC — frozen for implementation.
**Sprint:** 038
**Phase:** v0.5 — Continuous and Runtime Observation (slice 2)
**Type:** Vertical slice (small)
**Baseline:** S037 commit (post-`pico watch`).
**Depends on:** S037 (`watch.jsonl` v1 event log, `DiffService`, S033 projections)
**Authority:** `docs/internal/ROADMAP.md` §9 (local status and change
notification surfaces for small teams); `SPRINT-037.md` §2.4 (event shape).

---

# 1. Purpose

Turn the watch event stream into triaged attention:

> **Every watch event carries a deterministic notice level — URGENT, INFO,
> or QUIET — and `pico status` answers "what needs my attention right now?"
> from local state alone: freshness, last notices, and the honest next step.
> No push, no config, no new engine.**

---

# 2. Scope

## 2.1 Frozen notice rules (deterministic, no tuning knobs in this slice)

Computed per event from the same `FindingDiff` facts `watch` already holds:

```text
URGENT if findings.appeared > 0           → reasons: [finding_appeared]
       OR findings.strengthened > 0       → reasons: [finding_strengthened]
INFO   if findings.weakened/uncertain/disappeared > 0
                                          → reasons: [finding_weakened | finding_uncertain |
                                                     disappearance_unconfirmed]
       OR scan PARTIAL                    → reasons: [scan_partial]
       OR contracts_match == false        → reasons: [contracts_mismatch]
       OR attributed env change with zero finding deltas
                                          → reasons: [env_change_no_finding_delta]
QUIET  otherwise (no significant diff)    → reasons: [no_significant_change]
```

Priority: URGENT > INFO > QUIET. Reasons are stable codes (golden-tested).

## 2.2 Frozen interface (implementers: do not change these signatures)

```rust
// src/application/watch.rs (extend; owned by core agent)
pub enum Notice { Urgent, Info, Quiet }              // as_str: "urgent"|"info"|"quiet"; FromStr round-trip
pub fn classify(event_facts: &EventFacts) -> (Notice, Vec<&'static str>); // pure, deterministic
// EventFacts carries appeared/disappeared/weakened/strengthened/uncertain: usize,
//             contracts_match: bool, scan_status: ScanStatusView-like (COMPLETE|PARTIAL|FAILED),
//             env_change_observed: bool. No DiffService types leak into the signature
//   beyond what watch.rs already imports; keep the struct flat and Copy-friendly.
// WatchEvent gains: "notice": "<level>", "reasons": ["<codes>"]  (JSONL stays "v":1;
//   readers MUST tolerate unknown fields — document in code comment + test it).
// Watch loop prints one notice line per event, e.g.:
//   Pico watch: [URGENT] 1 finding appeared (finding_appeared) — run `pico findings`
//   Pico watch: [QUIET] no significant change. This is not an all-clear.

// src/application/status.rs (new; owned by interface agent)
pub struct StatusReport { /* freshness + last notices + next step, all Strings/ints */ }
pub fn status(workspace: &Path) -> Result<StatusReport, PicoError>; // read-only: history + watch.jsonl tail (cap 200 lines)
// CLI: `pico status` (no flags) → human render. Read-only command.
```

## 2.3 `pico status` contract

From local state only (latest COMPLETE scan, `watch.jsonl` tail):

```text
Pico status
Last COMPLETE scan: <id> (<age>; STALE if >24h → "run `pico scan`")
Watch events (retained log tail): <n> total, <u> URGENT, <i> INFO
Last URGENT: <ts> <one-line reasons>  (or "none recorded")
Next step: <"run `pico findings`" if unreviewed URGENT | "run `pico scan`" if stale | "nothing flagged">
This is not an all-clear: Pico reports what it observed, not safety.
```

- No watch process detection (no pidfiles — that is daemon machinery).
- Missing/empty log or no scans: explicit honest states, never blank reassurance.
- `STALE >24h` is a freshness heuristic, worded as such — never a safety claim.

---

# 3. Non-goals

- No push/desktop/sound/email/Slack delivery; no threshold configuration
  file (fixed rules until users demand knobs — no speculative config).
- No CI/policy exit codes; no auto-remediation; no new triggers.
- No SQLite schema change (stays v6); no MCP changes; no new dependencies.
- No closing of the carried independent comprehension gates.

---

# 4. Acceptance

- [ ] Every watch event carries `notice` + `reasons` per §2.1; golden updated;
  unknown-field tolerance test for the JSONL reader.
- [ ] Watch prints exactly one notice line per event with the prescribed
  wording family (`[URGENT]` names `pico findings`; `[QUIET]` keeps the
  not-an-all-clear).
- [ ] `pico status` matches §2.3 incl. STALE heuristic, empty-log honesty,
  and the closing not-an-all-clear line; read-only (digest-equal).
- [ ] Priority test: appeared + weakened in one event → URGENT with both reasons.
- [ ] Secret sweep: sentinel values in configs/DB never reach status output.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --all-targets`, `git diff --check` green; ignored tests listed.
- [ ] Manual verification in a disposable workspace: watch → deny change →
  `[URGENT]` line + JSONL notice → `pico status` shows URGENT + next step;
  quiet workspace → QUIET events + honest status.

# 5. Test plan (TDD)

- Unit, deterministic: full §2.1 rule matrix incl. priority overlap;
  `Notice` round-trip; status render goldens (fresh/stale/empty-log/
  missing-log/unreviewed-URGENT); JSONL tolerance (extra unknown field).
- Integration (binary-driven, temp dirs): watch→deny yields URGENT event +
  `status` surfaces it; interval-0-style arg errors n/a (status has no
  flags — test `status --help` documents read-only contract instead).
- Existing suites untouched and green.

---

# 6. Completion notes (2026-09-16, HEAD `ad13a2d` + working tree)

## Implemented

Two parallel subagents, file ownership respected, frozen §2.2 signatures
implemented exactly:
- Core (`watch.rs` only): `Notice` (as_str/FromStr/Display/serde
  lowercase), flat `Copy` `EventFacts`, `classify` with the exact §2.1
  matrix (reasons accumulate in stable order; QUIET →
  `[no_significant_change]`), `WatchEvent` gains `notice`+`reasons`
  (`"v":1` unchanged; unknown-field tolerance documented + tested),
  one notice line per event (`[URGENT] … run \`pico findings\``;
  `[QUIET] … This is not an all-clear.`).
- Interface: new `status.rs` (`StatusReport`, read-only `status()`:
  `open_read_only` + schema guard + `newest_complete`, 200-line JSONL
  tail cap, case-exact notice parsing, malformed lines skipped, STALE =
  no COMPLETE or age >24h with exactly-24h fresh, next-step precedence
  URGENT→findings / stale→scan / else nothing flagged), `Status`
  no-flag CLI variant (Doctor-style) with thin render incl. the literal
  closing honesty line; 8 unit + 6 integration tests.

## Deviations

None to the spec. Interpretations documented in code: `total` counts
parseable JSON-object lines (notice-less S037-era events count in total,
neither bucket); "unreviewed URGENT" = any URGENT in the retained tail
(no review state exists in this slice); render lives in `cli/mod.rs`
(`render.rs` was out of the interface agent's owned files).

## Validation

- New: 6 core unit (matrix, overlap, round-trip, golden, tolerance,
  wording) + 8 status unit + 6 integration (ONE timing test: real watch
  + allow→deny) — all PASS; S037's 4/4 unregressed.
- Full suite: 602 passed, 1 ignored, 0 failed; fmt, clippy `-D warnings`,
  `git diff --check` clean. No `Cargo.toml`/`Cargo.lock` change; schema
  stays v6; read-only proven by digest + JSONL-length equality; sentinel
  sweeps clean.
- Manual `/tmp/pico-038-20260916` (isolated HOME, scrubbed env): fresh
  state honest (`run \`pico scan\``); allow→deny on finding-free ws →
  `[INFO] … (contracts_mismatch, env_change_no_finding_delta)` (correct:
  single scan admits no pair comparison); `status` surfaces 1 INFO event,
  freshness, `nothing flagged`, and the closing line. URGENT render path
  proven deterministically by unit matrix (bare offline ws cannot produce
  findings). All PASS.

## Learnings

String-based notice parsing with case-exactness keeps `status` decoupled
from `watch` internals and forward-tolerant; the `max_events`/pure-function
pattern from S037 carried over and kept this slice to one timing test.

## Canon Changes

None (notification surfaces use existing evidence; no sequencing change).
