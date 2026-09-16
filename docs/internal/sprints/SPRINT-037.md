# Pico — Sprint 037: `pico watch` (v0.5 slice 1, FILESYSTEM_CHANGE)

**Status:** SPEC — frozen for implementation.
**Sprint:** 037
**Phase:** v0.5 — Continuous and Runtime Observation (slice 1)
**Type:** Vertical slice (small–medium)
**Baseline:** `396d472`
**Depends on:** v0.4 ADVANCE-with-caveats (ROADMAP §23); S024–S036 scan/diff/attribution/JSON contracts
**Authority:** `docs/internal/ROADMAP.md` §9; `docs/internal/ARCHITECTURE.md` §8.2 (reserved `FILESYSTEM_CHANGE` trigger); final implementation contracts take precedence.

---

# 1. Purpose

Prove the smallest timely-observation loop:

> **When a watched agent/MCP config file changes, Pico notices within one
> poll interval, runs the unchanged bounded scan pipeline, and shows the
> same diff a manual `scan` + `diff` would show — in a foreground process
> the user can stop with Ctrl-C, with no daemon, no content capture, and
> no new analysis semantics.**

---

# 2. Scope

## 2.1 Watch set (watch what you read)

At `watch` start, re-derive the candidate config paths using the adapters'
own resolution rules (no hardcoded home paths in the watcher):

- OpenCode: workspace-chain `opencode.json[c]`, `.opencode/opencode.json[c]`,
  `$HOME/.config/opencode/opencode.json[c]` (`discovery/agents/opencode.rs`
  candidate rules; `home` seam honored, `None` skips user files).
- Claude: workspace-chain `.claude/settings.json`, `settings.local.json`,
  `$HOME/.claude/settings.json`, workspace-chain `.mcp.json`
  (`discovery/agents/claude.rs` candidate rules).
- `.env` single file at git-root else workspace (token keys only, never values).

Missing files are watched for creation. The resolved set is printed at start
(watch-root-relative paths). File *contents* are never read by the watcher —
only `(mtime, len)` snapshots via std.

## 2.2 Frozen interface (implementers: do not change these signatures)

```rust
// src/domain/scan.rs
pub enum ScanTrigger { Manual, FilesystemChange } // + as_str/FromStr round-trip; unknown strings still error
impl Scan { pub fn start_with_trigger(trigger: ScanTrigger) -> Self } // start() keeps Manual default

// src/application/watch.rs (new; std only — no new dependencies)
pub struct WatchConfig { pub interval_secs: u64, pub max_events: Option<u64> } // None = run until killed
pub fn snapshot(paths: &[PathBuf]) -> Snapshot;              // pure: path -> Option<(mtime, len)>
pub fn detect_changes(before: &Snapshot, after: &Snapshot) -> Vec<PathBuf>; // pure, deterministic
pub fn relativize(path, workspace, home) -> String;          // persisted form; filename fallback outside both roots
pub fn run(workspace: &Path, home: Option<&Path>, cfg: &WatchConfig) -> Result<WatchReport, PicoError>;

// CLI (src/cli/mod.rs): Watch { #[arg(long, default_value_t = 2)] interval_secs: u64 } + run_watch() arm
```

Service entry threads the trigger into the existing pipeline
(`ScanService` gains a trigger-taking entry; all existing entries keep
`Manual`). `DiffService::latest` + S033 projections + human renderers are
reused unchanged.

## 2.3 Loop semantics

```text
resolve watch set → print set + budgets → snapshot
loop:
  sleep(interval) → snapshot → detect_changes
  if empty → continue (no scan, no writes)
  else → scan(FILESYSTEM_CHANGE) → DiffService::latest → print human diff
         → append one JSONL event to .pico/watch.jsonl → snapshot again
         → if changed during scan, exactly one follow-up iteration
```

- Sequential only: no overlapping scans from the watcher. External concurrent
  `pico scan` failures are logged to stderr; the watch continues.
- `PARTIAL`/`FAILED` scans are freshness context, never diff operands
  (Invariant 9): print status + freshness note, keep watching.
- Fatal (missing state, unsupported schema): actionable error + nonzero exit
  (`run pico init` / upgrade remedy, same wording family as existing errors).
- `interval_secs == 0` is a usage error (no busy loop), exit nonzero.
- Stop = kill (incl. Ctrl-C): no signal handling, no new deps. Safe because
  scan persistence is transactional and the JSONL append happens after the
  diff completes; a kill mid-iteration leaves at most an unscanned change,
  which the next `watch`/`scan` picks up.
- Budgets (documented in `--help`): one stat round per interval while idle;
  one bounded scan per change batch only; no network beyond what `scan`
  already does; no content/config-value capture anywhere.

## 2.4 Event record (frozen shape, golden-tested)

`.pico/watch.jsonl` — one object per trigger event, watch-root-relative
`changed` paths only (never contents, never absolute HOME paths):

```json
{"v":1,"ts":"<rfc3339>","trigger":"FILESYSTEM_CHANGE","changed":["opencode.json"],
 "scan_id":"<opaque>","scan_status":"COMPLETE","contracts_match":true,
 "findings":{"appeared":0,"disappeared":0,"weakened":0,"strengthened":0,"uncertain":0}}
```

---

# 3. Non-goals

- No daemon, background install, autostart, or service management.
- No notifications, thresholds, alerting, or CI/policy exits (slice 2).
- No `RUNTIME_EVENT` / `AGENT_REQUEST` / `SCHEDULED` / `CI` triggers; no
  execution/approval-event observation.
- No new analysis, attribution, finding, or scoring logic.
- No SQLite schema change (stays v6); no MCP changes; no new adapters.
- No new dependencies (`notify`, `ctrlc`, etc. — std polling is the design).
- No closing of the carried independent comprehension gates.

---

# 4. Acceptance

- [ ] `pico watch --help` documents what is watched, budgets, log location,
  and how to stop; `interval_secs=0` fails with an actionable error.
- [ ] Changing a watched config (allow→deny) triggers exactly one scan with
  `trigger=FILESYSTEM_CHANGE`, and the printed diff equals manual
  `scan` + `diff` output for the same pair (paired environment attribution
  preserved, "not an all-clear" preserved).
- [ ] Quiet periods perform zero scans and zero DB writes (digest-equal).
- [ ] `PARTIAL` scan during watch: freshness note, no diff operand, watch continues.
- [ ] Missing `.pico` / unsupported schema: actionable error, nonzero exit, no init side effects.
- [ ] `watch.jsonl` entries match the frozen shape golden; relative paths only.
- [ ] Secret sweep: sentinel config *values* never appear in stdout, JSONL, DB, or logs — paths and scan IDs only.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --all-targets`, `git diff --check` green; ignored tests listed.
- [ ] Manual verification in a disposable workspace (isolated HOME, scrubbed
  credential env): start `watch`, mutate config, observe trigger output,
  stop; validate JSONL with `python3 -c json.load`.

# 5. Test plan (TDD)

- Unit, deterministic, no sleeps: `snapshot`/`detect_changes` incl.
  appeared/disappeared/mtime-only/len-only cases; `relativize` incl.
  outside-both-roots fallback; trigger `as_str`/`FromStr` round-trip +
  unknown-string error; event-shape golden; invalid interval.
- Exactly ONE timing-tolerant integration test (short interval, generous
  timeout, `max_events=Some(1)`): mutate `opencode.json` in temp
  workspace+home → assert one `FILESYSTEM_CHANGE` scan + JSONL event with
  expected finding delta. All other integration coverage deterministic
  (`max_events=Some(0)` with a pending change asserts zero new scans).
- Existing suites (S025/S029/S031/S033/S034/S035) stay green untouched.

---

# 6. Completion notes (2026-09-16, HEAD `396d472` + working tree)

## Implemented

Two parallel subagents, file ownership respected, frozen §2.2 signatures
implemented exactly (no reconciliation needed):
- Core: `ScanTrigger::FilesystemChange` + `start_with_trigger` sharing
  `begin()` with `start()`; `run_pipeline(..., trigger)` refactor with all
  existing entries pinned to `Manual`; new `src/application/watch.rs`
  (std only): snapshot/detect/relativize, candidate-rule watch-set
  resolution, sequential loop with single follow-up, PARTIAL/FAILED =
  zeroed event + freshness note, transient errors → stderr + continue,
  missing state/unsupported schema fatal, `max_events` budget seam.
- Interface: `Watch{interval_secs default 2}` + dispatch arm + thin
  `run_watch()` (interval-0 usage error; cwd/HOME seam mirrors
  `run_scan`); 4-paragraph `--help` (watched set, budgets, log location,
  stop); zero scan/diff logic in CLI.

## Deviations

One inward deviation, constitution-correct: `run()` prints its compact
diff summary from the same `FindingDiff` facts instead of reusing
`cli/render.rs` (reusing it would invert the `cli → application`
boundary). Fact-level parity with `pico diff` is asserted by test.

## Validation

- New: 25 unit (trigger round-trip, threading, snapshot/detect ×3,
  relativize, watch-set ×2, event golden, interval-0, missing-state,
  zero-budget, sweeps) + 4 integration (help, interval-0, allow→deny
  trigger with JSONL + manual-`diff --json` counter parity, quiet
  zero-scan, sentinel sweep) — all PASS.
- Full suite: 583 passed, 1 ignored, 0 failed; fmt, clippy `-D warnings`,
  `git diff --check` clean. No `Cargo.toml`/`Cargo.lock` change (no new
  deps); `watch.rs` never reads contents (`metadata` only); schema stays
  v6 (read-only `require_schema_version` guard).
- Manual `/tmp/pico-037-20260916` (isolated HOME, scrubbed env): 11-path
  watch set printed; 4s quiet → zero scans; allow→deny → exactly one
  `FILESYSTEM_CHANGE` scan; single-scan honesty ("freshness context
  only", `contracts_match:false`, zeroed findings); JSONL valid with
  relative path only. All PASS.

## Learnings

`max_events` budget seam + pure `snapshot`/`detect` functions make a
time-based feature deterministically testable (one timing-tolerant test
suffices). Re-deriving the watch set from adapter candidate rules keeps
the watcher correct as adapters evolve, with no shared registry to drift.

## Canon Changes

None (new `FILESYSTEM_CHANGE` trigger uses the reserved ARCHITECTURE §8.2
slot; no product/technical/sequencing change).
