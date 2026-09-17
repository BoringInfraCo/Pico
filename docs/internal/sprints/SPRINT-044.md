# Pico — Sprint 044: v0.5 Closeout (measurement, continuity visibility, observation-data lifecycle, canon decision)

**Status:** SPEC — frozen for implementation.
**Sprint:** 044
**Phase:** v0.5 — Continuous and Runtime Observation (closeout)
**Type:** Closeout (medium)
**Baseline:** `67eb2ac`
**Depends on:** S037–S043
**Authority:** `docs/internal/ROADMAP.md` §24 (six required closeout items);
§9 (exit criteria #1, #4, #6, #7 and the distinctions wording); §17.

---

# 1. Purpose

Close the four v0.5 closeout items that do not require a human participant.

> **Pico measures what it claimed, states plainly when it is not observing,
> bounds and can delete its own observation data, and records an explicit canon
> decision about the runtime distinctions it can honestly support.**

Items 5 (real dogfood) and 6 (independent comprehension) remain open — they
require a human and are explicitly out of scope.

---

# 2. Scope

## 2.1 T1 — Observation continuity visibility (§24 item 2; §9 exit #6)

Today silence is indistinguishable from safety: `pico watch` can be stopped and
`pico status` says nothing about it.

- `pico watch` maintains a small continuity record at `.pico/watch.state.json`:

```json
{"v":1,"interval_secs":2,"last_check_at":"<rfc3339>","events_total":3}
```

  Written at most once per `HEARTBEAT_SECS` (15) while idle, and always when an
  event is recorded. No process detection, no pid, no daemon machinery — this is
  evidence *of observation*, not process introspection (S038's no-pidfile rule is
  preserved).
- `pico status` reports observation continuity additively, and never writes:

```text
Observation: watching (last check 4s ago)
Observation: NOT OBSERVING (last check 12m ago); changes since then may be unobserved
Observation: no watch record in this workspace (observer has not run)
```

  Verdict rule (frozen, deterministic): fresh when
  `now - last_check_at <= max(3 × interval_secs, 60s)`; otherwise
  `NOT OBSERVING`; absent/unparseable record → `no watch record`. An unreadable
  or malformed record must never be reported as watching.
- The existing `This is not an all-clear` line and all current status lines are
  preserved; the new line is additive.

## 2.2 T2 — Observation-data lifecycle (§24 item 3; §9 exit #7, scope "retention budgets")

`.pico/watch.jsonl` currently grows unbounded.

Frozen shared helper (single implementation, two callers):

```rust
// src/application/watch_log.rs (new)
pub const WATCH_LOG_MAX_EVENTS: usize = 1000;
pub const WATCH_LOG_TRIM_TARGET: usize = 500;
pub struct TrimReport { pub before: usize, pub after: usize, pub removed: usize }
pub fn len(path: &Path) -> Result<usize, PicoError>;              // 0 when absent
pub fn trim(path: &Path, keep: usize) -> Result<TrimReport, PicoError>;
```

- `trim` keeps the newest `keep` **whole lines**, drops only complete lines, is
  atomic (temp file inside `.pico/` + rename), is idempotent, and never creates
  the file when absent. A malformed trailing partial line is preserved as a line
  only if complete; a torn line is dropped rather than kept corrupt.
- `pico watch` self-bounds: when `len > WATCH_LOG_MAX_EVENTS`, it calls
  `trim(.., WATCH_LOG_TRIM_TARGET)`. Hysteresis (trim to 500 only above 1000)
  keeps rewrites rare (~every 500 events) and amortized.
- `pico prune` also trims to `WATCH_LOG_MAX_EVENTS` and reports the removed line
  count in its existing report (explicit user control, consistent with scan
  retention). Scan-unit semantics are unchanged.
- Deletion is documented: `pico prune --help` and `pico status` state that the
  observation log is bounded and that deleting `.pico/watch.jsonl` is safe
  because Pico never treats absence of a log as evidence of safety.

## 2.3 T3 — Measurement (§24 item 1; §9 exit #1/#4)

Numbers, not assertions. An opt-in measurement harness records:

| Measurement | Method |
| --- | --- |
| idle observation cost | one `watch` stat/snapshot round over the resolved watch set, median of N samples |
| detection latency | interval = 1s, mutate a watched config, time from mutation to event recorded; min/median/max over N samples |
| runtime ingest cost | `discovery::runtime::ingest` wall-clock over a synthetic store of M rows |
| log trim cost | `watch_log::trim` wall-clock at the cap |
| budget adherence | observed values vs the declared constants (`DEFAULT_MAX_ROWS`, `DEFAULT_WALL_CLOCK_MS`, poll interval) |

- The harness is **opt-in** (`PICO_S044_MEASURE=1` + `PICO_S044_MEASURE_OUT=<path>`),
  following the S035 capture pattern; default test runs do nothing extra.
- Tests assert only loose, non-flaky invariants (e.g. detection occurred within
  `3 × interval`; ingest respected the wall-clock cap). The measured values are
  written to JSON and recorded in the evidence artifact.
- `docs/internal/dogfood/evidence-v0.5-measurements.md` records the real numbers
  with the build (commit, binary hash, platform) and states plainly what was
  measured and what remains unmeasured.

## 2.4 T4 — Canon decision on runtime distinctions (§24 item 4)

§9 lists six distinctions (configured capability, available capability,
attempted use, approved use, denied use, completed consequential action); Pico
implements four.

**Decision (recorded, not silent):** keep four distinctions and amend §9's
wording, because the two missing ones cannot carry honest independent values:

- *available capability* is already represented by configured/effective
  capability resolution (v0.1–v0.4) and by the observability survey's
  `Observable` level; adding a fifth label with identical meaning is noise.
- *denied use* is not locally observable at all (S039: allow/deny exists only via
  live hooks/OTel), so it would be permanently `NOT_AVAILABLE` — indistinguishable
  from the existing `ApprovedUse` result.

`ROADMAP.md` §9 is amended with an explicit pointer to this decision; the change
is an adjudicated scope clarification, not canon-follows-code drift.

---

# 3. Non-goals

- No daemon, background service, pidfile, process detection, supervisor, or
  autostart; no notifications/alert delivery.
- No hook installation, OTel consumption, transcript parsing, or Claude evidence.
- No new provider, agent, MCP tool, or CLI flag for watch/status (the harness is
  env-var opt-in, not a product surface).
- No new dependencies; SQLite schema stays v6; no change to fingerprints,
  findings, comparison contracts, or scan semantics; default `pico scan` stays
  byte-identical.
- No mutation of the target environment; no LLM in the truth path.
- Items 5 (real dogfood) and 6 (independent comprehension) are NOT attempted.

---

# 4. Acceptance

- [ ] `pico status` distinguishes watching / NOT OBSERVING / no record, using the
      frozen freshness rule; malformed record → not watching; never writes.
- [ ] `pico watch` maintains the continuity record (idle heartbeat + on event),
      with no pid/process detection and no new flag.
- [ ] `trim` is atomic, whole-line, idempotent, absent-file-safe; torn lines are
      dropped not kept corrupt; `pico prune` reports the removed line count and
      leaves scan-unit semantics unchanged.
- [ ] Bounded growth proven: writing beyond the cap leaves the log ≤ cap; repeated
      trims are no-ops; the log never grows without bound across a long synthetic
      event series.
- [ ] Deletion is documented in `prune --help` and `status` output, and deleting
      the log leaves status honest (no false all-clear).
- [ ] Measurement harness produces real values; the evidence doc records build +
      numbers + explicit unmeasured list; default test runs are unaffected.
- [ ] §9 amended with the distinctions decision and a pointer to the record.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
      `cargo test --all-targets`, `git diff --check` green; `git diff Cargo.toml
      Cargo.lock` empty; `src/findings/engine.rs`, `src/findings/model.rs`,
      `src/application/compare_contract.rs` untouched.

# 5. Completion notes (2026-09-16, HEAD `67eb2ac` + working tree)

## Implemented

Three parallel subagents (continuity visibility / log lifecycle / measurement
harness) with disjoint file ownership, then an independent adversarial
verification pass, then coordinator defect fixes and the canon decision.

- **T1 continuity visibility** (`watch.rs`, `status.rs`, `cli/mod.rs`):
  `.pico/watch.state.json` v1 (`v`, `interval_secs`, `last_check_at`,
  `events_total` — no pid, no process detection), written atomically, rate-limited
  by `HEARTBEAT_SECS` while idle and always on event; `pico status` reports
  `watching` / `NOT OBSERVING` / `no watch record` via a pure, sleep-free verdict.
- **T2 log lifecycle**: new `watch_log.rs` (`len`, atomic whole-line `trim`,
  cap 1000 / target 500), wired into `pico prune` (reported as a line count,
  after a successful DB prune) and — see the fix below — into `pico watch`
  itself; the bounded/deletion-safe notice is rendered in the prune report.
- **T3 measurement**: opt-in harness (`PICO_S044_MEASURE=1`) recording idle stat
  cost, detection latency, runtime ingest cost, trim cost, and budget adherence,
  with a build record; numbers recorded in
  `docs/internal/dogfood/evidence-v0.5-measurements.md`.
- **T4 canon decision**: §9's distinctions wording amended with an explicit
  pointer to this decision (four distinctions; "available capability" is
  represented by configured/effective capability, "denied use" folded into
  `ApprovedUse → NOT_AVAILABLE`).

## Deviations

1. **Coordinator defect fix (HIGH) — observer self-bounding was missing.** §2.2
   requires `pico watch` to bound its own log; the task split left it unowned, so
   the log still grew unbounded between prunes. Added `trim_log_if_needed` to the
   watch loop with a regression test proving the cap holds across a long series.
   *This was an assignment error in the sprint's parallelisation, caught by the
   verifier, not by the implementing agents.*
2. **Coordinator defect fix (HIGH) — `pico status` could panic.** A field-valid
   record with a hostile `interval_secs` panicked `chrono::Duration::seconds`.
   Fixed by rejecting implausible intervals (> 3600 s) at parse time so a corrupt
   record yields `no record` rather than a widened window, plus a window clamp;
   regression test added.
3. **Coordinator defect fix (MEDIUM) — failed scan suppressed the heartbeat.** A
   detected change whose scan failed recorded neither an event nor a heartbeat,
   so a live watcher could be reported `NOT OBSERVING`. The loop now re-baselines
   and refreshes the rate-limited heartbeat on that path.
4. **Accepted residual (LOW)** — a log-trim failure after a committed DB prune
   reports the whole prune as failed (conservative; the trim is idempotent and
   re-runnable). Recorded, not silently changed.
5. `RuntimeReport.notes` type change and the S030 frozen prune-report goldens were
   updated by the implementing agents (additive lines only; scan-unit retention
   assertions unchanged).

## Validation

- Full suite: **750 passed, 1 ignored, 0 failed**; `fmt`, `clippy -D warnings`,
  `git diff --check` clean; `git diff Cargo.toml Cargo.lock` empty; `engine.rs`,
  `model.rs`, `compare_contract.rs` untouched.
- Adversarial verification found 4 issues (2 HIGH, 1 MEDIUM, 1 LOW) across 10
  checked claims; all HIGH/MEDIUM were fixed with regression tests, the LOW is
  recorded as accepted residual.
- Manual verification (isolated HOME): continuity `no record → watching (2s) →
  NOT OBSERVING (12m) → malformed → no record`; prune `2500 → 1000` lines with
  the newest event kept and a second prune removing 0; the state record contains
  no pid.
- Measurements (final tree): idle 21.29 µs median over 11 paths; detection
  620.63 ms median at a 1 s interval; runtime ingest 138.78 ms against a 3000 ms
  cap; log trim 5.77 ms median.

## Learnings

Measurement found nothing alarming — the design constants were honest — but it
converted "should be fast" into numbers, and it surfaced that detection latency
is poll-bound (~0.62 × interval), not event-driven. The verifier was decisive:
the most safety-relevant defect (a live observer reported as not observing, and
an unbounded log in the very slice meant to bound it) came from a task-assignment
gap, not from a hard implementation problem. Parallelising by file ownership
works, but the spec's cross-cutting requirements need an explicit owner.

## Canon Changes

`ROADMAP.md` §9 distinctions wording amended per the §2.4 decision (explicit,
reasoned, with a pointer — not silent drift).

Items 5 (real dogfood) and 6 (independent comprehension) remain OPEN and require
a human; they are not attempted here.
