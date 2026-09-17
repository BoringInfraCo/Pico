# v0.5 measurements — 2026-09-16

**Status:** Measured (S044 T3). These are the first measured values for v0.5;
before this, every performance claim was a design constant or an assertion.

**Build:** commit `67eb2ac` + S044 working tree (uncommitted at capture, 17 dirty
entries), `pico 0.1.0`, macOS aarch64.
**Harness:** `tests/integration/sprint044_measurements.rs`, opt-in via
`PICO_S044_MEASURE=1` / `PICO_S044_MEASURE_OUT=<path>`. Disabled runs do nothing
and take ~0.00 s.
**Artifact:** `/tmp/pico-s044-final2.json` (regenerate with the two env vars).
Figures below are the final capture, taken after the S044 verifier defects were
fixed (observer self-bounding, hostile-interval rejection, failed-scan heartbeat).

---

## 1. Measured values

| Measurement | Method | Result |
| --- | --- | --- |
| Idle observation cost | one real `watch::snapshot` (mtime+len stat round) over the 11 resolved watch paths; 25 samples | **min 20.83 µs · median 21.29 µs · max 51.17 µs** (median ≈ 0.021 ms) |
| Detection latency | real `watch::run`, `interval_secs = 1`, `max_events = 1`; wall-clock from config mutation to the appended `.pico/watch.jsonl` line becoming visible; 3 samples | **min 615.62 ms · median 620.63 ms · max 622.27 ms** (bound asserted: ≤ 3 × interval = 3000 ms) |
| Runtime ingest cost | `discovery::runtime::ingest_with_summary` over a synthetic OpenCode-shaped store, 10 000 rows, 7-day window | **138.78 ms** (declared wall-clock cap 3000 ms; rows scanned 10 000, not truncated) |
| Log trim cost | `application::watch_log::trim` at the cap over a synthetic log (1010 → 500 lines, 510 removed); 5 samples | **min 3.38 ms · median 5.77 ms · max 15.44 ms** |

## 2. Budget adherence (declared vs observed)

| Budget | Declared | Observed |
| --- | --- | --- |
| Runtime read window | 604 800 s (7 days) | 604 800 s |
| Runtime rows cap | 10 000 | 10 000 scanned, not truncated |
| Runtime wall-clock cap | 3 000 ms | 138.78 ms |
| Watch poll interval (test) | 1 s | 1 s; detection max 622.27 ms (< 3 × interval) |
| Observation log cap / trim target | 1 000 / 500 events | trims 2500 → 1000 (prune) and 1001 → 500 (observer self-bound) |

All measured values are within their declared budgets on this machine.

## 3. What this does NOT establish

Stated plainly, because the point of this record is to stop asserting what was
never measured:

- **Detection latency is poll-bound, not event-driven.** ~620 ms at a 1 s
  interval is the expected shape; the figure says nothing about accuracy, and
  accuracy is still fixture-level only (`detect_changes` unit tests), not a
  measured corpus rate.
- **Idle cost is a micro-measurement** (mtime+len over 11 paths), not a
  sustained-load profile: no CPU, I/O, memory, or long-running overhead figures.
- **Ingest correctness is not measured here** — only wall-clock cost. Accuracy of
  the content-free extraction is established by unit/integration fixtures.
- **Observer downtime measurement is out of scope** — S044 T1 now *reports*
  continuity (`watching` / `NOT OBSERVING` / `no record`), but how often a real
  observer runs, and what it misses while stopped, is not measured.
- **No real-environment figures.** All measurements use synthetic stores in temp
  directories; the real 13 GB OpenCode store and real `~/.claude` were never used.
- Timing values are single-machine and single-run; the asserted invariants are
  deliberately loose (3 × interval, 10 × cap) and are not performance gates.

## 4. Honest summary against ROADMAP §9

- Exit criterion **#1 "measured latency and accuracy"**: latency is now
  **measured**; **accuracy remains unmeasured** → still partially met.
- Exit criterion **#4 "overhead within explicit local budgets"**: declared
  budgets are now **compared against observed values** for the runtime read, the
  idle stat round, and the log trim → met for those surfaces; CPU/IO/memory and
  sustained operation remain unmeasured.
