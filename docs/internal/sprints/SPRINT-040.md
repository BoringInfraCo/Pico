# Pico — Sprint 040: Runtime Evidence Ingestion (v0.5 slice 4)

**Status:** SPEC — frozen for implementation.
**Sprint:** 040
**Phase:** v0.5 — Continuous and Runtime Observation (slice 4)
**Type:** Vertical slice (medium)
**Baseline:** `d3298d1`
**Depends on:** S039 (`pico runtime` survey + support note), S037/S038
**Authority:** `docs/internal/ROADMAP.md` §9; `docs/internal/TECHNICAL.md` §3.3;
`docs/internal/ARCHITECTURE.md` §8.2 / §28.2; the schema and safe-read research in
`SPRINT-040-support-note.md`.

---

# 0. Purpose

This is the slice where `attempted use` stops being `AVAILABLE_UNREAD`:

> **With explicit opt-in, `pico scan --runtime` reads the OpenCode store
> read-only and content-free, scopes what it finds to the scanned workspace,
> and — only when a real tool invocation is observed — records `DIRECT`
> evidence that upgrades the golden-path `agent → bash` capability from
> `DERIVED` (configured) to `CONFIRMED` (observed). When it cannot safely
> establish this, it says so and changes nothing.**

## 0.1 The one claim this slice may make

Allowed: *"Pico observed the OpenCode agent invoke Bash in this workspace within
the retained window."* (evidence-backed, scoped, timestamped)

Forbidden (unchanged canon): compromise, exploitation, propagation, malicious
intent, approval/denial, "the agent cannot execute" (absence ≠ absence),
or any claim outside the retained window.

---

# 1. Scope

## 1.1 Opt-in contract

- `pico scan` (default) is **byte-for-byte unchanged**: no store is opened, no
  new coverage entry, no `scope.runtime`, no metadata change, no new rows.
  Runtime absence-without-attempt is expressed by *omitting* the runtime
  coverage entry, never by fabricating a `NotAttempted` row that would alter
  every existing scan's coverage and canary diffs.
- `pico scan --runtime` enables ingestion for that scan only; the runtime
  coverage entry and `scope.runtime` appear **only** on such scans. A
  runtime-enabled scan compared against a default scan may honestly report
  `coverage_changed` (S032); that must never read as remediation or
  disappearance.
- No config file, no daemon, no background process, no hook installation.
- `pico watch` does **not** gain runtime ingestion in this slice (deferred).

## 1.2 Safe-read contract (frozen; from the support note §6)

```text
open:  file:<abs>?mode=ro&immutable=1
       SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_NOFOLLOW
       + PRAGMA query_only=ON ; short busy_timeout
budget: wall-clock via progress_handler; ≤10k rows/table; ≤50k rows total;
        keyset pagination on id/rowid; no bare COUNT(*) on large tables
```

- **Zero filesystem writes**: no `-wal`/`-shm` creation, no temp files, no
  copies. A kill or error mid-read leaves the store untouched.
- `immutable=1` means the read **ignores the WAL**: results are a possibly-stale
  snapshot. This is a documented limit, surfaced in coverage + scan metadata —
  never presented as real-time truth.
- A corrupt/racing store (`SQLITE_CORRUPT`, `SQLITE_BUSY`) yields
  `CoverageState::Incomplete` and no upgrade. Bounded retry is allowed; silent
  best-effort is not.

## 1.3 Content-free extraction (frozen allowlist)

Only these are ever selected, via `json_extract()` on whitelisted paths:

| Need | Path |
| --- | --- |
| Is this a tool call? | `part.data` → `$.type = 'tool'` |
| Tool name | `part.data` → `$.tool` |
| Call identity | `part.data` → `$.callID` |
| Invocation status | `part.data` → `$.state.status` (`pending`/`running`/`completed`/`error`) |
| Time + scope | `part.time_created`, `part.session_id`, `session.directory` |
| Schema version | `migration.id`, `migration.time_completed` |

**Never selected:** raw `part.data`, `part.data.$.state.input|output|text|metadata`,
`message.data`, `session_input.prompt`, `session.title`, `session.summary_*`,
`session.revert`, `todo.content`, `project.commands`, `event.data`, and any
`credential`/`account`/`control_account`/`session_share` column. The column
allowlist is enforced in code and asserted by tests using sentinel content
embedded in the forbidden paths.

## 1.4 Workspace scoping (correctness requirement)

The store is machine-global. Ingestion **must** restrict to sessions whose
`session.directory` canonically equals the scanned workspace root. If the
directory cannot be resolved or matched for any candidate row, that row is
excluded and counted — never attributed to this workspace.

## 1.5 Schema compatibility (fail closed)

- Supported range is frozen as a const pair
  (`SUPPORTED_MIGRATION_MIN`, `SUPPORTED_MIGRATION_MAX`, both `38` at
  v1.18.31) covering table/column presence the reader needs.
- Detection: `migration` (fallback `__drizzle_migrations`); unknown, missing,
  newer, or older-with-missing-columns → `CoverageState::Unknown`, **no
  ingestion**, no upgrade, and an actionable diagnostic.
- Missing optional tables/columns must degrade, not panic or guess.

## 1.6 The only graph effect (frozen rule table)

Target: the existing golden-path relationship
`agent:opencode | can_execute | shell:bash`.

```text
observed tool = "bash" (case-insensitive, exact tool-name match)
AND session.directory == scanned workspace
AND status ∈ {completed, running, error}
        → relationship-snapshot Observation with state CONFIRMED
        + same-scan DIRECT Evidence (source_type "opencode_runtime_observer")
        → can_execute may become CONFIRMED for this scan

status = pending only (observed but not executed)
        → no state change; DIRECT evidence records attempted_not_executed
          and coverage notes it

nothing observed / not readable / out of scope
        → NO observation claiming absence. Coverage is not-attempted/incomplete/
          unknown, freshness context only. Never "cannot execute".
```

- Only this one edge is promotable. Other tools are recorded as coverage-level
  counts at most, never as graph state changes.
- The upgrade must pass the **existing** `may_be_confirmed` + freshness gates
  (`src/findings/engine.rs:221–234`, `:477–489`); no gate is bypassed or
  weakened. S029 comparison contract must remain valid.

## 1.7 Frozen interface

```rust
// src/discovery/runtime/mod.rs (new; read-only, no new deps)
pub struct RuntimeIngestConfig { pub store: Option<PathBuf>, pub workspace: PathBuf,
                                 pub window_secs: i64, pub max_rows: usize,
                                 pub wall_clock_ms: u64 }   // defaults: 7d / 10k / 3000
pub enum RuntimeReadOutcome { Ingested { invocations: Vec<ToolInvocation>, truncated: bool },
                              NotAttempted, Unsupported { migrations: Option<u64> },
                              Unavailable { reason: &'static str } }
pub struct ToolInvocation { pub tool: String, pub status: ToolStatus,   // ToolStatus enum
                            pub call_id: String, pub session_id: String,
                            pub observed_at: DateTime<Utc> }
pub fn ingest(cfg: &RuntimeIngestConfig) -> Result<RuntimeReadOutcome, PicoError>;

// Scan::Scope/metadata additions (no schema change — `scope`/`metadata` are Option<Value>)
// scope.runtime = { enabled, store_present, migrations, window_secs, rows_scanned,
//                   truncated, read_mode: "ro+immutable", wal_note: "possibly_stale" }
// Coverage: new operation "runtime_artifacts" with honest CoverageState per §1.5
```

CLI: `Scan { #[arg(long)] runtime: bool }` → threads into `ScanService` via a
new trigger-independent entry. **No new `ScanTrigger` variant** (see §3).

---

# 2. Non-goals

- No daemon, background observer, hook, plugin, OTel, or live interception.
- No reading of content, prompts, tool arguments/outputs, or credential tables.
- No approval/denial claims (S039 established they are not locally available).
- No Claude Code transcript ingestion (internal, version-varying format).
- No new dependencies; SQLite schema stays v6; no new tables/columns/CHECKs.
- No `pico watch` runtime ingestion; no notifications; no enforcement.
- No promotion of any edge other than the golden-path bash capability.
- No bypass of confidence/freshness gates; no second risk engine.

---

# 3. Deliberate canon-facing decisions (flagged)

1. **No `RUNTIME_EVENT` trigger variant.** `ScanTrigger` describes what
   *initiated* the scan. An operator running `scan --runtime` is `MANUAL`; a
   runtime-*event*-initiated scan would require a daemon, which `ARCHITECTURE`
   §28.2 forbids in V0. Scope/metadata records the ingestion instead.
2. **`CONFIRMED` is used for observed capability.** `EvidenceClass::Direct`
   already means "directly observed"; the existing `RelationshipState::Confirmed`
   is the correct mapping for "we observed the invocation." The
   configured-vs-observed distinction is carried by the evidence *class*
   (formerly `DERIVED`, now `DIRECT`) and by the explanation text.
3. **`immutable=1` staleness is disclosed, not hidden.** Freshness/coverage
   surface that the read ignored the WAL.
4. **`--runtime` is opt-in and off by default** because reading a 13 GB,
   credential-adjacent store is a trust-relevant act.

---

# 4. Acceptance

- [ ] Default `pico scan` behavior is byte-for-byte unchanged: no store open, no
      sidecar, no new coverage entry or `scope` field, no new rows; existing
      golden fixtures byte-identical.
- [ ] A default scan compared with a `--runtime` scan reports `coverage_changed`
      honestly and never as remediation/disappearance.
- [ ] With `--runtime` on a synthetic store, a completed `bash` tool call in the
      scanned workspace promotes `can_execute` to `CONFIRMED` and the finding
      explanation cites the runtime evidence; `DIRECT` class is visible.
- [ ] A `bash` call with `status=pending` does **not** promote the edge but is
      recorded honestly (attempted, not executed).
- [ ] A `bash` call in a **different** `session.directory` does not affect the
      scanned workspace's edges (workspace scoping test).
- [ ] No `bash` call observed → no absence claim; state (and finding) unchanged;
      coverage says not-observed/incomplete honestly.
- [ ] Unknown/newer/older-broken schema → `CoverageState::Unknown`, zero
      ingestion, actionable diagnostic, nonzero exit only if the operator
      explicitly required runtime.
- [ ] Read-only proof: store directory listing + `-wal`/`-shm` state byte-identical
      before/after; no temp files; corrupt-store path yields `Incomplete`, no panic.
- [ ] Secret/content sweep: sentinels placed in `part.data.$.state.input`,
      `session_input.prompt`, `session.title`, and a credential table never appear
      in DB, evidence, logs, diagnostics, output, or the public JSON.
- [ ] Budget honesty: row cap and wall-clock cap enforced and reported as
      `truncated`/`Incomplete` when hit.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
      `cargo test --all-targets`, `git diff --check` green; ignored tests listed.
- [ ] Manual verification in a disposable workspace with a **synthetic** store
      (never the real 13 GB store).

# 5. Test plan (TDD)

- **Synthetic store fixtures**: build minimal OpenCode-shaped SQLite DBs in tests
  with rusqlite (tables: `session`, `part`, `message`, `migration`) populated with
  synthetic tool calls (various tools, statuses, directories, timestamps) and
  **sentinel content** in forbidden paths. No real store, no network.
- Unit: version detection + supported-range fail-closed; column allowlist; tool
  classification (bash vs other vs pending); workspace canonicalization/scoping;
  budget truncation; forbidden-path extraction never selected.
- Integration (binary-driven, temp dirs): default scan unchanged; `--runtime`
  promote path; no-promotion path; stderr/JSON diagnostics; read-only digests;
  sentinel sweep; determinism (repeat scan byte-equal diff/JSON).
- Golden: finding explanation must name the runtime evidence and must not use
  forbidden claim language (assert absence of "compromised"/"exploited").
- Existing suites (S024–S039) stay green untouched; S029 contract tuple
  unchanged.

---

# 6. Completion notes (fill on execution)

## Implemented / Deviations / Validation / Learnings / Canon Changes

- (pending)
