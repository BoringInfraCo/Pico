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

## 1.8 Evidence time and freshness (honesty rule)

Runtime evidence must not launder an old invocation into a fresh observation.

- `Evidence::captured_at` = the **newest** in-scope matching invocation's
  timestamp — i.e. when the fact was true — **not** the scan's wall-clock time.
- `Evidence::freshness` is classified from that timestamp relative to the scan
  time using the existing windows (`FRESH ≤1 h`, `AGING ≤24 h`, else `STALE`;
  `src/domain/evidence.rs`).
- Consequence: an invocation older than 24 h is recorded honestly as `STALE`
  and will **not** pass the existing freshness gate, so no promotion occurs.
  Pico confirms *recently observed* execution, never "execution at some point".
- `metadata` records the invocation window (`first`/`last` observed), the
  count, and per-status counts, so a reader can see exactly what was observed.

## 1.9 Frozen interface

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
- [ ] An in-scope `bash` call older than the freshness window is recorded as
      `STALE` and does **not** promote the edge (no laundering old execution
      into a fresh claim).
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

# 6. Completion notes (2026-09-16, HEAD `b73424a` + working tree)

## Implemented

Three parallel subagents (core reader / scan integration / CLI + integration
tests), file ownership respected, frozen §1.9 signatures implemented exactly.
Plus a coordinator change to close one acceptance gap.

- **Core** (`src/discovery/runtime/mod.rs`, new): read-only `mode=ro&immutable=1`
  open with `READ_ONLY|URI|NO_MUTEX|NOFOLLOW` + `query_only=ON`; fail-closed
  migration gate; const-driven content-free `SELECT` allowlist
  (`json_extract` on `$.type/$ .tool/$.callID/$.state.status` only); workspace
  canonicalization with lexical fallback + exclusion counters; keyset
  pagination, `max_rows` (+1 probe) and wall-clock caps; deterministic sort.
- **Integration** (`src/application/scan.rs`, `coverage.rs`, `attribution.rs`):
  `run_with_runtime(workspace, home, enabled)`; promotion of the single
  golden-path edge to `CONFIRMED` with same-scan `DIRECT` evidence linked via
  `relationship_evidence`; `scope.runtime`; `runtime_artifacts` coverage;
  `safe_source` + `Manifest` accept the new operation.
- **Interface** (`src/cli/mod.rs`): `scan --runtime` (default path untouched),
  HOME seam, documented help.
- **Coordinator**: additive `RuntimeDiagnostic` on `ScanDiagnostics`
  (`#[serde(default, skip_serializing_if)]` so default scans serialize
  identically) rendered as `Runtime evidence: <STATE>` in the incomplete-evidence
  block, closing §4's "actionable diagnostic" requirement (unsupported schema
  previously had only a structural signal).

## Deviations

1. **No Cargo change (remediated).** The first implementation enabled rusqlite's
   `hooks` feature for `progress_handler` — the only dependency-adjacent change in
   the project's history. Verified in vendored rusqlite 0.32.1 that
   `Connection::get_interrupt_handle()` / `InterruptHandle::interrupt()` are **not**
   feature-gated, so the wall-clock budget now uses an interrupt-handle watchdog
   (bounded poll → flag → `sqlite3_interrupt`, joined on every exit path).
   `Cargo.toml`/`Cargo.lock` are **unchanged**, and the hard bound on a single
   in-flight statement is preserved. A cooperative page-boundary deadline check
   was added so a tiny budget deterministically truncates rather than depending on
   thread scheduling.
2. **Migration version = count of applied migrations**, not `MAX(id)`: real
   `migration.id` values are timestamp strings, so a literal max can never equal
   `38`. Counts match the support-note series (30/32/38); a uniformly-numeric `id`
   column is still honored as its max.
3. **`ingest_with_summary`** added alongside the frozen `ingest` (which is
   unchanged) because §1.4's excluded-count reporting has no field in the frozen
   outcome.
4. **Single scan snapshot, not a second observation**: the projector rejects two
   relationship observations for one canonical key with differing state, so the
   edge is set to `CONFIRMED` before its one scan snapshot is written.
5. **Promotion guard `state != Blocked`**: an observed invocation never
   overwrites a configured hard-deny boundary (Invariant 5).
6. **Stale/pending evidence is recorded unlinked** so it cannot weaken or inflate
   the configured finding's freshness gate.
7. **URI uses the canonical path** after rejecting a symlinked store file, because
   `NOFOLLOW` cannot open through symlinked parents (macOS `/var → /private/var`).
8. **Combined provider+runtime seam** (`run_with_runtime_and_provider`) added so a
   controlled test can inject a synthetic Cloudflare result *and* enable runtime
   ingestion; existing entries are unchanged and runtime-disabled stays
   byte-identical.

## Validation

- New: 19 core unit + 16 scan-integration unit (incl. the end-to-end finding
  tests) + 2 coverage + 2 attribution + 10 binary-driven integration (S040) + 2
  MCP unit + 1 MCP integration — all PASS.
- Full suite: **665 passed, 1 ignored, 0 failed**; `fmt`, `clippy -D warnings`,
  `git diff --check` clean; `git diff Cargo.toml Cargo.lock` **empty**. SQLite
  schema stays v6; no new tables/columns/CHECKs.
- **Default-scan byte-identity PROVEN** two ways: (a) an in-process test showing
  the new entry with `false` is graph-identical to the existing default entry;
  (b) a cross-revision normalized shape digest at `b73424a` vs working tree with
  a store present (`PRE == POST`), store dir untouched.
- **Finding-level (end-to-end) proof added:** with a synthetic PRODUCTION-rated
  Cloudflare result plus a fresh completed `bash` invocation, a
  `UNTRUSTED_TO_PRODUCTION` finding is produced whose `evidence_ids` include the
  `DIRECT` `opencode_runtime_observer` evidence; the same scenario with runtime
  disabled produces the finding **without** it (attributable, not incidental);
  `render_finding_detail` shows `Source type: opencode_runtime_observer` /
  `Freshness: FRESH`. No `compromised`/`exploited`/`exfiltrat` claim language and
  no sentinel appears anywhere.
- **MCP parity closed:** `SafeScanDiagnostics` now projects the runtime
  limitation (`state`/`reason`/`migrations`, terminal-safe), omitted when `None`
  so existing goldens are unaffected; an integration test asserts the decoded MCP
  payload matches the application DTO and the CLI's rendered text.
- Manual `/tmp/pico-040-20260917` (synthetic store only, never the real one):
  default scan → snapshot `DERIVED`, no `scope.runtime`; `--runtime` → snapshot
  **`CONFIRMED`**, `DIRECT | opencode_runtime_observer | FRESH | INTERNAL`,
  1 `relationship_evidence` link, `scope.runtime` with
  `read_mode:"ro+immutable"`, `rows_scanned:1`, `wal_note:"possibly_stale"`.
  Store dir listing unchanged (no `-wal`/`-shm`); 0 sentinel hits.

## Learnings

The content-free signal was real: `json_extract` on four whitelisted paths
yields the tool name and invocation status without ever touching arguments or
output, so Pico can move `configured → observed` without reading one byte of
content. The freshness rule (§1.8) is what keeps this honest — reading an old
invocation is not a fresh observation, and the existing gate enforces it.

**Known limitation (reportable, not hidden):** the finding's *narrative*
(`title`/`summary` and the static reason explanations) does **not** name runtime
observation; runtime evidence is surfaced as linked evidence in the finding
detail and as step supporting evidence (and the dynamic "weakest evidence" line
names its evidence id on the `can_execute` edge). So `pico finding <id>` is
attributable and correct, but a reader of the one-line summary alone would not
see "observed execution". v0.5's exit criterion ("Pico clearly distinguishes
observed execution from inferred capability") is therefore only partially met at
the narrative level. Recommended next: narrate observed execution when runtime
evidence is present (small change, but it touches golden-tested finding text and
needs its own slice).

## Canon Changes

None. `scope`/`metadata` are existing `Option<Value>` fields; no trigger variant
was added; `RUNTIME_EVENT` remains reserved.
