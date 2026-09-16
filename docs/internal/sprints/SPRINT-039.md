# Pico — Sprint 039: Runtime Observability Survey (v0.5 slice 3)

**Status:** SPEC — frozen for implementation (direction confirmation pending).
**Sprint:** 039
**Phase:** v0.5 — Continuous and Runtime Observation (slice 3)
**Type:** Vertical slice (small) + support note
**Baseline:** `a0c3928`
**Depends on:** S037 (`pico watch`), S038 (`pico status`); v0.4 evidence/decay contracts
**Authority:** `docs/internal/ROADMAP.md` §9; `docs/internal/ARCHITECTURE.md` §8.2 / §28.2; `docs/internal/TECHNICAL.md` §3.3, §43.

---

# 0. Why this slice (research finding, recorded honestly)

S039 was originally imagined as "observe execution/approval events." A
read-only survey of the real environment and upstream docs (recorded in
`docs/internal/sprints/SPRINT-039-support-note.md`) found:

> **Approval/denial semantics are NOT reliably observable locally.**
> OpenCode stores sessions/messages/parts in `~/.local/share/opencode/opencode.db`
> (SQLite; ~13 GB), but its `permission` table is empty and
> `permission.asked`/`permission.replied` exist only as live plugin events.
> Claude Code records allow/deny decisions only through live hooks or OTel
> export, not in local state. Local decision *records* are therefore not a
> dependable evidence source, and live interception would require a daemon
> or hook installation — both expressly outside Pico's V0 non-goals.

Consequently S039 must **not** claim approval/denial observation. It reports
what is safely knowable and refuses the rest. Ingesting actual session/tool
metadata is a later slice (S040) that must first earn a schema/version
contract and synthetic-DB fixtures.

---

# 1. Purpose

> **`pico runtime` tells a developer exactly what runtime evidence exists on
> this machine about their agents, what Pico can safely read, and — per
> security distinction — whether Pico can observe it, cannot, or does not yet.
> It opens no content database, captures no prompts, and claims no execution.**

---

# 2. Scope

## 2.1 Read-only survey contract (what S039 may inspect)

For each supported agent (OpenCode, Claude Code), resolve the known runtime
artifact surfaces and report **filesystem metadata only**:

- allowed inspection: path resolution, existence, file kind (file/dir),
  byte size, extension, readability, `-wal`/`-shm` sidecar presence.
- **forbidden**: opening or querying any content database; reading prompt,
  message, transcript, or log contents; reading credential stores
  (`auth.json`, `account.json`, `mcp-auth.json`, `credential` tables);
  creating/modifying any file (including SQLite `-wal`/`-shm` sidecars);
  installing hooks; background processes.
- Detection is `DECLARED` evidence about *observability capability*, never
  evidence of agent activity, execution, or approval.

## 2.2 Frozen per-distinction report

```text
(a) configured capability      → OBSERVABLE (existing v0.1–v0.4 discovery)
(b) attempted use              → AVAILABLE_UNREAD (surface present, reading deferred to S040)
(c) approved vs denied use     → NOT_AVAILABLE  (no reliable local record; live-only upstream)
(d) completed consequential action → AVAILABLE_UNREAD (surface present, reading deferred to S040)
```

Levels are a closed enum `ObservabilityLevel { Observable, AvailableUnread,
NotAvailable, Unknown }` — `UNKNOWN` is preserved when a surface cannot be
resolved (missing home, unreadable, ambiguous format). No level is inferred
from another.

## 2.3 Frozen interface (implementers: do not change these signatures)

```rust
// src/application/runtime.rs (new; std only — no new dependencies, no sqlite open)
pub enum ObservabilityLevel { Observable, AvailableUnread, NotAvailable, Unknown }
pub enum Distinction { ConfiguredCapability, AttemptedUse, ApprovedUse, CompletedAction }
pub struct SurfaceReport { pub agent: String, pub label: String, pub path: String, // relative-or-~ form only
                           pub present: bool, pub bytes: Option<u64>, pub level: ObservabilityLevel }
pub struct RuntimeReport { pub surfaces: Vec<SurfaceReport>, pub distinctions: Vec<(Distinction, ObservabilityLevel)>, pub notes: Vec<&'static str> }
pub fn survey(workspace: &Path, home: Option<&Path>) -> Result<RuntimeReport, PicoError>; // read-only

// CLI (src/cli/mod.rs): Runtime { #[arg(long)] json: bool } + run_runtime() arm
```

- Human output: one line per surface (present/absent + size + level) and one
  line per distinction, ending with the honesty line
  `This reports what is observable, not what the agent did.`
- `--json` reuses the S033 public-output conventions (schema v1, new `command`
  value `"runtime"`); additive, no field removal.
- Deterministic ordering: agents, then surfaces by label; no timestamps in
  output (survey is a point-in-time *capability* read, not an event log).

## 2.4 Support note (required deliverable)

`docs/internal/sprints/SPRINT-039-support-note.md` records, in the S013-matrix
style: per-agent artifact paths, formats, what each would support, the
observed local state (present/empty/absent), the doc URLs consulted, the
(c)/(d) unreliability finding, and explicit limits. This is a working record,
not canon — canon stays untouched.

---

# 3. Non-goals

- No reading of session/message/transcript/event contents; no prompt, command
  body, or tool-argument capture.
- No SQLite open in this slice (no schema enumeration yet) — sidecar-safe.
- No hooks, no OTel, no plugin installation, no live interception.
- No daemon/background observer (Invariant 10; ARCHITECTURE §28.2).
- No approval/denial claims; no "executed"/"compromised" claims for any path.
- No new trigger variant (`RUNTIME_EVENT`), no graph/finding change, no
  confidence upgrade; no new dependencies; SQLite schema stays v6.

---

# 4. Acceptance

- [ ] `pico runtime` reports each supported agent's surfaces with metadata
      only; absent/missing-home cases report explicit `NOT_AVAILABLE`/`UNKNOWN`,
      never blank reassurance.
- [ ] (c) approved/denied is reported `NOT_AVAILABLE`; (b)/(d) `AVAILABLE_UNREAD`;
      (a) `Observable`. No level inferred from another; test each in isolation.
- [ ] No content database is opened: test asserts zero write/sidecar creation
      and digest-equality of agent state dirs before/after (including that no
      `-wal`/`-shm` appears).
- [ ] Secret sweep: synthetic sentinels placed in plausible prompt/credential
      files are absent from stdout, JSON, and any log.
- [ ] `--json` validated against the public schema (schema v1, `command:"runtime"`);
      deterministic across repeated runs (byte-equal).
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
      `cargo test --all-targets`, `git diff --check` green; ignored tests listed.
- [ ] Manual verification in a disposable workspace + synthetic fake agent home
      (never the real store): present, absent, empty, and unreadable surfaces.

# 5. Test plan (TDD)

- Unit: level matrix per distinction (no inference), surface ordering,
  absent/unreadable → `Unknown` vs `NotAvailable` boundaries, `--json` shape
  golden, honesty line present.
- Integration (binary-driven, temp dirs, synthetic fake agent home only):
  `runtime` human + JSON; read-only digest + no-sidecar assertion; sentinel
  sweep; deterministic repeat.
- Existing suites untouched and green.

---

# 6. Completion notes (2026-09-16, HEAD `a0c3928` + working tree)

## Implemented

Two parallel subagents, file ownership respected, frozen §2.3 signatures
implemented exactly (no seam reconciliation needed):
- Core (`src/application/runtime.rs`, new; `mod.rs` export): std-only
  metadata-only `survey()`; conservative surface whitelist (OpenCode
  `opencode.db` + `-wal`/`-shm`, `storage/`, `snapshot/`, `tool-output/`;
  Claude `projects/`, `sessions/`); policy exclusions named in notes
  (`prompt-history.jsonl`, `log/`, `auth.json`, `account.json`,
  `mcp-auth.json`, `.claude.json`); disjoint per-distinction level sets
  (no cross-inference); `ApprovedUse` → `NotAvailable` always; `home=None`
  → `Unknown`; readability from permission bits (no file open).
- Interface: `output::runtime` projection (schema v1, `command:"runtime"`,
  deterministic order, no timestamps); thin `Runtime { json }` CLI arm +
  human render ending in the exact honesty line; minimal additive public
  schema/docs update; 6 binary-driven integration tests over synthetic
  fake homes.
- Support note: `SPRINT-039-support-note.md` (spec §2.4) recording surfaces,
  formats, observed local state, non-dependable signals, and carried limits.

## Deviations

None to the frozen spec. Two additive helper consts (`HONESTY_LINE`,
`as_str()` on both enums) were added by the core agent; the interface agent
made the minimal additive public-schema change (new `"runtime"` command
value in both the success `oneOf` and the error `command` enum) per S033
rules. No field removed; `tests/sprint033_output.rs` unaffected (10/10).

## Validation

- New: 7 core unit (distinction isolation, `home=None` honesty,
  present/absent/unreadable, ordering + repeat equality, metadata-only
  digest, no-sidecar, forbidden-surface exclusion) + 6 integration (human
  contract, JSON schema + byte-determinism, missing-HOME levels, read-only
  digest, sentinel sweep, help) — all PASS.
- Full suite: 615 passed, 1 ignored, 0 failed; fmt, clippy `-D warnings`,
  `git diff --check` clean. No `Cargo.toml`/`Cargo.lock` change (no new
  deps); SQLite schema stays v6; no DB opened.
- Manual `/tmp/pico-039-20260916` (isolated HOME, synthetic fake agent home;
  never the real store): 8 surfaces reported with correct levels;
  `approved vs denied use = NOT_AVAILABLE`; `--json` valid + byte-equal
  across runs; directory listing byte-identical before/after (no sidecar
  created); 0 sentinel hits across stdout and JSON. All PASS.

## Learnings

The honest answer to ROADMAP §9's learning question ("can Pico observe
approval and execution semantics without capturing sensitive content?") is
currently **no for approval/denial** and **not-yet for execution**: the
decision records do not exist locally. Reporting `NOT_AVAILABLE` openly is
more valuable than a fabricated observation, and it defines S040's real
first task — a versioned, whitelisted, content-free reading contract for
session/tool metadata.

## Canon Changes

None (`docs/internal/ROADMAP.md` §9 and `TECHNICAL.md` §3.3 already require
this restraint; no sequencing change). Public output contract gained an
additive `runtime` command per S033 rules.
