# Sprint 040 support note — OpenCode store schema & safe-read research

**Status:** Working record (not canon). Input to `SPRINT-040.md`.
**Method:** upstream source review (`anomalyco/opencode`, formerly
`sst/opencode`, tag `v1.18.31`), plus a **bounded raw header read** of the local
store. **The local database was never opened** during research; no row data,
prompt, or credential was read.
**Date:** 2026-09-16. Installed OpenCode `1.18.31`.

---

## 1. Upstream schema (v1.18.31)

Authoritative consolidated DDL: `packages/core/src/database/schema.gen.ts`
(sources below). Classification: **(a)** structural/safe, **(b)** content,
**(c)** secret.

| Table | Safe columns (a) | Content (b) / secret (c) |
| --- | --- | --- |
| `session` | id, project_id, workspace_id, parent_id, slug, version, agent, model, directory, path, time_* | `title` (b), `summary_diffs` (b), `revert` (b), `permission` (?), `metadata` (?) |
| `message` | id, session_id, time_* | `data` (b) — role, prompts, system |
| `part` | id, message_id, session_id, time_* | `data` (b) — tool name/status + arguments/output |
| `event` | id, aggregate_id, `seq`, `type` | `data` (b) |
| `event_sequence` | aggregate_id, seq, owner_id | — |
| `session_input` | id, session_id, delivery, admitted_seq, promoted_seq, time_created | `prompt` (b, **plaintext**) |
| `session_context_epoch` | session_id, baseline_seq | `baseline`, `snapshot` (b) |
| `permission` | id, project_id, `action`, `resource`, time_* | — |
| `todo` | session_id, status, priority, position, time_* | `content` (b) |
| `project` | id, `worktree`, vcs, name, sandboxes, time_* | `commands` (?) |
| `workspace` | id, type, name, branch, `directory`, project_id, time_used | `extra` (?) |
| `migration` | id, time_completed | — (schema metadata) |
| `credential` | — | **all (c)** |
| `account` / `control_account` | id, email(?) | **access/refresh token (c)** |
| `session_share` | — | **secret, url (c)** |

## 2. Content-free tool signal (confidence: HIGH)

Inside `part.data` (JSON):

```text
$.type            = 'tool'                          (part kind enum: text, subtask,
                                                     reasoning, file, tool, step-start,
                                                     step-finish, snapshot, patch, agent,
                                                     retry, compaction)
$.tool            = tool name  (e.g. "bash")        ← the signal Pico needs
$.callID          = call identifier
$.state.status    = pending | running | completed | error
```

`message.data->>'$.role'` yields `user` | `assistant`.

**Explicitly NOT needed and never selected:** `$.state.input`, `$.state.output`,
`$.state.text`, `$.state.metadata`, or the raw `data` column. Extraction uses
`json_extract()` on the four whitelisted paths only.

## 3. Event types

Durable event store added by migration `20260323234822_events`; `event.type` is
a dot-namespaced string. Observed families: `session.created/updated/deleted`,
`message.updated/removed`, `message.part.updated/removed/delta`,
`session.diff/error`, and `session.next.*` (tool.input/called/progress/success/
failed, step.*, text.*, reasoning.*, compaction.*, …). **Full enumeration is
UNKNOWN** (`packages/schema/src/event-manifest.ts` spans many modules) — so the
reading contract must **not** depend on a closed event-type list.

## 4. Schema version detection

- **No `PRAGMA user_version`** is used by the OpenCode layer (locally it reads
  `0`, confirmed by header bytes at offset 60).
- Version is tracked by the **`migration` table** (`id TEXT PK`,
  `time_completed INTEGER`); legacy installs used `__drizzle_migrations`
  (`created_at`, maybe `name`). `data_migration` tracks data-only migrations.
- Migration counts by upstream version: v1.16.0 = 30, v1.17.0 = 32,
  v1.18.0 = 38, v1.18.31 = 38.
- Structural move: v1.14.x kept DDL under `packages/opencode/src/session/`
  with Drizzle journals; later moved to `packages/core/src/database/`.
- Post-v1.14 additions to tolerate: `event`, `event_sequence`,
  `session_input`, `session_context_epoch`, `credential`.

**Contract consequence:** detect version by reading `migration` (fallback
`__drizzle_migrations`), require `max(id)` within a supported range, and
tolerate **missing tables/columns** rather than assuming them.

## 5. Local store facts (bounded header read only)

| Field | Value |
| --- | --- |
| magic | `SQLite format 3\0` |
| page size | 4096 |
| read/write version | 2 / 2 (WAL mode) |
| database pages | 3,179,500 (≈13 GB) |
| schema cookie | 108 |
| `user_version` | 0 |
| SQLite version | 3.51.0 |
| `-wal` / `-shm` | 3,670,952 B (≈896 pages) / 32,768 B |

## 6. Safe-read strategy (recommended)

**Open mode (zero filesystem writes):**

```text
open_with_flags("file:<abs>?mode=ro&immutable=1",
                SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_URI |
                SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_NOFOLLOW)
```

- `immutable=1` skips locking and change detection → **never** creates `-shm`
  and performs **no** writes. Tradeoff: **it ignores the WAL**, so results are a
  possibly-stale snapshot and recent commits may be missed.
- `mode=ro` alone avoids DB/WAL writes but may create/mmap `-shm` marks, so it
  is *not* provably zero-write on macOS.
- `nolock=1` is unsafe with a concurrent writer (corruption risk).
- Because OpenCode auto-checkpoints near ~1000 WAL pages, a concurrent
  checkpoint can rewrite the main file under us → treat `SQLITE_CORRUPT` as
  **retryable**, and prefer reading when OpenCode is idle.
- rusqlite 0.32 (bundled libsqlite3-sys 0.30.1) supports URI filenames, but
  supplying `SQLITE_OPEN_READ_ONLY` **drops** the default URI bit — `SQLITE_OPEN_URI`
  must be OR'd in explicitly.
- Add `PRAGMA query_only=ON` as defense-in-depth.

**Bounded reads:** schema via `sqlite_master` + `PRAGMA table_info`; column
allowlist; never a bare `COUNT(*)` on huge tables (use keyset pagination on
`id`/`rowid`); require an indexed time column for time-window filters; enforce a
wall-clock budget via `progress_handler`; caps ≈10k rows/table, ≈50k total, and
a short `busy_timeout`.

Sources: `sqlite.org/uri.html`, `sqlite.org/wal.html` (§5, §8, §9),
`sqlite.org/c3rs open`; `docs.rs/rusqlite`.

## 7. Unverified / UNKNOWN

- The local schema was **not** read (no DB open), so local table/index presence
  and timestamp indexing are unverified; the spec must fail closed on mismatch.
- OpenCode's journal/synchronous/locking settings were not observed.
- Whether `permission` rows are ever populated locally is unverified (S039 found
  zero rows; the table exists).
- The full `event.type` enumeration is unknown.
- Claude Code transcripts remain a documented internal, version-varying format
  and are **out of scope** for S040.
