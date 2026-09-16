# Sprint 039 support note — runtime observability survey

**Status:** Working record (not canon). Records what S039's survey can and
cannot establish, mirroring the S013 support-matrix style.
**Sprint:** 039 (v0.5 slice 3)
**Method:** read-only filesystem/structure inspection of the local machine plus
upstream documentation review by research subagents. No file contents, prompts,
credentials, or transcripts were read; no live interception was performed.
**Environment inspected:** founder machine, 2026-09-16. Installed: OpenCode
`1.18.31`; Claude Code `2.1.260`.

---

## 1. Why this note exists

S039 was originally conceived as "observe execution/approval events." Research
showed that **approval/denial semantics are not reliably observable locally**,
and that live interception would require a daemon or hook installation — both
expressly outside Pico's V0 boundary (`ARCHITECTURE.md` §28.2; `SKILL.md`
Invariant 10). S039 therefore ships an observability *survey* that claims only
what is safely knowable, and refuses the rest. This note is the evidence behind
that decision and the input to a later ingestion slice (S040).

---

## 2. Artifact surfaces found

### 2.1 OpenCode

| Path (relative to home) | Format | Would support | Observed local state |
| --- | --- | --- | --- |
| `.local/share/opencode/opencode.db` | SQLite (+ `-wal`/`-shm`) | session/activity metadata | present, large |
| `.local/share/opencode/storage/` | JSON tree (legacy) | migrated session/message parts | present |
| `.local/share/opencode/snapshot/` | git object dirs | workspace snapshots | present |
| `.local/share/opencode/tool-output/` | files | tool output capture | absent |
| `.local/state/opencode/prompt-history.jsonl` | JSONL | **prompt content** — excluded by policy | present |
| `.local/share/opencode/{auth,account,mcp-auth}.json` | JSON | **credential material** — excluded by policy | present |

Reported DB tables: `session, message, part, event, event_sequence,
session_input, session_context_epoch, permission, todo, credential, account,
workspace, project`. The `event` table holds many rows with types such as
`message.part.updated`, `message.updated`, `session.*`, `message.removed`.
**The `permission` table existed with zero rows.**

### 2.2 Claude Code

| Path (relative to home) | Format | Would support | Observed local state |
| --- | --- | --- | --- |
| `.claude/projects/<project>/<session>.jsonl` | JSONL (internal) | tool_use / tool_result records | directory present, empty here |
| `.claude/sessions/` | dir | session metadata | present, empty here |
| `.claude.json` | JSON | account/mcp config — excluded by policy | present |
| `.claude/settings.json` | JSON | configured permissions (already covered by v0.1–v0.4) | present |

The Claude CLI was installed but not actively used on this machine, so no
transcript evidence was available. Upstream documents the transcript format as
internal and subject to change between versions.

---

## 3. Per-distinction observability (S039 result)

| Distinction | Level | Basis |
| --- | --- | --- |
| (a) configured capability | `OBSERVABLE` | existing v0.1–v0.4 config discovery |
| (b) attempted use | `AVAILABLE_UNREAD` | local session/part surfaces exist; reading deferred to S040 |
| (c) approved vs denied use | `NOT_AVAILABLE` | no reliable local record (see §4) |
| (d) completed consequential action | `AVAILABLE_UNREAD` | local surfaces exist (part state, snapshots, transcripts); reading deferred to S040 |

No level is inferred from another. `UNKNOWN` is preserved when a surface is
missing, unreadable, or the home seam is unavailable.

---

## 4. Signals that are NOT locally dependable

| Signal | Upstream source | Locally observable? |
| --- | --- | --- |
| `PreToolUse` / `PostToolUse` / `PostToolUseFailure` | Claude Code hooks | live only |
| `PermissionRequest` / `PermissionDenied` | Claude Code hooks | live only |
| `tool_decision` (allow/deny/ask), `tool_result` | Claude Code OTel export | export only |
| `permission.asked` / `permission.replied` | OpenCode plugin events | live only |
| stream-json output | `--print --output-format stream-json` | live capture only |

Upstream documentation consulted (as reported by the survey): Claude Code docs
on `sessions`, `hooks`, `monitoring-usage`, and `headless`; OpenCode docs on
`plugins`.

**Consequence:** Pico must not claim an observed approval or denial from local
state in this phase. Doing so would fabricate evidence. The honest state is
`NOT_AVAILABLE` (i.e. "Pico cannot establish this locally yet"), not a guess.

---

## 5. Safety limits carried into any future ingestion slice

- The OpenCode SQLite store **co-locates credential and account material**
  (`credential.value`, `account.access_token`/`refresh_token`) with session
  data. Any reader must whitelist columns and never touch those tables.
- Prompts and message content are co-located with structural metadata
  (`prompt-history.jsonl`, `event.data`, `part.data`, `log/*.log`). Any
  ingestion must read structural fields only and never content.
- The store was ~13 GB with active WAL sidecars: reads must be bounded,
  read-only, and must not create or modify `-wal`/`-shm` sidecars.
- Approval semantics are version-dependent and were absent even where the
  schema existed — a green schema is not evidence of available decisions.
- Claude transcripts are a documented internal, version-varying format.

## 6. Explicit limits of this survey

- It inspects **one machine** (the founder's). Presence/absence elsewhere may
  differ; the survey reports the local machine honestly, without generalizing.
- It reports **filesystem metadata only**; it does not read any database,
  transcript, or log, so it makes no claim about the *contents* of any surface.
- `AVAILABLE_UNREAD` means "a plausible surface exists," not "evidence is
  retrievable" — S040 must establish the reading contract before any claim.
- It does not establish whether any dangerous path was exercised. That remains
  `UNKNOWN` by design.
