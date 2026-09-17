# Sprint 043 support note — Claude Code observability probe

**Status:** Working record (not canon). Records the evidence behind S043's
**deferral decision**: Pico observes Claude Code runtime *surfaces* but does not
parse them.
**Method:** read-only local filesystem inspection (structure only), inspection of
the installed binary's string constants (field names only — no content), and
upstream documentation review. **No transcript, prompt, todo, or credential
content was read.**
**Date:** 2026-09-16. Installed Claude Code `2.1.260`.

---

## 1. Decision

> **Claude Code runtime ingestion is deliberately NOT implemented in v0.5.**
> `pico runtime` reports presence, `.jsonl` counts, and the detected CLI version,
> and states that parsing is deferred because no reliable, verifiable format
> contract exists yet.

This follows Invariant 7 (`UNKNOWN` is a valid result) and the anti-speculation
rule: a parser validated only against guessed field semantics would encode
uncertainty as certainty. `ARCHITECTURE.md` §28.2 and Invariant 10 also rule out
the alternative (live hooks), which would require installing hooks into the
user's agent.

---

## 2. Local state found (structure only)

| Path | Format | Observed |
| --- | --- | --- |
| `.claude/projects/` | dir | **empty** (no `<project>/<session>.jsonl` transcripts) |
| `.claude/sessions/` | dir | **empty** |
| `.claude/todos/` | 16 × JSON | 2 B (empty `[]`) – 1,309 B |
| `.claude/shell-snapshots/` | 7 × shell | ~176 KB each (Aug 2025) |
| `.claude/hooks/` | shell | one hook script |
| `.claude/plugins/config.json` | JSON | 24 B |
| `.claude/backups/.claude.json.backup.<ts>` | JSON | ~82 KB |
| `.claude.json` | JSON | ~7 KB — keys include `oauthAccount`, `customApiKeyResponses`, `projects`, `machineID`, `migrationVersion` (**credential-adjacent; not read**) |
| `history.jsonl` | — | **not present** |

**Consequence:** there is nothing on this machine to validate a parser against.

---

## 3. Field names recovered from the installed binary (not a published schema)

The install is a single Mach-O executable
(`~/.local/share/claude/versions/2.1.260`, ~198 MB) with no JS bundle, `.d.ts`,
or schema files on disk. The following names were recovered as string constants
and destructuring patterns **inside that one build** — they are evidence of the
binary's vocabulary, **not** a stable contract:

- entry envelope: `parentUuid`, `uuid`, `isSidechain`, `timestamp`, `sessionId`, `cwd`
- metadata list: `gitBranch`, `version`, `userType`, `entrypoint`, `promptId` (+ `requestId`)
- message roles: `user`, `assistant`, `attachment`, `system`
- metadata entry types: `file-history-snapshot`, `file-history-delta`,
  `queue-operation`, `summary`, `progress`, `last-prompt`, `continued-in`,
  `cost-state`, `observer-ref`
- content-block keys: `tool_use`, `tool_result`, `tool_use_id`, `is_error`, `name`, `content`

The meaning of the bundled `version` field is **UNKNOWN** (CLI version vs
something else), and no schema-version integer was found.

---

## 4. Upstream documentation

| Topic | What is documented | Source |
| --- | --- | --- |
| Transcript location | `~/.claude/projects/<project>/<session-id>.jsonl`, where `<project>` is the working directory with non-alphanumerics replaced by `-` | `code.claude.com/docs/en/sessions` |
| Transcript stability | The per-line entry format is **internal and version-varying**; direct parsers can break on any release; `/export` or script interfaces are recommended instead | `code.claude.com/docs/en/sessions#where-transcripts-are-stored` |
| SDK view | `SessionStoreEntry` is typed as `{ type: string; ... }` — opaque, one per JSONL line; `entry.uuid` and a `sessionId` field are named | `code.claude.com/docs/en/agent-sdk/session-storage` |
| Hooks | Common inputs: `session_id`, `prompt_id`, `transcript_path`, `cwd`, `permission_mode`, `effort`, `hook_event_name`. `PreToolUse`: `tool_name`, `tool_input`, `tool_use_id`. `PostToolUse`: + `tool_response`. `PostToolUseFailure`: + `error`, `is_interrupt`. `PermissionRequest` / `PermissionDenied` | `code.claude.com/docs/en/hooks` |
| Hook nature | Hooks are **live-only** and require hook installation — outside Pico's V0 boundary | `code.claude.com/docs/en/hooks` |

---

## 5. What would be derivable, and why it is not enough

| Fact | Verdict | Field |
| --- | --- | --- |
| (a) tool invoked + name | DERIVABLE but **version-fragile** | `message.content[*].type == "tool_use"`, `.name` |
| (b) status / result presence | presence only | matching `tool_result` + `tool_use_id`; `is_error` |
| (c) timestamps | DERIVABLE | top-level `timestamp` |
| (d) session id | DERIVABLE | top-level `sessionId` |
| (e) working directory (workspace scoping) | DERIVABLE | top-level `cwd`; `<project>` path encoding |

None of these are documented at entry level. They rest on binary strings from one
build, and the upstream docs explicitly warn that the format may change on any
release.

---

## 6. Version tolerance: no reliable marker

- No schema-version integer and no version marker in the directory layout.
- A per-entry `version` field exists in the binary's metadata vocabulary, but its
  semantics are unverified.
- Therefore a reader cannot reliably detect an unsupported format and fail
  closed. Without that gate, deployment across versions would silently produce
  wrong readings — the exact failure mode Pico's evidence honesty forbids.

---

## 7. Conditions that would unblock parsing

S043 should be revisited when **either** is true:

1. Real transcripts exist locally at a **known CLI version**, allowing the
   documented shape to be verified against real data (not binary strings); or
2. Upstream publishes a stable entry schema for transcripts (or a supported
   programmatic interface that returns structured session data); or
3. Pico adopts an **explicitly supported** integration (e.g. the documented
   session-store / script interface) rather than parsing private files.

Until then, the honest product behaviour is what S043 ships: report the surface,
report the count, report the version, and say that parsing is deferred.

---

## 8. Limits of this probe

- It reports **this machine's** state; the count/version are local facts, not
  general claims about Claude Code.
- It reads **no** transcript content, so it makes no claim about what any Claude
  session did.
- `AVAILABLE_UNREAD` for Claude means "a plausible surface exists", **not**
  "evidence is retrievable by Pico today".
- It does not establish whether any dangerous path was exercised by Claude Code;
  that remains `UNKNOWN` by design.
