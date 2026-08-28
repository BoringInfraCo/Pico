# Sprint 020 — Claude Code Adapter Support Note

This note defines, for operators and downstream consumers, exactly what Pico's
Claude Code adapter (SPRINT-020) observes, the evidence precision it is held to,
how it fails, which states it leaves unresolved, and how it behaves in a mixed
OpenCode + Claude Code workspace. It is the authoritative scope statement for
the second agent surface shipped in Sprint 020 (R1–R10).

## What the Claude Code adapter supports

The adapter observes the Claude Code actor from **documented static
configuration only**:

- project `.claude/settings.json` and `.claude/settings.local.json` (scoped to
  the workspace or its nearest `.git` ancestor),
- user `~/.claude/settings.json`,
- project `.mcp.json` for Claude-declared MCP servers.

It never reads environment variables, dotenv files, or runtime state. The
Cloudflare environment/.env credential reader remains the OpenCode adapter's
responsibility. Absence of a documented location is not a problem.

Supported observations:

- **Actor.** Each parsed settings file emits an `ObservedActor` with
  `provider: "claude"`, `source_type: "claude_settings"`, and a sanitized
  `source_locator` naming the config *path* (`project:.claude/settings.json`,
  `user:.claude/settings.json`, ...). A project `.mcp.json` alone is also a
  documented Claude presence.
- **Bash effective state.** Resolved from `permissions.allow` / `permissions.ask`
  / `permissions.deny` arrays (a rule is a Bash rule when it is exactly `"Bash"`
  or starts with `"Bash("`), `permissions.disableBash`, and a sandbox indicator
  (top-level `sandbox`, `permissions.sandbox`, or `bash.sandbox`). Precedence is
  deny > ask > allow; the last-listed Bash rule in an array governs. The resolved
  posture maps to the existing `EffectiveBashPermission` model:
  - `allow` with a catch-all Bash rule → `AUTO_ALLOW` (no boundary),
  - `ask` (or the documented product default when no Bash rule exists) →
    `APPROVAL_GATED` (interrupting boundary `MANDATORY_APPROVAL`),
  - `deny` / `disableBash` → `DENIED` (interrupting boundary `HARD_DENY`),
  - any sandbox indicator → `SANDBOXED` (interrupting boundary `SANDBOX`),
  - a pattern-scoped Bash rule that cannot be flattened → `UNKNOWN`/`BOUNDED`.
- **MCP servers.** Claude's `mcpServers` (from settings and the project
  `.mcp.json`, with the project file winning per server name) normalize into
  `ObservedMcpServer`: transport (stdio/local vs http/remote), official GitHub
  MCP identity, secret-free safe command/endpoint, environment *key names*, and
  tool/toolset declarations. The existing GitHub classifier (Sprint 017) applies
  to an official GitHub MCP server declared by Claude; per-tool permissions are
  left at the classifier's conservative Unknown default because Claude's static
  config does not resolve them individually.

## Evidence precision

Claude Code is a **config-only** adapter. Every fact Pico reports is bounded by
what documented static configuration admits:

- **Established:** the actor exists (a documented settings/MCP file was parsed),
  the effective Bash posture, the declared MCP server surface, and the GitHub
  MCP tool *contract* classification (content class / trust / influence).
- **Not established:** runtime session modes, whether Bash actually ran, which
  commands were issued, environment variables (including `CLOUDFLARE_API_TOKEN`),
  and any credential. `runtime_mode` is therefore always `UNKNOWN` for Claude —
  static configuration cannot observe an auto-approval session, and Pico never
  fabricates one. `permissions.defaultMode` informs but never alone produces
  `AUTO_ALLOW`.
- **Never reported:** raw configuration contents, token values, command
  arguments that look secret. The secret sweep (R10) asserts across the
  allow/ask/deny/sandbox/disable-bash postures that no secret-shaped value
  appears in the rendered CLI output, the MCP JSON, or persisted metadata.

## Failure behavior

- **Malformed config.** A settings/MCP file that is not valid JSON (or not a
  JSON object) is reported as a discovery problem carrying its source path, the
  actor is not emitted, and the scan becomes `PARTIAL` with `partial_reason`
  naming `claude`. Pico suppresses positive Findings under a partial scan rather
  than implying safety.
- **Partial parse.** Files that parse contribute their facts; files that fail are
  reported individually. One bad file does not discard the others.
- **Absence.** No documented Claude location is not a problem; the adapter emits
  no actor, no capability, and no problem.
- **Discovery problems never contain secret values.** Problem strings originate
  from redacting provider code.

## Unresolved states

- A Bash rule that is pattern-scoped and cannot be flattened (e.g.
  `Bash(git rm *)`) resolves to `(Unknown, Bounded)` — never an invented
  certainty.
- `permissions.defaultMode` alone never fabricates `AUTO_ALLOW`; the product
  default posture (approval-gated) is reported.
- Claude MCP tool permissions stay `Unknown` unless the GitHub contract
  classifier establishes them; there is no global MCP classification.
- Claude Code contributes no credential or Cloudflare facts, so its edges never
  feed the authority/sink projection.

## Mixed-environment behavior

When both OpenCode and Claude Code configuration are present, both actors and
both `agent:<provider>|can_execute|shell:bash` edges coexist without key
collision, duplicated findings, cross-agent evidence leakage, or graph
ambiguity. OpenCode remains the golden-path primary: credentials and the
Cloudflare provider projection come exclusively from the OpenCode adapter, and
the OpenCode-only golden path yields exactly one Finding with a single
`agent:opencode` actor. The explained finding (CLI and MCP `get_finding`) now
surfaces the effective Bash state **per agent**:

- mixed workspace: one `Agent <provider> effective Bash: <state>; boundary:
  <kind>` line per agent on the CLI, and an `agents` array
  (`[{provider, effective_bash_capability, bash_boundary}]`) in the MCP JSON.
  Sprint 023 also lists every agent's effective Bash on the `pico scan`
  summary (`<provider>: <effective_state>`) so a zero-Finding mixed scan
  still shows non-primary postures (F-U1).
- single-agent (golden) workspace: the legacy `Effective Bash capability:` /
  `Bash interrupting boundary:` fields and single `agent` entry, byte-identical
  to Sprint 016. The scan summary keeps `Effective Bash: ALLOW`.