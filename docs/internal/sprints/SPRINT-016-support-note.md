# SPRINT-016 — OpenCode Effective Bash Capability Support Note

**Agent:** opencode
**Scope:** Surface the resolved OpenCode effective Bash execution capability
(`effective_state`) and the interrupting boundary it implies, in the CLI
explained-finding view and the MCP `get_finding` tool. Add a credential
secret-sweep assertion across every resolved effective state.

This note documents the support boundary only. It does not change resolution
logic, enforcement, or providers.

## What "effective Bash capability" means

OpenCode's Bash permission is normalized into a single effective posture,
`EffectiveBashPermission`, defined in `src/discovery/mod.rs`:

- `AUTO_ALLOW` — Bash runs automatically (resolved `permission.bash` allow).
- `APPROVAL_GATED` — Bash may run only after an explicit human approval gate
  (resolved `permission.bash` ask).
- `DENIED` — Bash execution is denied outright (resolved `permission.bash` deny).
- `SANDBOXED` — Bash runs inside an isolating sandbox.
- `UNKNOWN` — the resolved policy was mixed/bounded; no concrete posture is
  invented.

## Config keys that drive resolution

Resolution is performed by `resolve_effective_bash` in
`src/discovery/agents/opencode.rs`:

- Top-level **`sandbox: true`** — enables the documented OpenCode project
  sandbox toggle; forces `SANDBOXED`.
- **`permission.bash.action`** — `allow | ask | deny` selects the effective
  posture (`allow` → `AUTO_ALLOW`, `ask` → `APPROVAL_GATED`,
  `deny` → `DENIED`).
- **`permission.bash.sandbox`** — per-Bash sandbox grant
  (`{ "action": "allow", "sandbox": true }`) also forces `SANDBOXED`.

## Precedence

Among the explicitly configured catch-all rule set the precedence is
**deny > ask > allow**:

- An explicit `deny` wins over an explicit `ask` or `allow`.
- An explicit `allow` overrides an explicit `ask`.
- The built-in `* = allow` fallback is excluded so an explicit `ask`/`deny` is
  honored rather than masked.
- Sandbox (`sandbox: true` or `permission.bash.sandbox: true`) dominates the
  action: any allow/ask under a sandbox becomes `SANDBOXED`.

A pattern-scoped (non-catch-all) rule after the last catch-all makes the policy
bounded and is reported as `UNKNOWN`.

## How it surfaces

The `can_execute` relationship (`agent:opencode -> shell:bash`) carries the
normalized `effective_state` and (for `SANDBOXED`) `boundary_kind` metadata,
produced in `src/application/scan.rs`. The explained-finding view
(`src/cli/render.rs`) renders:

```
Effective Bash capability: <AUTO_ALLOW | APPROVAL_GATED | DENIED | SANDBOXED | UNKNOWN>
Bash interrupting boundary: <MANDATORY_APPROVAL | HARD_DENY | SANDBOX | none>
```

The MCP `get_finding` tool (`src/mcp/tools.rs`) mirrors the same on each path
as `effective_bash_capability` and `bash_boundary`.

The boundary mapping (from `src/analysis/boundary.rs`) is:

- `AUTO_ALLOW` / `UNKNOWN` → no interrupting boundary.
- `APPROVAL_GATED` → `MandatoryApproval` (MANDATORY_APPROVAL).
- `DENIED` → `HardDeny` (HARD_DENY).
- `SANDBOXED` → `Sandbox` (SANDBOX).

## Auto-approval is NOT observable from static config

OpenCode's runtime auto-approval mode (`runtime_mode`) cannot be determined from
the static configuration alone. It is therefore reported as `UNKNOWN` by
design; this sprint does not claim to observe runtime behavior. Only the
configured permission posture and sandbox toggle are resolved.

## Scope of this sprint

In scope:

- Rendering the resolved effective Bash capability label in CLI and MCP.
- Rendering the interrupting boundary kind on the `can_execute` edge.
- A secret-sweep assertion that no raw credential material (e.g. a
  `cfut_…`/`cfr_…` token shape or the literal `.env` token value) appears in
  rendered output or persisted metadata for any resolved effective state.

Out of scope:

- **No enforcement.** Pico does not change, gate, or block Bash; it only
  reports the resolved posture.
- **No new providers.** Only the opencode agent adapter is read.
- **No runtime observation.** Auto-approval and live execution are not observed.

## Known limitations

- `APPROVAL_GATED` and `DENIED` resolve the Bash posture but also block or
  uncertaintys the production path, so the deterministic finding generator
  (which only emits `ACTIVE` candidates) produces no finding for those
  postures. Their resolution is therefore asserted at the normalized
  relationship/metadata layer and via the renderer for the label itself, not via
  an active explained finding.
- `UNKNOWN` (mixed/bounded policy) yields no concrete boundary label.
- Only the first observed Bash capability is consumed (`bash_capabilities[0]`).
- The capability is derived entirely from static config; runtime override of the
  configured posture is not detected.
