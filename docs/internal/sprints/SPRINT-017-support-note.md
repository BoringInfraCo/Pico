# SPRINT-017 — GitHub MCP Per-Tool Influence Support Note

**Agent:** opencode (GitHub MCP server surface)
**Scope:** Surface per-tool GitHub MCP influence on each explained attack path,
in both the CLI explained-finding view (`src/cli/render.rs`) and the MCP
`get_finding` tool (`src/mcp/tools.rs`). Add a credential secret-sweep assertion
across every GitHub MCP influence posture.

This note documents the support boundary only. It does not change resolution
logic, enforcement, or providers.

## What Pico can establish about GitHub MCP influence

Pico reads the static OpenCode configuration only. From it, for an **official**
GitHub MCP server identity (`ghcr.io/github/github-mcp-server` or the matching
remote endpoint), it establishes the following per declared tool:

- **The tool name** — the declared MCP tool (e.g. `issue_read`, `create_issue`).
- **A `content_class`** — the deterministic classification of the content the
  tool reaches (e.g. `github:public:issue-content`, `github:write:issue`,
  `github:repository-content`).
- **A `trust`** — the confidence Pico assigns to the source content. Issue/PR
  read surfaces are `PUBLIC_EXTERNAL`; repository/code and write surfaces are
  `UNKNOWN` because **repo visibility is not observable from static config**, so
  Pico will not fabricate `PRIVATE_EXTERNAL`.
- **An `influence_strength`** — `AGENT_INJECTABLE` for user-generated
  issue/PR content, `AGENT_RETRIEVABLE` for repository/code content, and
  `AGENT_MUTABLE` for documented write tools.

These facts are surfaced in the explained finding as a `GitHub MCP influence`
block per path and, in the MCP JSON, as a `github_influence` array on each
explained path entry (`tool_name`, `content_class`, `trust`,
`influence_strength`).

## What Pico cannot establish

- **Repo visibility / private content trust.** Static config cannot reveal
  whether a repository is public or private, so repository-content trust is
  reported as `UNKNOWN`, never as a fabricated `PRIVATE_EXTERNAL`.
- **Official-server-only admission.** Only the official GitHub MCP server
  identity is classified. Spoofed or non-official server identities are ignored
  by `classify` in `src/discovery/mcp.rs` and never produce GitHub influence
  entries.
- **No runtime GitHub contact.** Pico never connects to `api.github.com`, never
  executes the MCP server command, and never fetches live repository content.
  All influence entries are derived from the static config and the documented
  tool contract.
- **Write tools are a mutation boundary, not a guarantee of mutation.** A
  `can_mutate` relationship is emitted for `AGENT_MUTABLE` tools and the boundary
  layer surfaces a `Mutation` boundary (see `src/application/scan.rs` and
  `github_mcp_scan_test.rs`), but Pico does not verify that a write actually
  occurs.

## How it surfaces

For each explained path, edges whose canonical key contains `mcp:github` are
collected; the GitHub MCP tool resource among each edge's endpoints supplies the
classification facts. Each tool appears once (de-duplicated by tool name) on
`ExplainedPath.github_influence` (`src/application/findings.rs`).

The CLI (`src/cli/render.rs`) renders, inside the per-path block:

```
GitHub MCP influence:
  GitHub MCP issue_read: github:public:issue-content | trust=PUBLIC_EXTERNAL | influence=AGENT_INJECTABLE
  GitHub MCP create_issue: github:write:issue | trust=UNKNOWN | influence=AGENT_MUTABLE
```

The MCP `get_finding` tool (`src/mcp/tools.rs`) mirrors the same on each path as
`github_influence`, an array of `{ tool_name, content_class, trust,
influence_strength }`.

## Scope of this sprint

In scope:

- Per-tool GitHub MCP influence surfacing in CLI and MCP.
- A secret-sweep assertion that no synthetic credential value (e.g.
  `ghp_TESTFAKE0000000000000000000000000000`) appears in the rendered CLI
  influence block, the MCP JSON, or any persisted metadata across the
  RETRIEVABLE / INJECTABLE / MUTABLE influence postures and the UNKNOWN trust
  posture.

Out of scope:

- **No enforcement.** Pico does not change, gate, or block the GitHub MCP
  server or its tools; it only reports the established influence.
- **No new providers.** Only the opencode agent adapter and the bounded GitHub
  MCP classification are read.
- **No runtime observation.** No live GitHub contact is made and no execution is
  performed.
