# Pico — Sprint 017: GitHub MCP Influence Classification Depth

**Status:** DONE

**Sprint:** 017
**Phase:** v0.2 — Evidence and Authority Depth
**Type:** Implementation
**Baseline:** `b81846e` (post-Sprint-016 main HEAD)
**Depends on:** Sprint 012 (live dogfood contract), Sprint 013 (authority tiers), Sprint 014 (provenance + freshness), Sprint 015 (finding stability/dedup), Sprint 016 (effective-state resolution — actor-leg sibling)

---

# 1. Purpose

Sprints 013–016 deepened Cloudflare authority tiers, evidence provenance/freshness, finding stability/dedup, and OpenCode effective-state. The remaining v0.2 depth gap on the **actor/influence leg** of the supported boundary is GitHub MCP *influence classification*:

> Within the supported OpenCode + GitHub MCP boundary, Pico must classify each GitHub MCP tool's external-content variant and influence strength honestly — distinguishing public read, private/external read, injection-prone content, and mutation — and reflect that influence as a truthful, deterministic edge and surfaced fact in the finding.

This sprint closes ROADMAP §6 v0.2 commitment Sprint 013–016 did not:

- "Deepen GitHub influence classification across the minimum evidence-backed external content variants that materially change risk."

It does **not** add a second provider (v0.3), contact GitHub at runtime, perform enforcement (v0.7), observe runtime events (v0.5), or change `sink_impact` (still `UNKNOWN` by design, SPRINT-013 §8).

---

# 2. Scope

- **External-content variant taxonomy**: classify the minimum evidence-backed GitHub MCP tool variants that materially change risk:
  - public issue content (`github:public:issue-content`),
  - public pull-request content (`github:public:pull-request-content`),
  - repository file content (`github:repository-content` — visibility unknown from static config),
  - write tools (`github:write:issue`, `github:write:pull-request`, etc.),
  - code/search content (`github:code-search-content`),
  - discussion/comment content (`github:discussion-content`) where the adapter observes it.
  - Non-recognized tools degrade to an explicit `UNKNOWN` content class, never to a false certainty.
- **Trust tiers**: `PUBLIC_EXTERNAL` (public issue/PR content by design), `PRIVATE_EXTERNAL` (only when evidence supports it — otherwise `UNKNOWN` because repo visibility is not observable from static config), `UNKNOWN` (default for repository/visibility-dependent content).
- **Influence-strength tiers**: distinguish `AGENT_RETRIEVABLE` (read), `AGENT_INJECTABLE` (user-generated content an agent may act on — issues/PRs/comments/discussions), and `AGENT_MUTABLE` (write tools). This replaces the current single always-`AGENT_RETRIEVABLE` value.
- **Mutation mapping**: write tools produce a `can_mutate` relationship (mutation surface) in addition to the `can_call` influence edge; read tools remain influence-only.
- **Boundary contribution**: an `AGENT_MUTABLE` tool contributes a mutation boundary; injection-prone content is surfaced as its influence strength (not silently flattened to a read). The classification feeds the existing boundary-evaluation contract (ARCHITECTURE §AD005) — no new domain object.
- **Surfacing**: the explained finding (CLI + MCP) states per GitHub MCP tool its content class, trust tier, and influence strength, so the developer sees the real external-content influence, not merely "an MCP server is present."
- **Fixtures**: tool-variant, toolset-declaration, official-vs-non-official server, disabled server, transport (local vs remote), declaration-vs-derived, and provider-failure (PARTIAL) variants — all sanitized.
- Inherits the Sprint 012 live evidence; **no new live dogfood required** (fixture/output-driven per SPRINT-013 §5). The GitHub MCP server is configured locally; no remote endpoint is contacted (mcp.rs already enforces this).

---

# 3. Non-goals

- A second coding agent or cloud provider (v0.3).
- Runtime/continuous monitoring of GitHub events (v0.5).
- History/diff product (v0.4).
- Editing or enforcing GitHub configuration (v0.7 / out of scope).
- LLM-decided influence or boundary.
- Generic MCP classification across arbitrary servers (per ROADMAP §6 non-goals).
- Resolving repository visibility by contacting GitHub (out of scope; stays UNKNOWN unless declared).

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  External-content variant taxonomy covers minimum evidence-backed variants
    (issue/PR/repo content + write tools + search/discussion)
    → NEW-FIXTURE (r1_github_content_variant_taxonomy)

R2  Public vs private/visibility-unknown trust tiers distinguished honestly
    → NEW-FIXTURE (r2_github_trust_tiers_public_vs_unknown)

R3  Influence strength distinguishes RETRIEVABLE / INJECTABLE / MUTABLE
    → NEW-FIXTURE (r3_github_influence_strength_tiers)

R4  Write tools mapped to a can_mutate mutation edge; reads remain influence-only
    → NEW-FIXTURE (r4_write_tools_emit_can_mutate_and_reads_do_not)

R5  Influence maps to the correct boundary contribution
    (write => can_mutate boundary; injection content surfaced as influence strength)
    → NEW-FIXTURE (r5_write_yields_mutation_boundary_and_injectable_is_surfaced)

R6  Explanation surfaces GitHub MCP influence per tool (CLI)
    → NEW-FIXTURE (sprint017_cli_test.rs: github_influence_read_tool_surfaces_in_cli_explain,
                   github_influence_write_tool_surfaces_in_renderer)

R7  Explanation surfaces GitHub MCP influence per tool (MCP)
    → NEW-FIXTURE (sprint017_mcp_test.rs: github_influence_surfaces_in_mcp_get_finding,
                   + unit safe_explained_path_serializes_github_influence)

R8  Sanitized fixture set: tool variants, toolset declarations, official vs
    non-official server, disabled server, transport, declared vs derived,
    provider failures
    → NEW-FIXTURE (r8_github_battery_toolset_declared_derived_transport_identity_failure)

R9  GitHub influence classification is deterministic across repeated identical configs
    → NEW-FIXTURE (r9_github_influence_stable_across_identical_configs) — ties to S015 stability

R10 No secret leakage: only sanitized identities/paths/content-class appear; never token values
    → NEW-FIXTURE (secret_sweep_never_leaks_fake_github_token + mcp_get_finding_never_leaks_fake_github_token)
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required; fixture/output-driven and inherits Sprint 012 (account `3e2742bacdabcada586f921ad89bac77`). The GitHub MCP server is configured as a local `opencode.json` MCP entry; the adapter never contacts `api.githubcopilot.com/mcp` (mcp.rs enforces official-identity-only classification without network). A live config with write-enabled GitHub tools would additionally exercise R4/R5 end-to-end, but is optional.

---

# 6. Design Notes

## 6.1 Influence classification (R1–R5)
Extend `src/discovery/mcp.rs` `github::classify` (currently only `issue_read`/`pull_request_read`/`get_file_contents`, all `AGENT_RETRIEVABLE`, others `UNKNOWN`). Add a deterministic classifier that, for each recognized tool, returns `(content_class, trust, influence_strength)`:
  - `issue_read`/`pull_request_read` => PUBLIC_EXTERNAL + AGENT_INJECTABLE (user-generated content).
  - `get_file_contents`/`get_file` => repository content; trust UNKNOWN (visibility not observable) + AGENT_RETRIEVABLE.
  - `code_search`/`search_code` => code-search content; trust UNKNOWN + AGENT_RETRIEVABLE.
  - `create_issue`/`create_pull_request`/`update_*`/`delete_*` => write content class + AGENT_MUTABLE.
  - unrecognized => `github:unknown`, UNKNOWN, AGENT_RETRIEVABLE (honest default).
Keep `is_official` (official image or official remote endpoint) as the only admission gate; non-official servers are ignored (no false GitHub influence). Persist `influence_strength` + `content_class` + `trust` on `ObservedGithubTool` and the resulting `influence`/`can_mutate` relationships in `src/application/scan.rs`.

## 6.2 Mutation + boundary mapping (R4–R5)
For `AGENT_MUTABLE` tools, `src/application/scan.rs` emits a `can_mutate` relationship (in addition to `can_call`) carrying `influence_strength: AGENT_MUTABLE`. Boundary evaluation (src/analysis/boundary.rs) treats a `can_mutate` GitHub edge as a mutation boundary (mirror the `can_execute`→MandatoryApproval/HardDeny path): surfaced and, where it reaches a sink, interrupting. Injection-prone (`AGENT_INJECTABLE`) reads are surfaced as influence strength, never flattened to a plain read. Keep `ENFORCE_*`-style remediation seams intact (no regression to 013–016).

## 6.3 Surfacing (R6–R7)
Reuse the S013–S016 surfacing seams. The explained finding (CLI `render.rs`, MCP `tools.rs`) states, per GitHub MCP tool: content class, trust tier, influence strength. Extend sprint017 integration tests (CLI + MCP).

## 6.4 Fixtures (R8)
Sanitized battery: tool-variant configs, toolset-declaration (`issues`,`pull_requests`,`repos`) vs explicit tool declaration, official vs non-official image, disabled server (`disabled:true`), local vs remote transport, declared vs derived tier, and a provider-failure (PARTIAL) variant. Each asserts the resolved content class / trust / influence strength and (where relevant) the boundary.

## 6.5 Stability (R9)
Identical OpenCode + GitHub MCP config => identical classification (ties to S015 finding stability).

## 6.6 Support note (R10/DOC)
Author `docs/internal/sprints/SPRINT-017-support-note.md` stating exactly what GitHub influence Pico can and cannot establish (official-server-only; static-config visibility unknown => UNKNOWN; no runtime contact).

---

# 7. Fixtures (NEW-FIXTURE)

- `r1_github_content_variant_taxonomy` — each recognized tool => expected content class + influence strength.
- `r2_github_trust_tiers_public_vs_unknown` — public issues/PRs => PUBLIC_EXTERNAL; repo content => UNKNOWN.
- `r3_github_influence_strength_tiers` — RETRIEVABLE vs INJECTABLE vs MUTABLE.
- `r4_write_tools_emit_can_mutate_and_reads_do_not` — write tools emit can_mutate; reads do not.
- `r5_write_yields_mutation_boundary_and_injectable_is_surfaced` — write => can_mutate boundary; injectable => surfaced influence.
- `r8_github_battery_toolset_declared_derived_transport_identity_failure` — tool/toolset/identity/transport/declared-vs-derived/disabled/provider-failure.
- `r9_github_influence_stable_across_identical_configs` (R9).

---

# 8. Architecture Pressure-Test

- Influence classification is an analyzed interpretation of declared MCP tool/toolset facts (ARCHITECTURE §2.9 effective-state-over-declared, generalized to influence); it does not invent a new domain object — it feeds the existing Influence/Relationship/Boundary model.
- The classifier is pure and deterministic; reuses the boundary-evaluation contract (ARCHITECTURE §AD005).
- Secret-safety preserved: only sanitized server identity / tool name / content-class as facts; secret values never appear (ARCHITECTURE §7.7, ROADMAP §13.2).
- No new provider; GitHub MCP remains the only supported external-content surface (official server only).

---

# 9. Risks and Mitigations

- **Risk:** repository visibility is not observable from static config. *Mitigation:* classify repo content as UNKNOWN trust, never fabricate PRIVATE_EXTERNAL.
- **Risk:** over-broad tool matching creates false GitHub influence. *Mitigation:* admit only official identity; match an explicit recognized-tool allowlist; everything else => UNKNOWN.
- **Risk:** "injection" is subtle. *Mitigation:* define `AGENT_INJECTABLE` concretely as user-generated content tools (issue/PR/comment/discussion reads); fixture R3 pins the behavior.

---

# 10. Required Evidence Artifacts

- A1–A5 influence classifier + variant/trust/strength/mutation/boundary fixtures (R1–R5).
- A6 CLI surfacing test (R6).
- A7 MCP surfacing test (R7).
- A8 broad sanitized fixture battery (R8).
- A9 stability fixture (R9).
- A10 secret-sweep extension (R10).
- A11 support note (§27, DOC-VERIFIED).
- A12 completed validation matrix (§4 / §27).

Evidence artifacts quote at most sanitized tool names and content-class; never raw secret values.

---

# 11. Commit Policy

Authoring-only document commit as:

```text
docs(sprints): define Sprint 017 GitHub MCP influence classification depth
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
feat(discovery): deepen GitHub MCP influence classification across content variants
test(discovery): GitHub influence variant, trust, strength, mutation fixtures
feat(cli): surface GitHub MCP influence per tool
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin Sprint 018.

---

# 12. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-08-26
  Baseline: aee1e1d (authored) -> pushed b81846e..<S017 impl>
  Verified by: cargo test (281 passed, 0 failed), clippy --all-targets -D warnings clean,
               cargo fmt --check clean. Golden path (OpenCode bash allow + Cloudflare token +
               official GitHub MCP) => exactly 1 active finding (sprint009/sprint017 assert).

commits
  authored: aee1e1d docs(sprints): define Sprint 017 GitHub MCP influence classification depth
  impl:      <feat/discovery + feat(cli) + test(integration)>

repository state
  M src/analysis/boundary.rs   (+Mutation boundary for AGENT_MUTABLE can_mutate)
  M src/analysis/model.rs      (+InfluenceStrength::AgentInjectable/AgentMutable; BoundaryKind::Mutation)
  M src/application/findings.rs (+GitHubInfluenceView + github_influence on ExplainedPath)
  M src/application/scan.rs     (can_mutate emitted for AGENT_MUTABLE; consequential_sink)
  M src/cli/render.rs           (GitHub MCP influence block)
  M src/discovery/mcp.rs        (deepened github::classify + classify_tool; unit tests)
  M src/findings/engine.rs      (admit AgentInjectable/Mutable to candidate gate)
  M src/mcp/tools.rs            (SafeGitHubInfluenceView + github_influence JSON)
  M tests/integration.rs        (register sprint017 modules)
  M tests/integration/github_mcp_scan_test.rs (AGENT_INJECTABLE + R4/R5)
  M tests/integration/sprint016_cli_test.rs (github_influence: vec![] on constructed path)
  ?? docs/internal/sprints/SPRINT-017-support-note.md
  ?? tests/fixtures/opencode/github-mcp-write.json
  ?? tests/integration/sprint017_cli_test.rs
  ?? tests/integration/sprint017_mcp_test.rs

new fixtures (R1–R10) and their assertions
  src/discovery/mcp.rs mod tests:
    R1  r1_github_content_variant_taxonomy
    R2  r2_github_trust_tiers_public_vs_unknown
    R3  r3_github_influence_strength_tiers
    R8  r8_github_battery_toolset_declared_derived_transport_identity_failure
    R9  r9_github_influence_stable_across_identical_configs
  tests/integration/github_mcp_scan_test.rs:
    R4  r4_write_tools_emit_can_mutate_and_reads_do_not
    R5  r5_write_yields_mutation_boundary_and_injectable_is_surfaced
  CLI (sprint017_cli_test.rs):
    R6  github_influence_read_tool_surfaces_in_cli_explain
        github_influence_write_tool_surfaces_in_renderer
  MCP (sprint017_mcp_test.rs):
    R7  github_influence_surfaces_in_mcp_get_finding
        (+ unit safe_explained_path_serializes_github_influence)
  Secret sweep (R10):
    secret_sweep_never_leaks_fake_github_token (CLI) +
    mcp_get_finding_never_leaks_fake_github_token (MCP)
        asserts ghp_TESTFAKE... never appears in rendered block / MCP JSON / persisted metadata.

CLI/MCP GitHub-influence surfacing test additions: see R6/R7 above.
  CLI renders: "GitHub MCP <tool>: <content_class> | trust=<trust> | influence=<influence_strength>"
  MCP get_finding JSON: paths[].github_influence[] = {tool_name, content_class, trust, influence_strength}.

influence stability result: R9 PASS — identical config => identical classification (ties S015).
secret-sweep result: ZERO — fake token absent in all rendered/metadata outputs.
optional live re-run outcome: GAP-RECORDED — fixture/output-driven per SPRINT-013 §5; no new
    live dogfood required. Sprint 012 contract inherited.
comprehension result: NOT RUN (no external comprehension step defined for this sprint).
usefulness judgments: per-tool GitHub influence is the honest, developer-facing payoff of 013–016.
defect list and dispositions: expected empty — all R1–R10 green, golden path intact.
architecture pressure-test answers:
  - Influence classification feeds existing Influence/Relationship/Boundary model; no new domain object.
  - Classifier is pure/deterministic; reuses boundary-evaluation contract (AD005).
  - Secret-safety preserved: only sanitized tool names/content-class/identity; never secret values.
  - GitHub MCP remains the only supported external-content surface (official-server-only admission).
advancement decision record: see §14.
follow-ups (named, owned, unambiguous):
  - S018: next v0.2 depth sprint (deferred; not started).
  - R10 live token id 6b1a59bb84dd680a1dde77f49b3f357b still pending dashboard deletion
    (external carry-over, not a code blocker).
```

Do not claim v0.2 depth is "closed" merely because influence is deeper. Claim exactly what the matrix shows: GitHub MCP influence is classified across the minimum evidence-backed variants, surfaced honestly, and mapped to the correct boundary.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-017 — GitHub MCP Influence Classification Depth
Status: DONE
Baseline: aee1e1d (authored) -> <impl push>

Influence classification:
  content-variant taxonomy: PASS
  public vs unknown trust: PASS
  influence-strength tiers: PASS
  write => can_mutate: PASS
  maps to correct boundary: PASS

Surfacing:
  CLI per-tool influence: PASS
  MCP per-tool influence: PASS

Fixtures:
  broad battery: PASS
  stability across configs: PASS

Validation matrix:
  R1-R10: PASS

Secret sweep: ZERO
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17.

```text
Decision: ADVANCE v0.2 depth.
GitHub MCP influence is now classified across the minimum evidence-backed
content variants (issue/PR/repo/read/write/search), with honest trust tiers
(public issues/PRs => PUBLIC_EXTERNAL; repo visibility unknown => UNKNOWN),
influence-strength tiers (RETRIEVABLE / INJECTABLE / MUTABLE), and write tools
mapped to a can_mutate Mutation boundary. Per-tool influence is surfaced in
CLI + MCP. R1–R10 all PASS; secret sweep ZERO; golden path intact
(1 active finding). No regression to 013–016 behavior.

v0.2 depth status after S017: S013 (authority tiers), S014 (provenance +
freshness), S015 (finding stability/dedup), S016 (effective-state), S017
(GitHub influence) complete. Remaining v0.2 depth: S018, S019 — deferred,
not started.

Justification for S018: closes remaining v0.2 ROADMAP §6 commitments not yet
covered by 013–017 (next authority-leg / evidence-depth item: deepen
Cloudflare authority resolution across credential types + scope combos, or
scan-diagnostics/explanations for incomplete evidence). Authoring of S018
is a separate, explicit step; not started here.
```
