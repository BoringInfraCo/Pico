# Pico — Sprint 020: Claude Code Adapter — Earned Second Agent Surface

**Status:** DONE

**Sprint:** 020
**Phase:** v0.3 — Earned Agent and Provider Expansion
**Type:** Implementation
**Baseline:** `c02e124` (post-Sprint-019 main HEAD)
**Depends on:** Sprints 001–019 (complete golden path, v0.2 sign-off), ROADMAP §7 v0.3

---

# 1. Purpose

v0.2 (Sprints 013–019) closed every depth commitment on the single OpenCode actor path. v0.3 (ROADMAP §7) proves Pico's normalized model generalizes to a carefully selected second agent surface *without* reducing evidence quality or fragmenting the security engine:

> Pico can generalize its security primitive across products while preserving provider-specific evidence precision.

This sprint selects the first v0.3 candidate: **Claude Code** (Anthropic's CLI coding agent) — chosen because it is inspectable via static config (`.claude/settings.json`, `settings.local.json`, `~/.claude/settings.json`, `.mcp.json`), structurally parallel to OpenCode (Bash permission policy + MCP servers), and has real user demand. It reuses the existing domain model, graph projection, analysis engine, finding rules, and application services.

It does **not** add a cloud provider, does **not** classify any MCP server globally, and does **not** weaken the v0.2 evidence bar.

---

# 2. Scope

- **Claude Code actor discovery**: observe the actor from the documented config locations (project `.claude/settings.json`, project `.claude/settings.local.json`, user `~/.claude/settings.json`), emitting `ObservedActor { provider: "claude", source_type, source_locator }`. Absence is not a problem.
- **Bash effective-state resolution**: resolve Claude Code's Bash posture to the existing `EffectiveBashPermission`/`PermissionAction` model (S016):
  - `permissions.allow` / `permissions.ask` / `permissions.deny` arrays (a rule "Bash" or "Bash(<pattern>)"),
  - `permissions.disableBash` => `DENIED`,
  - `permissions.defaultMode` ("acceptEdits" implies automatic accept; a Bash rule list governs bash),
  - sandbox configuration => `SANDBOXED`,
  - unresolvable patterns => `UNKNOWN`/`BOUNDED` (never invented).
  - precedence: deny > ask/approval > allow (mirror S016).
- **Claude MCP discovery**: normalize Claude's MCP server declarations (project `.mcp.json` `mcpServers`, plus `mcpServers` in settings) into `ObservedMcpServer` (transport, identity, safe endpoint/command, env keys, tool/toolset declaration). The existing GitHub classifier (S017) applies to an official GitHub MCP server declared by Claude too.
- **Provider-aware generalization**: replace hardcoded `agent:opencode|…` relationship keys and the `actor.provider != "opencode"` filter in `src/application/scan.rs` with the actor's `provider`, so each actor gets its own Bash `can_execute` edge and `configured_with` MCP edges. OpenCode remains the golden-path primary; the refactor must not regress 001–019.
- **Mixed environments**: when both OpenCode and Claude Code configs are present, both actors + per-agent Bash edges coexist without key collision, duplicated findings, cross-agent evidence leakage, or graph ambiguity (ROADMAP §7 exit criteria).
- **Surfacing**: the explained finding (CLI + MCP) shows the Bash effective state per agent (OpenCode *and* Claude Code).
- **Adapter conformance + support note**: declare supported operations, evidence precision, failure behavior, and unresolved states for the Claude adapter; update the support matrix.
- **Fixtures**: config precedence (user vs project vs local), bash modes, sandbox, MCP transport local/remote, disabled server, mixed environments, provider-failure variants — all sanitized.

---

# 3. Non-goals

- A second *cloud provider* (separate v0.3 sprint; GitHub mutation authority is another candidate).
- Supporting every coding agent, MCP server, or credential type (ROADMAP §7 non-goals).
- Global MCP-server classification (tools are classified individually).
- Runtime monitoring, enforcement, or integration-intelligence substituting for environment evidence.
- Removing or weakening OpenCode/golden-path support.

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  Claude Code actor discovered from documented config locations
    → NEW-FIXTURE (claude_actor_discovered_from_documented_config)

R2  Bash effective state resolved from Claude permission arrays
    (allow/ask/deny + disableBash + defaultMode + sandbox; deny > ask > allow)
    → NEW-FIXTURE (claude_bash_effective_state_resolution)

R3  Claude MCP servers normalized (.mcp.json + settings mcpServers; local/remote; GitHub classifier applies)
    → NEW-FIXTURE (claude_mcp_servers_normalized)

R4  Provider-aware edges: per-agent can_execute/configured_with keys (no collision)
    → NEW-FIXTURE (provider_aware_relationship_keys)

R5  Mixed environment (OpenCode + Claude Code) coexists without collision/duplication/leakage
    → NEW-FIXTURE (mixed_environment_open_code_plus_claude)

R6  Explanation surfaces Bash effective state per agent (CLI)
    → NEW-FIXTURE (sprint020_cli_test.rs: cli_explain_surfaces_bash_effective_state_per_agent_for_mixed_workspace,
                   cli_explain_surfaces_approval_gated_claude_boundary)

R7  Explanation surfaces Bash effective state per agent (MCP)
    → NEW-FIXTURE (sprint020_mcp_test.rs: mcp_get_finding_includes_per_agent_bash_for_mixed_workspace,
                   + unit safe_explained_path_serializes_per_agent_bash)

R8  Sanitized fixture set: config precedence, bash modes, sandbox, MCP transport,
    disabled server, mixed env, provider failures
    → NEW-FIXTURE (r8_battery_claude_precedence_modes_sandbox_transport_disabled_mixed_failure)

R9  Claude discovery deterministic across repeated identical configs (ties S015 stability)
    → NEW-FIXTURE (claude_discovery_stable_across_identical_configs)

R10 No secret leakage: only sanitized config paths/tool names/content-class appear;
    never token values
    → NEW-FIXTURE (secret_sweep_never_leaks_fake_token_across_claude_postures +
                   mcp_secret_sweep_never_leaks_fake_token_across_claude_postures)
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required; fixture/output-driven. A real Claude Code install (`~/.claude/settings.json`) is NOT read during tests (tempdir-only fixtures). A live re-run in a Claude Code workspace would additionally exercise R1/R2/R5 end-to-end, but is optional. Cloudflare provider inspection remains via `FixtureTransport` (no network in tests).

---

# 6. Design Notes

## 6.1 Claude Code adapter (R1–R3)
Add `src/discovery/agents/claude.rs` (new adapter; `agents/mod.rs` gains `pub mod claude;`). It reads only documented files and retains only the small permission/MCP projection, discarding raw config. Reuse `parse/merge` patterns from opencode.rs (JSONC not needed — Claude settings are JSON) but do NOT share credential discovery: the Cloudflare env/.env credential reader stays in opencode.rs (it is environment-level and fingerprint-deduped). Bash rules: parse `permissions.allow/ask/deny` arrays for Bash rules; `disableBash: true` => Deny; sandbox key => Sandboxed; `defaultMode` informs but never fabricates AUTO_ALLOW. Emit `ObservedBashCapability` with `effective_state` (S016 model).

## 6.2 Provider-aware generalization (R4, R5)
In `src/application/scan.rs`, replace the 19 hardcoded `opencode` occurrences (actor filter ~165, resource/relationship keys ~168-464, provider diagnostics ~979) with the actor's `provider`. Each actor yields its own `agent:<provider>|can_execute|shell:bash` and `agent:<provider>|can_call|…` edges. Verify no relationship-key collision when both agents present. Keep the OpenCode golden path byte-identical in behavior.

## 6.3 Surfacing (R6–R7)
Extend the S016 effective-Bash surfacing (CLI `render.rs`, MCP `tools.rs`) to be per-agent: `Agent <provider> effective Bash: <state>; interrupting boundary: <kind>`. Extend sprint020 integration tests.

## 6.4 Fixtures (R8)
Sanitized battery: user-vs-project-vs-local precedence, bash allow/ask/deny/disableBash/sandbox/defaultMode, MCP local vs remote, disabled server, official GitHub MCP declared by Claude, mixed OpenCode+Claude, provider-failure (PARTIAL).

## 6.5 Conformance + support note (R10/DOC)
Author `docs/internal/sprints/SPRINT-020-support-note.md` (adapter conformance for Claude: supported ops, evidence precision, failure behavior, unresolved states) and update `SPRINT-013-support-matrix.md` with the Claude row.

---

# 7. Fixtures (NEW-FIXTURE)

- `claude_actor_discovered_from_documented_config` — project/user/local locations => actor.
- `claude_bash_effective_state_resolution` — allow/ask/deny/disableBash/defaultMode/sandbox => state.
- `claude_mcp_servers_normalized` — .mcp.json + settings; local/remote; GitHub classifier.
- `provider_aware_relationship_keys` — per-agent can_execute/configured_with keys.
- `mixed_environment_open_code_plus_claude` — both actors + edges coexist.
- `r8_battery_claude_precedence_modes_sandbox_transport_disabled_mixed_failure` — precedence/modes/sandbox/transport/disabled/mixed/failure.
- `claude_discovery_stable_across_identical_configs` (R9).

---

# 8. Architecture Pressure-Test

- The Claude adapter emits only the normalized `ObservedActor`/`ObservedBashCapability`/`ObservedMcpServer` projections (ARCHITECTURE §2.9 effective-state-over-declared); no new domain object.
- Provider-aware keys reuse the existing Relationship/Boundary/Finding contracts (ARCHITECTURE §AD005); OpenCode golden path unchanged.
- MCP tools are classified individually (S017); Claude never causes a global MCP classification.
- Secret-safety preserved (ARCHITECTURE §7.7, ROADMAP §13.2); config file paths may be source_locators, never secret values.
- Integration intelligence is NOT used as authority evidence (offline, built-in knowledge only).

---

# 9. Risks and Mitigations

- **Risk:** Claude Code config schema varies across versions. *Mitigation:* resolve only minimum golden-path fields; unknown => explicit UNKNOWN/BOUNDED, never a false certainty.
- **Risk:** provider-aware refactor regresses the golden path. *Mitigation:* keep OpenCode behavior byte-identical; run 001–019 suites; R4/R5 fixtures pin the keys.
- **Risk:** mixed environments create identity collision. *Mitigation:* per-provider relationship keys + canonical actor resources; R5 asserts no collision/duplication.

---

# 10. Required Evidence Artifacts

- A1–A5 Claude adapter + provider-aware keys + mixed-env fixtures (R1–R5).
- A6 CLI surfacing test (R6).
- A7 MCP surfacing test (R7).
- A8 broad sanitized fixture battery (R8).
- A9 stability fixture (R9).
- A10 secret-sweep extension (R10).
- A11 support note + support-matrix update (§27, DOC-VERIFIED).
- A12 completed validation matrix (§4 / §27).

Evidence artifacts quote at most sanitized config paths/tool names/content-class; never raw secret values.

---

# 11. Commit Policy

Authoring-only document commit as:

```text
docs(sprints): define Sprint 020 Claude Code adapter (earned second agent surface)
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
feat(discovery): add Claude Code adapter with Bash effective-state + MCP discovery
feat(scan): provider-aware relationship keys for multi-agent scans
test(discovery): Claude fixtures + mixed-environment validation
feat(cli): surface per-agent effective Bash capability
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin a new v0.3 sprint.

---

# 12. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-08-26
  Baseline: 048cac5 (authored) -> pushed c02e124..<S020 impl>
  Verified by: cargo test (329 passed, 0 failed, 1 ignored), clippy --all-targets -D warnings
               clean, cargo fmt --check clean. Golden path (opencode-only) => exactly 1 finding
               with agent:opencode keys intact; single-agent CLI/MCP output byte-identical.

commits
  authored: 048cac5 docs(sprints): define Sprint 020 Claude Code adapter (earned second agent surface)
  impl:      <feat(discovery) + feat(scan) + feat(cli,mcp) + test(integration)>

repository state
  ?? src/discovery/agents/claude.rs            (new config-only adapter)
  M  src/discovery/agents/mod.rs                (+pub mod claude)
  M  src/discovery/mod.rs                       (provider on ObservedBashCapability/ObservedMcpServer;
                                                 discover()/discover_with_environment() merge both)
  M  src/discovery/agents/opencode.rs           (provider fields)
  M  src/discovery/mcp.rs                       (test literals)
  M  src/application/scan.rs                    (provider-aware keys; multi-capability iterate)
  M  src/application/findings.rs                (+AgentBashView + agents on ExplainedPath)
  M  src/cli/render.rs                          (per-agent Bash block when >1 agent)
  M  src/mcp/tools.rs                           (SafeAgentBashView + agents JSON)
  M  tests/integration.rs + sprint016/017/018_cli_test.rs (agents: vec![])
  ?? docs/internal/sprints/SPRINT-020-support-note.md
  ?? tests/fixtures/claude/ + tests/fixtures/mixed/
  ?? tests/integration/sprint020_adapter_test.rs / sprint020_cli_test.rs / sprint020_mcp_test.rs

new fixtures (R1–R10) and their assertions
  claude.rs (unit):
    R1  claude_actor_discovered_from_documented_config
    R2  claude_bash_effective_state_resolution (allow/ask/deny/disableBash/defaultMode/sandbox/mixed)
    R3  claude_mcp_servers_normalized (.mcp.json + settings; local/remote; GitHub classifier)
    R9  claude_discovery_stable_across_identical_configs
  sprint020_adapter_test.rs:
    R4  provider_aware_relationship_keys (agent:opencode|... vs agent:claude|...)
    R5  mixed_environment_open_code_plus_claude
    R8  r8_battery_claude_precedence_modes_sandbox_transport_disabled_mixed_failure
  sprint020_cli_test.rs:
    R6  cli_explain_surfaces_bash_effective_state_per_agent_for_mixed_workspace
        cli_explain_surfaces_approval_gated_claude_boundary
        cli_explain_golden_path_keeps_single_opencode_line
  sprint020_mcp_test.rs:
    R7  mcp_get_finding_includes_per_agent_bash_for_mixed_workspace
        mcp_get_finding_surfaces_approval_gated_claude_boundary
        mcp_get_finding_golden_path_has_single_opencode_agent
        (+ unit safe_explained_path_serializes_per_agent_bash)
  Secret sweep (R10):
    secret_sweep_never_leaks_fake_token_across_claude_postures (CLI) +
    mcp_secret_sweep_never_leaks_fake_token_across_claude_postures (MCP)

CLI/MCP per-agent surfacing test additions: see R6/R7 above.
  CLI renders: "Agent opencode effective Bash: AUTO_ALLOW; boundary: none" and
               "Agent claude effective Bash: <state>; boundary: <kind>" per agent (>1 agent).
  MCP get_finding JSON: paths[].agents[] = {provider, effective_bash_capability, bash_boundary}.

mixed-environment result: R5 PASS — both actors + per-agent edges coexist; no key collision,
    no duplicated findings; exactly 1 finding on the golden (opencode-only) config.
discovery stability result: R9 PASS — identical config => identical Claude discovery (ties S015).
secret-sweep result: ZERO — synthetic token absent in all rendered/metadata outputs across
    claude postures; config paths only as source_locator.
optional live re-run outcome: GAP-RECORDED — fixture/output-driven per SPRINT-013 §5; a real
    Claude Code workspace re-run would exercise R1/R2/R5 end-to-end (optional).
comprehension result: NOT RUN (no external comprehension step defined for this sprint).
usefulness judgments: Claude Code is the first v0.3 second-agent surface; it reuses the core
    engine and coexists with OpenCode, proving the adapter model generalizes.
defect list and dispositions: expected empty — all R1–R10 green, golden path intact.
architecture pressure-test answers:
  - Claude adapter emits only normalized ObservedActor/BashCapability/McpServer projections;
    no new domain object.
  - Provider-aware keys reuse existing Relationship/Boundary/Finding contracts (AD005);
    OpenCode golden path byte-identical.
  - MCP tools classified individually (S017); no global MCP classification.
  - Secret-safety preserved (ARCHITECTURE §7.7, ROADMAP §13.2); no integration-intelligence
    substitution for environment evidence.
advancement decision record: see §14.
follow-ups (named, owned, unambiguous):
  - Next v0.3 sprint: a second authority surface OR GitHub repository mutation authority
    (ROADMAP §7 candidate choices) — deferred, not started.
  - R10 live token id 6b1a59bb84dd680a1dde77f49b3f357b still pending dashboard deletion
    (external carry-over, not a code blocker).
```

Do not claim v0.3 is "won" merely because Claude Code is added. Claim exactly what the matrix shows: the Claude Code adapter meets the v0.2 evidence bar, coexists with OpenCode, and reuses the core engine without regression.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-020 — Claude Code Adapter
Status: DONE
Baseline: 048cac5 (authored) -> <impl push>

Claude adapter:
  actor discovery: PASS
  Bash effective-state: PASS
  MCP normalization: PASS
  provider-aware keys: PASS
  mixed environment: PASS

Surfacing:
  CLI per-agent Bash state: PASS
  MCP per-agent Bash state: PASS

Fixtures:
  broad battery: PASS
  stability across configs: PASS

Validation matrix:
  R1-R10: PASS

Golden path: 1 finding intact
Secret sweep: ZERO
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17.

```text
Decision: ADVANCE v0.3.
Claude Code is the first earned second-agent surface. The adapter meets the
v0.2 evidence bar (actor + Bash effective-state + MCP normalization + GitHub
classifier reuse), coexists with OpenCode in mixed environments without
identity collision / duplicated findings / cross-agent leakage, and the core
engine is now provider-aware with the OpenCode golden path byte-identical
(1 finding, agent:opencode keys). R1–R10 all PASS; secret sweep ZERO.

v0.3 status after S020: one additional agent surface (Claude Code) complete.
Remaining ROADMAP §7 v0.3 items: at most one additional authority surface OR
one materially distinct GitHub authority path (candidate: GitHub repository
mutation authority); mixed-environment validation already partially proven in
R5; support matrices extended.

Justification for the next v0.3 sprint: prove the authority-side expansion
(GitHub repository mutation authority) through the same core engine, or select
a second authority surface. Authoring is a separate, explicit step; not
started here.
```