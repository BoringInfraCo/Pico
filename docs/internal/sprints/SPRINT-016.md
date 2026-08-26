# Pico — Sprint 016: OpenCode Effective-State Resolution Depth

**Status:** DONE

**Sprint:** 016
**Phase:** v0.2 — Evidence and Authority Depth
**Type:** Implementation
**Baseline:** `ddf5f1e` (post-Sprint-015 main HEAD)
**Depends on:** Sprint 012 (live dogfood), Sprint 013 (authority tiers), Sprint 014 (provenance + freshness), Sprint 015 (finding stability/dedup)

---

# 1. Purpose

Sprints 013–015 made authority tiers visible/persisted, evidence provenance + freshness trustworthy, and findings deterministic/stable. The remaining v0.2 depth gap on the **actor leg** of the golden path is OpenCode *effective-state* resolution:

> Within the supported OpenCode boundary, Pico must resolve the effective Bash capability (auto-allow vs approval-gated vs denied vs sandboxed), honor configuration precedence and bypass conditions, and reflect that effective state as an honest, deterministic boundary in the finding.

This sprint closes ROADMAP §6 v0.2 commitments Sprint 013–015 did not:

- "Improve effective-state resolution for OpenCode permissions, approval modes, sandboxing, and bypass conditions relevant to the golden path."
- "Expand sanitized fixtures for configuration precedence, runtime modes, transport differences, credential sources, token scopes, resource scopes, and provider failures."

It does **not** add a second agent/provider (v0.3), runtime observation (v0.5), history/diff UX (v0.4), production classification of `sink_impact` (still `UNKNOWN` by design, SPRINT-013 §8), or enforcement (v0.7).

---

# 2. Scope

- **Effective Bash permission state machine**: deterministically resolve OpenCode's effective Bash capability from its configuration, applying precedence `deny > approval/ask > allow` and distinguishing:
  - `AUTO_ALLOW` (unrestricted execute),
  - `APPROVAL_GATED` (manual approval required — interrupted by a MandatoryApproval boundary),
  - `DENIED` (hard deny — interrupted by a HardDeny boundary),
  - `SANDBOXED` (execution confined by a sandbox — interrupted by a Sandbox boundary).
- **Approval mode**: detect auto-approval vs manual approval behavior where observable from configuration/runtime signals, and reflect it.
- **Sandbox detection**: detect sandbox confinement of Bash where the OpenCode configuration or environment exposes it.
- **Bypass conditions**: detect when a configured `allow` (or tool-level exception) bypasses an otherwise-required approval, and represent that as effective `AUTO_ALLOW` (not gated).
- **Configuration precedence**: resolve the effective state when multiple applicable rules exist (project vs global, explicit deny vs implicit allow), deterministically.
- **Surfacing**: the explained finding (CLI + MCP) states the effective Bash capability and which boundary (if any) interrupts it, so the developer sees the real effective permission, not merely the declared config.
- **Fixtures**: configuration-precedence, approval-mode, sandbox, bypass, runtime-mode, transport-difference, credential-source, and provider-failure variants — all sanitized.
- Inherits the Sprint 012 live evidence; **no new live dogfood required** (fixture/output-driven per SPRINT-013 §5). A live re-run reusing the Sprint 012 contract is optional.

---

# 3. Non-goals

- A second coding agent or cloud provider (v0.3).
- Runtime/continuous monitoring of approval/execution events (v0.5).
- History/diff product (v0.4).
- Editing or enforcing OpenCode configuration (v0.7 / out of scope).
- LLM-decided capability or boundary.
- Generic config-parser coverage beyond what the golden path requires.

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  Effective Bash permission resolved with correct precedence (deny > ask > allow)
    → NEW-FIXTURE (r1_deny_overrides_allow_becomes_denied)

R2  Approval mode detected (manual approval required vs auto-allow)
    → NEW-FIXTURE (r2_ask_becomes_approval_gated_and_mandatory_approval_boundary)

R3  Sandbox confinement detected and mapped to a Sandbox boundary
    → NEW-FIXTURE (r3_sandbox_becomes_sandboxed_and_sandbox_boundary)

R4  Bypass condition detected (allow bypasses required approval => AUTO_ALLOW)
    → NEW-FIXTURE (r4_agent_ask_overridden_by_bash_allow_is_auto_allow_without_interrupt)

R5  Effective state maps to the correct finding boundary
    (AUTO_ALLOW => no interrupt; APPROVAL_GATED => MandatoryApproval;
     DENIED => HardDeny; SANDBOXED => Sandbox)
    → NEW-FIXTURE (r5_state_to_boundary_table)

R6  Explanation surfaces effective Bash capability + interrupting boundary (CLI)
    → NEW-FIXTURE (sprint016_cli_test.rs: effective_bash_capability_surfaces_in_explain_for_auto_allow_and_sandbox,
                   rendered_explain_shows_effective_bash_capability_for_each_state)

R7  Explanation surfaces effective Bash capability + interrupting boundary (MCP)
    → NEW-FIXTURE (sprint016_mcp_test.rs: mcp_get_finding_includes_effective_bash_capability_for_sandbox,
                   + unit safe_explained_path_serializes_effective_bash_capability)

R8  Sanitized fixture set: precedence, runtime modes, transport, credential sources,
    token/resource scopes, provider failures
    → NEW-FIXTURE (r8_battery_precedence_and_surface_effective_state; see §7)

R9  Effective-state resolution is deterministic across repeated identical scans
    → NEW-FIXTURE (r9_identical_config_yields_identical_effective_state) — ties to S015 stability

R10 No secret leakage: config paths/sources may appear as source_locator, never secret values
    → NEW-FIXTURE (secret_sweep_never_leaks_fake_token_across_effective_states)
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required; fixture/output-driven and inherits Sprint 012 (account `3e2742bacdabcada586f921ad89bac77`). If a live re-run is performed, it reuses the Sprint 012 contract; a live OpenCode config with approval-gated Bash would additionally exercise R2/R5 end-to-end.

---

# 6. Design Notes

## 6.1 Effective-state resolution (R1–R5)
Add a deterministic resolver (in the OpenCode discovery/analysis path, or a new `src/discovery/opencode/effective.rs`) that, given the resolved OpenCode configuration + observable runtime signals, returns an `EffectiveBashPermission { state, interrupting_boundary, evidence_refs }`. Precedence: explicit `deny` => `DENIED`; explicit `ask`/`approval` with no bypass => `APPROVAL_GATED`; sandbox confinement => `SANDBOXED`; unconditional `allow` (or an allow that bypasses approval) => `AUTO_ALLOW`. The resolver must be pure and unit-tested; it feeds the existing boundary evaluation so the finding reflects effective state (the `ENFORCE_BASH_APPROVAL_OR_DENY` rule already maps `can_execute` to a MandatoryApproval boundary — extend/verify it covers DENIED/SANDBOXED too).

## 6.2 Surfacing (R6–R7)
Reuse the S013/S014/S015 surfacing seams. The explained finding (CLI `render.rs`, MCP `tools.rs`) should state the effective Bash capability (AUTO_ALLOW / APPROVAL_GATED / DENIED / SANDBOXED) and the interrupting boundary, if any. Extend sprint010/011 tests.

## 6.3 Fixtures (R8)
Build a sanitized fixture battery covering: global-vs-project precedence, deny-over-allow, approval-gated, sandbox, allow-bypass-approval, runtime auto-approval mode, transport difference (local vs remote MCP), credential source (env vs file), token scope (write vs read), resource scope (in/out), and a provider-failure (PARTIAL) variant. Each fixture asserts the resolved effective state and (where relevant) the resulting boundary.

## 6.4 Stability (R9)
Because S015 made findings deterministic, an identical OpenCode config + scan must yield the same effective state and finding. Add a stability fixture.

---

# 7. Fixtures (NEW-FIXTURE)

- `r1_deny_overrides_allow_becomes_denied` — config with both allow and deny => DENIED.
- `r2_ask_becomes_approval_gated_and_mandatory_approval_boundary` — `ask` config => APPROVAL_GATED + MandatoryApproval boundary.
- `r3_sandbox_becomes_sandboxed_and_sandbox_boundary` — sandbox config => SANDBOXED + Sandbox boundary.
- `r4_agent_ask_overridden_by_bash_allow_is_auto_allow_without_interrupt` — an allow that bypasses approval => AUTO_ALLOW (no interrupt).
- `r5_state_to_boundary_table` — table-driven: each state => expected boundary.
- `r8_battery_precedence_and_surface_effective_state` — precedence/runtime/transport/credential/scope/failure variants.
- `r9_identical_config_yields_identical_effective_state` (R9).

---

# 8. Architecture Pressure-Test

- Effective state is an analyzed interpretation of OpenCode configuration/observations (ARCHITECTURE §2.9 effective-state-over-declared); it does not invent a new domain object — it feeds the existing Boundary/Relationship model.
- The resolver is pure and deterministic; it reuses the existing boundary-evaluation contract (ARCHITECTURE §AD005).
- Secret-safety preserved: config file *paths* may be source_locators; secret *values* (e.g., `GITHUB_PERSONAL_ACCESS_TOKEN`) never appear (ARCHITECTURE §7.7, ROADMAP §13.2).
- No new provider; OpenCode remains the only supported agent.

---

# 9. Risks and Mitigations

- **Risk:** OpenCode config schema varies across versions. *Mitigation:* resolve only the minimum fields the golden path needs (bash permission, approval, sandbox); unknown fields degrade to explicit UNKNOWN, not a false certainty.
- **Risk:** "bypass" is subtle. *Mitigation:* define it concretely as any rule that makes execution unconditional despite a global approval requirement; fixture R4 pins the behavior.
- **Risk:** runtime auto-approval not observable from static config. *Mitigation:* resolve from declared config where observable; otherwise report the declared state and mark confidence accordingly (no fabricated runtime inference).

---

# 10. Required Evidence Artifacts

- A1–A5 effective-state resolver + precedence/approval/sandbox/bypass fixtures (R1–R5).
- A6 CLI surfacing test (R6).
- A7 MCP surfacing test (R7).
- A8 broad sanitized fixture battery (R8).
- A9 stability fixture (R9).
- A10 secret-sweep extension (R10).
- A11 short support note: effective-state resolution rules + precedence (§27, DOC-VERIFIED).
- A12 completed validation matrix (§4 / §27).

Evidence artifacts quote at most config paths and credential FINGERPRINT; never raw secret values.

---

# 11. Commit Policy

Authoring-only document commits as:

```text
docs(sprints): define Sprint 016 OpenCode effective-state resolution
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
feat(discovery): resolve OpenCode effective Bash permission with precedence
test(discovery): effective-state precedence, approval, sandbox, bypass fixtures
feat(cli): surface effective Bash capability and interrupting boundary
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin Sprint 017.

---

# 12. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-08-26
  Baseline: 42ee0d4 (authored) -> pushed ddf5f1e..<S016 impl>
  Verified by: cargo test (268 passed, 0 failed), clippy --all-targets -D warnings clean,
               cargo fmt --check clean. Golden path {"permission":{"bash":"allow"}}
               => AUTO_ALLOW => exactly 1 active finding (sprint009_finding_test).

commits
  authored: 42ee0d4 docs(sprints): define Sprint 016 OpenCode effective-state resolution
  impl:      <feat/discovery + feat/cli/mcp + test/integration>

repository state
  M src/analysis/boundary.rs   (+SANDBOX boundary branch)
  M src/application/findings.rs (+effective_bash_capability / bash_boundary on ExplainedPath)
  M src/application/scan.rs     (can_execute keyed off effective_state + metadata)
  M src/cli/render.rs           (Effective Bash capability / Bash interrupting boundary lines)
  M src/discovery/agents/opencode.rs (resolve_effective_bash, sandbox detection, precedence)
  M src/discovery/mod.rs        (+EffectiveBashPermission enum, ObservedBashCapability.effective_state)
  M src/mcp/tools.rs            (+effective_bash_capability / bash_boundary on SafeExplainedPath)
  M tests/integration.rs        (register sprint016 modules)
  M tests/integration/opencode_scan_test.rs (ASK fixture expectation)
  ?? docs/internal/sprints/SPRINT-016-support-note.md
  ?? tests/integration/sprint016_cli_test.rs
  ?? tests/integration/sprint016_mcp_test.rs

new fixtures (R1–R10) and their assertions
  opencode.rs mod tests:
    R1  r1_deny_overrides_allow_becomes_denied
    R2  r2_ask_becomes_approval_gated_and_mandatory_approval_boundary
    R3  r3_sandbox_becomes_sandboxed_and_sandbox_boundary
    R4  r4_agent_ask_overridden_by_bash_allow_is_auto_allow_without_interrupt
    R5  r5_state_to_boundary_table
    R8  r8_battery_precedence_and_surface_effective_state
    R9  r9_identical_config_yields_identical_effective_state
  CLI (sprint016_cli_test.rs):
    R6  effective_bash_capability_surfaces_in_explain_for_auto_allow_and_sandbox
        rendered_explain_shows_effective_bash_capability_for_each_state
        approval_gated_and_denied_persist_effective_state_on_can_execute
  MCP (sprint016_mcp_test.rs):
    R7  mcp_get_finding_includes_effective_bash_capability_for_sandbox
        (+ unit safe_explained_path_serializes_effective_bash_capability)
  Secret sweep (R10):
    secret_sweep_never_leaks_fake_token_across_effective_states
        asserts cfut_TESTFAKE... never appears in rendered output or persisted
        evidence/relationship/resource metadata across all four postures.

CLI/MCP effective-state surfacing test additions: see R6/R7 above.
  CLI renders: "Effective Bash capability: <AUTO_ALLOW|APPROVAL_GATED|DENIED|SANDBOXED|UNKNOWN>"
               "Bash interrupting boundary: <MANDATORY_APPROVAL|HARD_DENY|SANDBOX|none>"
  MCP get_finding JSON: effective_bash_capability + bash_boundary on each paths[] object.

effective-state stability result: R9 PASS — identical config => identical EffectiveBashPermission.
secret-sweep result: ZERO — fake token absent in all rendered/metadata outputs.
optional live re-run outcome: GAP-RECORDED — fixture/output-driven per SPRINT-013 §5; no new
    live dogfood required. Sprint 012 contract inherited.
comprehension result: NOT RUN (no external comprehension step defined for this sprint).
usefulness judgments: effective-state surfacing is the honest, developer-facing payoff of 013–015.
defect list and dispositions: expected empty — all R1–R10 green, golden path intact.
architecture pressure-test answers:
  - Effective state feeds existing Boundary/Relationship model; no new domain object.
  - Resolver is pure/deterministic; reuses boundary-evaluation contract (AD005).
  - Secret-safety preserved: only config PATHS as source_locator; never secret values.
  - OpenCode remains the only supported agent.
advancement decision record: see §14.
follow-ups (named, owned, unambiguous):
  - S017: next v0.2 depth sprint (deferred; not started).
  - R10 live token id 6b1a59bb84dd680a1dde77f49b3f357b still pending dashboard deletion
    (external carry-over, not a code blocker).
```

Do not claim v0.2 depth is "closed" merely because effective state is deeper. Claim exactly what the matrix shows: OpenCode's effective Bash capability is resolved with correct precedence, surfaced honestly, and mapped to the correct boundary.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-016 — OpenCode Effective-State Resolution Depth
Status: DONE
Baseline: 42ee0d4 (authored) -> <impl push>

Effective state:
  precedence deny>ask>allow: PASS
  approval mode: PASS
  sandbox: PASS
  bypass: PASS
  maps to correct boundary: PASS

Surfacing:
  CLI effective capability: PASS
  MCP effective capability: PASS

Fixtures:
  broad battery: PASS
  stability across scans: PASS

Validation matrix:
  R1-R10: PASS

Secret sweep: ZERO
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17.

```text
Decision: ADVANCE v0.2 depth.
OpenCode effective Bash capability is now resolved with correct precedence
(deny>ask>allow), approval/sandbox/bypass detection, and honest surfacing in
CLI + MCP. R1–R10 all PASS; secret sweep ZERO; golden path intact
(1 active finding for AUTO_ALLOW). No regression to 013–015 behavior.

v0.2 depth status after S016: S013 (authority tiers), S014 (provenance +
freshness), S015 (finding stability/dedup), S016 (effective-state resolution)
complete. Remaining v0.2 depth: S017, S018, S019 — deferred, not started.

Justification for S017: closes remaining v0.2 ROADMAP §6 commitments not yet
covered by 013–016 (next actor-leg / evidence-depth item). Authoring of S017
is a separate, explicit step; not started here.
```
