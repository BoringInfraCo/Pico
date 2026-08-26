# Pico — Sprint 016: OpenCode Effective-State Resolution Depth

**Status:** READY

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
    → NEW-FIXTURE (effective_bash_precedence_deny_overrides_allow)

R2  Approval mode detected (manual approval required vs auto-allow)
    → NEW-FIXTURE (approval_mode_detected_as_approval_gated)

R3  Sandbox confinement detected and mapped to a Sandbox boundary
    → NEW-FIXTURE (sandbox_detected_as_sandbox_boundary)

R4  Bypass condition detected (allow bypasses required approval => AUTO_ALLOW)
    → NEW-FIXTURE (approval_bypass_resolves_to_auto_allow)

R5  Effective state maps to the correct finding boundary
    (AUTO_ALLOW => no interrupt; APPROVAL_GATED => MandatoryApproval;
     DENIED => HardDeny; SANDBOXED => Sandbox)
    → NEW-FIXTURE (effective_state_maps_to_correct_boundary)

R6  Explanation surfaces effective Bash capability + interrupting boundary (CLI)
    → FIXTURE-VERIFIED by sprint010_cli_test.rs (extends explained view) + NEW assertion

R7  Explanation surfaces effective Bash capability + interrupting boundary (MCP)
    → FIXTURE-VERIFIED by sprint011_mcp_golden_test.rs (extends) + NEW assertion

R8  Sanitized fixture set: precedence, runtime modes, transport, credential sources,
    token/resource scopes, provider failures
    → NEW-FIXTURE (broad fixture battery; see §7)

R9  Effective-state resolution is deterministic across repeated identical scans
    → NEW-FIXTURE (effective_state_stable_across_identical_scans) — ties to S015 stability

R10 No secret leakage: config paths/sources may appear as source_locator, never secret values
    → FIXTURE-VERIFIED by existing secret-sweep + NEW check on emitted source_locators
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

- `effective_bash_precedence_deny_overrides_allow` — config with both allow and deny => DENIED.
- `approval_mode_detected_as_approval_gated` — `ask`/`approval` config => APPROVAL_GATED + MandatoryApproval boundary.
- `sandbox_detected_as_sandbox_boundary` — sandbox config => SANDBOXED + Sandbox boundary.
- `approval_bypass_resolves_to_auto_allow` — an allow that bypasses approval => AUTO_ALLOW (no interrupt).
- `effective_state_maps_to_correct_boundary` — table-driven: each state => expected boundary.
- broad battery (R8): precedence/runtime/transport/credential/scope/failure variants.
- `effective_state_stable_across_identical_scans` (R9).

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

When validation concludes, set `Status: DONE` (or `BLOCKED`) and record:

```text
completion date and verified baseline
commits (authoring; any defect fixes; evidence record)
repository state
new fixtures (R1–R10) and their assertions
CLI/MCP effective-state surfacing test additions
effective-state stability result
secret-sweep result
optional live re-run outcome (or GAP-RECORDED with reason)
comprehension result (PASS/FAIL/NOT RUN + confusion points)
usefulness judgments
defect list and dispositions (expected empty)
architecture pressure-test answers
advancement decision record
follow-ups (named, owned, unambiguous)
```

Do not claim v0.2 depth is "closed" merely because effective state is deeper. Claim exactly what the matrix shows: OpenCode's effective Bash capability is resolved with correct precedence, surfaced honestly, and mapped to the correct boundary.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-016 — OpenCode Effective-State Resolution Depth
Status: DONE | BLOCKED
Baseline: <verified SHA>

Effective state:
  precedence deny>ask>allow: PASS | FAIL
  approval mode: PASS | FAIL
  sandbox: PASS | FAIL
  bypass: PASS | FAIL
  maps to correct boundary: PASS | FAIL

Surfacing:
  CLI effective capability: PASS | FAIL
  MCP effective capability: PASS | FAIL

Fixtures:
  broad battery: PASS | FAIL
  stability across scans: PASS | FAIL

Validation matrix:
  R1-R10: <statuses>

Secret sweep: ZERO | INCIDENT
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17. Records whether v0.2 depth is advanced, extended, refined, or stopped, and why the next v0.2 sprint (017) is justified.
