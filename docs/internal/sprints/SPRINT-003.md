# Pico — Sprint 003: First Capability — OpenCode Bash

**Status:** COMPLETE
**Sprint:** 003
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `ac76bb6`
**Depends on:** Sprint 002 — First Autonomous Actor: OpenCode
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Teach Pico to determine the first security-relevant capability of an observed autonomous actor.

At the end of Sprint 003, Pico must be able to resolve the effective OpenCode Bash permission that applies to the supported actor and represent the result with evidence-backed Pico domain state.

The core question for this sprint is:

> **Can the observed OpenCode actor execute Bash, is execution approval-gated or denied, and what evidence supports that conclusion?**

Conceptually:

```text
OpenCode Configuration
        +
Applicable Agent Configuration
        +
Bash-Specific Rules
        +
Observable Runtime Mode
        ↓
Effective Bash Permission
        ↓
OpenCode Resource
        ↓
can_execute
        ↓
Bash Resource
        ├── Evidence
        └── Observation
        ↓
SQLite
```

Sprint 001 proved:

> Pico can remember.

Sprint 002 proved:

> Pico can observe an autonomous actor.

Sprint 003 must prove:

> **Pico can resolve one capability without overstating what the actor can do.**

---

# 2. Roadmap Position

The v0.1 golden path is:

```text
External GitHub Content
        ↓
GitHub MCP
        ↓
OpenCode
        ↓
Bash
        ↓
Cloudflare Credential
        ↓
Cloudflare Worker
```

Sprint 003 implements only this edge:

```text
OpenCode
   ↓
Bash
```

This is the remaining capability portion of `ARCHITECTURE.md` Slice 2 — OpenCode discovery.

Sprint 002 deliberately split actor presence from capability analysis. Sprint 003 completes the Bash portion of that split.

MCP configuration and GitHub influence remain separate work.

---

# 3. Sprint Principle

> **Resolve effective capability. Do not infer downstream authority.**

Sprint 003 answers:

```text
Is Bash configured for the supported OpenCode actor?

Which applicable rule determines the result?

Is the effective result ALLOW, ASK, DENY, or UNKNOWN?

What local evidence supports the result?

Is any relevant runtime mode observable?
```

Sprint 003 does NOT answer:

```text
Which commands OpenCode will execute in the future?

Whether a user will approve an ASK request?

Which credentials Bash can access?

Which MCP servers or tools OpenCode can use?

Whether GitHub content can influence OpenCode?

Whether OpenCode can reach Cloudflare or production?

Whether an attack path or finding exists?
```

Configured capability is not proof of use.

Approval-gated capability is not automatic capability.

Bash capability alone is not cloud authority.

---

# 4. Expected User Experience

Given a supported OpenCode actor with effective Bash permission `ALLOW`:

```bash
pico scan
```

Pico should complete successfully and report one capability relationship.

Conceptually:

```text
Pico scan complete

Status: COMPLETE

Agents:         1
Resources:      2
Relationships:  1
Evidence:       2+
Findings:       0
```

The two Resources are conceptually:

```text
OpenCode
Bash
```

The Relationship is conceptually:

```text
OpenCode → can_execute → Bash
```

The effective permission must remain inspectable as:

```text
ALLOW
ASK
DENY
UNKNOWN
```

Exact CLI wording and count presentation may follow the existing application contract.

If OpenCode is absent:

```text
Status: COMPLETE
Agents: 0
Resources: 0
Relationships: 0
Findings: 0
```

Absence remains a valid scan result.

---

# 5. Scope

Sprint 003 includes only the minimum functionality required to resolve OpenCode Bash capability safely and deterministically.

## Required

Implement:

```text
OpenCode effective-configuration resolution needed for Bash

supported Bash permission parsing

applicable agent/default rule selection

applicable Bash pattern handling needed for the supported contract

observable runtime-mode handling

normalized effective result:
  ALLOW
  ASK
  DENY
  UNKNOWN

stable Bash Resource

stable OpenCode-to-Bash Relationship

supporting Evidence

scan-scoped Observations

ScanService integration

SQLite persistence

CLI/result count integration

sanitized fixtures

adapter, resolution, persistence, and integration tests
```

---

# 6. Required Research Before Implementation

Sprint 003 interprets external-system security semantics.

Do not implement permission resolution from memory or assumptions.

Before changing code, verify current authoritative OpenCode documentation and source behavior needed to establish:

```text
supported configuration locations and formats

configuration merge/precedence behavior

permission-rule representation

Bash-specific and wildcard rule behavior

pattern ordering or matching semantics

per-agent override behavior

default behavior when Bash is not explicitly configured

runtime or launch modes that change ASK behavior

which denies remain enforced
```

Research only what is required for this sprint.

Do not research or implement MCP behavior, provider credentials, GitHub influence, or Cloudflare authority.

If current OpenCode behavior contradicts the canonical assumptions materially, stop and report the contradiction before implementation.

Do not silently invent compatibility behavior.

---

# 7. Capability Resolution Contract

The adapter must resolve effective permission, not merely copy a field from one file.

Conceptually:

```text
Base Permission
      +
Tool-Specific Rule
      +
Pattern-Specific Rule
      +
Applicable Agent Override
      +
Observable Runtime Mode
      =
Effective Bash Permission
```

The supported algorithm must be deterministic and documented in code/tests.

Equivalent supported configuration and runtime inputs must produce equivalent normalized output.

Pico must preserve enough evidence to explain which inputs determined the result.

---

# 8. Normalized Permission Vocabulary

Use the smallest normalized vocabulary required by the canonical architecture:

```text
ALLOW
ASK
DENY
UNKNOWN
```

## ALLOW

The supported effective state permits Bash without an approval boundary that Pico can establish.

Pico may represent the capability relationship as usable, subject to evidence quality.

## ASK

Bash is available only through an approval step under the supported effective state.

`ASK` must not be normalized to `ALLOW`.

`ASK` must not be normalized to `DENY`.

Pico does not predict whether approval will be granted.

## DENY

The supported effective state explicitly prevents Bash execution.

Pico must preserve evidence of the explicit deny.

The representation must not claim usable Bash capability.

## UNKNOWN

Pico cannot establish the effective Bash result from supported evidence.

`UNKNOWN` is a valid security result.

Unknown must never be silently upgraded to `ALLOW`.

---

# 9. Runtime Mode

`TECHNICAL.md` warns that runtime behavior may change the effect of `ASK`, while explicit `DENY` may remain enforced.

Therefore:

```text
configured ASK
```

does not automatically mean:

```text
effective ASK
```

if an observable supported runtime mode bypasses or automatically approves it.

Sprint 003 must:

```text
use documented local runtime/launch evidence when safely observable

record runtime mode as UNKNOWN when it cannot be established

avoid claiming automatic execution when configured state alone is insufficient

preserve explicit DENY according to verified OpenCode semantics
```

Do not inspect unrelated processes broadly.

Do not attach to a running process.

Do not execute OpenCode to probe its behavior.

Do not manufacture a runtime mode from configuration prose.

---

# 10. Command and Pattern Scope

OpenCode may support granular Bash patterns.

Sprint 003 must not claim unrestricted Bash merely because one narrow command pattern is allowed.

The implementation must preserve the distinction between:

```text
unrestricted Bash

bounded Bash pattern(s)

approval-gated Bash

explicitly denied Bash

mixed or unresolved Bash rules
```

If the supported configuration allows only selected commands, evidence and normalized metadata must retain safe, non-secret scope information needed to avoid an unrestricted-capability claim.

Do not build command execution analysis.

Do not attempt to enumerate all possible shell commands.

Do not execute matching or non-matching commands as a probe.

If the current domain cannot truthfully represent bounded or mixed command scope, report the architectural friction instead of flattening it to `ALLOW`.

---

# 11. Adapter Boundary

OpenCode-specific permission knowledge belongs in the OpenCode adapter.

Conceptually:

```text
CLI
 ↓
ScanService
 ↓
Discovery
 ↓
OpenCode Adapter
 ├── configuration discovery
 ├── permission parsing
 ├── precedence resolution
 └── runtime-mode resolution
 ↓
Normalized Capability Fact
 ↓
Domain
 ↓
Persistence
```

The CLI must not parse OpenCode configuration.

`ScanService` must not implement OpenCode rule precedence.

The generic domain must not import OpenCode-specific permission types.

OpenCode-specific structures may exist behind the adapter boundary.

Do not create a plugin framework.

Do not add dynamic adapter loading.

---

# 12. Resource Normalization

Continue using the stable OpenCode Resource established by Sprint 002:

```text
agent:opencode
```

Represent Bash as a generic capability/tool Resource using the repository's existing canonical-key semantics.

The architecture and existing relationship contract anticipate:

```text
shell:bash
```

Do not introduce an OpenCode-specific Bash domain object.

Conceptually:

```text
Resource
  canonical_key: shell:bash
  kind: shell / capability vocabulary consistent with the domain
  provider: local
  name: Bash
```

The exact generic `kind` and provider vocabulary should remain consistent with canonical architecture and repository conventions.

---

# 13. Relationship Normalization

Represent the actor-to-capability edge using the generic `Relationship` domain.

The existing domain contract anticipates:

```text
canonical_key:
agent:opencode|can_execute|shell:bash

from:
agent:opencode

to:
shell:bash

kind:
can_execute
```

The representation must preserve two separate concepts:

```text
relationship evidential state

effective permission result
```

Do not use evidential state as an undocumented substitute for `ALLOW`, `ASK`, `DENY`, or `UNKNOWN`.

The normalized permission and any bounded command scope should be explicit, safe metadata or an equivalent small domain representation.

Expected conceptual mappings:

```text
ALLOW
  relationship exists
  effective permission = ALLOW

ASK
  relationship/capability availability is represented
  effective permission = ASK
  approval requirement remains explicit

DENY
  explicit blocked/denied state is represented without claiming usable execution
  effective permission = DENY

UNKNOWN
  uncertainty is represented honestly
  effective permission = UNKNOWN
```

If the existing `RelationshipState` mapping creates ambiguity, use the smallest in-scope clarification and test it exhaustively.

Do not build general boundary evaluation or attack-path logic.

---

# 14. Stable Identity and History

Repeated scans of unchanged effective state must produce:

```text
1 stable OpenCode Resource

1 stable Bash Resource

1 stable OpenCode-to-Bash Relationship

scan-specific Evidence

scan-specific Observations
```

The second scan must not duplicate the Resource or Relationship.

If effective permission changes between scans:

```text
ASK → ALLOW
```

or:

```text
ALLOW → DENY
```

the stable Relationship identity should remain the same while scan-specific evidence and observations preserve what each scan saw.

Do not rewrite historical Evidence to match the latest state.

---

# 15. Evidence

Every capability conclusion must answer:

> **Why does Pico believe OpenCode can, may with approval, cannot, or may not be able to execute Bash?**

Evidence should record only the minimum safe facts required to explain resolution.

Conceptually:

```text
Evidence
  scan_id
  class
  source_type
  source_locator
  subject
  normalized observation
  captured_at
  freshness
  sensitivity
  safe metadata
```

Useful evidence may include:

```text
applicable configuration locator

applicable rule class

normalized configured permission

normalized effective permission

safe command-scope summary

runtime mode or UNKNOWN

resolution inputs/provenance
```

Do not persist complete raw configuration.

Do not persist unrelated OpenCode fields.

---

# 16. Evidence Class and Derivation

Preserve the canonical distinction between directly observed input and deterministically resolved output.

Conceptually:

```text
DECLARED / DIRECT evidence
  authoritative OpenCode configuration states a rule

DERIVED evidence
  Pico combines applicable rules and observable runtime state
  into an effective permission
```

Do not label a derived effective result as direct merely because its inputs came from a file.

Do not use `INFERRED` when the result is deterministically established from supported authoritative inputs.

Use `UNKNOWN` when required resolution inputs are unavailable or unsupported.

---

# 17. Evidence Safety

OpenCode configuration may contain sensitive unrelated state.

Pico must not persist:

```text
API keys
tokens
passwords
credentials
private keys
secret environment values
authorization headers
provider configuration unrelated to Bash resolution
full raw configuration
```

Fixtures must contain no real secrets.

Use a synthetic sentinel such as:

```text
TEST_SECRET_SHOULD_NOT_PERSIST
```

Place it in an irrelevant or sensitive field of a supported fixture.

After scanning, verify that the sentinel does not appear in Pico-controlled persistent state, logs, or diagnostic output produced by the test.

---

# 18. Observations

Each scan that observes the OpenCode actor and resolves Bash state should create scan-scoped observations sufficient to preserve:

```text
the Bash Resource sighting

the OpenCode-to-Bash Relationship sighting

the effective permission seen during that Scan
```

Conceptually:

```text
Scan 12
OpenCode → Bash → ASK

Scan 13
OpenCode → Bash → ALLOW
```

The exact observation vocabulary should remain small and consistent with the existing domain.

Do not create a general event or change-detection system.

Sprint 003 preserves history; it does not alert on change.

---

# 19. Scan Semantics

For supported states:

```text
OpenCode absent
  → COMPLETE
  → no Bash capability state

OpenCode present, capability resolved
  → COMPLETE

OpenCode present, required supported configuration malformed
  → PARTIAL
  → retain only trustworthy evidence

OpenCode present, capability genuinely unresolvable from supported state
  → COMPLETE or PARTIAL according to the existing scan contract
  → effective permission UNKNOWN
  → no false capability claim
```

The implementation must distinguish:

```text
absence

explicit deny

approval-gated access

unknown effective state

adapter failure
```

Do not collapse these into one generic error.

---

# 20. Relationship and Finding Scope

Sprint 003 may create only the relationship required for the OpenCode-to-Bash capability edge.

Expected maximum security graph slice:

```text
OpenCode → can_execute → Bash
```

Do not create relationships to:

```text
credentials
environment variables
filesystems
MCP servers
GitHub
Cloudflare
production resources
```

Sprint 003 produces no Findings.

Expected:

```text
AttackPaths: 0
Findings: 0
```

A Bash capability is not inherently a vulnerability.

---

# 21. Filesystem and Process Safety

Discovery must remain bounded to documented OpenCode configuration and narrowly supported local runtime evidence.

Do not recursively crawl:

```text
/
the entire home directory
all mounted volumes
unrelated repositories
```

Do not:

```text
execute shell commands through OpenCode
launch OpenCode as a probe
attach to OpenCode processes
read arbitrary process memory
inspect unrelated environment secrets
trace system calls
modify configuration
```

Pico observes local declarative and safely observable state only.

---

# 22. Network Boundary

Sprint 003 requires no network access.

Do not contact:

```text
OpenCode services
model providers
GitHub
MCP servers
Cloudflare
package registries
telemetry endpoints
```

The sprint must be fully fixture-testable offline.

No credentials are required.

---

# 23. Required Fixtures

Add sanitized fixtures for at least:

```text
OpenCode absent

Bash explicitly ALLOW

Bash explicitly ASK

Bash explicitly DENY

Bash unspecified/default behavior

wildcard rule affecting Bash

Bash-specific rule overriding a broader rule

supported per-agent override

bounded Bash command pattern

mixed patterns that cannot be flattened safely

observable runtime mode affecting ASK, if supported

runtime mode unavailable

malformed supported configuration

irrelevant fields containing a synthetic secret sentinel
```

Fixture shape must follow verified current OpenCode behavior.

Do not preserve outdated or invented OpenCode semantics merely to satisfy a preconceived test.

---

# 24. Required Tests

## Permission resolution tests

Verify:

```text
ALLOW resolves deterministically

ASK remains distinct from ALLOW and DENY

DENY remains enforced according to supported semantics

UNKNOWN is produced honestly

default behavior matches authoritative OpenCode behavior

precedence and overrides match authoritative behavior

bounded patterns do not become unrestricted Bash

runtime mode affects resolution only when supported evidence exists
```

## Domain normalization tests

Verify:

```text
Bash normalizes into a generic Resource

OpenCode-to-Bash uses a generic Relationship

canonical Resource identity is deterministic

canonical Relationship identity is deterministic

effective permission remains separate from evidential state
```

## Evidence tests

Verify:

```text
source locators identify supported inputs

applicable rules are explainable

derived output references its resolution inputs as appropriate

ASK, DENY, bounded scope, and UNKNOWN remain distinguishable

raw configuration is not persisted

secret-like values do not enter persistence or diagnostics
```

## Observation tests

Verify:

```text
Bash Resource observation belongs to current Scan

Relationship observation belongs to current Scan

effective permission seen in each Scan is preserved

second scan creates new scan-scoped observations
```

## Integration tests

For controlled supported configurations, verify:

```text
ALLOW scan
ASK scan
DENY scan
UNKNOWN scan where applicable
OpenCode-absent scan
malformed-state scan
```

## Repeated-scan tests

Run the same configuration twice.

Verify:

```text
2 completed Scans
1 stable OpenCode Resource
1 stable Bash Resource
1 stable capability Relationship
scan-specific Evidence
scan-specific Observations
```

Change effective permission between controlled scans.

Verify:

```text
stable Resource identities
stable Relationship identity
historical scan evidence preserved
latest normalized state updated intentionally
no history rewritten
```

## Secret persistence regression

After scanning the sentinel fixture, search Pico-controlled persisted fields and produced diagnostics.

Expected:

```text
TEST_SECRET_SHOULD_NOT_PERSIST occurrences = 0
```

---

# 25. Definition of Done

Sprint 003 is COMPLETE only when all of the following are true:

- [ ] Current authoritative OpenCode Bash semantics have been verified.
- [ ] Supported effective configuration is resolved deterministically.
- [ ] Applicable Bash permission rules are resolved.
- [ ] Applicable agent overrides are resolved where supported.
- [ ] Observable runtime mode is incorporated safely.
- [ ] Unobservable runtime mode remains `UNKNOWN` where required.
- [ ] `ALLOW`, `ASK`, `DENY`, and `UNKNOWN` remain distinct.
- [ ] Bounded command scope is not overstated as unrestricted Bash.
- [ ] Bash normalizes into a generic Resource.
- [ ] OpenCode-to-Bash normalizes into a generic Relationship.
- [ ] Resource identity is stable across scans.
- [ ] Relationship identity is stable across scans.
- [ ] Detection produces supporting Evidence.
- [ ] Detection produces scan-scoped Observations.
- [ ] Permission changes preserve historical evidence.
- [ ] OpenCode absence remains a successful scan.
- [ ] Malformed supported state does not create false capability.
- [ ] Findings remain zero.
- [ ] No MCP discovery exists.
- [ ] No GitHub integration exists.
- [ ] No credential discovery exists.
- [ ] No Cloudflare integration exists.
- [ ] No AttackPath logic exists.
- [ ] No network access is required.
- [ ] No credentials are required.
- [ ] Raw OpenCode configuration is not indiscriminately persisted.
- [ ] Synthetic secret values do not enter Pico persistence or diagnostics.
- [ ] Full tests pass.
- [ ] `cargo check` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` passes.
- [ ] `cargo fmt --check` passes.
- [ ] `cargo build --release` passes.
- [ ] Working-tree diff contains only Sprint 003 work.

---

# 26. Manual Verification

Using controlled local fixtures/environments, verify at minimum:

## ALLOW

```text
pico init
pico scan

Status: COMPLETE
Agents: 1
Resources: 2
Relationships: 1
Findings: 0
Effective Bash: ALLOW
```

## ASK

```text
Status: COMPLETE
Effective Bash: ASK
```

Verify that Pico does not describe `ASK` as automatic execution.

## DENY

```text
Status: COMPLETE
Effective Bash: DENY
```

Verify that Pico does not claim usable execution.

## ABSENT

```text
Status: COMPLETE
Agents: 0
Resources: 0
Relationships: 0
Findings: 0
```

Inspect SQLite after repeated scans.

Verify stable Resources and Relationship plus scan-specific Evidence and Observations.

Perform the synthetic-secret persistence check.

---

# 27. Architecture Pressure Test

Before declaring completion, answer:

1. Can the OpenCode adapter resolve effective Bash permission rather than one declared field?
2. Can Pico distinguish capability availability from automatic execution?
3. Can Pico represent `ASK` without treating it as either `ALLOW` or `DENY`?
4. Can Pico represent bounded command patterns without overstating authority?
5. Does the generic Resource/Relationship model fit the first real capability edge?
6. Does Relationship evidential state remain separate from permission semantics?
7. Can scan-specific Evidence and Observations preserve permission changes over time?
8. Does OpenCode-specific precedence remain outside the generic domain?
9. Can Pico resolve the capability without persisting unrelated or secret configuration?
10. Did the implementation avoid beginning MCP/GitHub or credential work?

If any answer is materially **NO**, do not hide it.

Fix it only if the smallest correct fix is clearly within Sprint 003 scope.

Otherwise stop and report the architectural friction for review.

---

# 28. Stop Conditions

STOP implementation if Sprint 003 appears to require:

```text
MCP server discovery

MCP tool inspection

GitHub influence modeling

credential discovery

environment-secret discovery

Cloudflare integration

provider API calls

general command execution analysis

executing OpenCode or Bash as a probe

Security Graph traversal

Influence Analysis

Authority Analysis beyond the local Bash edge

Boundary Evaluation

AttackPath construction

Finding generation

severity or remediation

runtime monitoring

enforcement

arbitrary plugin loading

Sprint 004 functionality
```

Document the dependency.

Do not solve it in Sprint 003.

---

# 29. Sprint Deliverables

Expected deliverables:

```text
verified OpenCode Bash discovery contract

effective-configuration resolution required for Bash

Bash permission resolver

runtime-mode handling required for truthful resolution

generic Bash Resource normalization

generic can_execute Relationship normalization

Evidence generation

Observation generation

ScanService and persistence integration

CLI/result updates needed to expose the capability result

sanitized fixtures

adapter and resolver tests

domain/persistence tests as needed

integration and repeated-scan tests

secret-persistence regression

SPRINT-003.md completion evidence
```

Do not modify Sprint 001 or Sprint 002.

Do not rewrite canonical documents unless implementation exposes a genuine contradiction requiring founder review.

If such a contradiction exists, stop rather than silently rewriting Canon.

---

# 30. Completion Evidence

When implementation is complete, set:

```text
Status: COMPLETE
```

Record:

```text
Baseline:
ac76bb6

Implementation commit:
<sha>

Authoritative OpenCode contract:
<summary and sources>

Tests:
<result>

cargo check:
<result>

clippy:
<result>

fmt:
<result>

release build:
<result>

ALLOW scan:
<result>

ASK scan:
<result>

DENY scan:
<result>

UNKNOWN scan:
<result or documented non-applicability>

OpenCode-absent scan:
<result>

Repeated-scan identity:
<result>

Permission-change history:
<result>

Evidence persistence:
<result>

Observation persistence:
<result>

Secret-sentinel persistence check:
<result>

Relationships:
<expected capability-only result>

Findings:
0

Network required:
NO

Credentials required:
NO

Sprint 004+ functionality implemented:
NO
```

Also record the architecture pressure-test results.

## Completion Record

Baseline:
`6d379a7`

Implementation commit:
`13e469a feat(discovery): resolve OpenCode Bash capability`

Authoritative OpenCode contract:

- OpenCode merges configuration layers, with later supported local project configuration overriding user configuration.
- The built-in `build` agent starts with permissive defaults; top-level permission rules apply before per-agent overrides.
- Bash accepts `allow`, `ask`, and `deny`, including ordered command-pattern rules; the last matching rule wins.
- Auto mode can automatically approve `ask`, while explicit `deny` remains enforced.
- Pico resolves the Sprint 002 supported user/project JSON/JSONC configuration boundary. Static scans record runtime mode as `UNKNOWN` and never describe `ASK` as observed automatic execution.

Authoritative sources checked August 24, 2026:

- `https://opencode.ai/docs/config/`
- `https://opencode.ai/docs/permissions/`
- `https://opencode.ai/docs/agents/`
- `https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/permission/index.ts`
- `https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/agent/agent.ts`

Tests:
`90 passed / 0 failed`

`cargo check`:
PASS

`cargo clippy --all-targets -- -D warnings`:
PASS

`cargo fmt --check`:
PASS

`cargo build --release`:
PASS

ALLOW controlled scan:
COMPLETE — 1 Agent, 2 Resources, 1 capability Relationship, 0 Findings, effective Bash `ALLOW`.

ASK controlled scan:
COMPLETE — 1 Agent, 2 Resources, 1 capability Relationship, 0 Findings, effective Bash `ASK`, runtime mode `UNKNOWN`.

DENY controlled scan:
COMPLETE — 1 Agent, 2 Resources, 1 blocked capability Relationship, 0 Findings, effective Bash `DENY`.

UNKNOWN controlled scan:
COMPLETE — mixed bounded command policy remains `UNKNOWN` / `BOUNDED`; no unrestricted Bash claim.

OpenCode-absent controlled scan:
COMPLETE — 0 Agents, 0 Resources, 0 Relationships, 0 Evidence, 0 Findings.

Repeated-scan identity:
PASS — 2 Scans preserve 1 `agent:opencode` Resource, 1 `shell:bash` Resource, and 1 stable `can_execute` Relationship.

Permission-change history:
PASS — `ASK` followed by `ALLOW` preserves scan-specific Evidence and Relationship Observations without duplicating stable identity.

Evidence persistence:
PASS — each capability Evidence record is scan-scoped and linked through `relationship_evidence` to the stable Relationship.

Observation persistence:
PASS — Bash Resource and capability Relationship observations are scan-scoped and preserve normalized permission metadata.

Secret-sentinel persistence check:
PASS — `TEST_SECRET_SHOULD_NOT_PERSIST` occurred 0 times in Pico-controlled persisted state.

Relationships:
1 capability-only Relationship when supported OpenCode is present; 0 when absent.

Findings:
0

Network required at scan runtime:
NO

Credentials required:
NO

Raw OpenCode configuration persisted:
NO

Sprint 004+ functionality implemented:
NO

Architecture pressure test:

- Effective permission resolution: PASS within the explicitly supported local configuration boundary.
- Capability versus automatic execution: PASS.
- `ASK` representation: PASS.
- Bounded command-pattern honesty: PASS — mixed scope becomes `UNKNOWN` / `BOUNDED`.
- Generic Resource/Relationship model: PASS.
- Evidential state versus permission semantics: PASS.
- Historical Evidence/Observation model: PASS.
- Adapter boundary: PASS.
- Secret safety: PASS.
- Scope preservation: PASS.

Validation tooling notes:

- Agent CI reported no `.github/workflows` directory, so there was no local workflow to execute.
- `vet` was invoked after each logical change unit. Its direct model review could not run because no Anthropic API credential is configured; elevated agentic fallback was not authorized. Required Rust verification and manual inspection passed independently.

Follow-ups for the next authorized sprint:

- Custom, inline, remote, managed, and live session permission layers remain outside the Sprint 002/003 supported local adapter contract. They must not be silently treated as resolved when that contract expands.
- Live OpenCode auto-mode and session-persisted approvals remain runtime evidence questions. Static `ASK` evidence retains runtime mode `UNKNOWN`.
- Bounded/mixed Bash policies intentionally remain `UNKNOWN` at the command-independent relationship level until Pico has a truthful generic scope representation.

---

# 31. Commit

If and only if Sprint 003 is fully implemented and verified:

```text
stage only Sprint 003 changes

inspect the staged diff

commit with:

feat(discovery): resolve OpenCode Bash capability
```

Do not amend previous commits.

Do not push unless explicitly authorized at implementation time.

Do not begin Sprint 004.

---

# 32. Sprint Exit

Sprint 003 proves:

> **Pico can resolve whether its first observed autonomous actor has Bash capability and explain the result with evidence.**

At sprint exit, Pico should be able to represent:

```text
OpenCode
   ↓ can_execute
Bash

Effective permission:
ALLOW | ASK | DENY | UNKNOWN
```

It does not yet establish:

```text
what can influence OpenCode

what credentials Bash can reach

what cloud authority exists

whether a complete attack path exists
```

The next roadmap question is:

> **What external content can reach OpenCode through its configured MCP surface?**

That belongs to the next sprint.

Do not begin it here.
