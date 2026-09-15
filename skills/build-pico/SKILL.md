---
name: build-pico
description: The canonical engineering playbook for building Pico. Use for every substantive implementation, architectural review, sprint execution, refactor, documentation update, adapter integration, and engineering decision.
---

# SKILL.md

# Build Pico

> Engineering Constitution

This document defines how Pico is engineered.

It is the canonical engineering playbook for both human engineers and AI coding agents.

Its purpose is not to maximize code generation.

Its purpose is to maximize shipping velocity **without sacrificing architectural coherence or security honesty**.

Pico should move fast because the product stays focused.

Every meaningful implementation should follow this document.

---

# Why This Document Exists

Software projects become complicated gradually.

Not because engineers intentionally overbuild them.

Because small local decisions accumulate:

- abstractions are introduced too early
- future roadmap concepts leak into current implementation
- provider-specific logic spreads into the core
- documentation grows faster than the product
- AI agents optimize for completeness instead of scope
- implementation begins to redefine the architecture
- uncertainty gets silently upgraded into certainty
- secrets leak into persisted state because it was convenient

Pico intentionally avoids this.

The product should remain understandable.

The architecture should remain small.

The active Sprint should remain narrow.

Security claims should remain honest.

The code should reflect what Pico needs **today**, not everything it may need someday.

---

# The Engineering North Star

Every implementation should make Pico better at one or more of these things:

```text
Discover
Connect
Analyze
Explain
```

But only the capability required by the current roadmap phase should be implemented.

Whenever multiple implementation choices exist:

> Choose the smallest design that satisfies the active Sprint while preserving Pico's architectural boundaries and evidence honesty.

---

# What Pico Is

Pico is a local-first, read-only developer security tool that discovers coding agents, MCP capabilities, external influence, credential reachability, and connected infrastructure; constructs an evidence-backed security graph; and identifies dangerous potential attack paths from untrusted influence to consequential authority.

Pico's foundational thesis is:

> **Agent security risk emerges where untrusted influence intersects autonomous authority.**

The first product loop is:

```text
Discover
   ↓
Connect
   ↓
Analyze
   ↓
Explain
```

The longer-term progression is:

```text
Discover the path
      ↓
Remember the path
      ↓
Observe the path
      ↓
Understand influence across the path
      ↓
Detect dangerous change or compromise
      ↓
Control selected path boundaries
      ↓
Contain propagation
      ↓
Defend autonomous ecosystems
```

Pico's first supported environment is deliberately narrow:

- OpenCode (first agent adapter)
- GitHub MCP (first external-influence surface)
- Bash (first local execution capability)
- Cloudflare (first authority adapter)
- Cloudflare Worker (first consequential sink)

These adapters remain integrations.

They never define Pico.

---

# What Pico Is Not

Pico V0 is not:

- an enterprise security platform
- a SIEM
- an EDR
- a cloud security posture platform
- a generic asset inventory
- an agent runtime
- an agent sandbox
- an agent firewall
- a policy engine
- a prompt-injection classifier
- an AI penetration-testing product
- a hosted-first service
- an organization-wide dashboard
- a multi-user RBAC system
- a CI enforcement gate
- a broad integration catalog
- an arbitrary plugin platform
- a multi-agent defense system
- an automatic remediation system

Pico V0 does not:

- modify agent permissions
- modify MCP configuration
- rotate or revoke credentials
- change infrastructure
- deploy code
- execute an Attack Path
- prove authority with destructive operations
- shut down agents
- collect full prompt or source content by default
- use an LLM to establish security truth
- support every coding agent, MCP server, provider, or credential type

Pico may eventually observe runtime, remember history, and control selected boundaries.

None of those capabilities define V0.

---

# Product Philosophy

Pico begins with one belief:

> **Influence × Authority = Agent Attack Surface.**

Pico exists to discover, explain, and eventually control those paths.

The product should remain valuable without AI.

Resources, relationships, evidence, observations, attack paths, and findings should be deterministic wherever possible.

An LLM may explain a Pico conclusion. It must never create the conclusion.

---

# Engineering Philosophy

Pico should be built through short feedback loops.

Prefer shipping over predicting.

Prefer vertical slices over platform building.

Prefer real environment behavior over theoretical abstractions.

Prefer explicit behavior over hidden magic.

Prefer boring infrastructure over unnecessary cleverness.

Prefer effective state over declared state.

Prefer changing code over maintaining speculative documentation.

Prefer `UNKNOWN` over false precision.

The fastest path is not the one with the most code.

The fastest path is the one with the fewest wrong assumptions and the fewest invented certainties.

---

# The Pico Canon

Pico deliberately keeps its permanent documentation small.

The canonical product documents are:

1. `docs/internal/PRODUCT_DEFINITION.md`
2. `docs/internal/TECHNICAL.md`
3. `docs/internal/ARCHITECTURE.md`
4. `docs/internal/ROADMAP.md`
5. this `SKILL.md`

These are the guiding lights.

Everything else should exist only when it earns the right to exist.

---

# Product Canon

Read first:

- `docs/internal/PRODUCT_DEFINITION.md`

This answers:

> What is Pico?

> Why does it exist?

> What does it deliberately not become?

> What is the golden path?

> What promises must V0 keep?

---

# Technical Canon

Read second:

- `docs/internal/TECHNICAL.md`

This answers:

> What is technically feasible?

> What is the security equation?

> How are influence, authority, boundaries, and confidence modeled?

> What are the authority-resolution tiers?

> What can Pico claim, and what must it refuse to claim?

---

# Architecture Canon

Read third:

- `docs/internal/ARCHITECTURE.md`

This answers:

> How is Pico structured?

> What belongs in the observed domain vs the analyzed domain?

> What do Scan, Observation, Resource, Relationship, Evidence, Boundary, AttackPath, and Finding own?

> How do discovery, graph, analysis, and interfaces fit together?

> What are the settled architecture decisions?

---

# Roadmap Canon

Read fourth:

- `docs/internal/ROADMAP.md`

This answers:

> What are we proving now?

> What comes later?

The Roadmap describes direction.

It is **not permission to implement future features early**.

Future roadmap concepts must not leak into the active Sprint unless explicitly required.

---

# Execution Canon

Read fifth:

- Active Sprint under `docs/internal/sprints/`

This answers:

> What exactly are we building now?

The Sprint defines today's implementation boundary.

The Sprint never overrides the Product Definition, Technical model, Architecture, or Roadmap.

---

# Source of Truth Order

When sources disagree, use this order:

```text
PRODUCT_DEFINITION.md
   ↓
TECHNICAL.md
   ↓
ARCHITECTURE.md
   ↓
ROADMAP.md
   ↓
Active Sprint
   ↓
Current Code
```

The code reflects implementation reality.

It does not automatically redefine product direction.

If code conflicts with the Canon:

report the conflict.

Do not silently change the Canon to match the implementation.

---

# Core Product Progression

Pico evolves in this order:

```text
DISCOVER
   ↓
CONNECT
   ↓
ANALYZE
   ↓
EXPLAIN
   ↓
REMEMBER
   ↓
DETECT CHANGE
   ↓
OBSERVE RUNTIME
   ↓
INTERRUPT
```

This order is intentional.

Do not skip ahead.

v0.1 proves one path. v0.2 deepens its evidence. v0.3 earns limited expansion. v0.4 remembers change. v0.5 observes runtime. v0.6 follows agent handoffs. v0.7 interrupts selected paths.

---

# Architectural Invariants

These rules must remain true.

## Invariant 1 — Adapters Discover, the Graph Analyzes

OpenCode is an adapter.

GitHub MCP discovery is an adapter concern.

Cloudflare is an adapter.

No adapter should become Pico Core.

Adapters emit resources, relationships, and evidence.

Only the analysis engine constructs influence paths, authority paths, attack paths, boundaries, severity, confidence, and findings.

Adapters must never emit `attack_path` or findings directly.

Provider-specific API models must not spread through the domain.

---

## Invariant 2 — The Domain Model Is Provider-Independent

Pico Core reasons about normalized security concepts.

Examples include:

- Scan
- Observation
- Resource
- Relationship
- Evidence
- Boundary
- AttackPath
- Finding

Provider-specific metadata may exist in `metadata`.

Provider-specific concepts must not define the core architecture.

A new provider should fit the model without provider-specific finding logic.

---

## Invariant 3 — Deterministic Security Truth

Do not use an LLM where deterministic evidence solves the problem.

An LLM must never decide:

- whether an edge exists
- whether a credential has authority
- whether a trust boundary is enforced
- whether an attack path exists
- whether a finding is valid
- severity or confidence

Before introducing model reasoning, ask:

- Can the environment tell us this directly?
- Can provider introspection tell us this?
- Can the security graph tell us this?
- Can history tell us this?
- Can deterministic analysis tell us this?

Models may summarize or explain Pico conclusions.

They never create Pico conclusions.

---

## Invariant 4 — Secrets Are Transient, Never Persisted

Pico may briefly use an existing credential for safe, allowlisted provider introspection.

It stores security facts about the credential, never the raw value.

Pico must never persist raw secrets in:

- SQLite
- evidence
- observations
- logs
- diagnostics
- exports
- reports
- JSON output
- fixtures committed as real credentials
- commits

The principle is:

> Reachability, capability, scope, and authority — never credential material.

Use synthetic credentials in tests and dogfood. Sweep for canaries. Redact diagnostics.

---

## Invariant 5 — Only Enforced Boundaries Block Paths

A hint is not enforcement.

Prompts, instructions, documentation, warnings, comments, MCP hints, tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`), and expected user behavior do not by themselves block an autonomous path.

Only technically enforced controls block paths:

- hard deny
- sandbox or process isolation
- mandatory approval that cannot be bypassed
- credential scope
- resource scope
- network or resource isolation

A boundary blocks a path, not an entire actor. Alternative-path bypasses must remain visible.

Approval that auto/bypass mode can remove is not a strong boundary. Say so.

---

## Invariant 6 — Severity and Confidence Are Separate

Impact and evidentiary certainty are different dimensions.

Pico must represent both.

A finding may be `Severity: CRITICAL, Confidence: MEDIUM`. That means the consequence is critical but one or more security-critical edges are not fully established.

The weakest security-critical edge must materially constrain confidence.

Pico must not average uncertainty away.

Pico must never silently upgrade `INFERRED` or `UNKNOWN` into `CONFIRMED`.

---

## Invariant 7 — Unknown Is Valid

Pico must be able to represent:

```text
CONFIRMED
DERIVED
INFERRED
UNKNOWN
BLOCKED
```

`UNKNOWN` is not an error condition.

It is an honest representation of insufficient evidence.

Edge usability for attack-path analysis:

```text
CONFIRMED → traversable
DERIVED   → traversable
INFERRED  → traversable with confidence penalty
UNKNOWN   → not traversable by default
BLOCKED   → not traversable
```

Absence of evidence is not evidence of absence. Do not turn "not observed" into "does not exist" unless scan scope and freshness justify it.

Potential exposure is not exploitation. V0 discovers potential paths. Never claim compromise, propagation, or execution without runtime evidence.

---

## Invariant 8 — One Engine, Multiple Interfaces

CLI and MCP must call the same application services and security engine.

```text
pico init
pico scan
pico findings
pico finding <id>
pico history
pico diff [<from> <to>]
pico prune
pico doctor
pico mcp
```

and MCP tools such as `list_findings`, `get_finding`, `list_history`, `diff_scans` are views over the same engine.

Interfaces must not develop independent scan, graph, or risk logic.

An agent-triggered scan uses the same bounded pipeline as a CLI-triggered scan. The agent interface stays read-only: scan, list, inspect, explain, query — never revoke, delete, block, quarantine, rotate, deploy, or mutate.

---

## Invariant 9 — History Is Designed In, Comparisons Are Gated

Scans preserve temporal provenance from V0: stable canonical identity, scan-scoped observations, append-oriented evidence, stable finding fingerprints.

Compare coherent `COMPLETE` scan snapshots only. `PARTIAL`, `FAILED`, and `RUNNING` attempts are freshness context, never diff operands.

Collection failure or reduced scope is never disappearance or remediation. Unconfirmed absence stays `not_observed`.

Graph, analysis, or finding contract changes return explicit `NotComparable` / `not_comparable`, never ordinary lifecycle movement.

Retention deletes whole coherent scan units inside one fail-closed transaction and never fabricates disappearance.

---

## Invariant 10 — Build Only the Active Vertical Slice

Do not implement future roadmap concepts because they may eventually be useful.

If the active Sprint does not require:

- a new agent adapter
- a new provider adapter
- runtime observation or background daemon
- multi-agent traversal
- enforcement or remediation
- notifications, CI gates, or dashboards
- generic graph query
- plugin runtime
- hosted service

do not create them.

The Roadmap explains direction.

The Sprint defines scope.

---

# The Anti-Speculation Rule

Before creating any new abstraction, ask:

> Does the active Sprint require this abstraction today?

If the answer is no:

Do not create it.

Examples of premature abstractions include:

```text
RuntimeObserver
MultiAgentEngine
PolicyEngine
EnforcementController
NotificationService
AnomalyDetector
LlmRiskScorer
GenericGraphQuery
PluginRegistry
DashboardService
NewProviderAdapter
```

These concepts may be correct later.

That does not make them correct now.

Let real requirements earn abstractions.

---

# Adapter Development Philosophy

Adapter contracts should evolve from real environments.

Do not design a universal adapter framework from imagination.

If the golden path uses OpenCode + GitHub MCP + Cloudflare:

build the smallest adapter contract that path proves we need.

When the next adapter arrives:

test the abstraction.

The abstraction should become stronger through evidence.

Not prediction.

Rules:

- Evidence depth before integration breadth. One deeply supported path beats five shallow detections.
- Effective state matters more than declared state: `configured_permission + effective_runtime_mode = effective_capability`.
- Authority resolution is tiered: `EXACT`, `SCOPED`, `BEHAVIORAL_READ_ONLY`, `UNKNOWN`. Never upgrade a tier without evidence.
- Integration intelligence (schemas, catalogs, integrations.sh) is discovery intelligence, not security evidence. High-confidence findings require environment-specific evidence.
- MCP tool annotations are `DECLARED` hints, never boundaries, never safety proofs.
- Credential type matters: model GitHub/Cloudflare credential types separately. Do not create one generic token authority model.
- Every adapter declares supported operations, evidence precision, failure behavior, and unresolved states.

---

# Vertical Slice Discipline

Pico is built through complete vertical slices.

Every Sprint should leave the repository in a working and demonstrable state.

Prefer:

```text
One environment
↓
Real local discovery
↓
Normalized resources + relationships
↓
Evidence with provenance
↓
Graph projection
↓
Influence + authority analysis
↓
Boundary evaluation
↓
Finding + explanation
↓
CLI inspection (+ MCP parity only when the Sprint requires it)
```

over:

```text
Five unfinished adapters
+
future runtime observer
+
partial multi-agent layer
+
placeholder enforcement
+
generic policy framework
```

Depth wins over breadth.

---

# Documentation Discipline

Permanent documentation should remain intentionally small.

Do not create new permanent architectural documents unless explicitly requested or clearly justified by complexity.

Examples of documents that should **not** be created speculatively:

- `THREAT_MODEL.md`
- `POLICY_MODEL.md`
- `RUNTIME_SPEC.md`
- `MULTI_AGENT_SPEC.md`
- `ENFORCEMENT_SPEC.md`
- `PLUGIN_SPEC.md`

If a subsystem eventually becomes complicated enough that contributors cannot understand it from:

- `PRODUCT_DEFINITION.md`
- `TECHNICAL.md`
- `ARCHITECTURE.md`
- code
- tests

then a dedicated document may be warranted.

Documentation must be earned by complexity.

Dogfood evidence (`docs/internal/dogfood/`), sprint notes, and support matrices are working records, not new canon. Do not let them override the Canon.

---

# Documentation Update Rules

During implementation:

### If product direction changed materially

Update:

- `docs/internal/PRODUCT_DEFINITION.md`

### If technical feasibility or evidence model changed materially

Update:

- `docs/internal/TECHNICAL.md`

### If architectural boundaries changed materially

Update:

- `docs/internal/ARCHITECTURE.md`

### If release sequencing changed materially

Update:

- `docs/internal/ROADMAP.md`

### If implementation details changed

Prefer:

- code
- tests
- inline documentation

### If nothing canonical changed

Do not touch the canonical docs.

Avoid documentation churn.

---

# Repository Reading Order

Before implementing any meaningful change:

1. Read this `SKILL.md`
2. Read `docs/internal/PRODUCT_DEFINITION.md`
3. Read `docs/internal/TECHNICAL.md`
4. Read `docs/internal/ARCHITECTURE.md`
5. Read `docs/internal/ROADMAP.md`
6. Read the Active Sprint under `docs/internal/sprints/`
7. Inspect relevant source code and tests

Do not read every historical sprint unless required.

Do not let old implementation plans override current architecture.

Sprint support notes and dogfood transcripts are context, not authority. Final implementation contracts in the Sprint take precedence over proposed names in plans.

---

# Sprint Execution Protocol

When the user says:

```text
Implement Sprint X
```

or requests a substantive implementation belonging to an active Sprint, the coding agent MUST:

1. Read `SKILL.md`
2. Read `PRODUCT_DEFINITION.md`
3. Read `TECHNICAL.md`
4. Read `ARCHITECTURE.md`
5. Read `ROADMAP.md`
6. Read the Active Sprint
7. Inspect the repository
8. Produce the Repository Understanding Report
9. Validate architecture and Sprint scope
10. Produce an implementation plan
11. Implement using Red → Green → Refactor
12. Perform architecture review
13. Perform engineering review
14. Run focused validation
15. Run the full relevant test suite
16. Perform manual verification
17. Review the complete diff
18. Update documentation only when required
19. Commit when authorized
20. Verify repository state
21. Stop after the active Sprint

Do not continue into future Sprint work.

---

# Phase 1 — Understand Pico

Before changing code, understand the current product boundary.

Answer:

- What problem is this Sprint solving?
- Which roadmap version does it belong to?
- Which Canon documents govern this work?
- Which architectural invariants apply?
- What is explicitly out of scope?
- What must remain `UNKNOWN` rather than guessed?

If the Sprint conflicts with the Canon:

STOP.

Explain the conflict.

Do not silently choose one interpretation.

---

# Phase 2 — Repository Understanding

Inspect the current repository.

Produce a concise Repository Understanding Report.

Include:

## Repository Summary

- repository structure (`src/cli`, `src/application`, `src/domain`, `src/discovery`, `src/graph`, `src/analysis`, `src/findings`, `src/persistence`, `src/mcp`, `src/output`, `src/shared`, `tests/`)
- important modules for this Sprint
- current implementation maturity
- relevant tests and fixtures
- relevant commands

## Sprint Readiness

- what already exists
- what can be reused
- what must be added
- what should remain untouched

## Canon Alignment

- whether current implementation matches the Product Definition and Architecture
- any architectural drift relevant to the Sprint

## Risks

Identify concrete implementation risks.

Do not invent theoretical risks unrelated to the active work.

---

# Phase 3 — Scope Validation

Confirm:

- the Sprint belongs to the current Roadmap phase
- the Sprint is a complete vertical slice
- no future phase work is being introduced (runtime, multi-agent, enforcement, hosted, dashboard, notifications)
- no unnecessary adapter abstraction is being introduced
- no LLM-decided security truth is being added
- no mutation or enforcement capability is being added before v0.7
- no raw-secret persistence is being added
- canonical documentation does not need speculative expansion

If the proposed implementation exceeds Sprint scope:

reduce it.

---

# Phase 4 — Implementation Plan

Before modifying code, produce a concise implementation plan.

Include:

- files or modules to modify
- new modules if required
- responsibilities
- public interfaces
- tests to add (unit, fixture, integration, determinism, secret-safety, allowlist)
- migration / retention considerations
- meaningful risks

Avoid long implementation essays.

The plan should make the change understandable.

Then implement.

---

# Phase 5 — Red → Green → Refactor

Use test-driven development where practical.

## Red

Add or update tests that express the required Sprint behavior.

Confirm the required behavior is not already satisfied.

Prefer deterministic fixtures over live environments. Generate synthetic credentials, never borrow ambient credentials.

## Green

Implement the smallest amount of code required to satisfy the Sprint.

Do not build future capability.

Keep provider-specific logic inside the adapter. Keep security reasoning inside the analysis engine.

## Refactor

Improve:

- naming
- organization
- clarity
- error handling
- duplication

without increasing scope.

---

# Phase 6 — Architecture Review

After implementation, review the system architecture.

Ask:

- Did provider-specific concepts leak into Pico Core?
- Does the domain model remain provider-independent?
- Did adapters emit findings or attack paths directly?
- Did we introduce model reasoning where deterministic evidence was enough?
- Did we accidentally create inventory, observability, or surveillance infrastructure?
- Did we introduce future runtime, multi-agent, or enforcement capability?
- Did we add speculative abstractions or a generic graph language?
- Did we weaken secret, read-only, or boundary invariants?
- Did we make MCP or another interface part of the core?
- Did CLI and MCP diverge into two engines?
- Did we stay within the active Sprint?

Resolve architectural drift before declaring completion.

---

# Phase 7 — Engineering Review

Review implementation quality.

Evaluate:

- readability
- naming
- module boundaries (`cli -> application -> domain / persistence`)
- error handling
- test quality
- dead code
- duplication
- complexity
- unnecessary dependencies
- hidden state
- performance and local-resource concerns relevant to the Sprint
- Rust idioms: explicit errors, no panics on user input, no secret material in `Debug` output

Prefer simplification whenever possible.

---

# Phase 8 — Testing

Run focused validation first, then the full suite.

```bash
cargo test <focused-target>
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
git diff --check
```

Required coverage where applicable:

- unit tests
- adapter tests
- persistence tests
- CLI tests
- MCP tests
- fixture + integration tests
- determinism / replay tests
- secret-leakage / canary tests
- provider-allowlist tests
- retention / comparison-contract tests

All required tests must pass.

Do not hide failing tests.

Do not disable tests merely to make the build green. List ignored tests explicitly and do not count ignored live tests as passes.

---

# Phase 9 — Manual Verification

Perform representative manual verification whenever the Sprint produces user-visible or integration behavior.

Use a disposable workspace (for example `/tmp/pico-<sprint>-<date>`), never the founder store and never real `$HOME` as a state write unless the Sprint explicitly requires it.

Examples:

```text
pico init
pico scan
pico findings
pico finding <id>
pico history
pico diff
pico diff <from> <to>
pico doctor
```

and where the Sprint requires it, JSON and MCP parity:

```text
pico history --json
pico diff --json
pico diff <from> <to> --json
```

Verify:

- expected workflow succeeds
- errors are actionable and secret-free
- state persists correctly under `.pico/`
- `init` is idempotent and never resets existing state
- partial adapter failure yields `PARTIAL` with retained evidence, not false certainty
- existing behavior remains unchanged
- the Sprint is demonstrable
- read-only surfaces did not mutate the database (digest before/after where the Sprint requires it)

Automated tests do not replace representative manual verification.

For evidence-gated Sprints, record exact commit, dirty-tree status, binary SHA-256, `pico --version`, platform, commands, exit codes, separate stdout/stderr, full JSON, MCP request/response transcripts, digest method, sanitization manifest, and secret-sweep result. Do not present a seeded scan as a live run.

---

# Phase 10 — Documentation Review

Ask:

Did the product change?

Did the technical evidence model change?

Did architecture change?

Did roadmap sequencing change?

If no:

leave canonical docs unchanged.

If yes:

update only the affected canonical document.

Record Implemented / Deviations / Validation / Learnings in the Sprint doc per repository practice.

Do not create new permanent documentation by default.

Human output and JSON/schema wording must preserve the same limitations even when phrasing differs. Never normalize away an unexpected difference to obtain a pass.

---

# Phase 11 — Review the Complete Diff

Review every modified file.

Remove:

- temporary debugging
- abandoned experiments
- unnecessary TODOs
- commented-out code
- unused imports
- unused abstractions
- future-facing placeholders
- dead configuration
- secret or sensitive material
- control bytes that could corrupt output

Run `git diff --check`. The final diff should read like one coherent implementation.

---

# Phase 12 — Commit

Commit only when authorized by repository policy or the user.

Commits should represent meaningful engineering steps.

Prefer messages such as:

```text
feat(scan): resolve effective OpenCode Bash permission
feat(cloudflare): tiered Worker mutation authority
fix(storage): preserve canonical identity across scans
fix(retention): fail prune health gates closed
docs(sprints): define Sprint 036 scope
```

Avoid generic messages such as:

```text
update
fix
changes
stuff
```

Never commit secrets, private resource names, unredacted state databases, or real provider data.

---

# Phase 13 — Push

Push only when:

- repository policy explicitly allows it

or

- the user explicitly requests it

Never assume pushing is desired.

---

# Phase 14 — Verification

After committing or pushing, verify:

- correct repository
- correct branch
- expected commit
- clean working tree
- tests remain passing
- only intended files changed
- no secrets committed

Report exactly what was completed.

---

# Phase 15 — Sprint Completion

A completed Sprint should record enough implementation context for the next Sprint to begin safely.

Update the Active Sprint with concise completion notes if that is the repository practice: Implemented, Deviations, Validation, Learnings, Canon Changes.

Do not rewrite historical Sprint intent.

Do not begin the next Sprint.

Until an independent comprehension or release gate has actually passed, the phase remains in progress even if implementation is done. Automated success does not close a human gate.

---

# Phase 16 — Stop

Stop after the active Sprint.

Never:

- partially implement the next Sprint
- create scaffolding for later roadmap versions
- add future adapters "while already here"
- build runtime, multi-agent, or enforcement systems for hypothetical needs
- build generic systems for hypothetical needs
- introduce mutation or destructive probing early
- silently redesign Pico

One finished vertical slice is better than several partial ones.

---

# Definition of Done

A Sprint is complete only when:

✓ Sprint requirements are satisfied.

✓ Canon remains intact.

✓ Scope remains narrow.

✓ Architecture remains provider-independent.

✓ No speculative future work was introduced.

✓ Security invariants hold: deterministic truth, transient secrets, read-only behavior, enforced-only boundaries, honest `UNKNOWN`.

✓ Tests pass (`cargo test --all-targets`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --all -- --check`).

✓ Manual verification succeeds where applicable, in a disposable workspace.

✓ Secret sweeps and provider-allowlist checks pass where applicable.

✓ Documentation is accurate.

✓ The full diff was reviewed.

✓ Repository state is clean.

Anything less is incomplete.

---

# Engineering Decision Rules

Before implementing anything substantial, ask:

### Product

Does this strengthen Pico's ability to discover, connect, analyze, or explain dangerous paths?

Is that capability part of the current roadmap phase?

### Architecture

Does this belong in:

- interface (`cli`, `mcp`, `output`)
- application service
- observed domain (`domain`, `persistence`)
- analysis (`graph`, `analysis`, `findings`)
- adapter (`discovery` + provider/agent adapters)
- persistence

Is ownership clear? Does `cli -> application -> domain / persistence` hold?

### Scope

Does the active Sprint require it?

If not:

do not build it.

### Adapters

Is this abstraction based on real environment behavior?

Or are we guessing about future agents and providers?

### AI

Do we need model reasoning?

Or can deterministic evidence solve it?

If the model helps, is it explanation-only, outside the authoritative engine?

### Evidence

Do we have direct, declared, or derived evidence?

Or are we upgrading inferred/unknown into certainty?

What is the weakest security-critical edge, and does confidence reflect it?

### Secrets

Does this store, log, or export secret material?

If collection would require persisting secret material, redesign collection.

### Documentation

Did something canonical actually change?

Or can the code and tests remain the source of truth?

---

# Working With AI Coding Agents

AI coding agents are engineering partners.

They are not autonomous product designers.

Agents should:

- understand before implementing
- inspect before assuming
- plan before modifying
- test before claiming completion
- explain architectural uncertainty
- preserve `UNKNOWN` rather than guessing
- stay inside Sprint scope
- stop when the Sprint is done

Agents should never:

- invent product requirements
- silently change architecture
- implement future roadmap phases
- create speculative abstractions
- harvest or persist credentials
- scan arbitrary home directories or shell history looking for secrets
- bypass allowlists or policy boundaries
- execute attack paths or destructive probes
- use an LLM to decide security truth
- expand documentation unnecessarily

When genuinely uncertain about a canonical architectural conflict:

report it.

Do not guess.

---

# Coding Philosophy

Prefer explicit code over clever code.

Prefer small interfaces over broad frameworks.

Prefer composition.

Prefer predictable data flow.

Prefer typed domain concepts where they remove ambiguity.

Prefer explicit `Result` errors over panics on user-controlled input.

Avoid:

- speculative abstractions
- premature optimization
- unnecessary dependencies
- provider-specific core logic
- hidden mutable state
- framework-building without evidence
- secret material in `Debug`, logs, or error strings

Code should remain understandable months later.

Rust should read like the security boundary it enforces.

---

# Dependency Philosophy

New dependencies must justify their cost.

Before adding one, ask:

- Does the standard library already solve this adequately?
- Does the current repository already contain an appropriate dependency?
- Is this dependency maintained?
- Does it materially simplify the active Sprint?
- Does it introduce unnecessary architectural commitment or supply-chain risk near credentials?

Do not add frameworks because they may be useful later.

Adapters operate near sensitive configuration and credentials. Supply-chain caution is a security control.

---

# Error Philosophy

Errors should help humans understand what failed and what to do next.

Provider errors should preserve useful provider context without leaking secrets.

Prefer:

```text
Cloudflare authority unresolved: token details unavailable; authority tier UNKNOWN. Run `pico scan` after granting token read scope, or inspect `pico finding <id>` for evidence.
```

over:

```text
request failed
```

But avoid exposing:

- raw credentials
- secrets
- sensitive headers
- tokens
- private resource identifiers the user did not ask to disclose
- raw database internals

Errors go to stderr with existing exit codes. Human output stays default; `--json` errors use the versioned error payload without echoing rejected input.

---

# Security Philosophy

Agent credentials and infrastructure authority are highly sensitive.

Security is not future cleanup.

Always:

- minimize credential exposure
- prefer scoped, read-only authorization
- avoid plaintext secrets everywhere
- use synthetic credentials in tests and dogfood
- keep discovery narrow; no arbitrary recursive home-directory scanning
- enforce provider operation allowlists in tests
- keep the agent interface read-only
- preserve provider permission boundaries
- validate external input
- avoid arbitrary command execution
- maintain auditability without storing secrets
- separate detection from future enforcement

Convenience must not override trust.

Pico must not become a new privileged execution layer merely to inspect existing privileged execution layers.

---

# Performance Philosophy

Do not prematurely optimize.

But do not ignore obvious local-resource boundaries.

During early versions, prioritize:

- correctness
- clarity
- predictable scans
- understandable persistence
- deterministic behavior

Continuous operation, if ever added, must define explicit resource, CPU, I/O, privacy, and retention budgets — and remain opt-in, inspectable, pausable, and removable.

Optimize only after measurement or real user need.

---

# Local-First Philosophy

Pico should remain understandable and useful on one machine.

Avoid architecture that requires a hosted control plane for basic functionality.

Core scanning, analysis, storage, and explanation must work locally.

Outbound requests occur only when evidence collection requires provider or integration metadata, and must be explicit, read-only, and tied to evidence.

Local state must have safe permissions, retention behavior, and deletion semantics.

---

# The Pico Flywheel

The long-term system is:

```text
Discover
   ↓
Connect
   ↓
Analyze
   ↓
Explain
   ↓
Remember
   ↓
Detect change
   ↓
Observe runtime
   ↓
Interrupt
   ↓
Contain
   ↓
Learn
   │
   └──────────────↺
```

Do not attempt to build the whole flywheel at once.

Each roadmap version earns the next capability.

---

# Current Build Strategy

Pico should move through narrow, environment-backed vertical slices.

For the golden path:

```text
OpenCode discovery
   ↓
Effective Bash + MCP permission resolution
   ↓
GitHub MCP influence modeling
   ↓
Cloudflare credential reachability (value never stored)
   ↓
Read-only Cloudflare authority introspection
   ↓
Normalized graph
   ↓
Influence + authority analysis
   ↓
Boundary evaluation
   ↓
UNTRUSTED_TO_PRODUCTION finding + explanation
   ↓
CLI inspection (+ MCP parity only when required)
```

Then earn the next slice.

Use each real environment to challenge and improve the domain model.

Do not design for dozens of agents and providers before the first path is trustworthy.

---

# Success Criteria

Every Sprint should improve one of Pico's current roadmap capabilities while preserving the architectural foundation and security honesty.

A good Sprint:

- solves one clear problem
- is demonstrable (`pico scan` → `pico findings` → `pico finding <id>`)
- has a narrow diff
- strengthens real product behavior
- teaches us something about the architecture or evidence model
- avoids future work
- leaves the repository easier to understand
- keeps secrets out and determinism in

The goal is not to produce the largest change.

The goal is to produce the smallest valuable learning loop.

---

# Final Principle

Pico should move fast because it stays small and honest.

The Product Definition defines **why Pico exists**.

The Technical model defines **what Pico can honestly claim**.

The Architecture defines **what must remain true**.

The Roadmap defines **what we prove next**.

The Sprint defines **what we build today**.

The code brings that one slice to life.

Do not predict complexity.

Let real environments, real evidence, and real implementation pressure reveal it.

> **Discover first. Prove the path. Explain the evidence. Earn everything after that.**
