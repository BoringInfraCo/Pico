# Pico — Product Roadmap

**File:** `ROADMAP.md`  
**Status:** Planning baseline  
**Date:** August 18, 2026  
**Stage:** Post-architecture, pre-implementation  
**Depends on:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`

---

# 1. Purpose

This roadmap translates Pico's product definition, technical model, and architecture into disciplined product phases.

Pico's core thesis is:

> **Agent security risk emerges where untrusted influence intersects autonomous authority.**

Pico's product mission is to discover, explain, and eventually control the dangerous paths created around AI agents.

The roadmap is governed by one rule:

> **Architect for extension. Implement only the golden path.**

The architecture may anticipate additional agents, providers, runtime signals, multi-agent systems, and enforcement. The product must earn each expansion by first proving that the preceding layer is accurate, safe, explainable, and useful.

This is a sequence of learning gates, not a calendar commitment. A phase is complete only when its exit criteria are met. Shipping a version number does not justify advancing if the central uncertainty remains unresolved.

This document intentionally does not define Sprint 001, implementation tickets, staffing, or delivery dates.

---

# 2. Product Direction

Pico begins as a local-first security product for developers and startups using AI coding agents.

The first users should be able to install Pico in a real development environment, scan locally, and understand a dangerous agent path without deploying a hosted control plane or sending sensitive environment state to Pico-operated infrastructure.

The progression is:

```text
v0.1  Golden-path proof
  ↓
v0.2  Evidence and authority depth
  ↓
v0.3  Earned agent and provider expansion
  ↓
v0.4  Security memory and change detection
  ↓
v0.5  Continuous and runtime observation
  ↓
v0.6  Multi-agent and agent-to-agent defense
  ↓
v0.7  Controlled containment and enforcement
  ↓
v1.0  Trusted developer/startup product boundary
```

Each phase extends the same core model:

```text
DISCOVER
   ↓
OBSERVE
   ↓
EVIDENCE
   ↓
NORMALIZE
   ↓
GRAPH
   ↓
ANALYZE
   ↓
FIND
   ↓
EXPLAIN
```

Later phases may add:

```text
REMEMBER
   ↓
DETECT CHANGE
   ↓
OBSERVE RUNTIME
   ↓
INTERRUPT
```

They must not replace the evidence foundation.

---

# 3. Roadmap Guardrails

These rules apply to every phase.

## 3.1 Local-first remains the default

Core scanning, analysis, storage, and explanation must work locally.

A future hosted service may coordinate teams or aggregate intentionally shared results. It must not become a hidden requirement for Pico's core security engine.

## 3.2 Developer/startup-first remains the initial customer boundary

Pico should optimize first for:

- one developer or a small engineering team;
- a small number of agent environments;
- direct access to the environment being analyzed;
- fast installation and understandable local results;
- limited operational overhead;
- practical remediation at the developer boundary.

Pico should not prematurely optimize for organization-wide asset inventory, enterprise policy administration, multi-region service architecture, procurement workflows, or large security operations teams.

## 3.3 Evidence depth before integration breadth

One deeply supported agent/provider path is more valuable than many integrations that only detect product names or credential presence.

No new agent or provider surface should be added merely to expand a compatibility list.

## 3.4 Deterministic security truth

The authoritative engine must deterministically establish:

- resources and relationships;
- effective capability;
- credential reachability;
- authority and resource scope;
- enforced boundaries;
- attack paths;
- severity and confidence;
- finding identity and change.

LLMs may help explain results. They must not decide whether a security-significant edge or finding exists.

## 3.5 Read-only before control

Until the controlled-enforcement phase, Pico observes and explains.

It must not mutate agent configuration, revoke credentials, change infrastructure, execute attack paths, or perform destructive authority probes.

## 3.6 Secrets remain transient

Pico may temporarily use a credential for safe provider introspection. Raw secrets must not enter normalized adapter output, SQLite, evidence, logs, diagnostics, telemetry, or exported reports.

## 3.7 Unknown is honest

Pico must preserve uncertainty rather than manufacture precision.

`UNKNOWN`, partial scans, incomplete authority resolution, and stale evidence are valid product states.

## 3.8 One engine, multiple interfaces

CLI, MCP, future CI, Slack, UI, and API surfaces must call the same application services and security engine. Interfaces must not develop independent scan or risk logic.

## 3.9 Modular monolith until evidence requires otherwise

Pico should remain one local application with clear internal boundaries. Microservices, a dedicated graph database, distributed queues, and a hosted backend require demonstrated product or scale needs.

## 3.10 No arbitrary executable plugin ecosystem in early phases

Adapters operate near sensitive configuration and credentials. Pico should ship reviewed adapters until the adapter contract, isolation model, and supply-chain controls are mature enough to revisit third-party extensibility.

---

# 4. Phase-Gate Model

Every phase must answer seven questions:

1. **Goal** — What product claim does this phase prove?
2. **Scope** — What is included to prove it?
3. **Non-goals** — What remains deliberately excluded?
4. **Dependencies** — What prior capabilities must be trustworthy?
5. **Exit criteria** — What observable conditions make the phase complete?
6. **Required learning** — What must Pico learn before advancing?
7. **Sequencing rationale** — Why does this phase belong here?

Phase advancement requires all of the following:

```text
PRODUCT VALUE
The supported user can understand and act on the result.

SECURITY VALIDITY
Claims are supported by provenance and honest confidence.

SELF-SAFETY
Pico does not leak secrets or mutate the target environment.

DETERMINISM
Equivalent observed state produces equivalent conclusions.

RELIABILITY
Partial failure is explicit and useful evidence is preserved.

MAINTAINABILITY
The phase extends domain and adapter contracts without bypassing them.
```

---

# 5. v0.1 — Golden-Path Proof

## Goal

Prove that Pico can safely discover, construct, analyze, and explain one real evidence-backed path from external influence to consequential cloud authority.

The required golden path is:

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

The central product claim is:

> **Pico can show a developer how externally controlled content can reach production-capable authority through an AI coding agent, why Pico believes each edge exists, whether an enforced boundary interrupts it, and how to break the path.**

## Scope

- Local installation and initialization.
- A bounded manual scan.
- Local SQLite persistence under Pico-managed state.
- Stable domain concepts for `Scan`, `Observation`, `Resource`, `Relationship`, `Evidence`, `Boundary`, `AttackPath`, and `Finding`.
- OpenCode discovery limited to the effective configuration needed to establish the golden path.
- Bash permission, approval, explicit deny, sandbox, and relevant runtime-mode evidence when observable.
- GitHub MCP server and relevant tool discovery.
- Modeling of externally controlled GitHub content as an influence source.
- Cloudflare credential reference and agent/shell reachability discovery.
- Transient credential handling and safe credential fingerprinting.
- Safe, allowlisted Cloudflare introspection sufficient to resolve Worker mutation authority and resource scope when the provider exposes it.
- Provider-neutral graph projection and bounded traversal.
- Influence analysis, authority analysis, boundary evaluation, and attack-path construction.
- One primary finding class: `UNTRUSTED_TO_PRODUCTION`.
- Transparent severity and confidence.
- Evidence-backed CLI summary and finding detail.
- Minimal read-only Pico MCP access over the same application services, only after the CLI path works.
- Fixture, integration, determinism, secret-leakage, and controlled dogfood validation for the golden path.

## Non-goals

- Additional coding-agent adapters.
- Additional cloud providers.
- Broad GitHub authority analysis beyond what the influence path requires.
- Every GitHub MCP tool or content type.
- Generic integration-intelligence ingestion.
- Continuous monitoring or a background daemon.
- Change alerts, CI policy gates, Slack, dashboards, or a hosted service.
- Multi-agent analysis.
- Automatic remediation, containment, credential revocation, or configuration changes.
- Active exploitation or write-based authority validation.
- LLM-decided edges, paths, severity, or confidence.
- Enterprise RBAC, organization inventory, or policy administration.

## Dependencies

- The feasibility conclusions in `TECHNICAL.md`.
- The domain, evidence, graph, adapter, persistence, scan, and self-security boundaries in `ARCHITECTURE.md`.
- Safe access to representative OpenCode, GitHub MCP, and Cloudflare fixtures.
- A controlled dogfood environment that contains both safe and intentionally exposed variants of the golden path.

## Exit criteria

v0.1 is complete only when:

- `pico init` is idempotent and creates safe local state.
- `pico scan` completes the same bounded pipeline against fixtures and a controlled real environment.
- Pico detects the supported OpenCode instance and resolves the effective Bash and relevant MCP permissions needed for the path.
- Pico distinguishes GitHub external influence from mere GitHub product presence.
- Pico establishes whether Bash can reach a Cloudflare credential without persisting its value.
- Pico establishes Cloudflare Worker write authority from read-only authorization evidence, or explicitly reports the unresolved edge as `UNKNOWN` without claiming a confirmed path.
- A confirmed hard deny, mandatory approval, sandbox, or credential/resource scope boundary blocks only the path it actually interrupts.
- The unblocked fixture produces the expected `UNTRUSTED_TO_PRODUCTION` finding.
- The blocked and scoped fixtures do not produce the same active attack path.
- Every security-critical edge in the finding has inspectable provenance, freshness, and confidence.
- Repeating analysis over the same normalized graph produces the same paths, severity, confidence, and finding identity.
- Secret canaries have zero occurrences in the database, logs, diagnostics, and exports.
- Provider clients cannot invoke operations outside their explicit read/introspection allowlists.
- Partial adapter failure produces a `PARTIAL` scan with useful retained evidence and no false certainty.
- A developer unfamiliar with the internals can explain what the path is, why it matters, how Pico knows, what remains uncertain, and at least one practical cut point.
- The Pico MCP interface, if included in v0.1, returns the same underlying finding as the CLI and does not introduce a second scanner.

## What must be learned before advancing

- Can Pico reliably resolve OpenCode's effective state rather than only declared configuration?
- Can GitHub MCP availability support a defensible external-influence edge without overstating automatic consumption?
- Can Cloudflare authority and resource scope be resolved precisely enough for a high-confidence Worker mutation claim?
- Which evidence is stable across machines, versions, and configuration styles?
- Which boundary types can Pico prove are enforced and non-bypassable?
- Does the finding explanation lead developers to a real remediation decision?
- What are the dominant false-positive, false-negative, and `UNKNOWN` cases?
- Is local scanning fast and predictable enough to become a repeated developer habit?

If Pico cannot safely and credibly prove this path, the next action is to refine the product primitive or evidence model—not to add integrations.

## Sequencing rationale

The golden path is the smallest vertical slice that tests Pico's entire thesis. It crosses influence, agent capability, local credential reachability, provider authority, enforced boundaries, graph analysis, findings, explanation, persistence, and self-security. Proving these layers together is more informative than completing any one subsystem horizontally.

---

# 6. v0.2 — Evidence and Authority Depth

## Goal

Turn the golden-path prototype into a trustworthy security instrument by deepening precision, provenance, coverage of ambiguous states, and authority resolution before adding more products.

The central claim is:

> **Within Pico's supported OpenCode, GitHub MCP, Bash, and Cloudflare boundary, users can trust both what Pico says and what Pico refuses to claim.**

## Scope

- Harden canonical identities and evidence provenance across repeated scans.
- Expand sanitized fixtures for configuration precedence, runtime modes, transport differences, credential sources, token scopes, resource scopes, and provider failures.
- Improve effective-state resolution for OpenCode permissions, approval modes, sandboxing, and bypass conditions relevant to the golden path.
- Deepen GitHub influence classification across the minimum evidence-backed external content variants that materially change risk.
- Deepen Cloudflare authority resolution across supported credential types and scope combinations.
- Make authority-resolution tiers visible: `EXACT`, `SCOPED`, `BEHAVIORAL_READ_ONLY`, and `UNKNOWN`.
- Harden evidence freshness and partial-scan semantics.
- Validate path deduplication and finding stability.
- Refine deterministic severity, confidence, and remediation cut points using dogfood evidence.
- Improve scan diagnostics and explanations for incomplete evidence.
- Establish explicit adapter conformance and self-security test suites.
- Define a support matrix that states exactly what Pico can and cannot establish.

## Non-goals

- A second agent or cloud provider merely for market coverage.
- General-purpose MCP classification across arbitrary servers.
- A hosted knowledge service.
- Security history UX beyond what is required to verify identity and freshness.
- Continuous/runtime observation.
- Multi-agent graph analysis.
- Enforcement or automatic remediation.
- A generic policy language.

## Dependencies

- v0.1 has proven the complete golden path in fixtures and controlled dogfood.
- v0.1's evidence, graph, and finding contracts are stable enough to measure failure modes.
- A growing corpus of real, sanitized supported-environment cases exists.

## Exit criteria

- The supported-state matrix clearly distinguishes confirmed, derived, inferred, and unknown claims.
- Representative OpenCode precedence, approval, deny, sandbox, and runtime-mode combinations are covered by deterministic fixtures.
- Representative Cloudflare credential and resource-scope combinations produce correct authority tiers without write probes.
- Stale, contradictory, missing, or partial evidence cannot silently produce high-confidence authority.
- Finding fingerprints remain stable across unchanged scans and change predictably when security-significant state changes.
- Path grouping does not hide materially different boundaries or bypasses.
- Evidence explanations identify the weakest security-critical edge.
- False-positive and false-negative review against the controlled corpus meets an explicitly documented quality bar.
- Secret-leakage and provider-allowlist tests remain mandatory and passing.
- New Pico or provider versions cannot silently broaden what an adapter claims to support.
- At least several developer/startup dogfood environments produce results judged useful without expert interpretation.

## What must be learned before advancing

- Which ambiguity classes recur often enough to require first-class modeling?
- Which evidence sources are sufficiently authoritative and durable for compatibility commitments?
- Can Pico maintain deep provider support without fragile version-specific parsing?
- Where do users confuse capability, reachability, authority, and active exploitation?
- Which remediation cut points are both secure and operationally realistic?
- Is Pico's normalized adapter contract genuinely reusable, or still accidentally shaped only around OpenCode and Cloudflare?
- What measurable compatibility and evidence bar should every future adapter meet?

## Sequencing rationale

Breadth built on shallow evidence would multiply uncertainty and support burden. This phase turns the first path into a reference standard. Future adapters must match that standard rather than weakening Pico's claims to accommodate less inspectable systems.

---

# 7. v0.3 — Earned Agent and Provider Expansion

## Goal

Prove that Pico's normalized model can extend to carefully selected additional agent and provider surfaces without reducing evidence quality or fragmenting the security engine.

The central claim is:

> **Pico can generalize its security primitive across products while preserving provider-specific evidence precision.**

## Scope

- Select one additional agent surface based on inspectability, real user demand, and ability to meet the v0.2 adapter bar.
- Select at most one additional authority surface or one materially distinct GitHub authority path based on evidence quality and user value.
- Add only influence, capability, credential, authority, boundary, and sink semantics required by a specific new end-to-end path.
- Reuse the same domain model, graph projection, analysis engine, finding rules, and application services.
- Extend adapter capability declarations and support matrices.
- Evaluate MCP tools individually as influence, authority, or both; do not classify an MCP server globally.
- Use integration intelligence only to accelerate discovery and adapter research.
- Preserve offline core behavior with built-in knowledge for supported paths.
- Validate mixed environments where more than one supported agent or provider is present.

Candidate choices may include another coding agent such as Claude Code or Codex, GitHub repository mutation authority, or another provider whose effective credential scope can be established. Selection is a phase decision, not a pre-committed compatibility promise.

## Non-goals

- Supporting every coding agent, MCP server, credential type, or cloud provider.
- Counting shallow detection as support.
- Automatically generating authoritative adapters from integration catalogs or API schemas.
- An arbitrary third-party plugin runtime.
- Enterprise-wide inventory.
- Runtime monitoring or multi-agent propagation analysis.
- Enforcement.

## Dependencies

- v0.2 defines and meets a measurable adapter/evidence quality bar.
- The normalized domain and analysis contracts have survived real golden-path variation.
- Candidate surfaces expose enough safe evidence to support a specific user-valued path.

## Exit criteria

- At least one new end-to-end path works through the existing core engine without provider-specific finding logic.
- Each new adapter declares supported operations, evidence precision, failure behavior, and unresolved states.
- The new path has fixture, integration, determinism, secret-safety, and controlled dogfood coverage equivalent to the golden path.
- Mixed supported environments do not cause identity collision, duplicated findings, cross-provider evidence leakage, or graph ambiguity.
- Unsupported configurations degrade to explicit partial or unknown states.
- Integration intelligence never substitutes for environment-specific authority evidence.
- Adding the new surfaces does not materially regress scan clarity, local performance, or the quality bar established in v0.2.
- User demand and usefulness justify maintaining each added surface.

## What must be learned before advancing

- Does the adapter boundary genuinely isolate provider-specific behavior?
- Which concepts are universal and which must remain adapter metadata?
- How much maintenance does each supported surface create as upstream products change?
- Can Pico compare and combine multiple supported paths without confusing users?
- Which new path types produce distinct security value rather than duplicate inventory?
- Are external intelligence sources useful enough to retain without creating availability or trust dependencies?

## Sequencing rationale

Pico expands only after depth is proven because multi-product support is valuable only if the resulting claims remain trustworthy. This phase tests architectural extensibility with deliberately small breadth before history, runtime state, and agent interaction make the graph more complex.

---

# 8. v0.4 — Security Memory and Change Detection

## Goal

Use Pico's append-oriented scans, observations, stable identities, and evidence provenance to explain how agent security posture changes over time.

The central claim is:

> **Pico can tell a developer what dangerous path appeared, disappeared, weakened, strengthened, or became uncertain—and what observed change caused it.**

## Scope

- Compare coherent completed or partial scan snapshots.
- Track first seen, last seen, changed, disappeared, and reappeared resources and relationships.
- Detect security-significant changes in influence, capability, credential reachability, authority, scope, boundaries, attack paths, findings, severity, and confidence.
- Distinguish real change from collection failure, stale evidence, out-of-scope discovery, and identity churn.
- Provide local history and diff commands or equivalent product views.
- Explain causal change using evidence from both sides of a comparison.
- Define deterministic finding lifecycle states and stable fingerprints.
- Add local retention, pruning, and database-health controls that preserve provenance safely.
- Support developer-triggered and agent-triggered "what changed?" queries over the same application services.
- Establish the minimum machine-readable output needed for later CI or notification surfaces.

## Non-goals

- Always-on runtime monitoring.
- Real-time alerts.
- Organization-wide event aggregation.
- A hosted historical dashboard.
- Behavioral anomaly detection based on opaque models.
- Automatic remediation.

## Dependencies

- Stable canonical identities and finding fingerprints from v0.2.
- Multiple supported paths from v0.3 have demonstrated that change semantics are provider-neutral.
- Scan scope, freshness, partial failure, and evidence reuse are explicit.

## Exit criteria

- Unchanged environments produce no security-significant diff.
- Permission, approval, credential scope, resource scope, MCP availability, and authority changes produce expected deterministic diffs.
- Pico identifies when an active path first appeared and the smallest observed security-significant cause.
- Collection failure or reduced scan scope is never presented as remediation or disappearance.
- Finding lifecycle transitions remain stable across repeated scans and tool upgrades, or migrations explicitly account for analysis-version changes.
- Local history remains usable under a defined retention window without exposing secrets.
- Developers can distinguish "the environment changed" from "Pico's evidence changed" and "Pico's analysis version changed."
- Machine-readable diffs are stable enough for later automation without exposing SQLite internals as an API.

## What must be learned before advancing

- Which changes are urgent, meaningful, noisy, or merely informational?
- What history window is useful to small teams without creating local storage or privacy burden?
- How should analysis-version changes be separated from environment changes?
- Which scan triggers produce timely value without becoming continuous observation?
- What notification threshold would users trust enough to enable repeatedly?
- Can Pico explain causality from evidence rather than merely diffing serialized objects?

## Sequencing rationale

Runtime and continuous defenses require a trustworthy baseline and change model. Pico must first know what stable state means, how identity persists, and how to distinguish exposure from collection noise. Security memory is therefore the bridge from point-in-time scanning to continuous observation.

---

# 9. v0.5 — Continuous and Runtime Observation

## Goal

Move from manually requested snapshots toward timely observation of security-significant runtime state and changes while preserving Pico's local-first safety model.

The central claim is:

> **Pico can observe when a supported agent path becomes materially more or less dangerous during real operation, without becoming an invasive general-purpose endpoint monitor.**

## Scope

- Introduce bounded local continuous observation for validated security-significant events.
- Support a deliberately small trigger set such as relevant configuration changes, agent runtime-mode changes, MCP connection/capability changes, credential exposure changes, and supported execution/approval events.
- Correlate runtime observations with the existing security graph and evidence model.
- Distinguish configured capability, available capability, attempted use, approved use, denied use, and completed consequential action where safely observable.
- Preserve event provenance, time ordering, freshness, and scan/observation boundaries.
- Provide local status and change notification surfaces appropriate for individual developers and small teams.
- Define resource, CPU, I/O, privacy, and retention budgets for continuous operation.
- Make monitoring opt-in, inspectable, pausable, and removable.
- Keep point-in-time scanning functional without the runtime observer.

## Non-goals

- Full packet capture, syscall surveillance, or EDR replacement.
- Recording prompts, source content, command bodies, secret values, or unrelated developer activity by default.
- A hosted telemetry requirement.
- Broad behavioral anomaly detection.
- Multi-agent propagation as a first-class risk model.
- Automatic containment or policy enforcement.

## Dependencies

- v0.4 can establish baselines and explain security-significant changes.
- Runtime signals can be collected with a documented privacy and self-security model.
- Supported upstream systems expose stable enough runtime evidence to justify observation.

## Exit criteria

- The observer detects a defined set of supported runtime transitions with measured latency and accuracy.
- Runtime evidence joins the same normalized graph without creating a second risk engine.
- Pico clearly distinguishes observed execution from inferred capability.
- Monitoring overhead stays within explicit local budgets.
- Sensitive-content and secret canaries do not appear in retained events, logs, or notifications.
- Missed events, observer downtime, and unsupported runtime states are visible rather than silently treated as safety.
- Users can understand what Pico observes, why, where it is stored, and how to disable or delete it.
- Manual scans remain authoritative recovery points and work when continuous observation is disabled.
- Dogfood demonstrates that runtime observation changes at least one security decision or remediation priority that static scanning alone could not resolve.

## What must be learned before advancing

- Which runtime signals materially improve decisions rather than add noise?
- Can Pico observe approval and execution semantics without capturing sensitive content?
- What event loss and ordering guarantees are realistic locally?
- How do developers respond to timely findings, and what creates alert fatigue?
- Does continuous operation preserve the trust advantage of local-first scanning?
- Which runtime interactions form the minimum evidence required for safe multi-agent analysis?

## Sequencing rationale

Continuous observation comes after memory because events are useful only relative to a trusted baseline and change model. It comes before multi-agent defense because Pico must first understand the runtime semantics of one actor's influence and authority before tracing propagation across actors.

---

# 10. v0.6 — Multi-Agent and Agent-to-Agent Defense

## Goal

Extend Pico's influence and authority model across systems where agents delegate to, invoke, message, supervise, or share capabilities and credentials with other agents.

The central claim is:

> **Pico can identify when influence entering one agent propagates through other agents to reach authority that the original agent did not directly possess.**

## Scope

- Model agent-to-agent relationships such as delegation, invocation, messaging, shared workspace, shared credential reachability, and supervisory control.
- Preserve actor identity, delegation direction, trust, capability, and evidence at each hop.
- Extend bounded, cycle-safe traversal for multiple actors.
- Distinguish direct authority from delegated or transitive authority.
- Evaluate boundaries at each handoff and each authority path.
- Detect bypasses where one agent's approval, sandbox, or deny is circumvented through another agent.
- Group related paths into understandable multi-agent findings without hiding materially distinct handoffs.
- Use runtime evidence when it strengthens or disproves configured agent-to-agent reachability.
- Add controlled fixtures for cycles, fan-out, fan-in, confused-deputy behavior, shared credentials, delegated tasks, and partial observability.
- Keep analysis local for supported small-team environments.

## Non-goals

- Universal support for every agent protocol or orchestration framework.
- Assuming all messages or delegations are malicious.
- Full content inspection or semantic prompt-attack classification.
- Organization-wide identity governance.
- Autonomous response or agent shutdown.
- Unbounded traversal across arbitrary remote agent networks.

## Dependencies

- v0.3 has proven more than one agent/provider surface without fragmenting the core model.
- v0.4 provides stable identity and historical change.
- v0.5 provides validated runtime semantics for supported agent interactions where static configuration is insufficient.

## Exit criteria

- Pico constructs and explains a controlled path in which external influence enters Agent A and consequential authority is reached through Agent B.
- Direction, delegation, capability, and authority are supported by evidence at every security-critical hop.
- Cycles and repeated actors cannot cause unbounded traversal or duplicated security stories.
- A hard boundary on one handoff blocks only the affected path; alternative-agent bypasses remain visible.
- Shared credentials and shared workspaces do not automatically imply authority without reachability evidence.
- Direct, delegated, and transitive authority are clearly distinguished in findings.
- Multi-agent results remain understandable to a developer without requiring raw graph inspection.
- Unsupported or partially observable handoffs lower confidence or remain `UNKNOWN`.
- Performance remains bounded for explicitly defined small-team graph sizes.

## What must be learned before advancing

- Which agent-to-agent relationships produce real security outcomes in developer/startup environments?
- What evidence proves delegation, receipt, execution, and authority transfer?
- Where do trust boundaries actually exist between agents sharing a machine, workspace, MCP server, or credential?
- How should responsibility and remediation be explained when no single agent owns the full path?
- Which multi-agent paths are important enough to justify eventual interruption?
- Can Pico identify a safe, narrow control point without acting as a universal agent runtime?

## Sequencing rationale

Multi-agent paths compound uncertainty at every hop. Pico attempts them only after single-agent evidence, authority, history, and runtime semantics are proven. This prevents graph connectivity from being mistaken for real delegated risk.

---

# 11. v0.7 — Controlled Containment and Enforcement

## Goal

Introduce narrowly scoped, explicit, reversible controls at validated graph cut points while keeping detection independent from enforcement.

The central claim is:

> **For a small set of supported high-confidence paths, Pico can help a user interrupt dangerous autonomous reachability without silently taking control of the environment.**

## Scope

- Define a separate enforcement boundary, authorization model, and audit trail.
- Begin with user-initiated or user-approved controls at well-understood cut points.
- Prefer reversible, least-disruptive actions.
- Require precondition checks, exact target resolution, impact preview, explicit consent, and post-action verification.
- Reuse the detection graph to propose controls, but independently validate the current state before acting.
- Support a very small set of controls such as pausing a supported agent action, requiring an enforced approval, isolating credential access, or applying a supported narrow configuration change.
- Record who or what authorized the action, what changed, why, and whether rollback is available.
- Detect drift between the finding, proposed action, approval, and execution time.
- Provide dry-run and explanation modes.
- Maintain observation-only operation as the default and as a fully supported product mode.

## Non-goals

- Autonomous broad remediation.
- Generic credential rotation or revocation across providers.
- Killing arbitrary processes or agents.
- A universal policy language and enforcement fabric.
- Destructive cloud changes.
- Acting on low-confidence, inferred, stale, partial, or unresolved paths.
- Letting an LLM choose targets or authorize security-sensitive actions.
- Replacing provider IAM, sandboxes, endpoint controls, or human change management.

## Dependencies

- v0.6 identifies validated control points across direct and delegated paths.
- Detection quality, identity stability, freshness, and runtime preconditions meet a substantially higher bar than explanation-only findings.
- Supported systems expose safe, reversible, and verifiable control mechanisms.
- Pico has an explicit threat model for its own enforcement authority.

## Exit criteria

- Enforcement code is separated from discovery and analysis and can be disabled entirely.
- No action occurs without the defined authorization and freshness requirements.
- Targets are resolved by stable provider identity, not names or ambiguous patterns.
- Every supported action offers an accurate impact preview and clear rollback story where technically possible.
- Stale state, scope drift, partial evidence, or target mismatch fails closed.
- The control interrupts the intended path and post-action scanning verifies the result.
- Alternative paths are re-evaluated so a local cut is not misreported as complete containment.
- All actions are auditable without storing secrets.
- Controlled dogfood includes success, refusal, rollback, interruption, and partial-failure scenarios.
- Observation-only users incur no added mutation authority or operational dependency.

## What must be learned before advancing

- Which cut points are safe, reversible, and valuable enough to automate?
- What consent model works for developers, agents, and small teams?
- How quickly does environment state become too stale for safe action?
- What new attack surface is created by giving Pico control authority?
- Can controls be provider-native rather than requiring Pico to become a privileged universal proxy?
- What evidence and auditability are required before any control can become automatic?

## Sequencing rationale

Enforcement is intentionally last because mistakes change real systems. Pico must first prove that it can discover, remember, observe, and explain direct and transitive paths. Only then can it safely test narrow intervention at graph cut points with explicit human authority.

---

# 12. v1.0 — Trusted Developer/Startup Product Boundary

v1.0 is not defined by the number of integrations or by adding enterprise features.

It represents a product maturity threshold:

> **Pico is a dependable local-first security companion for developers and startups operating supported AI-agent environments.**

## Candidate v1.0 boundary

- The supported paths are explicitly documented and deeply evidence-backed.
- Installation, initialization, scanning, explanation, history, and supported observation are reliable.
- The local data and privacy model is understandable and inspectable.
- Security conclusions are deterministic and versioned.
- Findings are actionable and stable enough for repeated use.
- Partial evidence and unsupported states are honest.
- Secret safety and read-only behavior have a durable regression record.
- At least one additional agent or provider path has proven architectural extensibility.
- Security memory demonstrates durable value.
- Any runtime or enforcement capability included in v1.0 meets its own phase gate; otherwise it remains post-v1.0 without blocking the core product.

v1.0 does not require:

- every phase in this roadmap to be feature-complete;
- a hosted control plane;
- enterprise administration;
- broad enforcement;
- every agent or provider;
- arbitrary plugins.

The release boundary should be chosen from demonstrated user value and trust, not roadmap completeness theater.

---

# 13. Cross-Phase Quality Gates

The following gates remain cumulative.

## 13.1 Evidence gate

- Every security-significant claim has provenance.
- Evidence class, source, freshness, and uncertainty are visible.
- Unknown and partial states cannot silently become confirmed edges.

## 13.2 Secret-safety gate

- Raw secrets never enter persistent normalized state.
- Secret canaries are absent from databases, logs, diagnostics, fixtures, telemetry, reports, and notifications.
- Credential access is short-lived, scoped, and limited to approved provider clients.

## 13.3 Read-only gate

- Before v0.7, provider and environment operations are observation or metadata operations.
- Operation allowlists are enforced in tests.
- Pico never validates authority by exercising destructive capability.

## 13.4 Determinism gate

- Equivalent normalized state and analysis version produce equivalent results.
- Severity and confidence remain separate.
- The weakest security-critical edge constrains confidence.

## 13.5 Boundary gate

- Only technically enforced controls block paths.
- Prompts, instructions, documentation, warnings, and MCP hints do not become hard boundaries.
- Alternative paths are evaluated independently.

## 13.6 Local-first gate

- Core use remains possible without a Pico-hosted service.
- Network use is bounded, explained, and tied to evidence collection.
- Local state has safe permissions, retention behavior, and deletion semantics.

## 13.7 Usability gate

A supported developer should be able to answer:

```text
What did Pico find?
Why does it matter?
How does the path work?
How does Pico know?
What is uncertain?
What boundary is missing or working?
How can the path be broken?
What changed since the previous observation?
```

## 13.8 Compatibility gate

- Adapter capability declarations match implemented evidence depth.
- Upstream changes fail visibly.
- Support matrices describe tested configurations and known limits.

---

# 14. Product Metrics by Stage

Metrics should measure trust and usefulness, not integration count.

## Early proof metrics

- Golden-path fixture correctness.
- Percentage of security-critical edges with direct, declared, or deterministic derived evidence.
- Secret-leakage test failures.
- Deterministic replay consistency.
- Time for a developer to understand and remediate a finding.
- Frequency and cause of `UNKNOWN` or partial results.

## Depth metrics

- False-positive and false-negative review against the supported corpus.
- Authority-resolution precision by supported credential type.
- Upstream compatibility regressions.
- Finding stability across unchanged scans.
- Percentage of findings with a practical verified cut point.

## Expansion metrics

- End-to-end supported paths, not detected products.
- Adapter maintenance cost.
- Mixed-environment correctness.
- Reuse of core analysis without provider-specific exceptions.

## Memory and runtime metrics

- Security-significant change precision.
- Collection-noise rate.
- Runtime event loss and detection latency.
- Local resource overhead.
- Alert usefulness and dismissal rate.

## Enforcement metrics

- Refusal correctness under stale or incomplete state.
- Successful interruption and verification rate.
- Rollback success.
- Unintended impact.
- Alternative-path detection after control.

Vanity metrics such as number of integrations, resources inventoried, or graph edges stored must not substitute for these measures.

---

# 15. Explicitly Deferred Product Areas

The following areas remain outside the committed early roadmap unless user evidence changes the product boundary:

- Hosted-first architecture.
- Enterprise organization dashboards.
- SIEM replacement.
- EDR replacement.
- Cloud security posture management.
- Generic asset inventory.
- AI penetration testing or exploit execution.
- Full prompt-content surveillance.
- LLM-first risk scoring.
- Arbitrary executable third-party adapters.
- General-purpose graph query language.
- Broad policy authoring and distribution.
- Autonomous credential revocation.
- Automatic destructive remediation.
- Large-enterprise RBAC and compliance workflow.
- Support for integrations that cannot meet Pico's evidence standard.

Deferral is not rejection forever. It preserves the order in which Pico must earn complexity.

---

# 16. Sequencing Summary

The roadmap order is intentional.

```text
PROVE ONE PATH
The product thesis must work end to end.
        ↓
DEEPEN THE EVIDENCE
The first path must become trustworthy.
        ↓
GENERALIZE CAREFULLY
The architecture must survive limited product breadth.
        ↓
REMEMBER CHANGE
Stable identity and causality must exist before monitoring.
        ↓
OBSERVE RUNTIME
Timely signals must extend, not replace, the graph.
        ↓
FOLLOW AGENT HANDOFFS
Transitive risk requires proven single-agent semantics.
        ↓
INTERRUPT SELECTED PATHS
Control requires the highest confidence and safety bar.
```

Skipping a phase creates predictable failure:

| Skip | Likely result |
|---|---|
| Golden-path proof | A generalized architecture with no credible security primitive |
| Evidence depth | Many shallow integrations and untrustworthy findings |
| Careful expansion | A model overfit to one provider and one agent |
| Security memory | Runtime noise without a trustworthy baseline |
| Runtime observation | Multi-agent connectivity mistaken for actual propagation |
| Multi-agent defense | Enforcement at the wrong actor or cut point |
| Enforcement safety gate | Pico itself becomes a privileged security risk |

---

# 17. Advancement Decision Record

At the end of every phase, Pico should produce a short decision record:

```text
Phase:

Decision:
ADVANCE / EXTEND / REFINE / STOP

Product claim proven:

Exit criteria met:

Exit criteria not met:

What users demonstrated:

What the evidence demonstrated:

Known false positives:

Known false negatives:

Known UNKNOWN states:

Self-security results:

Compatibility limits:

What was learned:

Why the next phase is justified:
```

Possible decisions:

- `ADVANCE` — the phase claim is proven and the next uncertainty is now the highest-value one.
- `EXTEND` — the phase is directionally correct but needs more evidence or user validation.
- `REFINE` — the product primitive, evidence model, or architecture must change before proceeding.
- `STOP` — evidence does not support the product claim or the safety/value tradeoff.

The default is not `ADVANCE`.

---

# 18. Immediate Next Step

The next project artifact after this roadmap is an implementation plan for v0.1.

That future plan may define Sprint 001 and subsequent vertical slices, but it must inherit the v0.1 scope and gates in this document.

No implementation sprint should broaden the first product proof beyond:

```text
OpenCode
    +
GitHub MCP / external influence
    +
Bash
    +
Cloudflare credential
    +
Cloudflare Worker authority
    +
evidence-backed explanation
```

Until Pico proves that path, every additional integration, interface, runtime feature, and enforcement idea remains architecture—not implementation scope.

---

# 19. Final Roadmap Decision

Pico should grow in the following order:

> **Credibility before coverage. Depth before breadth. Memory before monitoring. Observation before enforcement.**

The first product is small on purpose:

> **A local-first security graph that shows a developer one real, evidence-backed path from external agent influence to consequential cloud authority—and explains how to break it.**

If Pico can do that reliably, the architecture has earned extension.

If it cannot, the roadmap requires Pico to learn and refine before it expands.
