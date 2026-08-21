# Pico — Product Definition

**File:** `PRODUCT_DEFINITION.md`  
**Status:** Complete — Canonical Product Definition  
**Verdict:** PASS  
**Date:** August 18, 2026  
**Stage:** Product Foundation  
**Followed by:** `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Executive Summary

Pico is a local-first, developer-first security product for AI-native engineering environments.

AI coding agents increasingly operate with access to:

- source code;
- local filesystems;
- shells;
- GitHub;
- MCP servers;
- credentials;
- databases;
- cloud providers;
- deployment systems;
- staging environments;
- production infrastructure.

At the same time, those agents consume information from sources with very different trust characteristics:

- GitHub issues and pull requests;
- repository content;
- webpages and documentation;
- MCP responses;
- APIs;
- user prompts;
- Slack and email;
- uploaded or local files.

The security problem appears when these two worlds intersect.

Pico's foundational thesis is:

> **Agent security risk emerges where untrusted influence intersects autonomous authority.**

An untrusted source alone is not necessarily dangerous.

A privileged agent alone is not necessarily dangerous.

The meaningful security condition occurs when information from a source with weak or external trust can reach an autonomous actor that can exercise consequential authority without an adequate enforced boundary.

Pico V0 therefore does not begin as an agent firewall, runtime sandbox, or autonomous response platform.

It begins by discovering and explaining potential paths through which untrusted information can reach consequential authority.

The initial product is:

> **A local-first, read-only developer security tool that discovers coding agents, MCP capabilities, external influence, credential reachability, and connected infrastructure; constructs an evidence-backed security graph; and identifies dangerous potential attack paths from untrusted sources to consequential authority.**

The primary product object is the:

# Attack Path

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

---

# 2. Product Thesis

The core model is:

```text
UNTRUSTED INFLUENCE
        ↓
 AUTONOMOUS ACTOR
        ↓
CONSEQUENTIAL AUTHORITY
```

Therefore:

> **Influence × Authority = Agent Attack Surface**

Pico exists to:

> **Discover, explain, and eventually control those paths.**

This thesis is deliberately broader than prompt injection.

Pico is concerned with the composition of:

- what can influence an agent;
- what the agent can do;
- which credentials and systems are reachable;
- what those credentials authorize;
- which consequential resources are affected;
- which enforced boundaries interrupt the path.

The product does not need to prove that a source is malicious to establish meaningful exposure.

It needs to establish that a source with relevant trust characteristics can reach authority with relevant consequences.

---

# 3. Product in One Sentence

Pico V0 can be described as:

> **A developer-first security tool that discovers the dangerous paths created by coding agents, their tools, credentials, external inputs, and infrastructure.**

Pico should not initially be described as:

- an AI cybersecurity platform;
- an agent firewall;
- agent-to-agent defense;
- an AI SOC;
- an MCP security gateway;
- an agent IAM platform;
- a prompt-injection detector;
- a cloud security posture platform;
- an AI penetration-testing system.

Those descriptions either overstate the first product or place it in an existing category that obscures Pico's primitive.

V0 does something more specific:

> **Discover → Connect → Analyze → Explain**

---

# 4. Primary Product Question

Everything in V0 should help answer:

> **How can something untrusted reach something important through my agents?**

If a feature does not materially improve Pico's ability to answer that question, it probably does not belong in V0.

Example:

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

The individual objects are not the central product insight.

The evidence-backed path connecting them is.

---

# 5. Initial User

The initial user is:

> **A technical founder or engineer at an AI-native startup operating privileged software-engineering agents.**

Pico does not require a company to operate a sophisticated multi-agent fleet.

One coding agent with broad input and meaningful authority is enough to create the precursor problem.

## 5.1 Initial company profile

Likely characteristics:

- approximately 5–50 engineers;
- AI-native engineering culture;
- aggressive adoption of coding agents;
- agents with meaningful local or remote tool access;
- use of MCP, repositories, cloud services, or deployment systems;
- agents that may reach staging or production;
- small or nonexistent dedicated AI security team;
- preference for developer tools over heavyweight security platforms.

## 5.2 Initial users

- technical founder;
- CTO;
- founding engineer;
- AI engineer;
- platform engineer;
- infrastructure engineer;
- staff engineer;
- security-minded developer.

Their first problem is not primarily:

> "Help us become compliant."

It is:

> **"What have we actually given these agents access to?"**

Then:

> **"What can influence them?"**

And ultimately:

> **"How could something an agent consumes reach production or another consequential system?"**

---

# 6. Initial Beachhead

Pico begins with:

# Software Engineering Agents

Examples of the broader product category include:

- OpenCode;
- Codex;
- Claude Code;
- Cursor;
- custom engineering agents.

The first supported implementation target is OpenCode.

Engineering agents are the best initial beachhead because they commonly combine:

```text
HIGH AUTONOMY
      +
BROAD CAPABILITY
      +
UNTRUSTED INPUT
      +
MEANINGFUL CONSEQUENCES
```

They may have access to:

- filesystem and source code;
- shell execution;
- Git and GitHub;
- package managers;
- browsers and open-world content;
- MCP servers and tools;
- environment credentials;
- databases;
- cloud providers;
- deployment and infrastructure systems.

Pico should not initially attempt to cover every organizational agent.

V0 does not begin with:

- marketing agents;
- sales agents;
- HR agents;
- support agents;
- finance agents;
- arbitrary enterprise automation.

Engineering provides sufficient depth and consequence to validate the thesis.

---

# 7. Product Principles

## 7.1 The path is the product

Pico is not primarily an agent inventory.

Agents, tools, credentials, resources, and boundaries matter because of the security paths they create.

## 7.2 Evidence before conclusions

Every security-significant claim must be traceable to evidence.

A finding that cannot answer "How do you know?" is not a valid Pico finding.

## 7.3 Local-first

Core discovery, persistence, analysis, and explanation work locally.

A hosted Pico account is not required for first use.

## 7.4 Read-only by default

Pico V0 observes and explains.

It does not change the target environment or exercise destructive authority.

## 7.5 Secrets are transient

Pico may use an existing credential briefly for safe provider introspection.

It stores security facts about the credential, never the raw value.

## 7.6 Deterministic security truth

Authoritative relationships, attack paths, severity, and confidence are established by deterministic logic.

An LLM may explain a Pico conclusion. It does not create the conclusion.

## 7.7 Severity and confidence are separate

Impact and evidentiary certainty are different dimensions.

Pico must represent both.

## 7.8 Unknown is valid

Pico must prefer `UNKNOWN` or partial evidence to false precision.

## 7.9 Developer actionability

A finding should explain how to break the path, even when Pico does not perform the remediation.

## 7.10 Architect for extension; implement only the golden path

Pico's concepts should allow future agents, providers, history, runtime observation, multi-agent defense, and enforcement.

V0 implements only what its first end-to-end path requires.

---

# 8. Primary Product Object

The primary product object is:

# Attack Path

The primary product experience should not begin as:

```text
Agents

OpenCode
Codex
Claude Code
```

It should begin closer to:

```text
Attack Paths

1 Critical
2 High
4 Medium
```

Agents are components inside security stories.

The customer's outcome is understanding:

- where influence originates;
- which actor receives it;
- which capability the actor can use;
- which authority is reachable;
- which consequential resource is exposed;
- whether a real boundary interrupts the path;
- why Pico believes the path exists;
- how the path can be broken.

---

# 9. Fundamental Security Model

The simplest conceptual graph is:

```text
SOURCE
   ↓
ACTOR
   ↓
CAPABILITY
   ↓
AUTHORITY
   ↓
SINK
```

`SOURCE`, `ACTOR`, `CAPABILITY`, `AUTHORITY`, `SINK`, and `BOUNDARY` are security roles, not mutually exclusive provider object types.

A resource may hold multiple roles.

For example, an MCP server or tool may participate as:

```text
SOURCE
because it returns external information

CAPABILITY
because an agent can invoke it

SINK
because it may expose a consequential operation
```

This prevents a rigid ontology that breaks as Pico grows.

---

# 10. Sources and Influence

A `SOURCE` is something capable of introducing information or instruction-bearing influence.

Examples:

- public GitHub issue;
- external pull request or comment;
- user prompt;
- webpage;
- web search result;
- external API response;
- MCP response;
- Slack message;
- email;
- uploaded file;
- repository content;
- external documentation.

A source does not need to be malicious.

Its control and trust characteristics matter.

Possible trust vocabulary includes:

```text
TRUSTED_INTERNAL
AUTHENTICATED_INTERNAL
AUTHENTICATED_EXTERNAL
PUBLIC_EXTERNAL
OPEN_WORLD
UNKNOWN
```

Pico should describe a public issue as externally controlled or public external—not as malicious without evidence.

Pico should also distinguish:

```text
AVAILABLE INFLUENCE
The agent can retrieve the source.

AUTOMATIC INFLUENCE
The source enters context automatically.
```

Availability does not imply automatic consumption.

---

# 11. Actors

An `ACTOR` is something capable of:

- receiving or processing information;
- transforming information;
- exercising capabilities;
- propagating influence;
- delegating work.

Initial actors include:

- OpenCode;
- relevant agent instances or profiles;
- an MCP-mediated capability where it acts in the path;
- a shell as an execution surface.

Future actors may include:

- Codex;
- Claude Code;
- Cursor;
- custom agents;
- subagents;
- orchestrators;
- shared memory systems;
- agent runtimes;
- agent-to-agent protocols.

The product must evaluate effective capability, not merely product installation.

---

# 12. Capabilities, Authority, and Sinks

A `CAPABILITY` describes what an actor can do.

Initial normalized classes may include:

```text
READ
WRITE
EXECUTE
ADMIN
EXTERNAL_SIDE_EFFECT
```

An `AUTHORITY` is the permission-bearing means through which consequential operations become possible.

Examples:

- environment credential;
- API token;
- OAuth grant;
- provider session;
- MCP authorization;
- local execution authority.

A `SINK` is a resource or operation where action produces meaningful consequence.

Examples:

- repository write;
- shell execution;
- secret access;
- database mutation;
- production deployment;
- infrastructure mutation;
- IAM modification;
- external communication;
- billing operation.

Possible sink impact includes:

```text
LOCAL_DEV
REPOSITORY
STAGING
PRODUCTION
SECRET_STORE
DATABASE
IAM
BILLING
EXTERNAL_SIDE_EFFECT
```

Credential presence does not equal authority.

Pico must establish:

```text
Actor
  ↓ can use
Capability
  ↓ can reach
Credential
  ↓ authorizes
Resource / Operation
```

---

# 13. Resources and Relationships

Pico preserves provider identity underneath the security roles.

Conceptually:

```text
Resource
────────────────────────

id
canonical identity
kind
provider
name
metadata
security roles
observed state
```

Examples:

```text
agent:opencode:default

mcp:github:server

mcp:github:tool:get_issue

credential:cloudflare:<safe-fingerprint>

cloudflare:worker:<account>:<worker>
```

Canonical identity must never contain a secret value.

Relationships describe security-relevant connections between resources.

Potential relationship kinds include:

```text
configured_with
exposes
can_call
can_retrieve
can_read
can_write
can_execute
can_access
uses_credential
authenticates_to
authorizes
scoped_to
can_mutate
can_deploy
protected_by
requires_approval
isolated_by
denied_by
```

Example:

```text
OpenCode
    ↓ can_execute
Bash

Bash
    ↓ can_access
Cloudflare Credential

Cloudflare Credential
    ↓ authorizes
Cloudflare Worker
```

Separately:

```text
External GitHub Content
    ↓ can_retrieve through
GitHub MCP
    ↓ available to
OpenCode
```

Together, these may form an Attack Path.

---

# 14. Evidence Is First-Class

Pico must never say:

> "Your agent can modify production."

without being able to answer:

> **"How do you know?"**

Evidence should explain:

- where the fact came from;
- when Pico observed it;
- what Pico observed;
- how authoritative the source is;
- whether the evidence is current;
- whether sensitive material was involved;
- what remains unknown.

Evidence classes include:

```text
DIRECT
Pico directly observed machine-readable state.

DECLARED
An authoritative system declared a capability or permission.

DERIVED
Pico deterministically combined stronger evidence.

INFERRED
Evidence suggests a conclusion but cannot fully establish it.
```

Example:

```text
OpenCode
    ↓ can_execute
Bash

Evidence:
effective permission resolution
runtime mode where observable
approval behavior
explicit deny or sandbox state
```

Example:

```text
Bash
    ↓ can_access
Cloudflare Credential

Evidence:
credential reference reachable in the execution environment
raw value never stored
```

Example:

```text
Cloudflare Credential
    ↓ can_mutate
Cloudflare Worker

Evidence:
provider authorization metadata
permission scope
resource scope
Worker identity
```

Evidence is not decorative product detail.

It is the foundation of Pico's credibility.

---

# 15. Secret Handling

Pico identifies credential capability without becoming a credential database.

It may persist facts such as:

```text
provider:
cloudflare

source:
agent-accessible environment

credential type:
API token

status:
valid / unknown

authority:
Workers write

resource scope:
supported account or resources

safe fingerprint:
optional

raw value:
NEVER STORED
```

Pico should aggressively avoid persisting:

- API tokens;
- passwords;
- private keys;
- OAuth access tokens;
- session cookies;
- credential material;
- secret-bearing command or configuration output.

Pico cares about:

> **Reachability, capability, scope, and authority**

not:

> **Credential material**

This is a foundational product promise.

---

# 16. Two Security Flows

An Attack Path contains two distinct flows.

## 16.1 Influence Flow

```text
External GitHub Content
        ↓
GitHub MCP
        ↓
OpenCode
```

Question:

> **What information can reach the autonomous actor?**

## 16.2 Authority Flow

```text
OpenCode
    ↓
Bash
    ↓
Cloudflare Credential
    ↓
Cloudflare Worker
```

Question:

> **What consequential authority can the autonomous actor exercise?**

The dangerous condition occurs at their intersection:

```text
              INFLUENCE

External GitHub Content
          ↓
      GitHub MCP
          ↓
       OpenCode
          │
          │ intersection
          ▼
       OpenCode
          ↓
         Bash
          ↓
 Cloudflare Credential
          ↓
 Cloudflare Worker

              AUTHORITY
```

Therefore:

> **Influence × Authority = Agent Attack Surface**

---

# 17. Attack Path Definition

A graph connection is not automatically an Attack Path.

A meaningful Attack Path requires four properties.

## 17.1 Influence reachability

Can information actually reach the actor?

It is not sufficient to know that GitHub exists or that an MCP server is configured.

Pico needs evidence that the relevant source is retrievable, exposed, injected, or otherwise available to the actor.

## 17.2 Capability reachability

Can the actor actually exercise the capability?

It is not sufficient that Bash exists on the machine.

Bash must be available under the effective agent configuration and runtime state.

## 17.3 Authority reachability

Does the reachable capability expose a credential or authorization that permits the consequential operation against the relevant resource?

It is not sufficient that a Cloudflare token exists.

Its permission and resource scope must matter.

## 17.4 Boundary continuity

Does an enforced trust boundary materially interrupt the path?

Example:

```text
External Influence
       ↓
Agent
       ↓
Mandatory Human Approval
       ↓
Production
```

differs from:

```text
External Influence
       ↓
Agent
       ↓
Production
```

Therefore:

> **An Attack Path is a continuous, evidence-backed chain of influence, capability, and authority connecting a relevant source to a consequential sink without an adequate enforced boundary.**

---

# 18. Trust Boundaries

Trust boundaries are first-class security semantics.

Potential enforced boundaries include:

- hard tool deny;
- sandbox or process isolation;
- mandatory approval;
- credential scope;
- resource scope;
- network isolation;
- protected-directory enforcement;
- provider authorization policy.

A control only blocks an autonomous path when it is technically enforced and cannot be bypassed through another available route.

The following do not become hard boundaries by themselves:

- prompts;
- instructions;
- documentation;
- warnings;
- comments;
- MCP hints;
- a request that the model voluntarily ask first.

These may describe intended policy.

They do not necessarily enforce it.

A boundary blocks a path, not an entire actor or resource.

If Bash requires approval but an MCP deployment tool bypasses that approval, Pico must preserve the alternative active path.

---

# 19. Potential, Observed, and Verified Paths

Pico must distinguish levels of evidence.

## 19.1 Potential Path

Configuration, provider evidence, and discovered relationships establish that the path is available.

```text
SOURCE ───────→ SINK
```

V0 primarily operates here.

## 19.2 Observed Path

Runtime evidence establishes that information or execution traveled along the path.

```text
SOURCE ═══════→ SINK
```

This belongs to a later product phase.

## 19.3 Verified Attack Path

Testing or stronger evidence establishes actual security impact.

```text
SOURCE █████══→ SINK
```

This is also future scope and must remain safe and controlled.

V0 must never imply:

> "This path has been exploited."

when it has only discovered potential exposure.

---

# 20. Finding Definition

A finding is not automatically a vulnerability.

A finding is:

> **An evidence-backed security story connecting a source of influence to consequential authority under conditions that create meaningful exposure.**

Potential finding classes include:

```text
UNTRUSTED_TO_PRODUCTION
UNTRUSTED_TO_SECRET
UNTRUSTED_TO_SHELL
UNTRUSTED_TO_DATABASE_MUTATION
UNBOUNDED_MCP_CAPABILITY
SHARED_PRIVILEGED_CREDENTIAL
CROSS_AGENT_PRIVILEGE_PATH
AGENT_TO_IAM
AGENT_TO_EXTERNAL_SIDE_EFFECT
```

V0 should not implement all of these merely because the domain anticipates them.

The first required class is:

```text
UNTRUSTED_TO_PRODUCTION
```

for the OpenCode-to-Cloudflare golden path.

---

# 21. Severity and Confidence

Pico keeps severity and confidence separate.

```text
SEVERITY
What happens if this path is usable?

CONFIDENCE
How strongly can Pico establish that the path exists?
```

A result may be:

```text
Severity:   CRITICAL
Confidence: MEDIUM
```

This means the consequence is critical, but one or more security-critical relationships are not fully established.

Potential deterministic severity inputs include:

- source trust;
- influence strength;
- actor autonomy;
- capability;
- authority;
- sink impact;
- enforced boundaries.

Potential confidence inputs include:

- evidence class;
- source authority;
- freshness;
- relationship state;
- provider resolution precision;
- runtime-state visibility;
- partial scan status.

The weakest security-critical edge must materially constrain the finding's confidence.

Pico must not average uncertainty away.

---

# 22. Risk Engine

V0 risk analysis is deterministic and explainable.

Pico should not begin with:

> "An AI model says this path is 87.3% dangerous."

The engine may derive transparent levels such as:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Example reasoning:

```text
PUBLIC_EXTERNAL source
        +
AGENT_RETRIEVABLE influence
        +
EXECUTE capability
        +
PRODUCTION WRITE authority
        +
NO ENFORCED BOUNDARY
        =
CRITICAL severity
```

The exact implementation belongs to architecture and implementation design.

The product requirement is that the reasoning remains inspectable and reproducible.

---

# 23. Findings Need Reasons

A finding should answer:

```text
WHAT did Pico find?

WHY does it matter?

HOW does the path work?

HOW does Pico know?

WHAT is uncertain?

WHAT boundary is missing or working?

HOW can the path be broken?
```

Example:

```text
CRITICAL
External GitHub content can reach Cloudflare
production mutation authority.

Path
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
  Production Worker

Confidence
  HIGH

Why
  GitHub content is externally controlled.
  OpenCode can retrieve it through the configured MCP tool.
  Effective Bash permission is ALLOW.
  Bash can reach the Cloudflare credential.
  Provider evidence establishes Workers write authority.
  The credential scope includes the target account.
  No enforced approval or isolation boundary interrupts the path.
```

Every part of the conclusion should be challengeable by the developer.

---

# 24. Avoiding Alert Fatigue

Pico should not report every raw graph traversal as a separate vulnerability.

Example raw paths:

```text
GitHub Issue → OpenCode → Bash → Token → Worker A
GitHub Issue → OpenCode → Bash → Token → Worker B
GitHub Issue → OpenCode → Bash → Token → Worker C
```

Preferred product output:

```text
1 Critical Exposure

External GitHub content can reach Cloudflare
production mutation authority.

Affected resources: 3 Workers
```

The user can inspect supporting paths and resources without receiving three copies of the same security story.

The goal is:

> **Find the few paths that actually matter.**

---

# 25. Remediation

V0 remains read-only, but every important finding should explain how a developer can break the path.

Potential cut points for the golden path include:

```text
1. Require an enforced approval for Bash.

2. Remove the Cloudflare credential from the
   agent-accessible execution environment.

3. Scope the Cloudflare credential away from
   production or from Workers write authority.

4. Restrict the relevant GitHub MCP retrieval
   capability for the privileged agent.

5. Move privileged operations behind an enforced,
   non-bypassable boundary.
```

Pico should prefer path-breaking recommendations with the smallest reasonable operational impact.

These cut points may become controlled enforcement points in later product phases.

V0 does not perform the change.

---

# 26. Local-First Product Model

Pico V0 runs locally.

Conceptually:

```text
Developer Machine
      │
      ▼
Pico Discovery
      │
      ▼
Local Evidence + Security Graph
      │
      ▼
Local Analysis + Findings
      │
      ├── CLI
      └── Coding-Agent Interface
```

No Pico cloud account is required for first use.

Reasons:

- Pico examines sensitive agent and infrastructure relationships;
- local operation lowers the initial trust barrier;
- raw credentials should remain in the user's environment;
- startups need low-overhead installation;
- offline analysis should remain possible;
- the environment is the primary source of truth.

Pico may make bounded outbound requests when provider introspection is required.

Those requests must be explicit, read-only, and tied to evidence collection.

---

# 27. Two Interfaces, One Security Engine

Pico has two first-class V0 interfaces:

```text
                  PICO SECURITY ENGINE
                         │
              ┌──────────┴──────────┐
              │                     │
             CLI              CODING AGENT
              │                     │
              └──────────┬──────────┘
                         ↓
               Local Security State
```

The CLI provides deterministic developer workflows.

Conceptually:

```text
pico init
pico scan
pico findings
pico finding <id>
pico agents
pico status
```

The coding-agent interface allows a developer to stay inside an existing workflow.

Example questions:

> "Check whether this project has any critical agent attack paths."

> "Can anything this agent reads reach production?"

> "Why is this finding critical?"

> "Did anything dangerous change?"

The likely initial structured interface is MCP.

It may expose read-only capabilities such as:

```text
get_status
scan
list_findings
get_finding
get_security_context
```

The coding agent may summarize or discuss Pico's results.

Pico remains authoritative about the security facts.

There must not be separate CLI and agent scanners or separate security logic.

---

# 28. Agent Interface Safety

The agent-facing interface is read-only in V0.

It may support:

```text
scan
list
inspect
explain
query
```

It must not support:

```text
revoke
delete
block
quarantine
rotate
kill
modify policy
change infrastructure
deploy a fix
```

Pico must not become another privileged execution surface simply because it is callable by an agent.

An agent-triggered scan must use the same bounded scan pipeline as a CLI-triggered scan.

---

# 29. First Five-Minute Experience

The first useful experience should be small and direct.

Conceptually:

```text
1. Install Pico.

2. Run:
   pico init

3. Run:
   pico scan

4. Pico discovers the supported local environment.

5. Pico returns either:
   - an evidence-backed finding;
   - a clear blocked path;
   - an honest partial/unknown result;
   - a concise all-clear within the supported scope.
```

Example summary:

```text
Pico scan complete

Agents
  1 discovered

MCP servers
  1 relevant server discovered

Credentials
  1 security-relevant credential discovered

Attack paths
  1 active

Findings

CRITICAL
External GitHub content can reach Cloudflare
production mutation authority.

Run:
  pico finding <id>

for evidence and remediation.
```

The first session should demonstrate Pico's core insight rather than make the user configure an enterprise platform.

---

# 30. V0 Golden Path

The first product proof is deliberately narrow:

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

Pico must safely establish:

1. OpenCode exists in the supported scan scope.
2. The relevant GitHub MCP capability is configured and available.
3. The capability can retrieve externally controlled GitHub content.
4. OpenCode's effective state permits the relevant MCP use and Bash execution.
5. Bash can reach a Cloudflare credential reference.
6. The credential value is never persisted.
7. Read-only provider evidence resolves relevant Cloudflare permission and resource scope.
8. The credential can mutate the relevant Worker or Pico reports the authority edge as unresolved.
9. No confirmed enforced boundary interrupts the candidate path.
10. The resulting finding explains evidence, severity, confidence, uncertainty, and remediation cut points.

Pico is not testing an attack.

It is proving whether each relationship can be established through safe observation.

---

# 31. V0 Scope

V0 includes only the capabilities necessary to prove the golden path well.

## 31.1 Included

- local CLI;
- local SQLite-backed state;
- manual bounded scans;
- OpenCode discovery;
- effective Bash and relevant MCP permission resolution;
- GitHub MCP discovery;
- external GitHub influence modeling;
- Cloudflare credential reference and reachability discovery;
- safe credential fingerprinting and transient use;
- read-only Cloudflare authority introspection;
- Cloudflare Worker resource and authority modeling;
- evidence provenance;
- normalized security graph;
- influence analysis;
- authority analysis;
- boundary evaluation;
- Attack Paths;
- `UNTRUSTED_TO_PRODUCTION` finding;
- transparent severity and confidence;
- finding explanation and remediation guidance;
- minimal read-only Pico MCP interface over the same engine;
- deterministic fixtures, integration tests, and controlled dogfood.

## 31.2 May be represented architecturally but not implemented broadly

- additional source types;
- additional agent adapters;
- additional provider adapters;
- additional finding classes;
- security history;
- runtime observation;
- multi-agent paths;
- enforcement cut points.

---

# 32. V0 Non-Goals

Pico V0 is not:

- an enterprise security platform;
- a SIEM;
- an EDR;
- a cloud security posture platform;
- a generic asset inventory;
- an agent runtime;
- an agent sandbox;
- a policy engine;
- a prompt-injection classifier;
- an AI penetration-testing product;
- a hosted-first service;
- an organization-wide dashboard;
- a multi-user RBAC system;
- a Slack bot;
- a CI enforcement gate;
- a broad integration catalog;
- an arbitrary plugin platform;
- a multi-agent defense system;
- an automatic remediation system.

V0 does not:

- modify agent permissions;
- modify MCP configuration;
- rotate or revoke credentials;
- change infrastructure;
- deploy code;
- execute an Attack Path;
- prove authority with destructive operations;
- shut down agents;
- collect full prompt or source content by default;
- use an LLM to establish security truth;
- support every coding agent, MCP server, provider, or credential type.

---

# 33. V0 Product Promises

Pico should make a small set of promises and keep them.

## 33.1 Evidence promise

Every security-significant conclusion is explainable through evidence.

## 33.2 Secret promise

Pico does not persist raw credential values.

## 33.3 Read-only promise

Pico does not change the environment it evaluates.

## 33.4 Honesty promise

Pico reports uncertainty, partial scans, unsupported states, and stale evidence explicitly.

## 33.5 Determinism promise

Equivalent observed state and analysis version produce equivalent conclusions.

## 33.6 Local-first promise

Core product value does not require a hosted Pico service.

## 33.7 Scope promise

Pico describes what it inspected and does not turn "not observed" into "does not exist."

---

# 34. V0 Definition of Done

Pico V0 is done when a developer can:

```text
install Pico

initialize Pico safely

scan a supported local environment

have Pico discover OpenCode

understand the relevant effective agent capabilities

discover GitHub MCP external influence

discover reachable Cloudflare credential authority

see an evidence-backed Attack Path to a Worker

understand why Pico considers the path dangerous

see Pico's confidence and unknowns

understand whether an enforced boundary blocks the path

see practical ways to break the path

query the same result from a coding agent
```

The product is not done merely because it can draw a graph.

The first supported user must be able to understand and act on the security story.

The golden path must also satisfy:

- no raw-secret persistence;
- deterministic analysis;
- read-only provider behavior;
- explicit partial failure;
- stable finding output;
- controlled real-environment validation;
- correct differentiation between active, blocked, inferred, and unknown paths.

---

# 35. Success Criteria

The most important early success criteria are qualitative and trust-oriented.

## Product value

- A developer discovers a path they did not understand before.
- The finding changes a permission, credential, approval, or architecture decision.
- The explanation is useful without a dedicated security analyst.
- The user wants Pico to remain installed and scan again.

## Security quality

- Security-critical edges have strong provenance.
- Pico refuses unsupported authority claims.
- Blocked paths are blocked only by enforced controls.
- Alternative-path bypasses remain visible.
- Findings are stable and reproducible.

## Self-safety

- Secret canaries never reach persistent state or logs.
- Provider operations remain within read-only allowlists.
- Agent-facing access cannot mutate the environment.

## Product discipline

- The golden path works end to end before integration breadth expands.
- Adapter count is not treated as the primary measure of progress.
- Unknown states become learning inputs rather than guessed conclusions.

---

# 36. Positioning

The strongest initial positioning territory is:

> **Pico discovers the dangerous paths your AI agents create.**

Supporting explanation:

> **Pico maps how external influence can move through coding agents, tools, credentials, and infrastructure to reach consequential authority.**

Pico should lead with the developer outcome:

- see what can influence an agent;
- see what the agent can reach;
- understand the dangerous intersection;
- see the evidence;
- break the path.

Pico should not lead with generic claims to "secure AI."

---

# 37. Long-Term Product Direction

Pico's north star is broader than static scanning.

The product may grow through the following layers:

```text
1. ATTACK-PATH DISCOVERY
   What dangerous paths exist?

2. SECURITY MEMORY
   When did the path appear and what changed?

3. CONTINUOUS OBSERVATION
   When does supported runtime state change the path?

4. MULTI-AGENT DEFENSE
   How does influence propagate across actors?

5. CONTROLLED ENFORCEMENT
   Where can a validated path be safely interrupted?

6. CONTAINMENT
   How can dangerous propagation be limited without
   shutting down the autonomous ecosystem?
```

The long-term metaphor is closer to an immune system than a perimeter firewall.

Autonomous systems will need to remain connected and useful.

Pico's eventual role is to understand what belongs, what can influence what, where authority flows, and where dangerous propagation should be interrupted.

That future does not justify prematurely implementing runtime control in V0.

---

# 38. Product Decisions Locked by This Definition

The following decisions are considered settled unless implementation evidence disproves them:

1. Pico is local-first.
2. Pico is developer/startup-first.
3. Software-engineering agents are the initial beachhead.
4. The primary product object is the Attack Path.
5. The core thesis is influence intersecting authority.
6. Evidence is first-class.
7. Severity and confidence remain separate.
8. Only enforced boundaries interrupt paths.
9. V0 operates on potential paths and does not imply exploitation.
10. V0 is read-only.
11. Raw secrets are never persisted.
12. Security truth is deterministic.
13. CLI and coding-agent interfaces share one engine.
14. OpenCode is the first agent adapter.
15. GitHub MCP provides the first external-influence surface.
16. Bash provides the first local execution capability.
17. Cloudflare provides the first authority adapter.
18. Cloudflare Worker authority is the first consequential sink.
19. `UNTRUSTED_TO_PRODUCTION` is the first required finding class.
20. Integration depth comes before integration breadth.
21. Detection remains separate from future enforcement.

---

# 39. Final Product Definition

Pico V0 is:

> **A local-first, read-only developer security product that discovers an evidence-backed path from external GitHub influence through GitHub MCP, OpenCode, Bash, and a reachable Cloudflare credential to Cloudflare Worker authority; determines whether an enforced boundary interrupts that path; and explains the exposure, evidence, uncertainty, and practical ways to break it.**

The product succeeds when a developer can say:

> **"I did not know my agent had that path to production. Now I understand exactly how it exists and how to break it."**

That is enough for V0.

Everything else must be earned from that proof.
