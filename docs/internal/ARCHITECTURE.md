# Pico — Architecture

**File:** `ARCHITECTURE.md`  
**Status:** Draft — Core Architecture  
**Date:** August 18, 2026  
**Stage:** Architecture Sprint  
**Depends on:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`

---

# 1. Purpose

This document defines the architecture of Pico.

Pico is a local-first, developer-first security product for AI-native engineering environments.

Its core security thesis is:

> **Agent security risk emerges where untrusted influence intersects autonomous authority.**

Pico discovers the systems surrounding an AI agent, collects evidence about what those systems can influence and what authority they possess, constructs a local security graph, and identifies evidence-backed paths from untrusted influence to consequential authority.

The architecture exists to make that process:

- evidence-backed;
- deterministic;
- explainable;
- local-first;
- read-only by default;
- safe around credentials;
- extensible across agents and providers;
- useful to both humans and AI agents.

Pico's architecture should allow the product to grow toward runtime observation and controlled containment without requiring those capabilities in V0.

The primary architecture rule is:

> **Architect for extension. Implement only the golden path.**

The initial golden path is:

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
 Cloudflare Resource
```

Pico V0 must prove that this path can be discovered, represented, analyzed, and explained using evidence gathered safely from a real developer environment.

---

# 2. Architecture Principles

The following principles govern Pico's architecture.

## 2.1 Evidence is the foundation

Pico is not primarily a scanner.

It is an evidence system that produces security conclusions.

Every security-significant claim should ultimately be traceable to evidence.

The core pipeline is:

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

A finding without explainable evidence is not a valid Pico finding.

---

## 2.2 The graph is the center of the system

Adapters should not generate security findings directly.

Adapters discover facts.

The graph represents those facts.

Analysis operates over the graph.

Findings are produced from analysis.

This separation prevents provider-specific logic from becoming Pico's security model.

```text
Agent Adapter ───┐
                 │
MCP Discovery ───┼──→ Evidence → Graph → Analysis → Findings
                 │
Provider Adapter ┤
                 │
Local Discovery ─┘
```

---

## 2.3 Security conclusions are deterministic

The authoritative Pico security engine must be deterministic.

An LLM must not decide:

- whether an edge exists;
- whether a credential has authority;
- whether a trust boundary is enforced;
- whether an attack path exists;
- whether a finding is valid.

Models may eventually help:

- summarize;
- explain;
- answer natural-language questions;
- generate remediation descriptions.

They do not establish security truth.

---

## 2.4 Severity and confidence are independent

Pico separates:

```text
SEVERITY
What happens if this path is usable?

CONFIDENCE
How strongly can Pico establish that the path exists?
```

A finding may therefore be:

```text
Severity:   CRITICAL
Confidence: MEDIUM
```

This is preferable to silently converting uncertainty into certainty.

---

## 2.5 Unknown is a valid result

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

---

## 2.6 Local-first

Pico V0 runs locally.

The user's environment remains the primary source of truth.

Pico should not require a hosted Pico control plane to perform a scan.

Outbound network requests occur only when evidence collection requires provider or integration metadata.

---

## 2.7 Read-only by default

Pico observes.

Pico does not modify the environment it is evaluating.

V0 does not:

- change agent permissions;
- modify MCP configuration;
- rotate credentials;
- revoke tokens;
- change infrastructure;
- deploy code;
- execute attack paths;
- perform destructive probes.

---

## 2.8 Secrets are transient inputs, not stored resources

Pico may temporarily use an existing credential when provider introspection requires authentication.

The raw secret must not become persisted Pico state.

Pico stores facts about credentials, not their values.

---

## 2.9 Effective state matters more than declared state

Configuration alone does not always determine effective capability.

Pico should prefer:

```text
configuration
+
runtime mode
+
enforced controls
=
effective capability
```

over:

```text
configuration
=
capability
```

This distinction is particularly important for approval, auto-approval, bypass, sandbox, and permission modes.

---

## 2.10 Architecture should preserve history

Pico V0 does not need to become an operational security timeline product.

However, the architecture should preserve enough scan and observation history to eventually answer:

> "When did this attack path appear?"

and:

> "What changed?"

without redesigning persistence.

---

# 3. System Overview

Pico V0 is a single local application composed of modular internal components.

Conceptually:

```text
                         ┌────────────────────┐
                         │        Pico        │
                         └─────────┬──────────┘
                                   │
                         ┌─────────▼──────────┐
                         │   Product Layer    │
                         │                    │
                         │ CLI      MCP       │
                         └─────────┬──────────┘
                                   │
                         ┌─────────▼──────────┐
                         │ Application Layer  │
                         │                    │
                         │ Scan               │
                         │ Query              │
                         │ Explain            │
                         └─────────┬──────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
      ┌───────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
      │   Discovery    │  │    Analysis     │  │   Persistence   │
      │                │  │                 │  │                 │
      │ Agent          │  │ Influence       │  │ Resources       │
      │ MCP            │  │ Authority       │  │ Relationships   │
      │ Local          │  │ Boundaries      │  │ Evidence        │
      │ Provider       │  │ Attack Paths    │  │ Observations    │
      │ Integration    │  │ Findings        │  │ Scans           │
      └───────┬────────┘  └────────┬────────┘  └─────────────────┘
              │                    │
      ┌───────▼────────┐           │
      │    Adapters    │           │
      │                │           │
      │ OpenCode       │           │
      │ GitHub         │           │
      │ Cloudflare     │           │
      └────────────────┘           │
                                   ▼
                           Security Graph
```

The architecture is intentionally modular inside one local application.

Pico V0 does **not** require:

- microservices;
- distributed queues;
- a remote graph database;
- a hosted backend;
- separate scanner daemons;
- multiple independently deployed services.

Modularity is achieved through code boundaries, not network boundaries.

---

# 4. Core Domain Model

The core Pico domain contains eight primary concepts:

```text
Scan
Observation
Resource
Relationship
Evidence
Boundary
AttackPath
Finding
```

Their responsibilities must remain distinct.

The conceptual lifecycle is:

```text
                    Scan
                     │
             ┌───────┴───────┐
             │               │
       Observation       Observation
             │               │
             ▼               ▼
         Resource        Relationship
             │               │
             └───────┬───────┘
                     │
                  Evidence
                     │
                     ▼
               Security Graph
                     │
              ┌──────┴──────┐
              │             │
          Influence      Authority
              │             │
              └──────┬──────┘
                     │
               Boundary Eval
                     │
                     ▼
                AttackPath
                     │
                     ▼
                  Finding
```

A useful distinction is:

```text
OBSERVED DOMAIN
────────────────────
Scan
Observation
Resource
Relationship
Evidence

ANALYZED DOMAIN
────────────────────
Boundary
AttackPath
Finding
```

The first group represents what Pico knows about the environment.

The second group represents what Pico concludes from that knowledge.

This boundary is important.

Pico should not confuse observation with analysis.

---

# 5. Resource

A `Resource` is a stable normalized representation of an entity Pico has discovered.

Examples:

```text
OpenCode agent

GitHub MCP server

GitHub issue-reading tool

Bash capability

Cloudflare API token

Cloudflare account

Cloudflare Worker
```

A Resource answers:

> **What exists?**

It does not answer:

> **What security risk does it create?**

---

## 5.1 Resource shape

Conceptually:

```text
Resource {
  id
  canonical_key
  kind
  provider
  name
  metadata
  first_observed_at
  last_observed_at
}
```

Example:

```text
Resource {
  id: "res_01..."
  canonical_key: "agent:opencode:default"
  kind: "agent"
  provider: "opencode"
  name: "OpenCode"
}
```

---

## 5.2 Canonical identity

Resources must have stable identity across scans whenever possible.

Pico should not create:

```text
Cloudflare Worker A — scan 1
Cloudflare Worker A — scan 2
Cloudflare Worker A — scan 3
```

as three unrelated resources.

Instead:

```text
Resource
  Cloudflare Worker A

Observed in:
  Scan 1
  Scan 2
  Scan 3
```

This enables history.

---

## 5.3 Canonical keys

Adapters should generate provider-aware canonical keys.

Examples:

```text
agent:opencode:default

mcp:github:server

mcp:github:tool:get_issue

credential:cloudflare:<fingerprint>

cloudflare:account:<account_id>

cloudflare:worker:<account_id>:<worker_name>

github:repo:<owner>/<repo>

github:issue:<owner>/<repo>#<number>
```

Canonical keys must never contain secret values.

---

## 5.4 Resource kinds

Initial kinds may include:

```text
agent
mcp_server
mcp_tool
shell
credential
repository
issue
pull_request
provider_account
project
deployment
worker
database
environment
sandbox
approval_gate
external_source
```

The vocabulary should remain intentionally small.

Provider-specific metadata belongs in `metadata`, not in an explosion of resource types.

---

## 5.5 Security roles

A Resource may participate in the graph as:

```text
SOURCE
ACTOR
CAPABILITY
AUTHORITY
SINK
BOUNDARY
```

These are roles, not primary resource types.

For example:

```text
GitHub Issue
kind: issue
role: SOURCE

OpenCode
kind: agent
role: ACTOR

Bash
kind: shell
role: CAPABILITY

Cloudflare API Token
kind: credential
role: AUTHORITY

Production Worker
kind: worker
role: SINK
```

A resource may have multiple roles.

---

# 6. Relationship

A `Relationship` represents a stable security-relevant connection between two Resources.

It answers:

> **How are these things connected?**

Example:

```text
OpenCode
   ↓ can_call
GitHub MCP Tool
```

or:

```text
Cloudflare Credential
   ↓ authorizes
Cloudflare Worker
```

---

## 6.1 Relationship shape

Conceptually:

```text
Relationship {
  id
  canonical_key
  from_resource_id
  to_resource_id
  kind
  state
  metadata
  first_observed_at
  last_observed_at
}
```

The relationship itself should remain stable across scans when the underlying relationship is the same.

Observations capture when Pico saw it.

Evidence captures why Pico believes it.

---

## 6.2 Relationship vocabulary

Initial vocabulary:

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

We should resist adding provider-specific verbs unless they represent a genuinely new security relationship.

For example:

```text
cloudflare_worker_edit
```

should probably remain:

```text
can_mutate
```

with provider-specific capability metadata.

---

## 6.3 Relationship state

A relationship can be:

```text
CONFIRMED
DERIVED
INFERRED
UNKNOWN
BLOCKED
```

### CONFIRMED

Strong direct or authoritative evidence establishes the relationship.

### DERIVED

Pico deterministically derives the relationship from stronger facts.

### INFERRED

Evidence suggests the relationship, but cannot fully prove it.

### UNKNOWN

Pico cannot determine whether the relationship exists.

### BLOCKED

An enforced control prevents the relationship from being usable under the observed state.

---

## 6.4 Relationships do not own evidence

A Relationship should reference supporting evidence.

Evidence should remain independently addressable.

This allows:

```text
Relationship A
Relationship B
Relationship C
```

to reference the same underlying observation where appropriate.

It also allows Pico to explain:

> "These two conclusions come from the same OpenCode permission rule."

---

# 7. Observation and Evidence

Observation and Evidence are intentionally separate concepts.

This distinction is one of the most important architecture decisions in Pico.

---

## 7.1 Observation

An `Observation` records:

> **What did Pico observe during this scan?**

Conceptually:

```text
Observation {
  id
  scan_id
  subject_type
  subject_id
  observation_type
  observed_at
  source
  metadata
}
```

Examples:

```text
Scan 17 observed Resource OpenCode

Scan 17 observed Relationship:
OpenCode → can_execute → Bash

Scan 17 observed Cloudflare Worker X

Scan 17 did not observe a previously known MCP server
```

Observation gives Pico temporal context.

---

## 7.2 Why Observation exists

Without Observation, Pico only knows current state:

```text
OpenCode → Bash
```

With Observation:

```text
Scan 12
OpenCode → Bash → ASK

Scan 13
OpenCode → Bash → ALLOW
```

Now Pico can eventually answer:

> "This exposure appeared after Bash changed from approval-gated to automatically allowed."

We do not need to expose that UX in V0.

But we should preserve the architecture required to support it.

---

## 7.3 Evidence

`Evidence` records:

> **Why does Pico believe a security claim?**

Conceptually:

```text
Evidence {
  id
  scan_id
  class
  source_type
  source_locator
  subject
  observation
  captured_at
  freshness
  sensitive
  metadata
}
```

Example:

```text
Evidence {
  class: DIRECT
  source_type: "opencode_config"
  source_locator: "~/.config/opencode/opencode.json"
  subject: "permission.bash"
  observation: "allow"
}
```

The raw secret value must never appear in evidence.

---

## 7.4 Evidence classes

Pico uses:

```text
DIRECT
DECLARED
DERIVED
INFERRED
```

### DIRECT

Pico directly observed machine-readable state.

### DECLARED

An authoritative system declares capability or permission.

### DERIVED

Pico deterministically combines stronger evidence.

### INFERRED

Evidence suggests a conclusion but cannot fully establish it.

---

## 7.5 Evidence provenance

Every Evidence object should answer:

```text
WHERE did this come from?

WHEN did Pico observe it?

WHAT exactly did Pico observe?

HOW trustworthy is the source?

IS the evidence still fresh?
```

This is essential to Pico's explainability.

---

## 7.6 Evidence immutability

Evidence should be append-oriented.

If a configuration changes, Pico should not rewrite old evidence to match the new state.

Instead:

```text
Scan 12 Evidence
Bash = ask

Scan 13 Evidence
Bash = allow
```

This gives Pico a trustworthy historical record.

Retention policies may eventually prune old evidence, but mutation should not destroy provenance.

---

## 7.7 Evidence sensitivity

Evidence should have a sensitivity classification.

Example:

```text
PUBLIC
INTERNAL
SENSITIVE_METADATA
SECRET
```

Pico V0 should almost never persist `SECRET`.

If collection would require persisting secret material, the collection strategy should be redesigned.

---

# 8. Scan

A `Scan` is a bounded evidence-collection event.

It answers:

> **What did Pico inspect, and what did Pico learn during this run?**

A scan is not merely a CLI command execution record.

It is the temporal boundary around a coherent environment observation.

---

## 8.1 Scan shape

Conceptually:

```text
Scan {
  id
  started_at
  completed_at
  status
  trigger
  scope
  pico_version
  environment_fingerprint
  metadata
}
```

Possible statuses:

```text
RUNNING
COMPLETE
PARTIAL
FAILED
```

`PARTIAL` is important.

Provider introspection may fail while local discovery succeeds.

Pico should preserve useful evidence instead of discarding the entire scan.

---

## 8.2 Scan trigger

Initial trigger:

```text
MANUAL
```

Future triggers may include:

```text
AGENT_REQUEST
SCHEDULED
FILESYSTEM_CHANGE
CI
RUNTIME_EVENT
```

These should not be implemented in V0 merely because the model supports them.

---

## 8.3 Scan scope

A scan should record what Pico intended to inspect.

Example:

```text
scope:
  agents:
    - opencode

  integrations:
    - github

  providers:
    - cloudflare

  local:
    - mcp
    - credentials
```

This matters because:

> "Pico did not observe AWS"

does not mean:

> "AWS does not exist"

if AWS was outside scan scope.

---

## 8.4 Scan lifecycle

Conceptually:

```text
pico scan
    │
    ▼
Create Scan
    │
    ▼
Resolve Scope
    │
    ▼
Run Discovery
    │
    ├── Agent Discovery
    ├── MCP Discovery
    ├── Local Capability Discovery
    └── Provider Discovery
    │
    ▼
Normalize Results
    │
    ▼
Persist Resources
    │
    ▼
Persist Relationships
    │
    ▼
Persist Evidence
    │
    ▼
Persist Observations
    │
    ▼
Build Security Graph
    │
    ▼
Analyze Influence
    │
    ▼
Analyze Authority
    │
    ▼
Evaluate Boundaries
    │
    ▼
Construct Attack Paths
    │
    ▼
Generate Findings
    │
    ▼
Complete Scan
```

---

## 8.5 Discovery failure

Adapters fail independently.

Example:

```text
OpenCode discovery     ✓
GitHub MCP discovery   ✓
Local credential scan  ✓
Cloudflare API         ✕ timeout
```

The result should be:

```text
Scan: PARTIAL
```

not:

```text
Scan: FAILED
```

Pico can still produce useful local evidence while clearly marking authority resolution incomplete.

---

## 8.6 Scan consistency

Analysis should operate against a coherent scan snapshot.

Pico should avoid constructing one finding using:

```text
OpenCode state from today
+
Cloudflare authority from three weeks ago
```

without making that discrepancy explicit.

Historical evidence may supplement analysis, but current findings should prefer evidence associated with the current scan or explicitly valid cached evidence.

---

## 8.7 Scan does not equal state

This distinction is important:

```text
RESOURCE
stable identity

RELATIONSHIP
stable connection

OBSERVATION
relationship/resource seen during a scan

EVIDENCE
why Pico believes a claim

SCAN
temporal collection boundary
```

This gives Pico both:

```text
CURRENT SECURITY GRAPH
```

and eventually:

```text
SECURITY HISTORY
```

without duplicating every domain object per scan.

---

# Architecture Decision 001 — Domain Separation

**Decision:** Separate observed domain objects from analyzed security objects.

Observed:

```text
Resource
Relationship
Observation
Evidence
Scan
```

Analyzed:

```text
Boundary
AttackPath
Finding
```

**Reason:**

Pico must distinguish:

> "This exists."

from:

> "This is dangerous."

Provider adapters are responsible for the former.

Pico's deterministic analysis engine is responsible for the latter.

---

# Architecture Decision 002 — No Graph Database in V0

**Decision:** Do not introduce a dedicated graph database for Pico V0.

The security graph is a logical graph over normalized persisted resources and relationships.

Conceptually:

```text
SQLite

resources
relationships
evidence
observations
scans
        │
        ▼
Graph Projection
        │
        ▼
Traversal / Analysis
```

**Reason:**

The V0 graph is expected to contain tens, hundreds, or perhaps thousands of resources—not billions.

A graph database would introduce:

- another runtime;
- additional operational complexity;
- additional dependency surface;
- more difficult local installation;
- migration complexity;

without solving a V0 problem.

The architecture should allow the graph implementation to change later if scale or query complexity justifies it.

---

# Architecture Decision 003 — AttackPath Is Computed

**Decision:** An `AttackPath` is an analysis result, not a manually discovered relationship.

Adapters must never emit:

```text
attack_path
```

Instead they emit:

```text
resources
relationships
evidence
```

The analysis engine constructs:

```text
AttackPath {
  source
  edges[]
  sink
  boundaries[]
  severity
  confidence
  evidence[]
}
```

This keeps Pico's security reasoning centralized and deterministic.

---

# Architecture Decision 004 — Boundary Is an Interpretation

**Decision:** A Boundary is primarily an analyzed interpretation of enforced resources and relationships rather than a completely separate discovery subsystem.

Examples:

```text
Relationship:
OpenCode
  → denied_by
Bash Policy

Analysis:
Boundary {
  kind: HARD_DENY
  interrupts: capability
}
```

or:

```text
Credential
  → scoped_to
Development Account

Production Worker
  ∉ credential scope

Analysis:
Boundary {
  kind: CREDENTIAL_SCOPE
  interrupts: authority
}
```

This prevents the domain model from duplicating the same security fact in multiple representations.

---

# Architecture Decision 005 — History Is Designed In, Not Built Out

**Decision:** Scans and observations preserve temporal provenance from V0.

Pico does not need a full history UI or change-detection product in V0.

However, persistence must not make future questions such as:

> "When did this attack path appear?"

architecturally impossible.

---

# Core Domain Pressure Test

The golden path should fit the model without introducing special cases.

```text
Resource
────────────────────────
github:issue:foo/bar#123

role:
SOURCE


Relationship
────────────────────────
GitHub Issue
→ can_retrieve →
GitHub MCP Tool

Evidence:
MCP tool schema + GitHub source metadata


Resource
────────────────────────
mcp:github:tool:get_issue

role:
CAPABILITY


Relationship
────────────────────────
OpenCode
→ can_call →
GitHub MCP Tool

Evidence:
OpenCode MCP configuration + effective permissions


Resource
────────────────────────
agent:opencode:default

role:
ACTOR


Relationship
────────────────────────
OpenCode
→ can_execute →
Bash

Evidence:
OpenCode effective Bash permission


Resource
────────────────────────
shell:bash

role:
CAPABILITY


Relationship
────────────────────────
Bash
→ can_access →
Cloudflare Credential

Evidence:
credential presence + environment inheritance


Resource
────────────────────────
credential:cloudflare:<fingerprint>

role:
AUTHORITY


Relationship
────────────────────────
Cloudflare Credential
→ authorizes →
Cloudflare Worker

Evidence:
token policy + resource scope


Resource
────────────────────────
cloudflare:worker:<id>

role:
SINK
```

Analysis then produces:

```text
AttackPath

GitHub Issue
     ↓
GitHub MCP Tool
     ↓
OpenCode
     ↓
Bash
     ↓
Cloudflare Credential
     ↓
Production Worker
```

Boundary evaluation:

```text
No hard deny
No sandbox interruption
No mandatory approval
Credential scope includes target
```

Finding:

```text
CRITICAL

External GitHub content can reach an autonomous
coding environment with Cloudflare production
mutation authority.

Confidence: HIGH
```

No special-case object was required for:

```text
GitHub
OpenCode
MCP
Bash
Cloudflare
```

That is the behavior we want from the domain model.

---

# Core Architecture Status

Sections 1–8 establish:

- Pico's architecture principles;
- local single-process V0;
- the graph as Pico's central representation;
- observed vs analyzed domains;
- stable Resources;
- stable Relationships;
- append-oriented Evidence;
- scan-scoped Observations;
- temporal Scans;
- computed AttackPaths;
- interpreted Boundaries;
- SQLite-compatible graph representation.

The golden path fits this model without provider-specific changes to the core domain.

**Core domain architecture: ACCEPTABLE FOR CONTINUED DESIGN.**

Absolutely. This is the part where Pico goes from **"we have a good data model"** to **"we have a security engine."**

I also want to keep the analysis deliberately narrower than a generic graph-query system. Pico isn't Neo4j for AI agents. It has a specific job: determine whether influence can reach authority, whether an enforced boundary interrupts that path, and whether the result deserves a finding.

Here's the continuation of `ARCHITECTURE.md`:

```markdown
# 9. Security Graph

The Security Graph is Pico's normalized in-memory representation of the security-relevant state discovered during a scan.

It is not a separate database.

It is a projection over Pico's persisted:

```text
Resources
+
Relationships
+
Evidence
+
Observations
```

for a specific analysis context.

Conceptually:

```text
SQLite
  │
  ├── Resources
  ├── Relationships
  ├── Evidence
  └── Observations
  │
  ▼
Graph Projection
  │
  ├── Nodes = Resources
  └── Edges = Relationships
  │
  ▼
Security Analysis
```

The graph answers:

> **What security-relevant paths exist through the environment Pico observed?**

---

## 9.1 Graph scope

A graph projection should normally be constructed for one Scan.

```text
SecurityGraph {
  scan_id
  resources[]
  relationships[]
  evidence_index
}
```

The graph should prefer:

- observations from the current scan;
- evidence captured during the current scan;
- explicitly reusable evidence that remains fresh.

Historical observations should not silently become current state.

---

## 9.2 Graph nodes

Every graph node corresponds to a `Resource`.

The graph engine should not create provider-specific node classes such as:

```text
CloudflareWorkerNode
GitHubIssueNode
OpenCodeAgentNode
```

Instead:

```text
GraphNode {
  resource
  roles[]
}
```

Provider-specific information remains resource metadata.

This keeps traversal provider-neutral.

---

## 9.3 Graph edges

Every graph edge corresponds to a `Relationship`.

Conceptually:

```text
GraphEdge {
  relationship
  evidence[]
  state
}
```

Only security-relevant relationships should enter the graph projection.

Pico should not become an inventory graph containing every possible relationship between every discovered object.

---

## 9.4 Edge usability

Not every observed relationship is traversable.

For attack-path analysis:

```text
CONFIRMED  → traversable
DERIVED    → traversable
INFERRED   → traversable with confidence penalty
UNKNOWN    → not traversable by default
BLOCKED    → not traversable
```

This rule is important.

Pico should not create a complete attack path by treating unknown relationships as true.

---

## 9.5 Direction matters

Relationships are directional.

```text
Agent
  → can_execute →
Shell
```

does not imply:

```text
Shell
  → can_execute →
Agent
```

Graph traversal must respect relationship direction.

---

## 9.6 Security semantics matter more than connectivity

A path through the graph is not automatically an Attack Path.

Example:

```text
Repository
   ↓
Project
   ↓
Deployment
```

may be structurally connected but security-irrelevant to Pico's core question.

Traversal should operate over approved security semantics rather than arbitrary graph connectivity.

---

## 9.7 No generic graph-query language in V0

Pico V0 does not need:

- Cypher;
- GraphQL graph traversal;
- arbitrary path expressions;
- user-defined traversal programs.

The analysis engine should implement explicit security algorithms.

This keeps Pico focused on its product primitive.

---

# 10. Influence Analysis

Influence Analysis determines:

> **What information sources can reach an autonomous actor?**

The output is an **Influence Path**.

An Influence Path is an intermediate analysis object used to construct Attack Paths.

It is not necessarily persisted as a first-class durable domain object.

---

## 10.1 Influence source

Influence analysis begins with Resources carrying the `SOURCE` security role.

Examples:

```text
public GitHub issue
external pull request
external MCP response
web search result
web page
Slack message
email
uploaded file
```

V0 should support only the source types required by the golden path.

---

## 10.2 Source trust

Each influence source should receive a trust classification.

Initial vocabulary:

```text
TRUSTED_INTERNAL
AUTHENTICATED_INTERNAL
AUTHENTICATED_EXTERNAL
PUBLIC_EXTERNAL
OPEN_WORLD
UNKNOWN
```

This describes **control characteristics**, not maliciousness.

Pico should say:

```text
PUBLIC_EXTERNAL
```

not:

```text
MALICIOUS
```

unless future evidence establishes malicious behavior.

---

## 10.3 Influence relationships

Influence traversal should use a constrained set of relationships such as:

```text
can_retrieve
receives_from
consumes
exposes
can_call
```

Not every relationship participates in influence propagation.

---

## 10.4 Influence reachability

An Influence Path exists when Pico can establish a directional route:

```text
SOURCE
  ↓
CAPABILITY
  ↓
ACTOR
```

Example:

```text
Public GitHub Issue
        ↓
GitHub MCP get_issue
        ↓
OpenCode
```

The exact edge direction in storage should remain semantically correct even if presentation reverses a capability relationship for readability.

---

## 10.5 Available vs automatically consumed

Pico should distinguish between:

```text
AVAILABLE_INFLUENCE
```

and:

```text
AUTOMATIC_INFLUENCE
```

Example:

A GitHub MCP tool may be available to an agent, but the agent must choose to invoke it.

That is different from content automatically inserted into the agent's context.

Possible influence strength:

```text
METADATA_ONLY
MANUAL_RETRIEVAL
AGENT_RETRIEVABLE
AUTOMATICALLY_INJECTED
INSTRUCTION_BEARING
```

V0 does not need perfect semantic content analysis.

It does need to avoid pretending all influence is equivalent.

---

## 10.6 Influence result

Conceptually:

```text
InfluencePath {
  source_resource_id
  actor_resource_id
  edge_ids[]
  trust
  influence_strength
  confidence
  evidence_ids[]
}
```

This is an analysis result.

It may be computed in memory during a scan.

---

## 10.7 Influence confidence

Confidence should reflect the weakest meaningful edge.

Example:

```text
GitHub issue exists             CONFIRMED
Tool retrieves GitHub issues    CONFIRMED
Agent can invoke tool           CONFIRMED
```

Result:

```text
Influence confidence: HIGH
```

If tool behavior is only inferred:

```text
Influence confidence: MEDIUM
```

---

# 11. Authority Analysis

Authority Analysis determines:

> **What consequential actions can an autonomous actor reach?**

The output is an **Authority Path**.

Conceptually:

```text
ACTOR
  ↓
CAPABILITY
  ↓
CREDENTIAL / AUTHORITY
  ↓
SINK
```

Example:

```text
OpenCode
   ↓
Bash
   ↓
Cloudflare Credential
   ↓
Production Worker
```

---

## 11.1 Capability analysis

Pico must evaluate effective capability rather than configuration presence.

For an agent:

```text
Configured permission
        +
Runtime mode
        +
Sandbox
        +
Approval behavior
        +
Explicit deny
        =
Effective capability
```

Possible capability classes:

```text
READ
WRITE
EXECUTE
ADMIN
```

Provider-specific operation details may remain metadata.

---

## 11.2 Credential reachability

Credential existence does not imply agent authority.

Pico must establish:

```text
Actor
  ↓
Capability
  ↓
Credential
```

For example:

```text
OpenCode
   ↓ can_execute
Bash
   ↓ can_access
Cloudflare Credential
```

If the credential exists elsewhere on the machine but is not reachable from the effective execution environment, the authority chain should not be created.

---

## 11.3 Authority resolution

Credential authority uses the resolution tiers defined in `TECHNICAL.md`:

```text
EXACT
SCOPED
BEHAVIORAL_READ_ONLY
UNKNOWN
```

The graph must preserve this precision.

Example:

```text
Credential
  ↓ authorizes
Production Worker

authority_resolution: EXACT
capability: WRITE
```

versus:

```text
Credential
  ↓ authenticates_to
Cloudflare Account

authority_resolution: UNKNOWN
```

The second does not justify a confirmed production-write edge.

---

## 11.4 Consequential sinks

Authority traversal should terminate at Resources classified as security-relevant `SINK`s.

Initial sink impact vocabulary:

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

Impact classification should be deterministic wherever possible.

---

## 11.5 Production classification

Pico should not assume:

```text
resource.name contains "prod"
```

means production.

Provider adapters should use authoritative metadata when available.

If environment classification cannot be established:

```text
environment: UNKNOWN
```

Pico may still report authority, but should avoid falsely calling the target production.

---

## 11.6 Authority result

Conceptually:

```text
AuthorityPath {
  actor_resource_id
  sink_resource_id
  edge_ids[]
  capability
  authority_resolution
  sink_impact
  confidence
  evidence_ids[]
}
```

Like InfluencePath, this is primarily an analysis object.

---

# 12. Boundary Evaluation

Boundary Evaluation determines:

> **Does an enforced control materially interrupt this candidate influence-to-authority path?**

Boundaries are evaluated after candidate influence and authority reachability is established.

---

## 12.1 Boundary types

Initial vocabulary:

```text
HARD_DENY
SANDBOX
MANDATORY_APPROVAL
CREDENTIAL_SCOPE
RESOURCE_SCOPE
NETWORK_ISOLATION
PROCESS_ISOLATION
```

The vocabulary should describe enforced security behavior.

---

## 12.2 Soft policy

Pico may observe soft policies such as:

```text
"Do not deploy without approval."

"Never access production."

"Ask the user before running destructive commands."
```

These may be useful context.

They are not hard boundaries unless the runtime enforces them.

Pico may represent them as:

```text
SOFT_POLICY
```

but they must not break graph traversal.

---

## 12.3 Boundary result

Conceptually:

```text
BoundaryEvaluation {
  kind
  resource_ids[]
  relationship_ids[]
  enforcement
  interrupts
  confidence
  evidence_ids[]
}
```

Possible `interrupts`:

```text
INFLUENCE
CAPABILITY
CREDENTIAL_ACCESS
AUTHORITY
RESOURCE_REACHABILITY
```

---

## 12.4 Mandatory approval

Approval deserves explicit evaluation.

A mandatory approval can interrupt autonomous authority when:

1. the system technically requires approval;
2. the actor cannot self-approve;
3. the operation cannot bypass the gate through another available path;
4. the current runtime mode does not disable the gate.

If all conditions hold:

```text
Boundary:
MANDATORY_APPROVAL

autonomous_path:
BLOCKED
```

The underlying capability may still exist.

The finding should reflect that human intervention is required.

---

## 12.5 Alternative paths

A boundary blocks a **path**, not necessarily a Resource.

Example:

```text
             ┌──→ Bash ──→ Approval ──→ Production
Agent ───────┤
             └──→ MCP Deploy Tool ─────→ Production
```

The approval boundary on Bash does not protect the second path.

Pico must evaluate each candidate path independently.

This is one of the primary reasons graph analysis is necessary.

---

## 12.6 Boundary confidence

Pico should require strong evidence before declaring an attack path blocked.

False confidence in a boundary is more dangerous than acknowledging uncertainty.

Therefore:

```text
CONFIRMED hard boundary → may block path

INFERRED boundary       → does not fully block;
                          reduces confidence /
                          appears in explanation

UNKNOWN boundary        → does not block
```

---

# 13. Attack Path Engine

The Attack Path Engine combines:

```text
Influence Path
      +
Authority Path
      +
Boundary Evaluation
      =
Attack Path
```

This is Pico's core security primitive.

---

## 13.1 Join point

The normal join point is an autonomous `ACTOR`.

Example:

```text
Public GitHub Issue
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
```

OpenCode is the point where:

```text
Influence
    intersects
Authority
```

---

## 13.2 Attack Path shape

Conceptually:

```text
AttackPath {
  id
  scan_id
  source_resource_id
  actor_resource_id
  sink_resource_id

  influence_edge_ids[]
  authority_edge_ids[]

  boundary_evaluations[]

  source_trust
  influence_strength
  capability
  authority_resolution
  sink_impact

  severity
  confidence

  evidence_ids[]
}
```

---

## 13.3 Attack Path construction

Conceptual algorithm:

```text
for each actor:

    influence_paths =
        find_influence_paths(actor)

    authority_paths =
        find_authority_paths(actor)

    for each influence_path:
        for each authority_path:

            candidate =
                join(influence_path, authority_path)

            boundaries =
                evaluate_boundaries(candidate)

            if hard_boundary_blocks(candidate):
                record as blocked candidate
                continue

            attack_path =
                build_attack_path(
                    candidate,
                    boundaries
                )

            emit attack_path
```

This algorithm should remain explicit and understandable.

Pico does not need a generalized graph reasoning engine.

---

## 13.4 Path limits

Traversal must be bounded.

Potential controls:

```text
maximum depth
allowed relationship kinds
allowed security roles
cycle detection
visited-edge tracking
```

V0 should prefer short, explainable paths.

A 37-edge path is unlikely to produce a useful developer finding.

---

## 13.5 Cycle handling

Agent environments may contain cycles.

Example:

```text
Agent A
  ↓
Agent B
  ↓
Agent A
```

or:

```text
Agent
 ↓
MCP
 ↓
Agent
```

Traversal must detect cycles and avoid infinite recursion.

Repeated nodes may still be meaningful in future multi-agent analysis, but V0 should avoid revisiting the same node/edge combination within one candidate path.

---

## 13.6 Path deduplication

Different low-level paths may represent the same security story.

Example:

```text
Issue
 ↓
Tool A
 ↓
Agent
 ↓
Bash
 ↓
Token
 ↓
Worker A
```

and:

```text
Issue
 ↓
Tool B
 ↓
Agent
 ↓
Bash
 ↓
Token
 ↓
Worker A
```

These may deserve one Finding with multiple supporting paths.

AttackPath and Finding are therefore not one-to-one.

---

## 13.7 Blocked paths

Blocked paths may be useful internally even if they do not generate vulnerabilities.

Example:

```text
External Issue
    ↓
Agent
    ↓
Bash
    ↓
MANDATORY APPROVAL
    ↓
Production
```

Pico may retain the analysis result so it can explain:

> "External influence reaches production authority, but a mandatory human approval currently interrupts autonomous execution."

V0 UI may choose not to display all blocked paths.

---

# 14. Finding Engine

The Finding Engine converts one or more Attack Paths into an actionable security story.

A Finding answers:

> **What should the user care about?**

An AttackPath is graph analysis.

A Finding is product-level security output.

---

## 14.1 Finding shape

Conceptually:

```text
Finding {
  id
  scan_id
  finding_class
  title
  summary

  severity
  confidence

  source_resource_ids[]
  actor_resource_ids[]
  sink_resource_ids[]

  attack_path_ids[]
  evidence_ids[]

  remediation[]
  status
}
```

---

## 14.2 Finding classes

Initial V0 candidates:

```text
UNTRUSTED_TO_PRODUCTION

UNTRUSTED_TO_SECRET

UNTRUSTED_TO_SHELL

UNTRUSTED_TO_DATABASE_MUTATION

UNBOUNDED_MCP_CAPABILITY

SHARED_PRIVILEGED_CREDENTIAL
```

We should not implement all of these merely because they are defined.

The golden path should initially require:

```text
UNTRUSTED_TO_PRODUCTION
```

with perhaps `UNTRUSTED_TO_SHELL` as a supporting lower-level finding if it proves useful.

---

## 14.3 Finding rules

Finding rules should be deterministic.

Conceptually:

```text
IF
    source.trust IN (
        PUBLIC_EXTERNAL,
        OPEN_WORLD,
        AUTHENTICATED_EXTERNAL
    )

AND
    actor is autonomously reachable

AND
    authority.capability >= WRITE

AND
    sink.impact == PRODUCTION

AND
    no hard boundary interrupts path

THEN
    UNTRUSTED_TO_PRODUCTION
```

This should be ordinary code.

Not an LLM prompt.

---

## 14.4 Severity

Severity should reflect consequence and autonomy.

Conceptual inputs:

```text
source trust
influence strength
capability
sink impact
boundary strength
autonomy
```

Example:

```text
PUBLIC_EXTERNAL
+
AGENT_RETRIEVABLE
+
EXECUTE
+
PRODUCTION WRITE
+
NO BOUNDARY
=
CRITICAL
```

The exact scoring function belongs in implementation design.

V0 should prefer transparent rule-based severity over an elaborate numerical risk score.

---

## 14.5 Confidence

Finding confidence should be derived from its Attack Paths.

The weakest security-critical relationship should materially constrain confidence.

Pico must not average uncertainty away.

Example:

```text
Influence: HIGH
Shell access: HIGH
Credential access: HIGH
Production authority: MEDIUM
```

Finding:

```text
Confidence: MEDIUM
```

not:

```text
Confidence: HIGH
```

because three strong edges outvote one uncertain edge.

---

## 14.6 Finding deduplication

Pico should group paths when they communicate the same security problem.

Example:

```text
External Issue
      ↓
Agent
      ↓
Credential
      ↓
Worker A

External Issue
      ↓
Agent
      ↓
Credential
      ↓
Worker B

External Issue
      ↓
Agent
      ↓
Credential
      ↓
Worker C
```

Preferred output:

```text
CRITICAL

External GitHub content can reach Cloudflare
production mutation authority.

Affected resources: 3 Workers
```

with expandable paths.

---

## 14.7 Remediation

Finding remediation should target graph cut points.

Example candidate cuts:

```text
Source
  ↓
Agent
  ↓
Bash
  ↓
Credential
  ↓
Production
```

Possible remediation:

```text
1. Require approval for Bash

2. Remove Cloudflare credential
   from agent-accessible environment

3. Scope Cloudflare credential
   away from production

4. Restrict external GitHub
   retrieval capability
```

Pico should prefer remediation that breaks the path with the smallest reasonable operational impact.

---

## 14.8 No automatic remediation in V0

Pico may say:

> "Scope this credential away from production."

Pico V0 should not perform that change.

The architecture should keep:

```text
DETECTION
```

separate from future:

```text
ENFORCEMENT
```

---

# 15. SQLite Persistence Model

Pico V0 uses SQLite as its local persistent store.

SQLite stores normalized security state and provenance.

It is not treated as a graph database.

The graph is projected from relational data during analysis.

---

## 15.1 Storage location

Conceptually:

```text
.pico/
    pico.db
```

The exact default/global/project storage strategy should be finalized during implementation planning.

The architecture assumes one local database can represent a Pico environment/workspace.

---

## 15.2 Core tables

Initial conceptual schema:

```text
scans

resources

relationships

observations

evidence

relationship_evidence

findings

finding_paths

attack_paths

attack_path_edges

attack_path_evidence
```

Not every table must exist exactly in this form.

The schema should preserve the domain boundaries defined in this document.

---

## 15.3 Scans

Conceptually:

```sql
scans (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    trigger TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    pico_version TEXT NOT NULL,
    environment_fingerprint TEXT,
    metadata_json TEXT
)
```

---

## 15.4 Resources

```sql
resources (
    id TEXT PRIMARY KEY,
    canonical_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    provider TEXT,
    name TEXT NOT NULL,
    metadata_json TEXT,
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL
)
```

Index:

```sql
UNIQUE(canonical_key)
```

Canonical keys provide stable identity across scans.

---

## 15.5 Relationships

```sql
relationships (
    id TEXT PRIMARY KEY,
    canonical_key TEXT NOT NULL UNIQUE,
    from_resource_id TEXT NOT NULL,
    to_resource_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    metadata_json TEXT,
    first_observed_at TEXT NOT NULL,
    last_observed_at TEXT NOT NULL,

    FOREIGN KEY(from_resource_id)
        REFERENCES resources(id),

    FOREIGN KEY(to_resource_id)
        REFERENCES resources(id)
)
```

Recommended indexes:

```text
from_resource_id
to_resource_id
kind
state
```

These are sufficient for V0 graph projection.

---

## 15.6 Observations

Observation needs to associate domain state with scans.

Conceptually:

```sql
observations (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,

    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,

    observation_type TEXT NOT NULL,

    observed_at TEXT NOT NULL,
    source TEXT NOT NULL,
    metadata_json TEXT,

    FOREIGN KEY(scan_id)
        REFERENCES scans(id)
)
```

This table provides temporal provenance without duplicating stable Resources and Relationships.

---

## 15.7 Evidence

```sql
evidence (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,

    class TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_locator TEXT,

    subject TEXT NOT NULL,
    observation TEXT NOT NULL,

    captured_at TEXT NOT NULL,
    freshness TEXT,
    sensitivity TEXT NOT NULL,

    metadata_json TEXT,

    FOREIGN KEY(scan_id)
        REFERENCES scans(id)
)
```

Evidence should be append-oriented.

Old evidence should not be rewritten to reflect new state.

---

## 15.8 Relationship evidence

Relationships may be supported by multiple pieces of evidence.

Evidence may support multiple relationships.

Therefore:

```sql
relationship_evidence (
    relationship_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,

    PRIMARY KEY (
        relationship_id,
        evidence_id
    ),

    FOREIGN KEY(relationship_id)
        REFERENCES relationships(id),

    FOREIGN KEY(evidence_id)
        REFERENCES evidence(id)
)
```

---

## 15.9 Attack path persistence

There are two reasonable architectural options.

### Option A — Never persist AttackPaths

Compute them from the graph every time.

### Option B — Persist scan analysis results

Persist the AttackPaths produced during a specific scan.

For Pico V0, **Option B is preferred**.

Why?

Because a Finding should remain explainable against the exact graph/evidence state that generated it.

Conceptually:

```sql
attack_paths (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,

    source_resource_id TEXT NOT NULL,
    actor_resource_id TEXT NOT NULL,
    sink_resource_id TEXT NOT NULL,

    source_trust TEXT,
    influence_strength TEXT,
    capability TEXT,
    authority_resolution TEXT,
    sink_impact TEXT,

    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,

    blocked INTEGER NOT NULL DEFAULT 0,

    metadata_json TEXT,

    FOREIGN KEY(scan_id)
        REFERENCES scans(id)
)
```

---

## 15.10 Attack path edges

```sql
attack_path_edges (
    attack_path_id TEXT NOT NULL,
    relationship_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    phase TEXT NOT NULL,

    PRIMARY KEY (
        attack_path_id,
        position
    ),

    FOREIGN KEY(attack_path_id)
        REFERENCES attack_paths(id),

    FOREIGN KEY(relationship_id)
        REFERENCES relationships(id)
)
```

Possible phase:

```text
INFLUENCE
AUTHORITY
```

Boundary evaluation may be represented through metadata initially or receive a normalized table if needed.

---

## 15.11 Findings

Conceptually:

```sql
findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,

    finding_class TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,

    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,

    status TEXT NOT NULL,

    metadata_json TEXT,

    created_at TEXT NOT NULL,

    FOREIGN KEY(scan_id)
        REFERENCES scans(id)
)
```

---

## 15.12 Finding paths

```sql
finding_paths (
    finding_id TEXT NOT NULL,
    attack_path_id TEXT NOT NULL,

    PRIMARY KEY (
        finding_id,
        attack_path_id
    ),

    FOREIGN KEY(finding_id)
        REFERENCES findings(id),

    FOREIGN KEY(attack_path_id)
        REFERENCES attack_paths(id)
)
```

This supports:

```text
one Finding
     ↓
multiple AttackPaths
```

which is important for deduplication.

---

## 15.13 JSON usage

SQLite JSON columns should be used for:

```text
provider-specific metadata
adapter-specific metadata
low-query-frequency details
forward-compatible extension
```

They should not hide core relationships.

Bad:

```text
resource.metadata_json = {
  "canExecuteBash": true,
  "canReachProduction": true,
  "attackPath": [...]
}
```

Good:

```text
resource.metadata_json = {
  "opencodeAgentName": "build"
}
```

Security semantics belong in normalized domain structures.

---

## 15.14 Transactions

A scan should use transactional persistence where practical.

However, because scans can be partial and provider calls may take time, Pico should not hold one SQLite transaction open across the entire discovery process.

Preferred pattern:

```text
Discovery
   ↓
Normalized batch
   ↓
Short transaction
   ↓
Persist
```

Analysis should begin only after the relevant scan observations have been persisted coherently.

---

## 15.15 Secret exclusion

Before persistence, all adapter outputs must pass through a secret-safety boundary.

Conceptually:

```text
Adapter
   ↓
Raw transient result
   ↓
Normalizer
   ↓
Secret Filter
   ↓
Persistence
```

Persistence APIs should not accept arbitrary adapter payloads.

This is defense in depth against accidentally writing raw credentials into:

```text
metadata_json
evidence.observation
logs
errors
```

---

## 15.16 Database permissions

The `.pico` storage directory and database should use restrictive filesystem permissions appropriate to the host platform.

Even without secret values, Pico may store sensitive security metadata such as:

```text
credential existence
provider identities
resource names
agent capabilities
security findings
infrastructure relationships
```

The database should therefore be treated as sensitive local application state.

---

# Architecture Decision 006 — Security Graph Is a Projection

**Decision:** The Security Graph is built from normalized persisted domain state rather than persisted as a separate graph representation.

```text
SQLite
   ↓
Graph Projection
   ↓
Analysis
```

**Reason:**

Avoid duplicated sources of truth.

---

# Architecture Decision 007 — Explicit Security Traversals

**Decision:** Pico implements explicit Influence and Authority traversal algorithms rather than a generic graph query engine.

**Reason:**

Pico is a security product, not a graph platform.

This keeps analysis:

- deterministic;
- explainable;
- testable;
- bounded;
- easier to audit.

---

# Architecture Decision 008 — Unknown Edges Do Not Complete Paths

**Decision:**

```text
UNKNOWN
```

relationships are not traversable by default.

**Reason:**

Pico must never turn missing evidence into a confirmed exposure.

`INFERRED` edges may participate with a confidence penalty.

---

# Architecture Decision 009 — Boundaries Block Paths, Not Nodes

**Decision:** A Boundary applies to the candidate path it actually interrupts.

**Reason:**

The same actor may possess alternate capabilities that bypass a control.

Pico must discover those alternate routes rather than declaring the entire actor safe.

---

# Architecture Decision 010 — Attack Paths Are Persisted Per Scan

**Decision:** Although AttackPaths are computed, the resulting analysis should be persisted with its Scan.

**Reason:**

This preserves the exact security conclusion generated from a historical scan and allows Findings to remain explainable even after the environment changes.

---

# Architecture Decision 011 — Findings Group Security Stories

**Decision:** Findings and AttackPaths are not one-to-one.

```text
Finding
  ↓
Attack Path
Attack Path
Attack Path
```

**Reason:**

Users care about security problems, not every graph permutation.

---

# Architecture Decision 012 — No LLM in Authoritative Analysis

**Decision:** Influence traversal, authority traversal, boundary evaluation, AttackPath construction, severity, confidence, and Finding generation are deterministic code.

LLMs may eventually consume those results for explanation.

**Reason:**

Security conclusions must be:

- reproducible;
- testable;
- auditable;
- explainable.

---

# Architecture Decision 013 — Persist Security Semantics, Not Adapter Blobs

**Decision:** Core security state must be normalized.

JSON metadata exists for extension, not as a substitute for domain modeling.

**Reason:**

Otherwise Pico's graph engine would eventually depend on provider-specific JSON parsing throughout the codebase.

---

# Analysis Architecture Pressure Test

Golden path:

```text
Public GitHub Issue
        ↓
GitHub MCP Tool
        ↓
OpenCode
        ↓
Bash
        ↓
Cloudflare Credential
        ↓
Production Worker
```

## Influence

```text
Source:
Public GitHub Issue

Trust:
PUBLIC_EXTERNAL

Path:
Issue
 ↓ can_retrieve
GitHub MCP Tool
 ↓ available_to
OpenCode

Confidence:
HIGH
```

## Authority

```text
Actor:
OpenCode

Path:
OpenCode
 ↓ can_execute
Bash
 ↓ can_access
Cloudflare Credential
 ↓ authorizes
Production Worker

Capability:
WRITE

Authority Resolution:
EXACT

Sink:
PRODUCTION

Confidence:
HIGH
```

## Boundary Evaluation

```text
Bash permission:
ALLOW

Runtime:
normal

Sandbox:
does not interrupt credential access

Approval:
none

Credential scope:
includes target

Result:
NO HARD BOUNDARY
```

## Attack Path

```text
Public GitHub Issue
        ↓
GitHub MCP Tool
        ↓
OpenCode
        ↓
Bash
        ↓
Cloudflare Credential
        ↓
Production Worker

Severity:
CRITICAL

Confidence:
HIGH
```

## Finding

```text
UNTRUSTED_TO_PRODUCTION

External GitHub content can reach an autonomous
coding environment with Cloudflare production
mutation authority.

Affected resources:
1 Worker

Break the path:
- require enforced approval for Bash; or
- remove the credential from the agent environment; or
- scope the credential away from production.
```

No generic graph query engine was required.

No provider-specific Finding class was required.

No LLM judgment was required.

No attack execution was required.

No raw credential needed to be persisted.

**Analysis architecture: ACCEPTABLE FOR CONTINUED DESIGN.**

---

# Architecture Status Through Section 15

Pico now has a defined architecture for:

```text
DISCOVERY
     ↓
OBSERVATION
     ↓
EVIDENCE
     ↓
RESOURCE + RELATIONSHIP
     ↓
SECURITY GRAPH
     ↓
┌───────────────┐
│               │
INFLUENCE    AUTHORITY
│               │
└───────┬───────┘
        ↓
BOUNDARY EVALUATION
        ↓
ATTACK PATH
        ↓
FINDING
        ↓
REMEDIATION
```

The model remains compatible with:

- local-first execution;
- SQLite persistence;
- historical scans;
- multiple agents;
- multiple providers;
- MCP;
- future runtime observations;
- future agent-to-agent relationships;
- future enforcement.

Without requiring those future capabilities in V0.

The next sections should define:

```text
16. Adapter Architecture
17. Agent Adapters
18. MCP Discovery
19. Provider Authority Adapters
20. Integration Intelligence
21. Discovery / Scan Pipeline
22. Secret Handling & Pico Self-Security
23. CLI Architecture
24. MCP / Agent Interface
25. Testing Architecture
26. Repository / Package Structure
27. Golden Path Implementation
28. V0 Boundaries
29. Rejected Alternatives
30. Final Architecture Decisions
```
```

### One architecture choice here I especially like

We're effectively building **two directional analyses around the agent**:

```text
                INFLUENCE
                    ↓
External ───────→ AGENT
                    │
                    │
                    ↓
                AUTHORITY
                    ↓
                Production
```

Then Pico asks:

> **Can I join those two graphs through the same autonomous actor without encountering an enforced boundary?**

That's considerably cleaner than blindly traversing every possible path from every external node to every production node.

It also becomes extremely interesting once Pico eventually sees multiple agents:

```text
External
   ↓
Agent A
   ↓
Agent B
   ↓
Agent C
   ↓
Production
```

The architecture we just defined can grow into that **without designing multi-agent security today**.

Yes — this is the right next chunk. Sections **16–22** define how Pico reaches into the outside world without letting provider-specific behavior leak into the security engine, and—critically—how Pico avoids becoming a security problem itself.

```markdown
# 16. Adapter Architecture

Adapters are Pico's boundary between external systems and the normalized Pico domain.

An adapter answers:

> **What can Pico safely observe about this system?**

Adapters do not decide:

> **Is this dangerous?**

That distinction is fundamental.

```text
External System
      ↓
    Adapter
      ↓
Transient Raw State
      ↓
  Normalization
      ↓
 Secret Safety
      ↓
Resources
Relationships
Evidence
Observations
      ↓
Security Graph
      ↓
Analysis
```

Adapters collect facts.

Pico's core analysis engine interprets those facts.

---

## 16.1 Adapter responsibilities

An adapter may:

- detect whether a supported system exists;
- inspect supported configuration;
- enumerate resources;
- inspect permissions;
- inspect capability metadata;
- inspect authorization metadata;
- identify credential references;
- query provider APIs using existing credentials;
- collect evidence;
- normalize provider-specific concepts into Pico concepts.

An adapter must not:

- generate Findings;
- assign final severity;
- decide whether an AttackPath exists;
- execute destructive operations;
- modify the target system;
- persist raw credentials;
- bypass approval controls;
- weaken security configuration.

---

## 16.2 Adapter categories

Pico initially has four adapter categories:

```text
Agent Adapters
MCP Discovery
Provider Authority Adapters
Integration Intelligence
```

Conceptually:

```text
                     Pico Discovery
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
       Agents             MCP           Providers
          │                │                │
          │                │                │
      OpenCode        MCP Servers       Cloudflare
      Claude          MCP Tools         GitHub
      Codex           Metadata          Vercel
          │                │                │
          └────────────────┼────────────────┘
                           │
                           ▼
                     Normalized Facts
                           │
                           ▼
                     Security Graph

Integration Intelligence
        │
        └── assists discovery/adapters
            but does not establish
            environment-specific authority
```

---

## 16.3 Adapter output

Adapters should return normalized discovery results rather than writing directly to SQLite.

Conceptually:

```text
DiscoveryResult {
  resources[]
  relationships[]
  evidence[]
  diagnostics[]
}
```

The application layer then validates and persists the result.

This creates an important boundary:

```text
Adapter
   ↓
DiscoveryResult
   ↓
Validation
   ↓
Secret Filter
   ↓
Persistence
```

Adapters should not receive arbitrary database access.

---

## 16.4 Adapter identity

Every adapter should expose metadata such as:

```text
AdapterMetadata {
  id
  kind
  provider
  version
  capabilities[]
}
```

Example:

```text
id:
agent.opencode

kind:
AGENT

provider:
opencode

capabilities:
- discover_config
- discover_permissions
- discover_mcp
- resolve_runtime_mode
```

This gives Pico explicit knowledge of what each adapter claims to support.

---

## 16.5 Adapter capability declarations

Pico should not assume every adapter can answer every question.

For example:

```text
Cloudflare Adapter

discover_resources:       YES
verify_credential:        YES
resolve_authority:        YES
resolve_resource_scope:   YES
```

while another provider may expose:

```text
Provider X

discover_resources:       YES
verify_credential:        YES
resolve_authority:        PARTIAL
resolve_resource_scope:   UNKNOWN
```

Adapter capability declarations help prevent false precision.

---

## 16.6 Adapter failure

Adapter failures should be isolated.

Example:

```text
OpenCode Adapter      COMPLETE
MCP Discovery         COMPLETE
GitHub Adapter        COMPLETE
Cloudflare Adapter    PARTIAL
```

The scan becomes:

```text
PARTIAL
```

rather than losing all useful evidence.

Each adapter should return structured diagnostics.

Conceptually:

```text
AdapterDiagnostic {
  adapter_id
  severity
  code
  message
  recoverable
}
```

---

## 16.7 No plugin runtime in V0

Pico V0 should not implement arbitrary third-party executable plugins.

Adapters should ship with Pico.

Reason:

Security adapters inspect highly sensitive environments.

An arbitrary plugin system would create a new supply-chain and code-execution surface before Pico needs one.

Future extensibility can be considered after the adapter contract stabilizes.

---

# 17. Agent Adapters

Agent Adapters discover the effective capabilities and configuration of AI agents.

An Agent Adapter answers:

> **What can this agent actually reach and do under the observed configuration?**

The first implementation target is:

```text
OpenCode
```

Future adapters may include:

```text
Claude Code
Codex
Cursor
other coding agents
custom enterprise agents
```

---

## 17.1 Agent Adapter contract

Conceptually:

```text
AgentAdapter {
  detect()

  discover_instances()

  discover_configuration()

  discover_permissions()

  discover_mcp_servers()

  discover_capabilities()

  resolve_runtime_mode()

  discover_boundaries()

  collect_evidence()
}
```

Not every method must map directly to a public interface.

The contract describes responsibilities.

---

## 17.2 Detection

`detect()` determines whether the agent exists in the current scan scope.

Detection may inspect:

- known configuration paths;
- project configuration;
- executable presence;
- explicitly supplied scan configuration.

Detection should remain narrow.

Pico should not recursively inspect the entire user's home directory merely to find every possible agent.

---

## 17.3 Agent instances

Pico should not assume:

```text
OpenCode = one agent
```

A tool may define multiple configured agents or profiles.

Therefore:

```text
Agent Platform
      ↓
Agent Instance
```

Example canonical keys:

```text
agent:opencode:default

agent:opencode:build

agent:opencode:review
```

V0 may only need the effective default/current agent.

The architecture should not make multiple instances impossible.

---

## 17.4 Permission resolution

Agent adapters must resolve effective permission.

For OpenCode:

```text
Base Permission
      +
Tool-specific Rule
      +
Pattern-specific Rule
      +
Agent Override
      +
Runtime Mode
      =
Effective Permission
```

Possible normalized results:

```text
ALLOW
ASK
DENY
UNKNOWN
```

Pico should preserve the original source evidence used to derive the result.

---

## 17.5 Capability normalization

Agent-specific tools should normalize into security capabilities.

Example:

```text
OpenCode bash
      ↓
EXECUTE

OpenCode read
      ↓
READ

OpenCode edit
      ↓
WRITE

MCP deploy tool
      ↓
WRITE / EXTERNAL_SIDE_EFFECT
```

The original tool identity remains a Resource.

Normalization adds security semantics without replacing provider identity.

---

## 17.6 Runtime mode

Agent adapters should attempt to determine effective runtime mode.

If Pico can only determine configured state:

```text
runtime_mode:
UNKNOWN
```

Confidence must reflect that uncertainty.

Runtime modes that bypass or automatically approve requests are security-significant.

---

## 17.7 Agent boundary discovery

Agent adapters should discover enforced controls such as:

- hard tool denies;
- sandbox configuration;
- approval requirements;
- protected directories;
- external-directory restrictions;
- managed configuration;
- network restrictions.

These become Resources, Relationships, and Evidence.

The adapter does not itself decide whether the control blocks an AttackPath.

Boundary Evaluation handles that later.

---

## 17.8 OpenCode V0 adapter

The OpenCode adapter is Pico's first agent adapter.

V0 responsibilities:

```text
detect OpenCode

discover effective configuration

discover configured agents

discover MCP servers

resolve Bash permission

resolve relevant MCP tool permission

identify approval behavior

identify explicit denies

identify runtime mode when possible

emit evidence
```

Pico does not need to model every OpenCode feature in V0.

Only features relevant to the golden path should be implemented.

---

# 18. MCP Discovery

MCP is treated as a first-class capability surface.

MCP discovery answers:

> **What external capabilities and information surfaces are exposed to this agent?**

Pico should represent:

```text
Agent
  ↓ configured_with
MCP Server
  ↓ exposes
MCP Tool
```

and separately determine whether the agent may invoke the tool.

---

## 18.1 MCP resources

Initial MCP resource kinds:

```text
mcp_server
mcp_tool
```

Future Pico versions may model:

```text
mcp_resource
mcp_prompt
```

when those become necessary for influence analysis.

---

## 18.2 MCP configuration discovery

Pico should inspect agent configuration to determine:

- server identity;
- transport;
- command or URL;
- enabled state;
- environment references;
- relevant tool permissions.

Possible transports:

```text
STDIO
HTTP
UNKNOWN
```

Transport is security-significant.

---

## 18.3 STDIO MCP

STDIO MCP deserves special attention because server processes may inherit local environment state.

Conceptually:

```text
Agent
  ↓ launches
STDIO MCP Server
  ↓ inherits
Environment
  ↓ contains
Credential Reference
```

Pico must not assume environment inheritance automatically.

It should establish inheritance from observable launch/configuration behavior where possible.

---

## 18.4 HTTP MCP

HTTP MCP may introduce:

- OAuth authorization;
- bearer credentials;
- remote service authority;
- open-world network interactions.

The credential model should remain separate from the MCP server itself.

Example:

```text
Agent
  ↓ can_call
MCP Server
  ↓ authenticates_with
Credential
  ↓ authorizes
Remote Service
```

---

## 18.5 Tool discovery

When safe and supported, Pico may perform MCP capability discovery to enumerate available tools.

This is a read-only metadata operation.

Pico should not invoke arbitrary tools merely to determine what they do.

Tool discovery should collect:

- name;
- description;
- input schema;
- annotations;
- server identity.

---

## 18.6 MCP annotations

Pico may observe:

```text
readOnlyHint
destructiveHint
idempotentHint
openWorldHint
```

These become declared evidence.

Example:

```text
MCP Tool
  destructiveHint: true

Evidence class:
DECLARED
```

They do not establish actual authority.

They do not establish a trust boundary.

They do not prove safety.

---

## 18.7 MCP security classification

Pico may normalize MCP tools into broad capability classes using:

1. authoritative metadata;
2. MCP annotations;
3. adapter knowledge;
4. deterministic schema/name/operation mapping where justified.

If capability cannot be established:

```text
capability:
UNKNOWN
```

Pico should not use an LLM to guess tool authority in the authoritative V0 engine.

---

## 18.8 MCP and external influence

MCP may participate in both sides of Pico's model.

### Influence

```text
External GitHub Issue
        ↓
GitHub MCP Tool
        ↓
Agent
```

### Authority

```text
Agent
   ↓
Deployment MCP Tool
   ↓
Production
```

Therefore MCP must not be classified globally as either:

```text
input
```

or:

```text
authority
```

Individual MCP capabilities participate in the graph according to their actual behavior.

---

# 19. Provider Authority Adapters

Provider Authority Adapters determine what consequential external authority Pico can safely establish.

A Provider Adapter answers:

> **What resources exist, and what authority does the observed credential have over them?**

The first V0 provider is:

```text
Cloudflare
```

GitHub participates initially as an influence/integration surface.

---

## 19.1 Provider Adapter contract

Conceptually:

```text
ProviderAdapter {
  detect_credentials()

  identify_credential_type()

  verify_credential()

  discover_resources()

  resolve_authority()

  resolve_resource_scope()

  classify_environment()

  collect_evidence()
}
```

---

## 19.2 Credential handling

The provider adapter may receive a secret transiently when required for authenticated provider introspection.

The secret must remain outside normalized adapter output.

Conceptually:

```text
Secret Source
     ↓
Transient Credential Handle
     ↓
Provider Client
     ↓
Provider API
     ↓
Normalized Evidence
```

not:

```text
Secret
  ↓
DiscoveryResult
  ↓
SQLite
```

---

## 19.3 Credential handles

Internally, Pico should prefer a short-lived credential handle abstraction.

Conceptually:

```text
CredentialHandle {
  provider
  credential_type
  source
  access()
}
```

`access()` provides the secret only to the provider client requiring it.

The normalized Credential Resource stores only safe metadata.

---

## 19.4 Authority resolution

Provider adapters return explicit resolution precision.

Conceptually:

```text
AuthorityResolution {
  tier
  permissions[]
  resource_scopes[]
  evidence[]
  unknowns[]
}
```

Possible tiers:

```text
EXACT
SCOPED
BEHAVIORAL_READ_ONLY
UNKNOWN
```

The adapter should explain what it could not determine.

---

## 19.5 Read-only provider behavior

Pico provider adapters should use:

- metadata endpoints;
- list endpoints;
- token verification;
- permission introspection;
- resource enumeration.

They should not test write authority by performing writes.

For example:

Bad:

```text
Can this token modify Worker X?

Let's modify Worker X and see.
```

Good:

```text
Token policy:
Workers Write

Resource scope:
Account X

Worker X:
belongs to Account X

Derived authority:
can_mutate Worker X
```

---

## 19.6 Cloudflare V0 adapter

The Cloudflare adapter should initially support the minimum authority model required for the golden path.

Responsibilities:

```text
detect Cloudflare credential reference

identify supported credential type

verify credential status when safe

discover relevant account

discover relevant Workers

resolve available token policy / permissions

resolve resource scope

derive Worker mutation authority

emit evidence
```

If exact authority cannot be introspected:

```text
authority_resolution:
SCOPED / UNKNOWN
```

Pico must lower confidence rather than probe destructively.

---

## 19.7 GitHub adapter

GitHub initially serves two purposes:

```text
Influence discovery
+
credential/resource authority where needed
```

For the golden path, GitHub primarily establishes:

```text
External GitHub Content
      ↓
GitHub capability
      ↓
Agent
```

Later Pico may also analyze:

```text
Agent
  ↓
GitHub Credential
  ↓
Repository Write
```

The architecture supports both without requiring both in V0.

---

## 19.8 Vercel adapter

Vercel should not be required for the golden path.

When introduced, it should use the same authority-resolution contract.

If token-level authority cannot be established precisely:

```text
UNKNOWN
```

is preferable to provider-specific guessing.

---

# 20. Integration Intelligence

Integration Intelligence helps Pico understand what integration surfaces may exist.

Its purpose is:

> **Discovery acceleration, not security truth.**

Potential intelligence sources include:

```text
integrations.sh
OpenAPI specifications
MCP metadata
GraphQL schemas
CLI metadata
provider documentation
```

---

## 20.1 Architecture position

Integration Intelligence sits beside adapters.

```text
                Integration Intelligence
                        │
                        ▼
Agent Adapter ─────→ Discovery
MCP Discovery ─────→ Discovery
Provider Adapter ──→ Discovery
                        │
                        ▼
                 Environment Evidence
```

It helps adapters know what to look for.

It does not override what the environment actually says.

---

## 20.2 integrations.sh

Pico may use integrations.sh to discover information such as:

- known service identity;
- MCP availability;
- API surfaces;
- CLI surfaces;
- OpenAPI specifications;
- GraphQL specifications;
- authentication patterns;
- credential naming conventions.

This can significantly reduce bespoke integration research.

---

## 20.3 Intelligence evidence class

Integration Intelligence should generally not create `DIRECT` environment evidence.

Instead it may produce:

```text
INTELLIGENCE
```

or remain outside the authoritative Evidence model entirely.

Example:

```text
integrations.sh says:
Cloudflare commonly uses CLOUDFLARE_API_TOKEN
```

This may guide discovery.

It does not prove:

```text
this environment has that credential
```

Local discovery must establish that separately.

---

## 20.4 Offline behavior

Pico's core scan should not become dependent on integrations.sh availability.

Provider/agent adapters required by V0 should contain enough built-in knowledge to operate independently.

Integration Intelligence should enrich discovery, not make Pico unusable offline.

---

## 20.5 Intelligence caching

Future Pico versions may cache integration intelligence locally.

V0 should avoid building a generalized integration-spec cache unless the golden path requires it.

---

# 21. Discovery and Scan Pipeline

The Discovery Pipeline orchestrates adapters and converts their outputs into a coherent Pico scan.

The pipeline is responsible for:

```text
scope
ordering
collection
normalization
secret safety
persistence
analysis
diagnostics
```

---

## 21.1 Pipeline overview

```text
pico scan
    │
    ▼
Create Scan
    │
    ▼
Resolve Scan Scope
    │
    ▼
Discover Local Environment
    │
    ▼
Discover Agents
    │
    ▼
Discover MCP
    │
    ▼
Discover Credential References
    │
    ▼
Resolve Provider Evidence
    │
    ▼
Normalize
    │
    ▼
Secret Safety Boundary
    │
    ▼
Persist Observed Domain
    │
    ▼
Project Security Graph
    │
    ▼
Influence Analysis
    │
    ▼
Authority Analysis
    │
    ▼
Boundary Evaluation
    │
    ▼
Attack Path Construction
    │
    ▼
Finding Generation
    │
    ▼
Persist Analysis
    │
    ▼
Complete Scan
```

---

## 21.2 Discovery ordering

Some discovery depends on previous results.

Example:

```text
OpenCode Discovery
      ↓
MCP Configuration
      ↓
GitHub MCP Discovery
```

and:

```text
Local Credential Discovery
      ↓
Cloudflare Credential
      ↓
Cloudflare Provider Discovery
```

Therefore adapters should not simply execute every possible operation concurrently without dependency awareness.

---

## 21.3 Discovery plan

The application layer should create a bounded discovery plan.

Conceptually:

```text
DiscoveryPlan {
  agent_adapters[]
  mcp_targets[]
  provider_targets[]
  integration_intelligence[]
}
```

The plan may expand as evidence is discovered.

Example:

```text
OpenCode found
   ↓
GitHub MCP found
   ↓
Add GitHub MCP discovery

Cloudflare credential found
   ↓
Add Cloudflare provider discovery
```

---

## 21.4 Dynamic discovery must be bounded

Pico should not recursively discover integrations forever.

The scan should have:

```text
allowed adapter categories
maximum discovery depth
provider allowlist
network request limits
timeouts
```

V0 should be particularly conservative.

---

## 21.5 Normalization

Raw adapter output should become normalized Pico domain candidates.

Conceptually:

```text
RawAgentState
      ↓
Normalizer
      ↓
ResourceCandidate
RelationshipCandidate
EvidenceCandidate
```

Provider-specific parsing should end at this boundary.

The Security Graph should not understand OpenCode configuration syntax or Cloudflare API response structures.

---

## 21.6 Validation

Before persistence, normalized candidates should be validated.

Examples:

- canonical key exists;
- resource kind is supported;
- relationship endpoints exist;
- relationship kind is supported;
- relationship state is valid;
- evidence class is valid;
- secret-like fields are absent;
- required provenance exists.

Invalid adapter output should produce a diagnostic rather than corrupting graph state.

---

## 21.7 Partial scans

The pipeline should preserve partial success.

Example:

```text
Agent discovery       ✓
MCP discovery         ✓
Credential discovery  ✓
Cloudflare API        ✕
```

Pico may still conclude:

```text
External GitHub content
can reach an agent
with shell access
to a Cloudflare credential.
```

But Pico cannot conclude:

```text
The credential can mutate production.
```

The resulting Finding, if any, must reflect the missing authority evidence.

---

## 21.8 Analysis isolation

Adapters finish collecting evidence before authoritative graph analysis begins.

Adapters should not mutate the graph while the analysis engine traverses it.

Preferred model:

```text
DISCOVERY PHASE
      ↓
PERSIST
      ↓
ANALYSIS PHASE
```

This gives Pico a coherent scan snapshot.

---

## 21.9 Determinism

Given the same normalized graph and analysis-engine version, Pico should produce the same:

```text
Attack Paths
Severity
Confidence
Findings
```

This property is essential for testing and trust.

---

# 22. Secret Handling and Pico Self-Security

Pico inspects security-sensitive developer environments.

That means Pico itself becomes part of the security model.

The architecture must minimize the authority Pico requires and the sensitive information Pico retains.

The governing principle is:

> **Pico should learn about authority without becoming another authority holder.**

---

## 22.1 Secret lifecycle

Preferred secret lifecycle:

```text
Existing Secret Source
        ↓
Transient Read
        ↓
Credential Handle
        ↓
Provider Client
        ↓
Read-only Introspection
        ↓
Normalized Metadata
        ↓
Secret Destroyed / Released
```

The raw secret should never intentionally cross into:

```text
SQLite
logs
Evidence
Resources
Relationships
Findings
diagnostics
telemetry
```

---

## 22.2 Credential Resources

Pico may persist:

```text
provider
credential type
source type
source location
safe fingerprint
validity
authority resolution
last verified
```

Pico must not persist:

```text
token value
password
private key
refresh token
session cookie
secret environment value
```

---

## 22.3 Credential fingerprints

Pico may need stable credential identity across scans.

A fingerprint must be:

- one-way;
- non-recoverable;
- safe to persist;
- unable to authenticate to the provider.

The exact construction belongs in implementation design.

Raw token substrings should not be used as identifiers.

---

## 22.4 Secret detection boundary

All normalized adapter output must pass through a secret-safety validator.

Conceptually:

```text
Adapter Output
     ↓
Normalizer
     ↓
Secret Safety Validator
     ↓
Persistence
```

The validator should inspect:

- evidence observations;
- metadata;
- diagnostics;
- resource names;
- source locators;
- error messages.

This is defense in depth.

---

## 22.5 Logging

Pico logging must be structured and secret-safe.

Avoid logging:

```text
environment dumps
full HTTP headers
Authorization headers
raw provider responses
complete command environments
```

Provider clients should redact sensitive fields before errors reach shared logging.

---

## 22.6 Provider API permissions

Pico should prefer read-only API access.

However, an important reality exists:

Pico may be inspecting an existing credential that itself has write authority.

Pico does not control the authority of that credential.

Therefore Pico must ensure its own provider client only performs an allowlisted set of safe read/introspection operations.

---

## 22.7 Provider operation allowlist

Each provider adapter should define explicit allowed operations.

Example:

```text
Cloudflare V0

ALLOW
────────────────────────
verify token
read token metadata
read permission metadata
list accounts
list Workers
read resource metadata

DENY
────────────────────────
deploy Worker
delete Worker
modify route
write KV
modify D1
change DNS
rotate token
delete token
```

The provider client should expose only the operations required by the adapter where practical.

This reduces the chance of accidental mutation.

---

## 22.8 Network behavior

Pico should make outbound network requests only when required by:

```text
provider introspection
MCP metadata discovery
explicit integration intelligence
```

Pico should not silently upload the user's security graph to a Pico service.

V0 should operate without a Pico cloud account.

---

## 22.9 Telemetry

If telemetry is ever introduced, security graph contents must not be collected by default.

Potentially sensitive data includes:

```text
repository names
resource names
provider accounts
credential existence
agent configuration
MCP servers
security findings
attack paths
infrastructure relationships
```

V0 should strongly prefer no security-content telemetry.

---

## 22.10 Filesystem scope

Pico should inspect known, bounded locations.

Preferred:

```text
known OpenCode config path
current project
explicitly configured Pico paths
known provider configuration
```

Avoid:

```text
recursively scan entire home directory
```

unless a future explicit user action requests broader discovery.

---

## 22.11 Pico database security

`.pico/pico.db` contains sensitive metadata even without secrets.

The storage directory should use restrictive host filesystem permissions.

Pico should treat the database as sensitive local state.

---

## 22.12 Database contents

A compromised Pico database may reveal:

```text
which agents exist
which providers exist
which credentials exist
what those credentials can access
where production resources exist
what attack paths Pico discovered
```

This is valuable attacker reconnaissance.

Therefore secret exclusion alone is insufficient.

Local database protection matters.

---

## 22.13 Evidence minimization

Pico should persist the minimum evidence necessary to reproduce and explain a conclusion.

Example:

Instead of storing an entire provider response:

```text
{
  ... 400 fields ...
}
```

store:

```text
permission:
Workers Write

scope:
Account 123

source:
Cloudflare token metadata endpoint

observed_at:
...
```

This reduces both privacy risk and schema coupling.

---

## 22.14 Error safety

Errors are a common secret-leak path.

Adapters must avoid returning raw errors that may contain:

```text
tokens
headers
URLs with credentials
environment values
request bodies
```

Errors should be sanitized at the adapter boundary.

---

## 22.15 MCP safety

Pico must be especially careful when inspecting MCP.

Pico should not invoke arbitrary MCP tools merely to classify them.

Preferred V0 behavior:

```text
inspect configuration
discover tool metadata
inspect schemas
inspect annotations
inspect agent permissions
```

not:

```text
call every tool and see what happens
```

---

## 22.16 No attack simulation in V0

Pico V0 does not validate an AttackPath by attempting exploitation.

It validates the path using configuration and authorization evidence.

This keeps Pico on the defensive side of the boundary and prevents the scanner from creating the incident it is attempting to identify.

---

## 22.17 Pico compromise model

Pico should assume:

> If Pico itself is compromised while temporarily holding a credential, that credential could be exposed.

Therefore Pico should minimize:

```text
credential lifetime
credential copies
provider client surface
network operations
memory retention
```

Pico cannot eliminate this risk entirely.

It can minimize it architecturally.

---

## 22.18 Future privilege separation

V0 does not require multiple processes.

Future Pico versions may benefit from separating:

```text
Discovery
Provider Credential Access
Analysis
UI / Agent Interface
```

into stronger isolation boundaries.

Do not build that complexity in V0.

The current architecture should avoid making future privilege separation impossible.

---

# Architecture Decision 014 — Adapters Produce Facts, Not Findings

**Decision:** Adapters return normalized discovery facts and evidence.

They do not generate security Findings.

**Reason:**

Security reasoning must remain centralized, deterministic, and provider-neutral.

---

# Architecture Decision 015 — Built-In Adapters Only in V0

**Decision:** Pico does not support arbitrary executable third-party adapters/plugins in V0.

**Reason:**

A plugin system would introduce an unnecessary supply-chain and code-execution surface into a security-sensitive application.

---

# Architecture Decision 016 — Effective Agent Permissions

**Decision:** Agent adapters resolve effective capability from configuration, overrides, runtime mode, and enforced controls.

**Reason:**

Static configuration alone may misrepresent actual agent authority.

---

# Architecture Decision 017 — MCP Is Capability-Neutral

**Decision:** MCP is not globally classified as either influence or authority.

Individual MCP tools participate in the graph according to observed behavior and evidence.

**Reason:**

The same protocol can expose:

```text
untrusted information
```

or:

```text
production mutation authority
```

or both.

---

# Architecture Decision 018 — MCP Annotations Are Evidence, Not Truth

**Decision:** MCP tool annotations are treated as declared evidence.

They do not independently establish authority or safety.

---

# Architecture Decision 019 — Provider Authority Is Explicitly Partial

**Decision:** Provider adapters must expose authority-resolution precision.

```text
EXACT
SCOPED
BEHAVIORAL_READ_ONLY
UNKNOWN
```

**Reason:**

Different providers and credential types expose different levels of introspection.

Pico must not manufacture uniform certainty.

---

# Architecture Decision 020 — Integration Intelligence Is Non-Authoritative

**Decision:** integrations.sh and similar catalogs accelerate discovery but do not establish environment-specific security truth.

---

# Architecture Decision 021 — Discovery Is Dependency-Aware

**Decision:** Pico uses a bounded Discovery Plan rather than blindly executing every adapter.

**Reason:**

Discovery naturally produces new targets:

```text
Agent
 ↓
MCP

Credential
 ↓
Provider
```

The pipeline should support this without becoming uncontrolled recursive discovery.

---

# Architecture Decision 022 — Discovery and Analysis Are Separate Phases

**Decision:**

```text
DISCOVER
   ↓
PERSIST
   ↓
ANALYZE
```

Authoritative analysis operates on a coherent graph snapshot.

Adapters do not mutate the graph during analysis.

---

# Architecture Decision 023 — Raw Secrets Never Enter the Domain Model

**Decision:** Raw credential values remain transient and outside:

```text
Resources
Relationships
Evidence
Observations
AttackPaths
Findings
SQLite
```

---

# Architecture Decision 024 — Provider Operations Are Allowlisted

**Decision:** Every provider adapter has an explicit read/introspection operation allowlist.

**Reason:**

Pico may temporarily use credentials with destructive authority.

Pico's own code should expose only the safe operations it needs.

---

# Architecture Decision 025 — No Arbitrary MCP Invocation During Discovery

**Decision:** Pico does not call arbitrary MCP tools to determine what they do.

V0 relies on:

```text
configuration
tool discovery
schemas
annotations
known adapter intelligence
```

**Reason:**

Discovery should not create external side effects.

---

# Architecture Decision 026 — Security Metadata Is Sensitive

**Decision:** Pico treats its local database as sensitive even though it excludes raw secrets.

**Reason:**

The graph itself contains valuable security reconnaissance.

---

# Adapter Architecture Pressure Test

The golden path now passes through the complete discovery architecture.

```text
                  PICO SCAN
                      │
                      ▼
               OpenCode Adapter
                      │
              discovers OpenCode
                      │
                      ▼
                MCP Discovery
                      │
              discovers GitHub MCP
                      │
                      ▼
             GitHub Capability
                      │
              external influence
                      │
                      ▼
               OpenCode Agent
                      │
              effective Bash
                      │
                      ▼
            Credential Discovery
                      │
        Cloudflare credential found
                      │
                      ▼
           Cloudflare Adapter
                      │
        read-only introspection
                      │
                      ▼
        Cloudflare Worker authority
                      │
                      ▼
                NORMALIZATION
                      │
                      ▼
             SECRET SAFETY
                      │
                      ▼
                 SQLITE
                      │
                      ▼
             SECURITY GRAPH
                      │
                      ▼
                 ANALYSIS
```

At no point does:

```text
OpenCode Adapter
GitHub MCP Discovery
Cloudflare Adapter
```

decide:

```text
"This is a critical vulnerability."
```

They establish facts.

The core engine makes the security conclusion.

---

# Self-Security Pressure Test

Assume Pico discovers:

```text
CLOUDFLARE_API_TOKEN
```

and that token has production mutation authority.

Pico:

```text
1. Identifies credential presence.

2. Creates a transient credential handle.

3. Passes the handle only to the
   Cloudflare provider client.

4. Calls allowlisted read/introspection
   endpoints.

5. Receives token/resource metadata.

6. Converts that response into the
   minimum normalized evidence required.

7. Discards the raw provider response.

8. Releases the credential handle.

9. Passes normalized output through
   secret-safety validation.

10. Persists only safe metadata.
```

SQLite receives:

```text
Credential:
Cloudflare API Token

Fingerprint:
<safe one-way identifier>

Validity:
ACTIVE

Permission:
Workers Write

Scope:
Account X

Secret Stored:
false
```

SQLite never receives:

```text
CLOUDFLARE_API_TOKEN=abc123...
```

The AttackPath Engine can still establish:

```text
OpenCode
   ↓
Bash
   ↓
Cloudflare Credential
   ↓
Production Worker
```

without retaining the credential required to authenticate that relationship.

**Adapter and self-security architecture: ACCEPTABLE FOR CONTINUED DESIGN.**

---

# Architecture Status Through Section 22

Pico now has defined architecture for:

```text
DOMAIN
  ↓
Resource
Relationship
Observation
Evidence
Scan

GRAPH
  ↓
Influence
Authority
Boundary
AttackPath
Finding

DISCOVERY
  ↓
Agent Adapters
MCP Discovery
Provider Adapters
Integration Intelligence

PIPELINE
  ↓
Discover
Normalize
Validate
Secret Safety
Persist
Analyze

SELF-SECURITY
  ↓
Transient Credentials
Provider Allowlisting
Secret Exclusion
Evidence Minimization
Bounded Filesystem Access
Bounded Network Access
Sensitive Local Storage
```

The architecture still satisfies Pico's primary constraint:

> **Architect for extension. Implement only the golden path.**

V0 therefore still means:

```text
OpenCode
   +
GitHub MCP
   +
Bash
   +
Cloudflare Credential
   +
Cloudflare Resource
   +
SQLite
   +
Deterministic Analysis
   +
CLI
```

Not:

```text
every agent
every MCP server
every cloud provider
runtime interception
automatic remediation
hosted control plane
plugin marketplace
SIEM
SOC platform
```

---

# Next Architecture Sections

The remaining architecture should define:

```text
23. CLI Architecture

24. MCP / Agent Interface

25. Testing Architecture

26. Repository / Package Structure

27. Golden Path Implementation

28. V0 Product Boundary

29. Rejected Architectural Alternatives

30. Final Architecture Decisions

31. Architecture Definition of Done


# 23. CLI Architecture

The CLI is Pico V0's primary human interface.

The CLI should expose Pico's domain and analysis capabilities without becoming the location where those capabilities are implemented.

The governing rule is:

> **The CLI orchestrates Pico. It does not contain Pico's security logic.**

Conceptually:

```text
CLI
 │
 ▼
Application Services
 │
 ├── Scan
 ├── Query
 ├── Explain
 └── Status
 │
 ▼
Core Pico Engine
```

This separation allows the same Pico capabilities to later be exposed through:

```text
CLI
MCP
Slack
UI
CI
API
```

without duplicating security logic.

---

## 23.1 Initial CLI shape

The initial Pico command surface should remain deliberately small.

Conceptually:

```text
pico init

pico scan

pico findings

pico finding <id>

pico agents

pico status
```

Potential future commands:

```text
pico graph

pico resources

pico explain

pico history

pico diff

pico providers

pico integrations
```

These should not be implemented merely because the architecture anticipates them.

---

## 23.2 `pico init`

`pico init` establishes Pico state for the current environment.

Responsibilities may include:

```text
create .pico/

create pico.db

initialize schema

create safe local configuration

detect supported environment basics

optionally configure agent integration
```

`pico init` should be idempotent.

Running:

```text
pico init
```

twice must not destroy existing Pico state.

---

## 23.3 `pico scan`

`pico scan` executes the primary Pico workflow.

```text
pico scan
   │
   ▼
Discover
   │
   ▼
Collect Evidence
   │
   ▼
Normalize
   │
   ▼
Persist
   │
   ▼
Build Graph
   │
   ▼
Analyze
   │
   ▼
Generate Findings
   │
   ▼
Present Summary
```

Example output:

```text
Pico scan complete

Agents
  1 discovered

MCP servers
  2 discovered

Credentials
  1 security-relevant credential discovered

Resources
  8 analyzed

Attack paths
  1 active
  2 blocked

Findings

CRITICAL
External GitHub content can reach Cloudflare
production mutation authority.

Run:

  pico finding pcf_01...

for evidence and remediation.
```

The exact UI belongs in product implementation.

The architecture requires that CLI output be generated from application/domain results rather than from adapter-specific print statements.

---

## 23.4 `pico findings`

Displays Findings from the latest completed scan by default.

Possible future filters:

```text
--severity
--confidence
--status
--scan
--agent
--provider
```

V0 should avoid excessive filtering unless needed.

---

## 23.5 `pico finding`

A Finding detail view should answer:

```text
WHAT did Pico find?

WHY does it matter?

HOW does the path work?

HOW does Pico know?

WHAT boundary is missing?

HOW can the path be broken?
```

Conceptually:

```text
CRITICAL
Untrusted content can reach production authority

Source
  Public GitHub Issue

Actor
  OpenCode

Path
  GitHub Issue
    ↓
  GitHub MCP
    ↓
  OpenCode
    ↓
  Bash
    ↓
  Cloudflare API Token
    ↓
  Production Worker

Confidence
  HIGH

Evidence
  OpenCode Bash permission: ALLOW
  GitHub MCP enabled
  Cloudflare token: Workers Write
  Token scope includes production account

Boundaries
  No enforced approval interrupts the path.

Recommended cuts
  1. Require enforced Bash approval.
  2. Remove the production credential from the agent environment.
  3. Scope the credential away from production.
```

This view embodies Pico's evidence-first product philosophy.

---

## 23.6 Machine-readable output

Core commands should eventually support structured output.

Preferred:

```text
--json
```

The JSON representation should expose stable application-level DTOs rather than dumping SQLite rows.

This enables:

```text
CI
agents
scripts
future integrations
```

without exposing persistence internals as an API contract.

---

## 23.7 Exit codes

CLI exit codes should eventually support automation.

Conceptually:

```text
0 = scan completed / no policy-triggering condition
1 = Pico execution failure
2 = security finding threshold reached
```

Exact semantics should be defined before CI integration.

V0 should not overcomplicate exit-code policy prematurely.

---

# 24. MCP / Agent Interface

Pico should be directly usable by AI coding agents.

This is not a secondary integration.

It is part of Pico's AI-native product model.

A developer should eventually be able to ask:

> "Pico, check whether anything dangerous changed."

or:

> "Ask Pico whether this agent can reach production."

without manually translating that request into CLI commands.

---

## 24.1 Architecture position

MCP sits above Pico's application layer.

```text
Coding Agent
     │
     ▼
   Pico MCP
     │
     ▼
Application Services
     │
     ▼
Pico Core
     │
     ▼
SQLite / Analysis
```

The MCP server does not implement separate security reasoning.

---

## 24.2 Initial MCP capability

V0 should expose the minimum capabilities required for agent-native use.

Candidate tools:

```text
scan

list_findings

get_finding

get_security_context
```

However, we should be conservative about exposing a tool that automatically initiates broad scans.

A safer initial surface may be:

```text
get_status

list_findings

get_finding

scan
```

with clear read-only semantics.

---

## 24.3 Agent-triggered scan

If an agent invokes:

```text
pico.scan
```

the resulting scan must use the exact same pipeline as:

```text
pico scan
```

There must not be:

```text
CLI scanner
```

and:

```text
MCP scanner
```

as separate implementations.

Both call:

```text
ScanService
```

---

## 24.4 MCP output

Pico MCP responses should return structured security context.

Example:

```text
Finding:
UNTRUSTED_TO_PRODUCTION

Severity:
CRITICAL

Confidence:
HIGH

Actor:
OpenCode

Source:
GitHub

Sink:
Cloudflare Worker

Attack Path:
[...]

Evidence:
[...]

Recommended Cuts:
[...]
```

The coding agent may summarize this for the user.

Pico remains the authority for the underlying security conclusion.

---

## 24.5 Pico should not become an execution proxy

Pico MCP V0 should not expose:

```text
fix_finding

revoke_credential

disable_agent

change_permission

deploy_policy

kill_agent
```

Those belong to a possible future enforcement layer.

Pico V0 is:

```text
OBSERVE
UNDERSTAND
EXPLAIN
```

not:

```text
CONTROL
```

---

## 24.6 MCP self-description

Pico's own MCP tools should use accurate annotations.

If a Pico tool is read-only, declare it read-only.

If a scan may perform network requests, document that behavior.

Pico should model the MCP hygiene it expects from other systems.

---

# 25. Testing Architecture

Security products require deterministic, reproducible testing.

Pico should not require real production credentials or destructive cloud environments to test its core security engine.

The testing architecture should be layered.

```text
Unit Tests
    ↓
Domain Tests
    ↓
Graph Tests
    ↓
Adapter Fixture Tests
    ↓
Pipeline Tests
    ↓
Integration Tests
    ↓
Golden Path Dogfood
```

---

## 25.1 Domain tests

Test core invariants.

Examples:

```text
canonical Resource identity remains stable

Relationships require valid endpoints

Evidence cannot contain prohibited secret fields

UNKNOWN relationships do not become traversable

BLOCKED relationships do not complete AttackPaths
```

---

## 25.2 Graph tests

Graph tests should use small synthetic environments.

Example:

```text
External
   ↓
Agent
   ↓
Shell
   ↓
Credential
   ↓
Production
```

Expected:

```text
1 active AttackPath
```

Add:

```text
Shell
   ↓
Mandatory Approval
```

Expected:

```text
0 active AttackPaths
1 blocked candidate
```

These tests should require no network access.

---

## 25.3 Attack-path fixtures

Pico should maintain security scenario fixtures.

Examples:

```text
safe-agent-no-authority

external-to-shell

external-to-production

external-to-production-with-approval

external-to-production-scoped-credential

multiple-path-bypass

unknown-authority

inferred-influence

multi-agent-cycle
```

These become a durable security regression suite.

---

## 25.4 Adapter fixture tests

Adapters should be tested against sanitized provider/configuration fixtures.

Example:

```text
fixtures/
  opencode/
    bash-allow.json
    bash-ask.json
    bash-deny.json

  cloudflare/
    token-workers-write.json
    token-read-only.json
    token-unknown-scope.json

  mcp/
    github-tools.json
```

No real secrets should exist in fixtures.

---

## 25.5 Secret leakage tests

Pico should explicitly test that secret-like values never reach persistence.

Example:

```text
TEST_SECRET_abc123
```

may be injected into a transient adapter fixture.

After scan:

```text
search pico.db
search logs
search diagnostics
```

Expected:

```text
0 occurrences
```

This should become a core regression test.

---

## 25.6 Determinism tests

Given:

```text
same normalized graph
+
same analysis version
```

Pico should produce:

```text
same AttackPaths
same severity
same confidence
same Findings
```

Stable IDs may require deterministic fingerprinting or normalized comparison.

---

## 25.7 Provider client tests

Provider operation allowlists should be tested.

A provider adapter test should fail if the adapter attempts an operation outside its approved read/introspection surface.

This makes Pico's read-only promise testable rather than aspirational.

---

## 25.8 Integration tests

Integration tests may exercise:

```text
temporary SQLite database

fixture OpenCode configuration

fixture MCP metadata

mock Cloudflare provider

full scan pipeline
```

Expected result:

```text
known Finding
+
known evidence
+
known AttackPath
```

---

## 25.9 Live dogfood

Real-world validation remains necessary.

Pico should eventually be run against a controlled developer environment owned by the project.

The purpose is to validate:

```text
discovery correctness
provider behavior
configuration assumptions
CLI usability
performance
unexpected edge cases
```

Live dogfood should not replace fixture-based tests.

---

# 26. Repository / Package Structure

Pico should begin as a modular monolith.

Do not create separate deployable services.

A conceptual repository structure:

```text
pico/
│
├── src/
│   │
│   ├── cli/
│   │
│   ├── mcp/
│   │
│   ├── application/
│   │
│   ├── domain/
│   │
│   ├── graph/
│   │
│   ├── analysis/
│   │
│   ├── discovery/
│   │
│   ├── adapters/
│   │   ├── agents/
│   │   │   └── opencode/
│   │   │
│   │   ├── mcp/
│   │   │
│   │   └── providers/
│   │       ├── cloudflare/
│   │       └── github/
│   │
│   ├── persistence/
│   │
│   ├── security/
│   │
│   └── shared/
│
├── tests/
│   ├── fixtures/
│   ├── domain/
│   ├── graph/
│   ├── analysis/
│   ├── adapters/
│   └── integration/
│
├── docs/
│
├── PRODUCT_DEFINITION.md
├── TECHNICAL.md
├── ARCHITECTURE.md
├── ROADMAP.md
└── README.md
```

The exact language/framework-specific structure can change.

The architectural boundaries should remain recognizable.

---

## 26.1 Domain

`domain/` contains normalized Pico concepts.

Examples:

```text
Resource
Relationship
Evidence
Observation
Scan
AttackPath
Finding
```

Domain code must not import:

```text
OpenCode
Cloudflare SDK
GitHub SDK
CLI framework
MCP transport
SQLite driver
```

---

## 26.2 Analysis

`analysis/` contains deterministic security reasoning.

Examples:

```text
influence analysis
authority analysis
boundary evaluation
attack-path construction
finding rules
severity
confidence
```

Analysis operates on normalized Pico concepts.

---

## 26.3 Adapters

`adapters/` contains system-specific knowledge.

This is where Pico knows:

```text
how OpenCode represents permissions

how Cloudflare represents token policy

how GitHub MCP exposes tools
```

That knowledge should stop at the adapter boundary.

---

## 26.4 Security

`security/` contains Pico's own safety mechanisms.

Examples:

```text
secret redaction
credential handles
provider operation allowlists
sensitive logging
filesystem protections
```

This prevents self-security concerns from being scattered throughout the repository.

---

## 26.5 Application

`application/` orchestrates use cases.

Examples:

```text
InitService
ScanService
FindingService
StatusService
```

Interfaces call application services.

Application services coordinate domain, discovery, persistence, and analysis.

---

# 27. Golden Path Implementation

The architecture should now be reduced to one narrow implementation path.

Pico V0's first proof should establish:

> **Pico can discover and explain a real evidence-backed path from external agent influence to consequential cloud authority.**

The golden path is:

```text
GitHub External Content
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

---

## 27.1 Implementation slices

The golden path should be built vertically rather than building every subsystem horizontally.

### Slice 1 — Local foundation

Implement:

```text
CLI skeleton
.pico/
SQLite
migrations
Scan
Resource
Relationship
Evidence
Observation
```

Success:

```text
pico init
pico scan
```

can create and persist an empty/local scan.

---

### Slice 2 — OpenCode discovery

Implement:

```text
OpenCode detection
effective configuration
agent identity
Bash permission
MCP configuration
evidence
```

Success:

Pico can answer:

> "What agent exists and can it execute Bash?"

---

### Slice 3 — MCP / GitHub influence

Implement:

```text
MCP server discovery
GitHub MCP identification
relevant tool metadata
external-source modeling
influence relationships
```

Success:

Pico can establish:

```text
GitHub External Content
        ↓
GitHub MCP
        ↓
OpenCode
```

---

### Slice 4 — Cloudflare credential reachability

Implement:

```text
credential reference discovery
shell/environment reachability
safe fingerprint
transient credential handle
```

Success:

Pico can establish:

```text
OpenCode
   ↓
Bash
   ↓
Cloudflare Credential
```

without persisting the token.

---

### Slice 5 — Cloudflare authority

Implement:

```text
safe provider client
operation allowlist
credential verification
permission introspection
resource enumeration
Worker authority
```

Success:

Pico can establish:

```text
Cloudflare Credential
        ↓
Cloudflare Worker
```

with explicit authority resolution.

---

### Slice 6 — Security graph

Implement:

```text
graph projection
directional edges
edge usability
cycle protection
bounded traversal
```

Success:

The complete golden path exists as normalized graph state.

---

### Slice 7 — Analysis

Implement:

```text
InfluencePath
AuthorityPath
BoundaryEvaluation
AttackPath
```

Success:

Pico deterministically identifies whether the golden path is active or blocked.

---

### Slice 8 — Finding

Implement:

```text
UNTRUSTED_TO_PRODUCTION
severity
confidence
evidence aggregation
remediation cut points
```

Success:

```text
pico scan
```

produces the first useful Pico security Finding.

---

### Slice 9 — Explanation UX

Implement:

```text
pico findings
pico finding <id>
```

Success:

A developer can understand:

```text
what exists
what path Pico found
why Pico believes it
how severe it is
how confident Pico is
how to break the path
```

---

### Slice 10 — Agent-native interface

Implement minimal Pico MCP exposure over existing application services.

Success:

A coding agent can ask Pico for the same Finding visible through the CLI.

No duplicate scanner exists.

---

# 28. V0 Product Boundary

Pico V0 is intentionally narrow.

It is not an enterprise security platform.

It is not a SIEM.

It is not an EDR.

It is not an agent runtime.

It is not an agent sandbox.

It is not a policy engine.

It is not a cloud security posture platform.

It is not a generic asset inventory.

It is not an AI penetration-testing system.

Pico V0 is:

> **A local-first security graph that discovers evidence-backed paths between untrusted influence and autonomous authority in AI-native developer environments.**

---

## 28.1 V0 supports

```text
local CLI

OpenCode

GitHub MCP influence

Bash capability

Cloudflare credential discovery

Cloudflare Worker authority

SQLite

evidence provenance

security graph

influence analysis

authority analysis

boundary evaluation

AttackPaths

Findings

CLI explanation

minimal Pico MCP interface
```

---

## 28.2 V0 does not support

```text
automatic remediation

agent shutdown

credential revocation

runtime packet inspection

runtime syscall monitoring

continuous daemon monitoring

hosted Pico cloud

organization-wide dashboard

multi-user RBAC

Slack bot

SIEM export

every coding agent

every MCP server

every cloud provider

arbitrary third-party plugins

attack execution

exploit validation

LLM-based security decisions

full historical UI

enterprise policy management
```

---

## 28.3 V0 success criteria

Pico V0 succeeds if a developer can:

```text
install Pico

initialize Pico

scan their environment

have Pico discover their supported agent

understand the agent's effective capability

discover supported external influence

discover reachable cloud authority

see an evidence-backed AttackPath

understand why Pico considers it dangerous

see how to break the path

query the result from their coding agent
```

That is enough.

---

# 29. Rejected Architectural Alternatives

Architecture is defined partly by what Pico intentionally does not build.

---

## 29.1 Dedicated graph database

Rejected for V0.

Why:

```text
unnecessary runtime complexity
installation burden
duplicate persistence concerns
V0 graph size does not justify it
SQLite is sufficient
```

Revisit only if actual scale/query requirements demand it.

---

## 29.2 Hosted-first architecture

Rejected.

Why:

Pico's first users are developers and startups operating agent-heavy environments.

Local-first provides:

```text
lower trust barrier
faster adoption
better secret isolation
offline capability
simpler deployment
```

A hosted control plane may exist later.

---

## 29.3 LLM-first risk engine

Rejected.

Why:

Security truth must be:

```text
deterministic
reproducible
testable
auditable
```

LLMs may explain results.

They do not establish authoritative graph relationships.

---

## 29.4 Active exploitation

Rejected.

Pico does not prove authority by exercising destructive capability.

It uses authorization and configuration evidence.

---

## 29.5 Full runtime sandbox

Rejected for V0.

Pico is not initially competing with sandbox providers.

Runtime containment may eventually become a complementary enforcement layer.

---

## 29.6 Generic policy engine

Rejected for V0.

Pico should first prove that it can accurately discover attack paths.

Building:

```text
policy language
policy compiler
policy distribution
policy enforcement
```

before validating detection would dramatically expand scope.

---

## 29.7 Arbitrary plugin system

Rejected.

Pico security adapters run near sensitive configuration and credentials.

A third-party executable plugin ecosystem creates unacceptable early complexity and supply-chain risk.

---

## 29.8 Broad provider support before depth

Rejected.

Preferred:

```text
1 agent
+
1 influence surface
+
1 provider
+
deep evidence
```

over:

```text
15 shallow integrations
```

Pico's value depends on trustworthy authority resolution.

---

## 29.9 Generic inventory product

Rejected.

Pico should not collect infrastructure merely because it can.

Every discovered object should contribute to understanding:

```text
influence
authority
boundaries
attack paths
```

or support those analyses.

---

## 29.10 Separate CLI and agent engines

Rejected.

CLI and MCP are interfaces over the same application services.

Pico must have one security engine.

---

# 30. Final Architecture Decisions

The following decisions are now considered architectural invariants for Pico V0.

### AD-001
Observed domain and analyzed domain are separate.

### AD-002
SQLite is Pico V0's persistent store.

### AD-003
The Security Graph is a projection over normalized relational state.

### AD-004
AttackPaths are computed by Pico's deterministic analysis engine.

### AD-005
Boundaries represent technically enforced interruption, not merely written policy.

### AD-006
Scan history and Observation provenance exist from V0.

### AD-007
Influence and Authority are analyzed separately and joined through autonomous actors.

### AD-008
UNKNOWN edges do not complete confirmed AttackPaths.

### AD-009
INFERRED relationships may participate with reduced confidence.

### AD-010
Boundaries block specific paths, not entire actors.

### AD-011
AttackPaths are persisted with the Scan that generated them.

### AD-012
Findings may group multiple AttackPaths.

### AD-013
Security reasoning is deterministic code, not LLM judgment.

### AD-014
Adapters produce facts, not Findings.

### AD-015
Adapters ship with Pico in V0.

### AD-016
Agent capability is based on effective permission, not configuration presence alone.

### AD-017
MCP is capability-neutral and may participate in Influence, Authority, or both.

### AD-018
MCP annotations are declared evidence, not security guarantees.

### AD-019
Provider authority precision is explicit.

### AD-020
Integration Intelligence is non-authoritative.

### AD-021
Discovery is bounded and dependency-aware.

### AD-022
Discovery and authoritative analysis occur as separate phases.

### AD-023
Raw secrets never enter Pico's persistent domain.

### AD-024
Provider API operations are explicitly allowlisted.

### AD-025
Pico does not invoke arbitrary MCP tools during discovery.

### AD-026
Pico's local security metadata is treated as sensitive.

### AD-027
CLI and MCP use the same application services and security engine.

### AD-028
Pico V0 is a modular monolith.

### AD-029
Testing uses deterministic security fixtures rather than destructive production validation.

### AD-030
Pico V0 implements one deep golden path before expanding provider breadth.

---

# 31. Architecture Definition of Done

Pico's Architecture Sprint is complete when this document provides enough clarity that implementation can begin without inventing major product architecture during coding.

The following questions must have explicit answers.

---

## 31.1 Domain

Can Pico represent:

```text
agents?
external sources?
capabilities?
credentials?
cloud resources?
relationships?
evidence?
observations?
scans?
boundaries?
AttackPaths?
Findings?
```

**YES**

---

## 31.2 Evidence

Can every security-significant conclusion answer:

> "How does Pico know?"

**YES**

Evidence includes provenance, scan association, class, source, observation, and freshness.

---

## 31.3 History

Can Pico eventually answer:

> "When did this exposure appear?"

without redesigning the entire persistence model?

**YES**

Stable Resources and Relationships are combined with scan-scoped Observations and append-oriented Evidence.

---

## 31.4 Graph

Can Pico represent security relationships without requiring a dedicated graph database?

**YES**

SQLite stores normalized state.

The Security Graph is projected for analysis.

---

## 31.5 Influence

Can Pico represent:

```text
External Content
      ↓
Capability
      ↓
Agent
```

**YES**

---

## 31.6 Authority

Can Pico represent:

```text
Agent
  ↓
Capability
  ↓
Credential
  ↓
Production Resource
```

**YES**

---

## 31.7 Boundaries

Can Pico distinguish:

```text
written instruction
```

from:

```text
technically enforced control
```

**YES**

Only enforced boundaries interrupt autonomous AttackPaths.

---

## 31.8 Alternate paths

Can Pico detect when one security boundary exists but another route bypasses it?

**YES**

Boundary evaluation occurs per candidate path.

---

## 31.9 Provider uncertainty

Can Pico say:

> "I know this credential exists, but I cannot establish its exact authority."

**YES**

Authority resolution supports:

```text
EXACT
SCOPED
BEHAVIORAL_READ_ONLY
UNKNOWN
```

---

## 31.10 Agent uncertainty

Can Pico distinguish configured permission from effective capability?

**YES**

Agent adapters account for runtime modes, overrides, approvals, denies, and sandbox controls where observable.

---

## 31.11 Secrets

Can Pico inspect credential authority without intentionally storing the credential?

**YES**

Secrets remain transient behind Credential Handles.

Normalized security metadata crosses the persistence boundary.

---

## 31.12 Self-security

Can Pico restrict itself from accidentally exercising a credential's destructive authority?

**YES**

Provider operations are explicitly allowlisted to safe read/introspection operations.

---

## 31.13 Determinism

Given identical normalized security state, can Pico reproduce the same security conclusion?

**YES**

Authoritative analysis contains no LLM judgment.

---

## 31.14 Agent-native workflow

Can Pico's security context be exposed directly to coding agents without implementing another scanner?

**YES**

CLI and MCP share application services.

---

## 31.15 Golden path

Can the architecture represent:

```text
Public GitHub Content
        ↓
GitHub MCP
        ↓
OpenCode
        ↓
Bash
        ↓
Cloudflare Credential
        ↓
Cloudflare Production Worker
```

without provider-specific changes to Pico's core security engine?

**YES**

---

## 31.16 V0 scope

Can Pico implement that golden path without also building:

```text
runtime containment
enterprise SOC platform
SIEM
hosted control plane
automatic remediation
multi-agent orchestration
plugin ecosystem
every provider
every coding agent
```

**YES**

---

# Final Architecture

Pico's architecture can now be summarized as:

```text
                     EXTERNAL ENVIRONMENT
                              │
                              ▼
                         DISCOVERY
                              │
             ┌────────────────┼────────────────┐
             │                │                │
          Agents             MCP           Providers
             │                │                │
             └────────────────┼────────────────┘
                              │
                              ▼
                           EVIDENCE
                              │
                              ▼
                        NORMALIZATION
                              │
                              ▼
                        SECRET SAFETY
                              │
                              ▼
                           SQLITE
                              │
                              ▼
                     SECURITY GRAPH
                              │
                   ┌──────────┴──────────┐
                   │                     │
                   ▼                     ▼
               INFLUENCE             AUTHORITY
                   │                     │
                   └──────────┬──────────┘
                              │
                              ▼
                    BOUNDARY EVALUATION
                              │
                              ▼
                        ATTACK PATH
                              │
                              ▼
                          FINDING
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
                   CLI                 MCP
                    │                   │
                    ▼                   ▼
                  Human              Agent
```

The core Pico security question remains:

> **Can untrusted influence reach consequential autonomous authority without encountering an enforced trust boundary?**

Everything in the V0 architecture exists to answer that question accurately, safely, locally, deterministically, and with evidence.

---

# Architecture Sprint Result

**Status: PASS**

The architecture successfully supports Pico's product definition and technical requirements without requiring:

- a graph database;
- a hosted backend;
- an LLM risk engine;
- destructive security testing;
- a plugin ecosystem;
- an enterprise control plane;
- runtime enforcement.

The golden path fits the architecture without special-case security logic.

Pico can begin as a small local developer tool while preserving an architectural path toward:

```text
more coding agents
more providers
more MCP surfaces
multi-agent environments
runtime observations
security memory
continuous monitoring
controlled containment
agent-to-agent defense
```

without building those systems today.
