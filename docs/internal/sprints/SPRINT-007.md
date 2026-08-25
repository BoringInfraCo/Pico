# Pico — Sprint 007: First Security Graph — Golden-Path Projection

**Status:** COMPLETE
**Sprint:** 007
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `ceaa420`
**Depends on:** Sprint 006 — First Provider Authority — Cloudflare Worker
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Teach Pico to assemble its observed security facts into its first normalized
Security Graph.

At the end of Sprint 007, Pico must be able to project the Resources,
Relationships, Evidence, and Observations belonging to one scan into a
deterministic, provider-neutral, in-memory graph.

The core question is:

> **Can Pico assemble one scan's complete golden-path facts into trustworthy
> graph state without leaking historical state or claiming an AttackPath?**

Conceptually:

```text
SQLite observed state for Scan N
        │
        ├── Resources observed in Scan N
        ├── Relationships observed in Scan N
        ├── Evidence captured in Scan N
        └── Observation snapshots from Scan N
        │
        ▼
Scan-Scoped Graph Projection
        │
        ├── provider-neutral GraphNodes
        ├── directional GraphEdges
        ├── SecurityRoles
        ├── Evidence index
        └── edge usability
        │
        ▼
Deterministic SecurityGraph
```

Sprint 001 proved:

> Pico can remember.

Sprint 002 proved:

> Pico can observe an autonomous actor.

Sprint 003 proved:

> Pico can resolve one actor capability.

Sprint 004 proved:

> Pico can observe one external influence surface.

Sprint 005 proved:

> Pico can observe credential reachability without retaining credential
> material.

Sprint 006 proved:

> Pico can resolve consequential provider authority without using it.

Sprint 007 must prove:

> **Pico can project the complete observed golden path into coherent,
> scan-scoped graph state.**

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

Sprints 002–006 persisted the individual facts needed to describe this path.

Sprint 007 implements `ARCHITECTURE.md` Slice 6 — Security graph:

```text
graph projection
directional edges
edge usability
cycle protection
bounded traversal primitives
```

Sprint 007 does not implement `ARCHITECTURE.md` Slice 7 — Analysis.

It must not emit:

```text
InfluencePath
AuthorityPath
BoundaryEvaluation
AttackPath
```

It also does not implement Slice 8 — Finding.

The graph is the deterministic input to those later slices. It is not their
output.

---

# 3. Sprint Principle

> **Project observed state. Do not analyze it.**

Sprint 007 answers:

```text
Which Resources belonged to this scan?

Which security-relevant Relationships belonged to this scan?

Which same-scan Evidence supports those facts?

What generic security roles do the Resources play?

Which edges are eligible for later traversal?

What direction was each Relationship stored with?

Can bounded graph operations terminate safely in the presence of cycles?

Can the same scan state produce the same ordered graph every time?
```

Sprint 007 does not answer:

```text
Can external influence reach OpenCode?

Can OpenCode reach consequential authority?

Does an approval or sandbox interrupt the path?

Is the complete path active or blocked?

How severe is the exposure?

Is there a Finding?
```

The distinction is foundational:

```text
CONNECTED GRAPH
is not
ATTACK PATH

TRAVERSABLE EDGE
is not
ACTIVE AUTONOMOUS PATH

DERIVED RELATIONSHIP
is not
BOUNDARY EVALUATION
```

---

# 4. Required Graph Claim

Sprint 007 should establish the smallest defensible graph claim:

> **For this scan, Pico projected the normalized Resources and
> security-relevant Relationships it observed, preserved their direction and
> evidential state, attached only same-scan evidence, and classified their
> eligibility for later deterministic analysis.**

That claim requires:

```text
one explicit scan identity

scan-scoped Resource membership

scan-scoped Relationship membership and state

same-scan Evidence selection

valid Relationship endpoints

generic security-role mapping

explicit security-relevant Relationship vocabulary

deterministic node and edge ordering

honest edge usability

bounded work and cycle protection
```

It does not establish that any graph route is an AttackPath.

---

# 5. Expected User Experience

Given a controlled fixture containing all supported Sprint 002–006 facts,
invoke the existing application-level integration seam:

```text
ScanService::run_with_home_and_environment_and_provider
```

The structured result should complete and support a CLI-equivalent graph
summary:

```text
Status: COMPLETE

Graph Nodes:             8
Graph Edges:             8
State-Eligible Edges:    8
Non-Eligible Edges:      0

Analysis:                NOT RUN
Findings:                0
```

The controlled fixture must declare an exact manifest of canonical node and
edge identities. Tests and manual verification must assert that manifest and
its exact counts rather than using a lower bound.

For an empty supported environment:

```text
Status: COMPLETE
Graph Nodes: 0
Graph Edges: 0
Analysis: NOT RUN
Findings: 0
```

An empty graph is valid.

For a partial scan:

```text
Status: PARTIAL
Graph Nodes: <safely observed subset>
Graph Edges: <valid same-scan subset>
Analysis: NOT RUN
Findings: 0
```

Partial discovery must not discard trustworthy graph state, and missing facts
must not be manufactured.

---

# 6. Scope

Sprint 007 includes only the minimum implementation required to create the
first trustworthy Security Graph projection.

## Required

Implement:

```text
provider-neutral SecurityGraph

GraphNode

GraphEdge

SecurityRole

EdgeUsability

scan-scoped graph projection

current-scan Resource and Relationship selection

same-scan Evidence indexing

explicit security Relationship vocabulary

direction-preserving adjacency indexes

deterministic ordering

bounded traversal support for later analyzers

cycle protection

graph integrity validation

ScanService integration

small CLI graph summary

sanitized graph fixtures and tests

the bounded Bash-scope prerequisite correction described in Section 8

the canonical Resource-kind prerequisite corrections described in Section 8
```

## Explicitly excluded

Do not implement:

```text
InfluencePath construction

AuthorityPath construction

BoundaryEvaluation

AttackPath construction or persistence

UNTRUSTED_TO_PRODUCTION

Finding generation or persistence

severity

confidence scoring

remediation cut points

finding explanation UX

pico findings

pico finding <id>

Pico MCP

new agent adapters

new MCP adapters

new provider adapters

runtime monitoring

active exploitation

write-based validation

enforcement

a graph database

a generic graph-query language

Cypher, GraphQL traversal, or user-defined path programs

dynamic graph plugins

Sprint 008 functionality
```

---

# 7. Baseline and Preflight

Expected baseline:

```text
ceaa420
```

Before implementation, report:

```text
branch
HEAD SHA
origin/main SHA
ahead/behind
working-tree state
repository structure
current Rust module boundaries
current ScanService pipeline
current Resource and Relationship contracts
current RelationshipState vocabulary
current Evidence and Observation contracts
current repository query APIs
current SQLite schema and migrations
current Sprint 002–006 relationship vocabulary
current test count
cargo check
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

Expected entering test baseline:

```text
109 passed / 0 failed
```

Verify the count rather than assuming it.

If the repository is dirty or HEAD materially differs from the expected
baseline:

```text
STOP
```

Report the difference before building on it.

The uncommitted Sprint 007 document itself is expected when implementation
begins after an authoring-only handoff. No other change is implied by that
exception.

---

# 8. Known Baseline Architecture Friction

Sprint 007 begins with six known pressure points.

## 8.1 Stable rows are not scan snapshots

`Resource` and `Relationship` rows are stable identities updated across scans.

Their current metadata and Relationship state may be overwritten by a later
scan.

Observations establish scan membership, but the baseline does not consistently
store every graph-relevant field as a scan-specific Observation snapshot.

Therefore this is unsafe:

```text
request graph for Scan A
        ↓
load every current Resource/Relationship row
        ↓
accidentally use state written by Scan B
```

Sprint 007 must not silently claim arbitrary historical replay from
insufficient snapshots.

Required response:

```text
project the scan being executed from its own Observations and Evidence

make every new Relationship Observation carry its scan-specific state

capture the safe graph-relevant metadata needed by projection

reject or explicitly mark unsupported any older snapshot that cannot be
reconstructed safely
```

Do not use the globally latest row as historical truth.

New graph-capable Observations must carry a versioned minimum snapshot.

Conceptually:

```text
Scan metadata {
  graph_snapshot_version: 1
}

Resource Observation metadata {
  graph_snapshot_version: 1
  subject_type: resource
  resource: {
    canonical_key
    kind
    provider
    name
    safe_metadata
  }
}

Relationship Observation metadata {
  graph_snapshot_version: 1
  subject_type: relationship
  relationship: {
    canonical_key
    from_resource_id
    to_resource_id
    kind
    state
    safe_metadata
  }
}
```

Re-projection must read graph state and metadata from the scan-specific
snapshot.

The stable row may validate object identity and referential integrity. Its
newer mutable state or metadata must not replace the snapshot.

If this minimum snapshot is absent, arbitrary historical replay is
unsupported and must fail explicitly.

The scan-level version distinguishes a legitimately empty Observation payload
from a scan created before this snapshot contract existed.

## 8.2 Repository graph reads do not exist

The repositories can fetch individual stable objects and global counts, but do
not yet expose the scan-scoped reads needed by a projector.

Sprint 007 may add focused read methods or a dedicated projection repository.

It must not place SQL inside graph algorithms or CLI handlers.

## 8.3 Security roles are not typed

The current `Resource` domain stores generic kind and metadata but has no typed
graph-role vocabulary.

Sprint 007 may introduce provider-neutral graph roles:

```text
SOURCE
ACTOR
CAPABILITY
AUTHORITY
SINK
BOUNDARY
```

Do not introduce provider-specific node types.

## 8.4 Bounded Bash scope currently overstates reachability

The baseline credential-reachability branch derives `REACHABLE` from:

```text
environment reachability PROVEN
+
Bash permission ALLOW
```

without also checking the effective Bash capability scope.

Sprint 005 requires:

```text
ALLOW + UNRESTRICTED + proven environment
→ DERIVED / REACHABLE

ASK + UNRESTRICTED + proven environment
→ DERIVED / APPROVAL_GATED

DENY
→ BLOCKED

BOUNDED or otherwise unresolved scope
→ UNKNOWN
```

This is a confirmed prerequisite defect because a graph must not classify an
overstated credential edge as usable.

Before accepting the golden-path graph fixture, add a regression test and make
the smallest correction to the existing reachability decision.

The graph projector must not contain provider or OpenCode-specific logic to
compensate for incorrect normalized input.

Do not broaden this repair into unrelated Sprint 005 refactoring.

## 8.5 Controlled-real-environment gate remains open

Sprint 006 completed its fixture-backed provider adapter verification without
performing a live controlled Cloudflare scan.

That does not block Sprint 007's deterministic fixture-backed graph work.

It does mean Sprint 007 must not claim that the roadmap's v0.1 controlled-real-
environment exit gate has passed.

The implementation report should preserve this as an explicit roadmap
follow-up rather than attempting live provider work inside the graph sprint.

## 8.6 Baseline Resource kinds diverge from Canon

Canon defines the relevant generic kinds as:

```text
external_source
provider_account
```

The baseline currently persists:

```text
external_content
account
```

The graph layer must not invent aliases that silently normalize this mismatch.

Before role projection, make the smallest normalization repair in the existing
application persistence path:

```text
GitHub external content class Resource
→ kind: external_source

Cloudflare account Resource
→ kind: provider_account
```

Preserve existing canonical Resource keys.

Add regression tests proving the canonical kinds. Do not broaden the repair
into a Resource migration framework or rewrite prior completion records.

---

# 9. Architecture Boundary

Maintain:

```text
CLI
 ↓
Application / ScanService
 ↓
Discovery Adapters
 ↓
Generic Domain Persistence
 ↓
Graph Projection Repository
 ↓
Provider-Neutral SecurityGraph
 ↓
Future Deterministic Analysis
```

Ownership rules:

```text
Adapters produce facts.

Persistence stores normalized observed state.

The projector selects one scan's facts and validates them.

The graph represents nodes, edges, roles, evidence, direction, and usability.

Future analyzers interpret influence, authority, and boundaries.

The CLI displays application results only.
```

Do not place:

```text
OpenCode configuration parsing in the graph layer

GitHub MCP classification in the graph layer

Cloudflare response parsing in the graph layer

SQLite queries in GraphNode or GraphEdge

graph construction in CLI handlers

AttackPath decisions in adapters
```

Suggested module boundary:

```text
src/
  graph/
    mod.rs
    model.rs
    projection.rs
    traversal.rs
```

or an equivalently small provider-neutral boundary.

Do not create empty layers or a framework merely to match this sketch.

---

# 10. SecurityGraph Contract

The smallest useful conceptual contract is:

```text
SecurityGraph {
  scan_id
  nodes
  edges
  outgoing_index
  incoming_index
  evidence_index
}
```

Required properties:

```text
belongs to exactly one scan

contains no adapter-specific graph types

contains only Resources observed in that scan

contains only Relationships observed in that scan

contains only Evidence captured for that scan

preserves stable Resource and Relationship identities

preserves stored direction

preserves Relationship state

retains non-traversable edges for explanation

has deterministic iteration order

does not own or persist raw credentials
```

The graph is an in-memory projection.

It is not a second source of truth.

---

# 11. Scan and Currentness Boundary

Every graph projection must name one `scan_id`.

Membership is established by scan-scoped Observations, not global table
presence.

Conceptually:

```text
Resource node membership
  = Resource Observation for Scan N

Relationship edge membership
  = Relationship Observation for Scan N

Evidence membership
  = Evidence.scan_id == Scan N
```

The projector must not:

```text
load every Resource ever observed

load every Relationship ever observed

attach Evidence from a later scan

attach Evidence merely because it references the same stable Relationship

reuse a stale credential or Worker absent from the current scan

silently reconstruct old state from a newer mutable row
```

Sprint 007 must support the graph created during the current scan after
normalized persistence and before final scan completion.

Scans produced after the Sprint 007 snapshot contract is introduced may be
projected again if all required snapshot fields exist.

For pre-Sprint-007 or incomplete historical data:

```text
fail closed with a typed projection error or explicit unsupported-snapshot
diagnostic
```

Do not fall back to the latest state.

---

# 12. GraphNode and SecurityRole

Every graph node corresponds to one generic `Resource`.

Conceptually:

```text
GraphNode {
  resource_id
  canonical_key
  kind
  provider
  name
  safe_metadata
  roles[]
}
```

Do not create:

```text
OpenCodeNode
GitHubMcpNode
CloudflareCredentialNode
CloudflareWorkerNode
```

Use the canonical security-role vocabulary:

```text
SOURCE
ACTOR
CAPABILITY
AUTHORITY
SINK
BOUNDARY
```

For the golden path, deterministic generic mappings are expected:

```text
external_source kind
→ SOURCE

agent kind
→ ACTOR

shell and MCP tool kinds
→ CAPABILITY

credential kind
→ AUTHORITY

resource marked as a consequential sink
→ SINK

approval gate or sandbox kind, when observed
→ BOUNDARY
```

One Resource may hold multiple roles.

`roles[]` may also be empty.

For example, the current GitHub MCP server and Cloudflare account may be useful
intermediate graph nodes without independently carrying a canonical security
role.

Role derivation must use normalized generic fields and explicit safe metadata.

It must not inspect:

```text
provider response JSON

OpenCode syntax

resource display-name substrings

secret values
```

A Cloudflare Worker with environment `UNKNOWN` may be a consequential `SINK`
without being labeled `PRODUCTION`.

Production classification remains later analysis input and must not be guessed
from a name.

---

# 13. GraphEdge

Every graph edge corresponds to one generic `Relationship` observed in the
selected scan.

Conceptually:

```text
GraphEdge {
  relationship_id
  canonical_key
  from_resource_id
  to_resource_id
  kind
  state
  usability
  safe_metadata
  evidence_ids[]
}
```

Required invariants:

```text
from and to endpoints exist in the same graph

from and to are distinct

canonical identity is stable

kind is security-relevant and supported

state is scan-specific

metadata remains generic input, not provider parsing

evidence belongs to the graph's scan
```

Edges with `UNKNOWN` or `BLOCKED` state remain present.

The graph must preserve uncertainty and enforced interruption as data.

---

# 14. Relationship Vocabulary

Project only the small, canonical, security-relevant vocabulary needed by
Pico.

The current golden path uses:

```text
configured_with
exposes
can_call
can_retrieve
can_execute
can_access
scoped_to
can_mutate
```

The graph design may recognize the additional canonical relationship kinds
already defined by Architecture when they appear in normalized state:

```text
can_read
can_write
uses_credential
authenticates_to
authorizes
can_deploy
protected_by
requires_approval
isolated_by
denied_by
```

Do not add provider-specific verbs such as:

```text
cloudflare_worker_edit
github_issue_influence
opencode_bash_permission
```

An unsupported relationship kind must not silently become traversable.

Return a typed validation error or explicit projection diagnostic.

Do not build a user-extensible vocabulary in this sprint.

---

# 15. Evidence Index

The graph must make provenance available without duplicating or rewriting
Evidence.

Conceptually:

```text
GraphEvidenceIndex {
  by_evidence_id
  by_relationship_id
  by_subject
}
```

Relationship Evidence must be selected through:

```text
relationship_evidence
+
evidence.scan_id == graph.scan_id
```

Resource Evidence must be indexed by exact Resource canonical key:

```text
Evidence.subject == GraphNode.canonical_key
```

Relationship Evidence remains authoritative only through:

```text
relationship_evidence link
+
Evidence.scan_id == graph.scan_id
```

Node-subject and Relationship-link indexes remain separate, so an identical
text value cannot blur their subject type.

Do not use fuzzy names, provider-specific parsing, or substring matching.

The evidence index must never attach:

```text
evidence from a different scan

an unlinked relationship evidence record

raw provider responses

credential material
```

Every projected Relationship must have at least one supporting Evidence record
from the selected scan.

If a Relationship lacks same-scan evidence, projection must fail closed with a
typed integrity result. It must not become usable merely because the stable
Relationship row currently says `CONFIRMED` or `DERIVED`.

Evidence objects remain immutable, independently addressable domain state.

The graph holds references/indexes needed for later explanation.

`safe_metadata` must be constructed from the already normalized
Resource/Relationship metadata and pass through the same centralized
safe-metadata validator before entering an Observation snapshot or graph.

The projector must never clone unchecked adapter output or raw JSON merely
because its type is `serde_json::Value`.

---

# 16. Edge Usability

Define a provider-neutral usability classification derived from
`RelationshipState`.

Required semantics:

```text
CONFIRMED
→ TRAVERSABLE

DERIVED
→ TRAVERSABLE

INFERRED
→ TRAVERSABLE_WITH_PENALTY

UNKNOWN
→ NON_TRAVERSABLE_UNKNOWN

BLOCKED
→ NON_TRAVERSABLE_BLOCKED
```

`TRAVERSABLE` means only:

> eligible for a later semantic analyzer to consider.

It does not mean:

```text
active AttackPath
automatic agent action
boundary-free route
high confidence
exploitation
```

Approval-related metadata on a `DERIVED` edge must remain available for Sprint
008 Boundary Evaluation.

Sprint 007 must not resolve approval semantics into an AttackPath conclusion.

---

# 17. Directionality

Preserve the stored direction of every Relationship.

Examples:

```text
OpenCode
  → can_call →
GitHub MCP Tool

GitHub MCP Tool
  → can_retrieve →
External GitHub Content

OpenCode
  → can_execute →
Bash

Bash
  → can_access →
Cloudflare Credential

Cloudflare Credential
  → can_mutate →
Cloudflare Worker
```

The influence story may be presented later as:

```text
External Content
  ↓
Tool
  ↓
Actor
```

That presentation does not authorize Sprint 007 to reverse or duplicate the
stored semantic Relationships.

The graph should provide both outgoing and incoming indexes so a later explicit
Influence analyzer can interpret relationship semantics deliberately.

Do not create synthetic reverse Relationships.

Do not assume an edge is bidirectional.

---

# 18. Determinism

Equivalent normalized scan state must produce an equivalent graph independent
of SQLite row order, insertion order, hash-map seed, or fixture construction
order.

Required deterministic behavior:

```text
nodes ordered by canonical Resource identity

edges ordered by canonical Relationship identity

roles ordered by canonical role vocabulary

evidence references ordered by stable Evidence identity

adjacency lists ordered by canonical Relationship identity

duplicate observations do not duplicate nodes or edges
```

Tests should compare a normalized graph representation rather than timestamps
or randomly generated database IDs where those are not security-significant.

Insertion-order equivalence fixtures must reuse identical preassigned object
and Evidence IDs. Separately generated timestamps or append-only Evidence IDs
are not required to be byte-identical.

Do not introduce a persisted graph identity unless implementation proves it is
necessary.

AttackPath and Finding fingerprints belong to later sprints.

---

# 19. Bounded Traversal Primitives

Architecture Slice 6 requires bounded traversal support so later deterministic
analyzers cannot accidentally perform unbounded work.

Sprint 007 may implement only the smallest provider-neutral traversal
primitives required to prove:

```text
direction is respected

only allowed relationship kinds are considered

non-traversable states are rejected

maximum depth is enforced

maximum visited-edge/work budget is enforced

cycles terminate
```

The traversal primitive must accept an explicit, code-owned policy.

Conceptually:

```text
TraversalPolicy {
  direction
  allowed_relationship_kinds
  inferred_edge_policy
}

TraversalLimits {
  maximum_depth: 8
  maximum_edge_examinations: 256
  maximum_frontier_nodes: 128
  maximum_reachable_nodes: 128
}

BoundedReachabilityResult {
  reachable_node_ids[]
  examined_edge_ids[]
  completion
}

TraversalCompletion {
  COMPLETE
  DEPTH_LIMITED
  WORK_LIMITED
  FRONTIER_LIMITED
  RESULT_LIMITED
}
```

These are V0 hard caps, not user-provided values.

An edge examination is counted whenever traversal inspects an adjacency edge,
before filtering its kind or usability. This prevents a dense set of unusable
edges from bypassing the work budget.

Depth counts crossed edges from the start node. The start node is depth zero.

The implementation must use named constants and test the exact boundary around
every limit.

Do not expose arbitrary traversal expressions through the CLI.

Do not encode Influence or Authority semantics in this generic primitive.

Do not emit `InfluencePath`, `AuthorityPath`, or `AttackPath`.

---

# 20. Cycle Protection and Work Budgets

Cycle protection is mandatory even though the v0.1 golden path is acyclic.

The traversal state should track at least:

```text
visited node and edge identities

current depth

total adjacency-edge examinations

frontier size

reachable-result size
```

Required outcomes:

```text
self-loop
→ rejected by the existing Relationship invariant

A → B → A
→ terminates

duplicate edge
→ does not create duplicate work

depth limit reached
→ DEPTH_LIMITED

work budget reached
→ WORK_LIMITED

frontier limit reached
→ FRONTIER_LIMITED

reachable-result limit reached
→ RESULT_LIMITED
```

Do not silently drop a limit event if doing so would make later analysis appear
complete.

Expose enough structured state for Sprint 008 to distinguish:

```text
no path exists
```

from:

```text
traversal was truncated by a safety limit
```

---

# 21. Graph Integrity Validation

Projection must validate before returning a graph.

At minimum reject or diagnose:

```text
unknown scan

Resource Observation referencing a missing Resource

Relationship Observation referencing a missing Relationship

Relationship endpoint absent from the selected scan

self-relationship

duplicate canonical identity with conflicting object identity

unsupported Relationship kind

invalid Relationship state

Evidence linked from another scan

Relationship with no supporting same-scan Evidence

missing required scan-state snapshot

secret-prohibited metadata field
```

Reuse Pico's existing safe-metadata validation boundary.

Do not create a separate graph-only substring heuristic. Safe normalized facts
such as:

```text
secret_stored: false
```

must remain valid, while prohibited values and fields remain rejected.

Fail closed with one required policy:

```text
discovery PARTIAL + internally valid observed subset
→ return the valid graph and preserve Scan status PARTIAL

any graph-integrity violation
→ return no graph
→ record a typed, secret-safe projection diagnostic
→ mark the Scan FAILED, never COMPLETE or PARTIAL
```

Re-projecting a pre-Sprint-007 scan with no declared snapshot version returns
`UNSUPPORTED_SNAPSHOT` and does not rewrite that already completed historical
Scan.

Do not create placeholder nodes that make an invalid edge appear connected.

One malformed graph edge invalidates the projection. It must never be dropped
in a way that makes the remaining graph appear complete.

---

# 22. Partial-Scan Semantics

A `PARTIAL` scan may still produce a valid Security Graph for the facts it
safely observed.

Example:

```text
OpenCode               observed
GitHub MCP             observed
Bash                   observed
Cloudflare credential  observed
Cloudflare API         failed
```

Expected graph:

```text
contains the valid same-scan influence and credential-reachability facts

contains no invented Cloudflare Worker authority

contains UNKNOWN edges only when the adapter actually persisted that state

does not inherit a Worker or can_mutate edge from an older scan
```

Discovery partiality and graph corruption are different conditions.

```text
PARTIAL discovery with valid normalized facts
→ graph may be returned

invalid graph integrity
→ no graph returned
→ typed projection diagnostic
→ Scan status FAILED
```

Do not silently convert graph-integrity failure into a complete scan.

---

# 23. Application Integration

Integrate graph projection after normalized persistence and before scan
completion.

Conceptually:

```text
Create Scan
    ↓
Discover
    ↓
Normalize and Persist Observed Domain
    ↓
Project SecurityGraph for this Scan
    ↓
Validate and summarize graph
    ↓
Complete or mark Scan PARTIAL
```

The application layer may expose:

```text
GraphService::project_scan(...)
```

or an equivalently narrow use case.

`ScanResult` should add only graph-level summary fields, for example:

```text
graph_node_count
graph_edge_count
state_eligible_edge_count
non_eligible_edge_count
graph_projection_status
```

Allowed projection statuses are:

```text
PROJECTED   valid non-empty graph
EMPTY       valid empty graph
FAILED      current-scan integrity failure; no graph returned
UNSUPPORTED historical scan lacks the versioned snapshot contract
```

A valid graph projected from a discovery-`PARTIAL` scan is still `PROJECTED`
or `EMPTY`. Scan status communicates discovery partiality.

Keep:

```text
finding_count = 0

analysis_status = NOT_RUN, if a status field is exposed
```

Do not let the CLI call persistence repositories or build the graph itself.

If projection returns a graph-integrity error, `ScanService` must persist the
Scan transition to `FAILED` with a typed, secret-safe diagnostic before
returning the application error. It must not leave the Scan `RUNNING`.

---

# 24. Persistence Decision

The Security Graph is a projection over SQLite observed state.

Do not add:

```text
graph_nodes table

graph_edges table

Neo4j

embedded graph database

serialized graph blob
```

Focused persistence changes are allowed only when required to make scan state
truthful, such as:

```text
consistent relationship Observation state snapshots

safe graph-relevant Resource Observation snapshots

scan-scoped repository query methods

same-scan evidence retrieval
```

Prefer extending the existing observation/evidence contract over duplicating
the observed domain.

Do not add AttackPath or Finding tables in this sprint.

---

# 25. CLI Result

Add only a concise graph projection summary to `pico scan`.

Conceptually:

```text
Security Graph: PROJECTED | EMPTY
Graph Nodes: <count>
Graph Edges: <count>
State-Eligible Edges: <count>
Non-Eligible Edges: <count>
Analysis: NOT RUN
Findings: 0
```

`State-Eligible` means eligible under `RelationshipState` only. It does not
mean autonomously reachable, boundary-free, or confirmed by analysis.

Current-scan projection failure returns an application error after persisting
the `FAILED` Scan; it is not rendered as a successful scan summary.

Do not display:

```text
active path
blocked attack path
severity
confidence
remediation
production exposure
```

Do not dump node metadata, Evidence, provider responses, credential
fingerprints, or source-locator secrets merely to prove the graph exists.

Machine-readable graph output is not required.

---

# 26. Fixtures

Add small sanitized graph fixtures independent of real provider credentials.

At minimum include:

```text
empty graph

complete golden-path graph

UNKNOWN edge

BLOCKED edge

INFERRED edge

approval-gated DERIVED edge with preserved metadata

cycle A → B → A

depth-limit chain

dangling endpoint

duplicate observations

partial scan

repeated scans with state change

credential rotation

secret sentinel
```

The complete fixture should use the existing sanitized OpenCode, GitHub MCP,
and fake Cloudflare provider seams.

It must include a checked-in manifest containing the exact canonical Resource
and Relationship key sets plus expected role and usability values.

The primary manifest should use the existing synthetic account/Worker fixture
and exactly these eight Resource keys:

```text
agent:opencode

shell:bash

mcp:github:official

mcp:github:official:tool:issue_read

source:github:public:issue-content

credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f

cloudflare:account:account-1234567890123456

cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456
```

The credential fingerprint above is derived only from the synthetic string
`synthetic-token`; it is not real credential material.

The primary manifest should contain exactly these eight Relationship keys:

```text
agent:opencode|can_execute|shell:bash

agent:opencode|configured_with|mcp:github:official

mcp:github:official|exposes|mcp:github:official:tool:issue_read

agent:opencode|can_call|mcp:github:official:tool:issue_read

mcp:github:official:tool:issue_read|can_retrieve|source:github:public:issue-content

shell:bash|can_access|credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f

credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f|scoped_to|cloudflare:account:account-1234567890123456

credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f|can_mutate|cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456
```

For this exact positive fixture:

```text
Graph Nodes: 8
Graph Edges: 8
State-Eligible Edges: 8
Non-Eligible Edges: 0
Analysis: NOT RUN
Findings: 0
```

Negative-state and partial fixtures have their own explicit manifests. Do not
relax the primary manifest when adding them.

No real API credential is required.

Use a sentinel such as:

```text
TEST_SECRET_SHOULD_NOT_PERSIST
```

The sentinel must not appear in:

```text
SQLite
graph nodes
graph edges
evidence index
Debug output
CLI output
diagnostics
```

---

# 27. Required Tests

## Projection

Test:

```text
empty scan projects an empty graph

complete fixture projects all expected current-scan nodes

complete fixture projects all expected current-scan relationships

complete fixture exactly matches its canonical manifest and counts

every edge endpoint exists

duplicate observations do not duplicate graph objects

global repository counts do not determine graph counts
```

## Security roles

Test:

```text
external content → SOURCE

OpenCode → ACTOR

Bash → CAPABILITY

GitHub MCP tool → CAPABILITY

Cloudflare credential → AUTHORITY

consequential Worker → SINK

approval/sandbox Resource → BOUNDARY when present

provider names do not create roles by substring
```

## Direction

Test:

```text
stored from/to direction is preserved

outgoing index contains only outgoing edges

incoming index contains only incoming edges

no synthetic reverse Relationship is created

directional traversal does not cross an edge backward
```

## Edge usability

Test every state:

```text
CONFIRMED → TRAVERSABLE

DERIVED → TRAVERSABLE

INFERRED → TRAVERSABLE_WITH_PENALTY

UNKNOWN → NON_TRAVERSABLE_UNKNOWN

BLOCKED → NON_TRAVERSABLE_BLOCKED
```

Also verify:

```text
UNKNOWN and BLOCKED remain visible in the graph

approval metadata remains preserved on DERIVED edges

usability does not emit an AttackPath conclusion
```

## Scan isolation and evidence

Test:

```text
Scan B does not inherit a Resource seen only in Scan A

Scan B does not inherit a Relationship seen only in Scan A

Scan A evidence does not attach to Scan B

Scan B evidence does not attach to Scan A

later state updates do not silently rewrite a supported earlier snapshot

unsupported legacy snapshot fails explicitly

credential rotation excludes the stale credential from the newer graph

Relationship evidence is indexed only through exact linkage and scan id
```

## Determinism

Test:

```text
different insertion order produces equivalent ordered graph state

insertion-order fixtures reuse identical preassigned IDs

cross-scan semantic equivalence ignores generated timestamps and Evidence IDs
while comparing normalized Evidence content and exact subjects

repeated projection of the same scan is equivalent

node ordering is stable

edge ordering is stable

adjacency ordering is stable

evidence reference ordering is stable
```

## Bounded traversal

Test:

```text
A → B → A terminates

maximum depth is enforced

maximum work budget is enforced

maximum frontier size is enforced

maximum reachable-result size is enforced

non-traversable edges are not crossed

disallowed Relationship kinds are not crossed

limit exhaustion is distinguishable from no route
```

## Baseline correctness repair

Test:

```text
Bash ALLOW + UNRESTRICTED + proven environment
→ credential edge DERIVED / REACHABLE

Bash ASK + UNRESTRICTED + proven environment
→ credential edge DERIVED / APPROVAL_GATED

Bash DENY
→ credential edge BLOCKED

Bash ALLOW + BOUNDED
→ credential edge UNKNOWN / UNKNOWN

Bash ALLOW + unresolved or absent capability scope
→ credential edge UNKNOWN / UNKNOWN

GitHub content Resource
→ kind external_source

Cloudflare account Resource
→ kind provider_account

graph role projection contains no compatibility alias for legacy kind names
```

## Integrity and safety

Test:

```text
dangling endpoint fails closed

missing snapshot state fails closed

unsupported Relationship kind does not become traversable

partial scan retains valid same-scan subgraph

secret sentinel has zero occurrences everywhere

graph tests require no network

provider mutation requests remain zero

AttackPaths remain zero

Findings remain zero
```

---

# 28. Controlled Manual Verification

Use a temporary initialized workspace and sanitized fixtures.

Do not require a production Cloudflare credential.

Verify the empty case:

```text
pico init
pico scan

Status: COMPLETE
Graph Nodes: 0
Graph Edges: 0
Analysis: NOT RUN
Findings: 0
```

Verify the complete controlled fixture through the existing application-level
integration seam:

```text
ScanService::run_with_home_and_environment_and_provider

OpenCode actor observed
GitHub MCP influence facts observed
Bash capability observed
Cloudflare credential reachability observed
fake Cloudflare account/Worker authority observed

Security Graph: PROJECTED
Graph Nodes: 8
Graph Edges: 8
State-Eligible Edges: 8
Non-Eligible Edges: 0
Analysis: NOT RUN
Findings: 0
```

Do not add a hidden CLI flag, environment variable, or fixture-injection path
to pass a fake provider result into `pico scan`.

Inspect the graph through a test-only or application-level structured result.

Verify:

```text
generic roles are correct
directions are preserved
same-scan Evidence is attached
UNKNOWN/BLOCKED are visible but non-traversable
ordered projection is stable
```

Run a second scan after removing or rotating the credential.

Verify:

```text
the new graph excludes the stale credential and its edges
stable Resources remain valid historical domain records
the current graph does not inherit stale state
```

Perform the secret-sentinel search across SQLite and captured output.

Expected:

```text
0 occurrences
```

---

# 29. Expected Security State

Sprint 007 ends with:

```text
SecurityGraph: present

GraphNodes: present when supported Resources were observed

GraphEdges: present when supported Relationships were observed

EvidenceIndex: present

InfluencePaths: 0 / not implemented

AuthorityPaths: 0 / not implemented

BoundaryEvaluations: 0 / not implemented

AttackPaths: 0

Findings: 0
```

The complete golden-path topology exists as graph state.

Pico still does not claim whether that topology forms an active or blocked
AttackPath.

---

# 30. Scope Guardrails

Sprint 007 must end at:

```text
Observed Domain
      ↓
Scan-Scoped SecurityGraph
```

It must not continue to:

```text
Influence Analysis

Authority Analysis

Boundary Evaluation

AttackPath

Finding

Severity

Confidence

Remediation

Explanation UX

Pico MCP
```

Do not add:

```text
provider-specific graph nodes

provider-specific traversal rules

generic query language

graph database

new integrations

unrelated persistence redesign

runtime state

enforcement
```

Architect for extension.

Implement only the graph slice.

---

# 31. Architecture Pressure Test

Before completion, explicitly answer:

1. Is the Security Graph a projection rather than a second source of truth?
2. Does every graph belong to exactly one scan?
3. Can a newer scan avoid leaking Resources, Relationships, state, metadata,
   and Evidence into an older or current projection?
4. Are graph nodes provider-neutral Resources with generic roles?
5. Are graph edges provider-neutral Relationships with preserved direction?
6. Are `UNKNOWN` and `BLOCKED` retained but non-traversable?
7. Is `INFERRED` distinguishable from stronger traversable evidence?
8. Can later analyzers inspect approval and boundary metadata without Sprint
   007 deciding the result?
9. Are traversal work and cycles bounded deterministically?
10. Does the graph require no graph database or query language?
11. Does the graph contain no provider parsing or secret material?
12. Did the bounded Bash prerequisite correction remain outside graph logic?
13. Are AttackPaths and Findings still absent?

If any answer is `NO`, do not hide it.

Fix only friction clearly within Sprint 007 scope.

Otherwise stop and report it for review.

---

# 32. Definition of Done

Sprint 007 is complete only when:

```text
the expected baseline is verified

the bounded Bash-scope regression is corrected and tested

one scan-scoped SecurityGraph projection exists

the graph is provider-neutral

scan membership comes from Observations

same-scan Evidence selection is enforced

historical state does not silently bleed into projection

generic SecurityRoles are deterministic

Relationship direction is preserved

all five RelationshipState values have explicit usability

UNKNOWN and BLOCKED are visible but non-traversable

deterministic ordering is verified

cycle protection is verified

depth and work budgets are verified

empty and partial graphs are valid

the complete golden-path fixture projects correctly

secret-sentinel checks pass

no network is required by graph tests

no provider mutation is performed

AttackPaths remain 0

Findings remain 0

all required verification passes

the final diff contains no Sprint 008 functionality
```

The sprint's product statement is:

> **Pico can assemble the security-relevant facts from one scan into a
> trustworthy graph ready for analysis.**

---

# 33. Full Verification

After implementation run:

```bash
cargo test

cargo check

cargo clippy --all-targets -- -D warnings

cargo fmt --check

cargo build --release
```

Then run the controlled fixture verification from Section 28.

Record:

```text
tests passed / failed

empty graph result

complete golden-path graph result

role mapping result

direction result

all five edge-usability states

scan isolation result

historical snapshot behavior

same-scan Evidence result

determinism result

cycle result

depth/work-budget result

partial-graph result

bounded Bash correction result

secret sentinel result

network requests required by graph tests

provider mutation requests

AttackPath count

Finding count
```

---

# 34. Final Diff Inspection

Review the entire Sprint 007 diff.

Check for:

```text
accidental files
build artifacts
.pico state
real credentials
secret-like fixture values outside intentional sentinels
machine-specific paths
raw provider responses
Authorization headers
debug dumps
unnecessary dependencies
graph database dependencies
provider-specific graph types
generic query-language abstractions
unbounded traversal
historical state leakage
unrelated refactoring
Sprint 008+ functionality
```

Do not modify Sprint 001–006 completion records.

Do not rewrite Canon unless implementation uncovers a genuine contradiction
requiring founder review.

---

# 35. Stop Conditions

Stop and report before or during implementation if:

```text
the baseline is unexpected or dirty

the complete golden-path facts are not present in normalized state

scan membership cannot be established without treating global rows as current

the graph would silently leak newer state into an older scan

same-scan Evidence cannot be selected deterministically

correct projection would require provider-specific graph parsing

the bounded Bash reachability defect cannot be fixed within its prior contract

cycle/work limits cannot be made explicit

tests would require a real credential or provider mutation

implementation requires a graph database

implementation requires a generic graph-query language

Canon would need silent revision
```

Do not hide architectural friction inside metadata or adapter-specific code.

---

# 36. Deliverables

Required deliverables:

```text
bounded Bash-scope prerequisite regression fix

provider-neutral graph module

SecurityGraph

GraphNode

GraphEdge

SecurityRole

EdgeUsability

scan-scoped projection repository/API

same-scan Evidence index

consistent graph-relevant Observation snapshots

directional incoming/outgoing indexes

deterministic ordering

bounded traversal primitives

cycle/work protection

graph integrity validation

ScanService integration

CLI graph summary

sanitized fixtures

unit, domain, persistence, and integration tests

secret-sentinel validation

completion evidence in this document
```

## Recorded completion

- Completion date: 2026-08-25
- Verified baseline: `ceaa420dea0e8f0bdf710374cb37322d66595ed5`
- Implementation commit: recorded in the final repository handoff after commit
- Branch: `main`
- Baseline origin/main: `6d379a7de5f4a84c20f7c518f58d943625d4ed75`
- Verification: 46 unit tests, 30 domain tests, 28 integration tests, and 14 persistence tests passed; doc-tests passed.
- `cargo check`: PASS
- `cargo clippy --all-targets -- -D warnings`: PASS
- `cargo fmt --check`: PASS
- `cargo build --release`: PASS
- Bounded Bash scope: PASS; unrestricted allow is reachable, bounded/unknown remains unknown, ask is approval-gated, deny is blocked.
- Empty graph: PASS; scans with no observed resources project `EMPTY` with zero nodes and edges.
- Complete golden path: PASS; 8 nodes, 8 edges, 8 state-eligible edges, 0 non-eligible edges.
- SecurityRole mapping: PASS; source, actor, capability, authority, sink, and boundary roles remain provider-neutral.
- Edge usability: PASS; confirmed/derived traversable, inferred penalty-traversable, unknown/blocked non-traversable.
- Direction: PASS; outgoing and incoming indexes preserve relationship direction.
- Scan isolation: PASS; repeated scans retain stable Resources while projecting only current-scan Observations and Evidence.
- Secret safety: PASS; synthetic secret sentinel is absent from persisted state and graph output.

---

# 37. Completion Evidence

When implementation and verification pass, set:

```text
Status: COMPLETE
```

Record:

```text
completion date
verified baseline SHA
implementation commit SHA and message
branch
HEAD
origin/main
ahead/behind
working-tree state
test totals
cargo check
clippy
fmt
release build
bounded Bash-scope correction result
empty graph result
complete golden-path graph counts
SecurityRole mapping result
edge-usability result
direction result
scan isolation result
historical snapshot behavior
same-scan Evidence result
determinism result
cycle/depth/work-budget result
partial-graph result
secret-sentinel result
network requests required
provider mutation requests
AttackPath count
Finding count
architecture pressure-test answers
```

Leave this section incomplete until the implementation exists and every
required check passes.

---

# 38. Commit

If and only if Sprint 007 is fully implemented and verified:

```text
stage only Sprint 007 changes

inspect the staged diff

commit with:

feat(graph): project the golden-path security graph
```

Do not amend previous commits.

Do not push unless explicitly instructed by repository policy or the user.

Do not begin Sprint 008.

The authoring-only document may be committed separately with:

```text
docs(sprints): define Sprint 007 security graph
```

---

# 39. Final Report Contract

Report:

```text
Sprint
SPRINT-007 — First Security Graph — Golden-Path Projection

Status
COMPLETE or BLOCKED

Baseline
<verified SHA>

Implementation commit
<SHA + message>

Graph contract
<scan scope, nodes, roles, edges, evidence, usability>

Implementation
<projection boundary, repositories, graph model, traversal safety, integration>

Verification
<tests and all required checks>

Graph result
Nodes: <count>
Edges: <count>
Traversable: <count>
Non-traversable: <count>

Currentness
Cross-scan leakage: NO
Same-scan Evidence only: YES
Unsupported historical snapshot behavior: <result>

Safety
Network required by graph tests: NO
Provider mutation requests: 0
Raw credentials persisted: NO
Secret sentinel persisted or emitted: NO

Expected security state
InfluencePaths: 0 / not implemented
AuthorityPaths: 0 / not implemented
BoundaryEvaluations: 0 / not implemented
Analysis: NOT RUN
Findings: 0

Architecture pressure test
<PASS / FAIL for every question>

Repository
Branch: <branch>
HEAD: <SHA>
origin/main: <SHA>
Ahead/behind: <state>
Working tree: <state>

Follow-ups
<only genuine observations for Sprint 008>
```

Do not report the graph as an active or blocked AttackPath.

---

# 40. Sprint Exit

Sprint 007 ends when Pico can reliably say:

> **I assembled the security-relevant facts from this scan into a
> deterministic, evidence-backed graph.**

It does not yet answer:

> **Does this graph contain an active or blocked AttackPath?**

That question belongs to the next explicitly authorized analysis sprint.

Do not begin Sprint 008.

Wait for explicit authorization.
