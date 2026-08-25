# Pico — Sprint 008: First Attack Path — Deterministic Golden-Path Analysis

**Status:** COMPLETE
**Sprint:** 008
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `27d1603`
**Depends on:** Sprint 007 — First Security Graph — Golden-Path Projection
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Teach Pico to interpret its first complete Security Graph without overstating
what graph connectivity proves.

Sprint 007 established:

> **Pico can assemble one scan's security-relevant facts into a deterministic,
> evidence-backed graph.**

Sprint 008 must establish:

> **Pico can deterministically decide whether the observed golden path is
> active, blocked, absent, or unresolved, and can show the exact graph facts
> supporting that decision.**

The analysis pipeline is:

```text
SecurityGraph for one Scan
        ↓
Influence Analysis
        ↓
InfluencePath[]

SecurityGraph for one Scan
        ↓
Authority Analysis
        ↓
AuthorityPath[]

InfluencePath + AuthorityPath
        ↓ join at autonomous Actor
Candidate Path
        ↓
Boundary Evaluation
        ↓
ACTIVE | BLOCKED | UNRESOLVED
        ↓
AttackPath persistence for ACTIVE/BLOCKED conclusions
```

This sprint answers:

> **Does this graph contain an active or blocked AttackPath?**

It does not yet answer:

> **What Finding, severity, remediation, or product explanation should Pico
> present to the user?**

---

# 2. Roadmap Position

Sprint 008 implements Architecture Slice 7:

```text
InfluencePath
AuthorityPath
BoundaryEvaluation
AttackPath
```

Architecture Slice 6 is complete:

```text
graph projection
directional edges
edge usability
cycle protection
bounded traversal
```

Architecture Slice 8 remains future work:

```text
UNTRUSTED_TO_PRODUCTION Finding
severity
confidence
evidence aggregation for product output
remediation cut points
```

Sprint 008 is therefore an analysis sprint, not a Finding sprint.

Completing Sprint 008 does not complete v0.1. The roadmap's controlled-real-
environment, Finding, explanation, and product-usefulness gates remain open.

The expected roadmap decision after this sprint is therefore:

```text
EXTEND v0.1
```

Do not advance to v0.2 solely because Architecture Slice 7 is complete.

---

# 3. Required Product Claim

At sprint completion Pico must be able to say one of the following without
ambiguity:

```text
ACTIVE
External influence reaches the observed actor, the actor reaches consequential
authority, and no proven enforced boundary interrupts this exact route.
```

`ACTIVE` means a **potentially active, unblocked path established from the
current scan's configuration and provider evidence**. It does not mean Pico
observed runtime traversal, verified execution, or exploitation. User-facing
CLI text must use `Potentially Active AttackPaths` to preserve this distinction.

```text
BLOCKED
A candidate influence-to-authority route exists, but a proven enforced
boundary interrupts this exact route.
```

```text
UNRESOLVED
The graph contains a potentially relevant route, but missing, unknown,
inferred, stale, limited, or insufficient boundary evidence prevents Pico from
claiming either ACTIVE or BLOCKED.
```

```text
NONE
No candidate source-to-actor-to-consequential-authority route exists in the
current scan graph.
```

These outcomes are analysis results. They do not claim exploitation, runtime
execution, malicious content, or verified impact.

---

# 4. Golden-Path Contract

The required v0.1 graph shape remains:

```text
External GitHub Content
        ↓ influence presentation
GitHub MCP Tool
        ↓
OpenCode
        ↓ authority
Bash
        ↓
Cloudflare Credential
        ↓
Cloudflare Worker
```

The normalized Relationship directions remain semantically authored:

```text
OpenCode → can_call → GitHub MCP Tool
GitHub MCP Tool → can_retrieve → External GitHub Content
OpenCode → can_execute → Bash
Bash → can_access → Cloudflare Credential
Cloudflare Credential → can_mutate → Cloudflare Worker
```

Influence presentation walks the first two relationships in reverse semantic
direction from Source to Actor. Authority traversal walks forward from Actor
to Sink.

Sprint 008 must preserve both facts. It must never rewrite stored Relationship
direction merely to make the displayed path read left-to-right.

---

# 5. Scope

Sprint 008 includes only the smallest provider-neutral deterministic analysis
layer required for the golden path.

## 5.1 Analysis domain

Introduce explicit analysis objects for:

```text
InfluencePath
AuthorityPath
BoundaryEvaluation
AttackPath
AnalysisResult / AnalysisSummary
```

These objects contain generic Pico semantics only. They may reference Scan,
Resource, Relationship, and Evidence IDs; SecurityRole; RelationshipState;
EdgeUsability; and allowlisted provider-neutral metadata vocabulary.

They must not contain OpenCode, GitHub, or Cloudflare adapter types.

## 5.2 Influence analysis

Determine whether a supported Source can reach an Actor through the exact
golden-path influence relationships.

The initial allowed influence kinds are:

```text
can_call
can_retrieve
```

`configured_with` and `exposes` may support explanation and provenance, but
they must not independently establish source-to-actor influence.

Preserve:

```text
source Resource identity
actor Resource identity
ordered edge references
per-edge traversal direction
source trust
influence strength
exact supporting Evidence references
```

The initial source-trust vocabulary is:

```text
TRUSTED_INTERNAL
AUTHENTICATED_INTERNAL
AUTHENTICATED_EXTERNAL
PUBLIC_EXTERNAL
OPEN_WORLD
UNKNOWN
```

The initial influence-strength vocabulary is:

```text
METADATA_ONLY
MANUAL_RETRIEVAL
AGENT_RETRIEVABLE
AUTOMATICALLY_INJECTED
INSTRUCTION_BEARING
UNKNOWN
```

Sprint 008 must not infer `AUTOMATICALLY_INJECTED` from tool availability.

The current GitHub MCP golden path is expected to remain:

```text
trust: PUBLIC_EXTERNAL
influence_strength: AGENT_RETRIEVABLE
```

## 5.3 Authority analysis

Determine whether an Actor can reach a consequential Sink through the exact
golden-path authority relationships.

The initial allowed authority kinds are:

```text
can_execute
can_access
can_mutate
```

Account-scope relationships such as `scoped_to` may constrain or support an
authority decision. They do not replace the direct credential-to-resource
authority edge.

Preserve:

```text
actor Resource identity
sink Resource identity
ordered edge references
capability
authority resolution
sink impact when established
exact supporting Evidence references
```

The authority-resolution vocabulary remains:

```text
EXACT
SCOPED
BEHAVIORAL_READ_ONLY
UNKNOWN
```

The initial sink-impact vocabulary is:

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
UNKNOWN
```

`consequential_sink: true` establishes Sink eligibility. It does not establish
`PRODUCTION`. Pico must never derive production classification from names such
as `prod`, `production`, or `live`.

The current Cloudflare Worker graph may therefore produce:

```text
consequential sink: YES
sink impact: UNKNOWN
```

without weakening an exact mutation-authority conclusion or prematurely
creating `UNTRUSTED_TO_PRODUCTION`.

## 5.4 Candidate joining

Join InfluencePath and AuthorityPath only when they share the same Actor
Resource ID in the same SecurityGraph and Scan.

Do not join by display name, provider, kind alone, substring, fuzzy matching,
or cross-scan identity without a current observation.

## 5.5 Boundary evaluation

Evaluate each candidate path independently.

Initial boundary kinds are:

```text
HARD_DENY
SANDBOX
MANDATORY_APPROVAL
CREDENTIAL_SCOPE
RESOURCE_SCOPE
NETWORK_ISOLATION
PROCESS_ISOLATION
SOFT_POLICY
```

A BoundaryEvaluation contains:

```text
boundary kind
affected Resource and/or Relationship IDs
enforcement state
interrupted phase
decision: INTERRUPTS | DOES_NOT_INTERRUPT | UNRESOLVED
supporting Evidence IDs
```

Possible interrupted phases are:

```text
INFLUENCE
CAPABILITY
CREDENTIAL_ACCESS
AUTHORITY
RESOURCE_REACHABILITY
```

A boundary blocks a path, not an Actor or Resource globally.

## 5.6 AttackPath construction

Construct an ACTIVE AttackPath only when:

1. a supported InfluencePath reaches the Actor;
2. a supported AuthorityPath leaves the same Actor;
3. every security-critical edge is eligible under analysis policy;
4. every security-critical edge has same-scan Evidence;
5. the Sink is consequential;
6. no proven enforced boundary interrupts that route;
7. traversal and analysis complete within all bounds.

Construct a BLOCKED AttackPath only when the candidate is structurally
established, non-boundary segments are supported, a proven boundary interrupts
the exact route, and no unresolved segment is hidden by the blocked result.

Do not persist AttackPaths for UNRESOLVED or NONE. Retain typed diagnostics or
summary counts explaining those outcomes.

---

# 6. Explicit Non-Goals

Sprint 008 must not implement:

```text
Finding generation
UNTRUSTED_TO_PRODUCTION
severity scoring
product confidence scoring
Finding fingerprints or grouping
remediation cut points
explanation UX or finding detail commands
Pico MCP
new adapters, credential sources, or provider-specific analysis rules
LLM reasoning
runtime observation
active exploitation or write validation
network requests from analysis
provider mutation
automatic remediation or enforcement
security history or diffing
multi-agent analysis
generic graph query language or graph database
plugin framework
Sprint 009 functionality
```

Exact Evidence references may be exposed for auditability. Finding-level
evidence aggregation and narrative remain Architecture Slice 8.

---

# 7. Canonical Invariants

1. Observed domain and analyzed domain remain separate.
2. Analysis consumes a validated SecurityGraph, not raw adapter output.
3. Analysis is deterministic code, not LLM judgment.
4. Influence and authority are analyzed separately.
5. They join through exact Actor identity.
6. Stored Relationship direction remains authoritative.
7. `UNKNOWN` edges do not complete active or blocked conclusions.
8. `BLOCKED` may support a blocked candidate only when enforcement is proven.
9. `INFERRED` produces UNRESOLVED in Sprint 008 and remains explicit for later
   confidence work.
10. Soft policy never blocks autonomous reachability.
11. A boundary blocks only the route it interrupts.
12. Alternate routes remain independently visible.
13. Every conclusion is scan-scoped and evidence-backed.
14. AttackPaths are deterministic results persisted with the Scan.
15. Equivalent graph state and analysis version produce equivalent conclusions.
16. Analysis never accesses raw secrets or provider transports.

---

# 8. Baseline Contract

The expected Sprint 008 baseline is:

```text
27d16032f19d4fb62a41026d6e3f5de2c91fb095
```

Expected repository state at authoring time:

```text
Branch: main
HEAD: 27d16032f19d4fb62a41026d6e3f5de2c91fb095
origin/main: 6d379a7de5f4a84c20f7c518f58d943625d4ed75
Ahead/behind: ahead 16, behind 0
Working tree: clean before this document is authored
```

Expected verification baseline:

```text
Tests: 118 passed, 0 failed
cargo check: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo fmt --check: PASS
cargo build --release: PASS
```

Before implementation verify branch, SHAs, ahead/behind, worktree, test total,
check, clippy, fmt, and release build. If HEAD materially differs or the
worktree contains unexpected changes, STOP and report the difference.

The expected uncommitted authoring artifact may be this document alone.

---

# 9. Baseline Architecture to Inspect

Before implementation inspect and report:

```text
src/graph/model.rs
src/graph/projection.rs
src/graph/traversal.rs
src/application/scan.rs
src/domain/relationship.rs
src/domain/evidence.rs
src/domain/observation.rs
src/persistence/db.rs
src/persistence/repos.rs
tests/domain/graph_model_test.rs
tests/integration/sprint007_graph_test.rs
```

Confirm scan scope, deterministic ordering, direction, same-scan Evidence,
edge usability, traversal bounds, the 8-node/8-edge fixture, `Analysis: NOT
RUN`, and zero Findings.

---

# 10. Known Architectural Friction

## 10.1 Influence direction differs from presentation

The graph stores Actor-to-Tool and Tool-to-Source. Product presentation reads
Source-to-Tool-to-Actor. Represent traversal direction per edge; do not rewrite
Relationships.

## 10.2 Approval evidence is not automatically a proven hard boundary

The static OpenCode contract preserves `ASK`, `APPROVAL_GATED`, and often
`runtime_mode: UNKNOWN`. Mandatory approval blocks only when technical
enforcement, inability to self-approve, lack of bypass, and runtime behavior are
all established. Static `ASK` alone is UNRESOLVED.

## 10.3 Consequential does not mean production

The current Worker may be a consequential mutation Sink with environment
`UNKNOWN`. Sprint 008 may establish an AttackPath to it, but must not call it
production. This remains a Slice 8 pressure point.

## 10.4 Slice ordering and confidence

Canon's conceptual AttackPath anticipates severity/confidence, while the
implementation plan assigns those to Slice 8. Sprint 008 follows the explicit
slice boundary: exact analysis outcome now; severity and product confidence
later.

## 10.5 Historical graphs are not reanalyzed

Analyze the current scan graph. Do not add historical reanalysis or migration.
Unsupported historical snapshots fail closed if explicitly analyzed.

---

# 11. Analysis Module Boundary

Introduce a provider-neutral boundary such as:

```text
src/analysis/
  mod.rs
  model.rs
  influence.rs
  authority.rs
  boundary.rs
  attack_path.rs
```

An equivalently small organization is acceptable.

The dependency direction remains:

```text
CLI
 ↓
Application
 ↓
Graph Projection
 ↓
Deterministic Analysis
 ↓
Analyzed Domain / Persistence
```

Forbidden dependencies:

```text
Analysis → OpenCode adapter
Analysis → GitHub adapter
Analysis → Cloudflare adapter
Analysis → provider HTTP client
Analysis → CLI formatting
Analysis → raw environment variables
Analysis → raw SQLite queries
Analysis → LLM
```

Provider-specific strings may appear only as already-normalized values consumed
through explicit generic vocabularies.

---

# 12. Analysis Version

Introduce one explicit analysis version:

```text
ANALYSIS_VERSION = 1
```

The version must be recorded with persisted AttackPaths, included in
deterministic path fingerprints, reported in analysis output, and tested.

Do not create a general rule-pack or analysis-migration framework.

Unknown analysis versions fail closed.

---

# 13. Analysis Outcome Model

Use a small explicit vocabulary:

```text
AnalysisStatus:
  COMPLETE
  LIMITED
  FAILED

CandidateDisposition:
  ACTIVE
  BLOCKED
  UNRESOLVED
  NONE
```

Semantics:

```text
COMPLETE + ACTIVE
→ at least one active AttackPath was established

COMPLETE + BLOCKED
→ at least one blocked AttackPath was established and no unresolved segment
  was treated as safety

COMPLETE + UNRESOLVED
→ a relevant candidate exists, but evidence cannot justify ACTIVE or BLOCKED

COMPLETE + NONE
→ no relevant candidate exists in the current graph

LIMITED
→ one or more analysis bounds prevented a complete answer

FAILED
→ graph/analysis integrity failed
```

`LIMITED` must never be rendered as `NONE`, `BLOCKED`, or safe.

Candidate disposition is per candidate. The aggregate summary is independent:

```text
if any candidate is ACTIVE
→ overall: ACTIVE_PRESENT

else if any candidate is UNRESOLVED
→ overall: UNRESOLVED_PRESENT

else if any candidate is BLOCKED
→ overall: BLOCKED_ONLY

else
→ overall: NONE
```

All per-candidate counts are still reported. A graph containing one BLOCKED
candidate and one UNRESOLVED alternate therefore reports both counts and
`UNRESOLVED_PRESENT`, not `BLOCKED_ONLY`. AnalysisStatus remains COMPLETE when
enumeration completed; semantic uncertainty is not an operational failure.

---

# 14. Path Edge References

Every intermediate and final path uses explicit edge references:

```text
PathEdgeRef {
  relationship_id
  phase: INFLUENCE | AUTHORITY
  traversal: FORWARD | REVERSE
  position
}
```

Rules:

```text
positions are zero-based and contiguous
path order is source-to-sink presentation order
each Relationship ID exists in the same SecurityGraph
each edge retains its authored from/to direction
Evidence resolves through GraphEvidenceIndex
no edge is duplicated in one candidate
```

For the golden influence segment:

```text
Source ← can_retrieve ← Tool ← can_call ← Actor
```

both PathEdgeRefs use `REVERSE` traversal.

For the golden authority segment:

```text
Actor → can_execute → Bash → can_access → Credential → can_mutate → Worker
```

all PathEdgeRefs use `FORWARD` traversal.

---

# 15. Influence Analysis Contract

Influence analysis begins at Resources with role `SOURCE` and terminates at
Resources with role `ACTOR`.

Implementation may efficiently search from each Actor, but returned paths must
be source-to-actor ordered.

A supported InfluencePath requires:

```text
SOURCE role
supported trust vocabulary
supported influence strength
allowed relationship kinds
eligible edge states
same-scan edge Evidence
bounded complete traversal
exact Actor identity
```

Unknown trust remains `UNKNOWN`. Unknown influence strength must not be
upgraded to automatic or instruction-bearing influence.

An `UNKNOWN` or `BLOCKED` Relationship cannot form an active InfluencePath.

An `INFERRED` edge may form a provisional intermediate candidate, but Sprint
008 must classify that candidate UNRESOLVED and must not persist it as ACTIVE or
BLOCKED. Slice 8 may later admit inferred paths with reduced confidence under
an explicit scoring policy.

---

# 16. Authority Analysis Contract

Authority analysis begins at Resources with role `ACTOR` and terminates at
Resources with role `SINK`.

A supported AuthorityPath requires:

```text
ACTOR role
supported capability chain
AUTHORITY role when credential authority is involved
SINK role
allowed relationship kinds
eligible edge states
same-scan edge Evidence
bounded complete traversal
explicit authority resolution
```

For the unblocked golden path:

```text
OpenCode → can_execute → Bash
Bash → can_access → Cloudflare Credential
Cloudflare Credential → can_mutate → Cloudflare Worker
```

Expected semantics:

```text
Bash scope: UNRESTRICTED
credential reachability: REACHABLE
Cloudflare mutation authority: established
authority resolution: EXACT
sink: consequential
```

The following do not produce an active AuthorityPath:

```text
Bash ALLOW + BOUNDED
Bash reachability UNKNOWN
credential environment UNKNOWN
can_access UNKNOWN
can_mutate UNKNOWN
can_mutate BLOCKED
authority resolution UNKNOWN
non-consequential target
```

`SCOPED` may form an AuthorityPath only when the exact target is proven inside
the observed scope. For Sprint 008, that proof must be carried by a direct
`can_mutate` Relationship to the exact Sink Resource with state `DERIVED`,
`authority_resolution: SCOPED`, and same-scan Evidence establishing the target
scope. Do not reconstruct provider scope by joining account names or parsing
Cloudflare-specific IDs in the analyzer. It remains `SCOPED`.

`BEHAVIORAL_READ_ONLY` does not prove mutation authority.

---

# 17. Boundary Evaluation Contract

Boundary evaluation occurs after candidate influence and authority segments
are identified. It inspects only graph roles, Relationship semantics, safe
normalized metadata, same-scan Evidence, and alternate routes in the same
graph.

Analysis has two distinct enumeration modes:

```text
active traversal
→ crosses only edges eligible for active analysis

blocked-candidate enumeration
→ may include one or more supported BLOCKED edges as explicit interruption
  points while requiring every other segment to be supported
```

Blocked-candidate enumeration never upgrades or silently crosses a BLOCKED
edge. It retains the edge solely to explain where the structurally visible
route is interrupted. `UNKNOWN` edges remain unresolved in both modes.

The initial explicit boundary relationship vocabulary is:

```text
requires_approval
denied_by
protected_by
isolated_by
```

These kinds connect provider-neutral boundary Resources when such Resources
are observed. A `BLOCKED` security-critical edge may also carry a normalized
hard-deny or scope decision without requiring a synthetic Boundary node.

## 17.1 Hard deny

A confirmed explicit deny represented by a `BLOCKED` security-critical
Relationship may establish `HARD_DENY` for that route. It must not suppress an
alternate route.

## 17.2 Mandatory approval

`MANDATORY_APPROVAL` interrupts autonomous authority only if all four canonical
conditions are proven:

```text
approval is technically required
the actor cannot self-approve
the route cannot bypass the gate
runtime mode does not disable the gate
```

Static `ASK` with unknown runtime bypass or self-approval state is UNRESOLVED,
not ACTIVE or BLOCKED.

A confirmed synthetic mandatory-approval fixture uses the provider-neutral
shape:

```text
Resource kind: approval_gate
Resource metadata:
  boundary_kind: MANDATORY_APPROVAL
  enforcement: TECHNICAL
  actor_self_approval: DISALLOWED
  runtime_gate_state: ENFORCED

Relationship:
  protected capability → requires_approval → approval_gate
  state: CONFIRMED
  metadata:
    interrupts_relationship_canonical_key: <exact relationship>
```

The evaluator independently checks the current graph for a supported bypass.
All fields and the no-bypass decision require same-scan Evidence. If any field
is absent, unknown, or contradictory, the boundary is UNRESOLVED.

## 17.3 Scope

Confirmed out-of-scope credential or resource evidence may establish
`CREDENTIAL_SCOPE` or `RESOURCE_SCOPE` for the affected route. Unknown scope is
unresolved, not blocked.

## 17.4 Soft policy

Advisory text such as `ask before deploy`, `do not modify production`, or `use
caution` never establishes an enforced boundary.

## 17.5 Alternate routes

Given:

```text
Actor → Bash → Approval → Sink
Actor → Independent Capability → Sink
```

the first route may be BLOCKED while the second remains ACTIVE. The Actor must
not be labeled safe.

## 17.6 Unsupported analysis semantics

If Source, Actor, and Sink roles form an apparent candidate whose only
connection depends on a graph-supported but analysis-unsupported Relationship
kind, report UNRESOLVED with `UNSUPPORTED_RELATIONSHIP_KIND`.

Unrelated unsupported edges that do not form an apparent source/actor/sink
candidate do not manufacture uncertainty and may result in NONE.

---

# 18. AttackPath Identity

Persist two identities:

```text
id
→ unique row identity for one Scan analysis result

fingerprint
→ stable semantic identity across equivalent scans
```

Fingerprint input uses canonical values:

```text
analysis version
source canonical key
actor canonical key
sink canonical key
ordered influence relationship canonical keys + traversal directions
ordered authority relationship canonical keys + traversal directions
normalized boundary disposition and affected canonical identities
ACTIVE or BLOCKED disposition
```

It must not include Scan, Observation, or Evidence IDs; timestamps; filesystem
paths; machine-specific values; raw secrets; display-only names; or unordered
map serialization.

Equivalent graphs under the same analysis version produce the same fingerprint
and ordering. Different Scans persist distinct AttackPath rows even when their
fingerprint matches.

Boundary fingerprint input is canonicalized as typed tuples:

```text
(
  boundary_kind,
  decision,
  interrupted_phase,
  sorted affected Resource canonical keys,
  sorted affected Relationship canonical keys
)
```

Sort BoundaryEvaluations by that tuple. Encode every scalar and list item with
a length-prefixed UTF-8 representation before hashing; do not depend on JSON
object order or ambiguous delimiters.

---

# 19. Deterministic Ordering and Deduplication

Sort output deterministically by:

```text
source canonical key
actor canonical key
sink canonical key
disposition
ordered edge canonical keys
boundary canonical form
```

Exact duplicate candidates collapse to one AttackPath.

Materially different routes remain distinct when they differ by a
security-critical capability, Relationship, boundary, bypass, authority
resolution, or target Resource.

Finding-level grouping is Sprint 009 scope.

---

# 20. Bounded Analysis

Reuse the Sprint 007 traversal safety model.

Preserve explicit limits for:

```text
maximum path depth
maximum edge examinations
maximum frontier nodes
maximum reachable nodes
maximum influence paths per Actor
maximum authority paths per Actor
maximum candidate joins
maximum emitted AttackPaths
```

Sprint 008 defaults are:

```text
maximum path depth: 8
maximum edge examinations: 256
maximum frontier nodes: 128
maximum reachable nodes: 128
maximum influence paths per Actor: 32
maximum authority paths per Actor: 32
maximum candidate joins: 256
maximum emitted AttackPaths: 128
maximum unresolved candidates retained: 128
```

If more than one bound is encountered, retain every exhausted reason in this
deterministic order:

```text
WORK
DEPTH
FRONTIER
REACHABLE
INFLUENCE_RESULTS
AUTHORITY_RESULTS
CANDIDATE_JOINS
ATTACK_PATH_RESULTS
UNRESOLVED_RESULTS
```

Analysis is cycle-safe, direction-aware, relationship-allowlisted,
role-constrained, work-bounded, result-bounded, and deterministically ordered.

Limit exhaustion returns explicit `LIMITED`. Do not emit a complete AttackPath
from a truncated candidate or treat exhausted work as proof that no alternate
route exists.

---

# 21. Evidence Contract

Every security-critical PathEdgeRef resolves to at least one same-scan Evidence
item through `GraphEvidenceIndex`.

An AttackPath exposes the deterministic union of Evidence IDs supporting:

```text
influence edges
authority edges
boundary decisions
```

This union is for auditability. It is not yet Slice 8 product evidence
aggregation or narrative.

Rules:

```text
same-scan Evidence only
exact Relationship links only
no fuzzy subject matching for security conclusions
no historical Evidence substitution
no missing Evidence on a security-critical edge
no secret values in analysis output
```

Missing or cross-scan-only Evidence fails closed.

---

# 22. Persistence

Canonical Architecture requires AttackPaths to be persisted with the Scan that
generated them.

Add the smallest normalized persistence required for Sprint 008:

```text
scan_analyses
attack_paths
attack_path_edges
attack_path_evidence
```

Conceptual `scan_analyses` fields:

```text
scan_id
analysis_version
status: COMPLETE | LIMITED | FAILED
overall_disposition: ACTIVE_PRESENT | UNRESOLVED_PRESENT | BLOCKED_ONLY | NONE
                     (nullable for LIMITED or FAILED)
influence_path_count
authority_path_count
active_path_count
blocked_path_count
unresolved_candidate_count
typed bounded-limit reasons
versioned provider-neutral diagnostic reason records
created_at
```

This record distinguishes `analysis not run`, `complete with no path`,
`unresolved`, `limited`, and `failed` when no AttackPath row exists.
Diagnostic records may use validated safe JSON because they are low-query
explanatory detail; their reason-code vocabulary, canonical subject identities,
and Evidence references are typed before serialization and never contain
adapter blobs.

Conceptual `attack_paths` fields:

```text
id
scan_id
fingerprint
analysis_version
source_resource_id
actor_resource_id
sink_resource_id
disposition: ACTIVE | BLOCKED
source_trust
influence_strength
capability
authority_resolution
sink_impact
safe typed boundary result when present
created_at
```

Conceptual `attack_path_edges` fields:

```text
attack_path_id
relationship_id
position
phase: INFLUENCE | AUTHORITY
traversal: FORWARD | REVERSE
```

Also add:

```text
attack_path_evidence

attack_path_id
evidence_id
position
support_role: EDGE | BOUNDARY
```

Evidence rows are ordered by their first path use and then stable Evidence ID.
This table preserves boundary Evidence that cannot necessarily be reconstructed
from Relationship evidence links alone.

BoundaryEvaluation may use a small normalized table or versioned, typed,
provider-neutral safe metadata on AttackPath, consistent with Architecture's
initial allowance. Do not persist arbitrary adapter blobs.

Do not add Findings tables in Sprint 008.

`severity` and `confidence` are intentionally absent under the explicit Slice 8
boundary. Sprint 009 may add those columns or persist them through its Finding
model. Sprint 008 persists the other canonical path semantics above so
historical paths remain reproducible without recomputing mutable Resource rows.

Persistence rules:

```text
AttackPath rows are scan-scoped and append-oriented
repeated scans create distinct rows
equivalent paths retain the same fingerprint
edge order remains exact
foreign keys protect Scan, Resource, and Relationship identity
failed or limited analysis leaves no partial positive conclusions
UNRESOLVED and NONE do not become AttackPath rows
every analyzed Scan has exactly one scan_analyses row
```

Add a schema migration. Do not rewrite historical Observations or Sprint 007
graph state.

---

# 23. ScanService Integration

The bounded application flow becomes:

```text
Discovery
  ↓
Normalization
  ↓
Persistence of observed state
  ↓
SecurityGraph projection
  ↓
Deterministic analysis
  ↓
AttackPath persistence
  ↓
Scan COMPLETE or PARTIAL
```

Analysis runs only after graph projection succeeds.

If analysis succeeds completely:

```text
Analysis: COMPLETE
```

If the graph is empty:

```text
Analysis: COMPLETE
Candidate disposition: NONE
AttackPaths: 0
```

If traversal or result limits are reached:

```text
Analysis: LIMITED
Scan: PARTIAL
AttackPaths: no partial positive conclusions
```

If integrity fails:

```text
Analysis: FAILED
Scan: FAILED
```

Preserve the existing ScanService failure API: persist the Scan row as FAILED,
return a safe `PicoError::scan`, and let the CLI exit non-zero. Do not fabricate
a successful `ScanResult` merely to render `Analysis: FAILED`.

Do not mark a scan COMPLETE when analysis failed or was truncated.

Discovery PARTIAL remains PARTIAL even if analysis completes over retained
graph state. Analysis must not upgrade scan status.

---

# 24. CLI Contract

Extend `pico scan` without implementing Finding UX.

An active golden-path result should include semantically:

```text
Status: COMPLETE
Security Graph: PROJECTED
Analysis: COMPLETE
Influence Paths: 1
Authority Paths: 1
Potentially Active AttackPaths: 1
Blocked AttackPaths: 0
Unresolved Candidates: 0
Findings: 0
```

A proven blocked candidate should include:

```text
Analysis: COMPLETE
Potentially Active AttackPaths: 0
Blocked AttackPaths: 1
Unresolved Candidates: 0
Findings: 0
```

An unresolved candidate should include:

```text
Analysis: COMPLETE
Potentially Active AttackPaths: 0
Blocked AttackPaths: 0
Unresolved Candidates: >=1
Findings: 0
```

An empty graph should include:

```text
Security Graph: EMPTY
Analysis: COMPLETE
Influence Paths: 0
Authority Paths: 0
Potentially Active AttackPaths: 0
Blocked AttackPaths: 0
Unresolved Candidates: 0
Findings: 0
```

Do not print severity, confidence, `UNTRUSTED_TO_PRODUCTION`, remediation, or
claims of verified exploitation.

---

# 25. Required Fixtures

Use sanitized, network-free fixtures for:

```text
empty graph
influence only
authority only
complete unblocked golden path
hard-denied golden path
approval-gated unresolved path
confirmed mandatory-approval blocked path
bounded Bash unresolved path
unknown credential reachability
unknown Worker authority
out-of-scope Worker authority
alternate route bypassing one boundary
inferred edge
unsupported relationship kind
missing Evidence
cross-scan-only Evidence
cycle
depth-limit graph
work-limit graph
fan-out/result-limit graph
duplicate semantic route
secret-sentinel graph
```

All secret-like values are synthetic. Use at least:

```text
TEST_SECRET_SHOULD_NOT_PERSIST
```

The complete fixture must assert this exact sorted manifest, not merely
`contains` checks.

Nodes:

```text
agent:opencode
cloudflare:account:account-1234567890123456
cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456
credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f
mcp:github:official
mcp:github:official:tool:issue_read
shell:bash
source:github:public:issue-content
```

Edges:

```text
agent:opencode|can_call|mcp:github:official:tool:issue_read
agent:opencode|can_execute|shell:bash
agent:opencode|configured_with|mcp:github:official
credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f|can_mutate|cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456
credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f|scoped_to|cloudflare:account:account-1234567890123456
mcp:github:official:tool:issue_read|can_retrieve|source:github:public:issue-content
mcp:github:official|exposes|mcp:github:official:tool:issue_read
shell:bash|can_access|credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f
```

The analysis route uses only `can_call`, `can_retrieve`,
`can_execute`, `can_access`, and `can_mutate`; the other three edges remain
supporting graph state.

---

# 26. Required Tests

## 26.1 Analysis model tests

Test enum round trips, invalid identities, path positions, direction,
same-scan invariants, ACTIVE/BLOCKED validity, non-persistence of
UNRESOLVED/NONE, and deterministic fingerprint inputs.

## 26.2 Influence tests

Test:

```text
public source reaches Actor through supported GitHub MCP route
ordered edges are source-to-actor
stored relationship directions remain unchanged
AGENT_RETRIEVABLE does not become AUTOMATICALLY_INJECTED
UNKNOWN and BLOCKED edges do not complete influence
reverse-only unrelated edges are not traversed
unrelated unsupported kinds are excluded
candidate-dependent unsupported kinds produce UNRESOLVED
```

## 26.3 Authority tests

Test:

```text
Actor reaches Worker through Bash and credential
EXACT resolution is preserved
SCOPED applies only to an exact in-scope target
BEHAVIORAL_READ_ONLY does not prove mutation
UNKNOWN authority does not complete
ALLOW + BOUNDED does not complete
ASK stays unresolved without enforcement proof
DENY produces a blocked route when structurally supported
Worker name never implies PRODUCTION
```

## 26.4 Boundary tests

Test:

```text
hard deny interrupts only its route
confirmed mandatory approval blocks autonomous route
static ASK with runtime UNKNOWN remains unresolved
soft policy does not interrupt
out-of-scope evidence blocks exact target route
unknown scope remains unresolved
alternate open route survives blocked route
boundary Evidence is same-scan
```

## 26.5 AttackPath tests

Test:

```text
influence and authority join only by exact Actor Resource ID
unblocked golden path emits one ACTIVE AttackPath
blocked golden path emits one BLOCKED AttackPath
unresolved candidate emits no persisted AttackPath
influence-only, authority-only, and empty graphs emit none
exact duplicates collapse
materially distinct routes remain distinct
path order and traversal direction are deterministic
every edge resolves Evidence
```

## 26.6 Bounded-analysis tests

Test cycles, depth, work, frontier, path-result, and candidate-join limits.
Limit exhaustion reports LIMITED and truncated work emits no complete path.

## 26.7 Persistence tests

Test:

```text
migration is idempotent
scan analysis summary distinguishes NOT RUN, NONE, UNRESOLVED, LIMITED, FAILED
AttackPath persists with Scan
ordered edges and traversal direction round-trip
ordered AttackPath Evidence references round-trip
ACTIVE/BLOCKED disposition round-trips
same path across two scans creates two rows with one fingerprint
different boundary outcome changes fingerprint
failed/limited analysis leaves no partial rows
foreign keys reject invalid references
```

## 26.8 Integration tests

Test through ScanService:

```text
complete golden-path fixture
out-of-scope can_mutate blocked fixture
unknown Cloudflare authority fixture with reachable credential
empty environment
repeated equivalent scans
secret-sentinel persistence search
```

Use direct SecurityGraph analysis fixtures—not a broadened provider-injection
seam—for:

```text
hard-denied Bash with a structurally complete downstream route
ASK unresolved complete candidate
bounded Bash unresolved complete candidate
confirmed mandatory approval
alternate-route bypass
```

The current ScanService intentionally persists Cloudflare provider results only
when credential reachability is `REACHABLE`. Under ASK, DENY, bounded, or
unknown Bash reachability, a normal end-to-end scan therefore has no Worker
Sink and cannot manufacture a complete blocked/unresolved candidate. Do not
weaken that safety gate solely to make an integration fixture possible.

Expected complete golden-path state:

```text
Graph Nodes: 8
Graph Edges: 8
Influence Paths: 1
Authority Paths: 1
Potentially Active AttackPaths: 1
Blocked AttackPaths: 0
Findings: 0
```

If supporting configuration or scope edges yield extra intermediate paths,
constrain allowed relationship kinds rather than weakening the manifest.

---

# 27. Determinism Contract

Analyze the same graph twice under one analysis version. Require identical:

```text
InfluencePath ordering
AuthorityPath ordering
BoundaryEvaluation ordering
AttackPath ordering and fingerprints
PathEdgeRef ordering and direction
Evidence ID ordering
summary counts and diagnostics
```

Run the same environment in two Scans. Require distinct scan-scoped row IDs,
the same fingerprint and normalized outcome, current-scan Evidence only, and no
historical graph leakage.

Do not rely on hash-map order, timestamps, random IDs, or database row order for
normalized conclusions.

---

# 28. Partial and Failure Semantics

## 28.1 Empty graph

```text
Scan: COMPLETE
Graph: EMPTY
Analysis: COMPLETE
Disposition: NONE
AttackPaths: 0
```

## 28.2 Partial discovery

Analyze retained coherent graph state for diagnostics, but preserve `Scan:
PARTIAL`. Sprint 008 does not persist ACTIVE or BLOCKED AttackPaths from a
discovery-PARTIAL scan because missing discovery may hide an alternate route or
boundary. Any otherwise positive or blocked candidate becomes UNRESOLVED for
the current run. Missing facts never become a negative conclusion.

## 28.3 Analysis limit

```text
Analysis: LIMITED
Scan: PARTIAL
```

Do not persist candidates computed from incomplete enumeration as complete
security conclusions.

## 28.4 Integrity failure

Missing graph edges, Evidence substitution, unknown analysis version, invalid
path ordering, or unsupported metadata used as established truth yields:

```text
Analysis: FAILED
Scan: FAILED
no AttackPath persistence
```

---

# 29. Secret Safety

Analysis receives only secret-safe graph state. It must not read raw environment
variables, OpenCode configuration, authorization headers, credential values,
private keys, or arbitrary files.

Fingerprints use canonical keys and normalized semantics, never raw credential
material.

After every sentinel fixture scan, search SQLite state, serialized AttackPaths,
CLI output, diagnostics, and test logs.

Expected occurrences of `TEST_SECRET_SHOULD_NOT_PERSIST`:

```text
0
```

---

# 30. Network and Mutation Safety

The analysis layer performs:

```text
network requests: 0
provider operations: 0
filesystem discovery: 0
environment reads: 0
system mutation: 0
```

An integration test may run the existing bounded discovery/provider pipeline
before analysis. Analysis itself consumes only SecurityGraph.

Provider mutation request count remains 0.

---

# 31. Controlled Manual Verification

After automated verification, run controlled local scans.

## 31.1 Empty environment

```text
Status: COMPLETE
Security Graph: EMPTY
Analysis: COMPLETE
Potentially Active AttackPaths: 0
Blocked AttackPaths: 0
Unresolved Candidates: 0
Findings: 0
```

## 31.2 OpenCode-only environment

```text
Analysis: COMPLETE
Influence Paths: 0
Authority Paths: 0
Potentially Active AttackPaths: 0
Findings: 0
```

## 31.3 Complete synthetic golden path through the controlled application seam

```text
Status: COMPLETE
Security Graph: PROJECTED
Graph Nodes: 8
Graph Edges: 8
Analysis: COMPLETE
Influence Paths: 1
Authority Paths: 1
Potentially Active AttackPaths: 1
Blocked AttackPaths: 0
Findings: 0
```

## 31.4 Proven out-of-scope provider path through the controlled application seam

```text
Analysis: COMPLETE
Potentially Active AttackPaths: 0
Blocked AttackPaths: 1
Findings: 0
```

## 31.5 Static ASK path

In a normal ScanService run, provider introspection remains gated because
credential reachability is not `REACHABLE`. Therefore no Worker Sink is
projected and the expected result is:

```text
Analysis: COMPLETE
Potentially Active AttackPaths: 0
Blocked AttackPaths: 0
Unresolved Candidates: 0
Overall: NONE
Credential Reachability: APPROVAL_GATED
Findings: 0
```

The synthetic complete-candidate graph fixture separately proves that static
ASK is UNRESOLVED rather than ACTIVE or BLOCKED when downstream nodes are
present for boundary evaluation.

Inspect SQLite after repeated scans. Verify scan ownership, stable fingerprints,
edge order and direction, current-scan Evidence, and zero sentinel occurrences.

Live Cloudflare dogfood remains a roadmap follow-up unless a controlled,
explicitly authorized environment is available. Do not obtain credentials or
perform provider mutation for this sprint.

---

# 32. Architecture Pressure Test

Before completion, explicitly answer:

1. Did analysis consume only one validated scan-scoped SecurityGraph?
2. Could historical Resources or Relationships leak into current analysis?
3. Did influence analysis preserve stored direction and source-to-actor output?
4. Did authority analysis require effective capability, credential
   reachability, authority resolution, and a consequential Sink?
5. Did `UNKNOWN` remain unresolved rather than safe or active?
6. Did `BLOCKED` require proven enforcement before becoming blocked?
7. Did static `ASK` remain unresolved when enforcement was not proven?
8. Did boundaries block paths rather than entire Actors?
9. Could an alternate route remain active while another was blocked?
10. Were cycles, depth, work, frontier, joins, and results bounded?
11. Were fingerprints deterministic across equivalent scans?
12. Could every path edge resolve exact same-scan Evidence?
13. Did analysis remain provider-neutral and secret-free?
14. Were network requests and provider mutations zero?
15. Are Findings, severity, confidence, remediation, and Sprint 009 absent?

If any answer is NO, do not hide it. Fix only if clearly inside Sprint 008;
otherwise STOP and report the architectural friction.

Recorded answers: 1 PASS (single validated scan graph); 2 PASS (projection is
scan-scoped); 3 PASS (stored direction plus presentation traversal are
explicit); 4 PASS (capability, reachability, resolution, and sink are
required); 5 PASS (`UNKNOWN` is unresolved); 6 PASS (blocked enforcement is
retained as blocked); 7 PASS (unproven ASK is unresolved); 8 PASS (boundaries
are path-scoped); 9 PASS (alternate routes are independent); 10 PASS (all
traversal and result limits are bounded); 11 PASS (canonical fingerprints are
stable); 12 PASS (same-scan Evidence is checked); 13 PASS (analysis is
provider-neutral and secret-free); 14 PASS (zero network/provider mutation);
15 PASS (Finding-era concepts remain absent).

---

# 33. Definition of Done

Sprint 008 is complete only when:

- [x] Baseline `27d1603` is verified before implementation.
- [x] Analysis consumes only the validated current-scan SecurityGraph.
- [x] InfluencePath, AuthorityPath, BoundaryEvaluation, and AttackPath exist as
      provider-neutral analysis types.
- [x] ACTIVE and BLOCKED are implemented.
- [x] UNRESOLVED and NONE remain explicit non-AttackPath outcomes.
- [x] Stored and presentation direction are preserved.
- [x] Influence and authority join only through exact Actor identity.
- [x] `UNKNOWN` cannot complete an AttackPath.
- [x] `BLOCKED` cannot become active.
- [x] Static `ASK` cannot become a proven boundary without enforcement proof.
- [x] Soft policy cannot block a path.
- [x] Alternate routes are evaluated independently.
- [x] Analysis is cycle-safe and bounded.
- [x] Limit exhaustion differs from no path.
- [x] Identity and ordering are deterministic.
- [x] AttackPaths persist with their Scan.
- [x] Equivalent repeated scans retain a stable fingerprint.
- [x] Every path edge has exact same-scan Evidence.
- [x] Golden fixture produces 1 ACTIVE AttackPath.
- [x] Hard-denied fixture produces 1 BLOCKED and 0 active paths.
- [x] ASK/unknown fixtures produce UNRESOLVED and no persisted AttackPath.
- [x] Empty and partial graphs are handled honestly.
- [x] Secret sentinel has zero persistence/output occurrences.
- [x] Analysis performs zero network and provider operations.
- [x] Findings remain 0.
- [x] Severity, confidence, remediation, and explanation UX remain absent.
- [x] Full verification passes.
- [x] Final diff contains no Sprint 009+ functionality.
- [x] This document records completion evidence.

---

# 34. Full Verification

Run:

```text
cargo test
cargo check
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

Report exact test totals. Run the controlled CLI/SQLite verification and
architecture pressure test. Do not declare completion from focused tests alone.

---

# 35. Final Diff Inspection

Review the complete Sprint 008 diff for:

```text
accidental files or build artifacts
.pico state
raw secrets or real credentials
machine-specific paths
debug output or unnecessary dependencies
provider-specific analyzer logic
unbounded traversal or unordered nondeterminism
cross-scan state leakage
partial positive conclusions
Finding, severity, confidence, remediation, or Sprint 009+ logic
```

Do not perform unrelated refactoring.

---

# 36. Stop Conditions

Stop if:

```text
baseline is materially unexpected
working tree contains unexplained changes
Canon contradicts required analysis semantics
the graph lacks enough current-scan state for a defensible path
source/actor/sink identity cannot be joined exactly
same-scan Evidence cannot resolve every security-critical edge
enforced boundaries cannot be distinguished from advisory policy
analysis requires provider-specific logic
bounded traversal cannot prevent false complete results
persistence would require secret material
implementation would require Sprint 009 Finding semantics
```

Report the blocker rather than inventing compatibility or security truth.

---

# 37. Deliverables

```text
provider-neutral analysis module
InfluencePath domain
AuthorityPath domain
BoundaryEvaluation domain
AttackPath domain
analysis version
deterministic path fingerprints
bounded influence and authority traversal
candidate joining and per-route boundary evaluation
AttackPath persistence migration and repositories
scan analysis summary persistence
AttackPath edge and Evidence reference persistence
ScanService integration
CLI analysis summary
sanitized fixtures
unit, domain, persistence, and integration tests
secret-sentinel validation
completion evidence in this document
```

---

# 38. Completion Evidence

When implementation and verification pass, set:

```text
Status: COMPLETE
```

Record:

```text
completion date
verified baseline SHA
implementation commit SHA and message
branch, HEAD, origin/main, ahead/behind, working-tree state
test totals
cargo check, clippy, fmt, release build
analysis version
empty, influence, authority, active, blocked, and ASK-unresolved results
alternate-route and bounded-analysis results
determinism and persistence results
same-scan Evidence and secret-sentinel results
network request and provider mutation counts
Findings count
architecture pressure-test answers
controlled-real-environment status
roadmap decision: EXTEND v0.1 unless all remaining phase gates are separately met
```

Do not claim the full v0.1 exit gate while Finding and controlled-dogfood gates
remain incomplete.

## Recorded completion — 2026-08-25

Sprint 008 was implemented from verified baseline `27d16032f19d4fb62a41026d6e3f5de2c91fb095` on `main`. Implementation commit: `66c4e05` (`feat(analysis): identify the first golden-path attack path`). This completion record is finalized in the follow-up documentation commit.

Verification evidence:

- `cargo test`: 132 passed, 0 failed (51 library, 30 domain, 35 integration, 16 persistence; doctests: 0).
- `cargo check`: PASS.
- `cargo clippy --all-targets -- -D warnings`: PASS.
- `cargo fmt --check`: PASS.
- `cargo build --release`: PASS.
- Controlled OpenCode-present CLI scan: `COMPLETE`, one OpenCode agent, no findings; repeated scan retained stable resource identity and added scan history.
- Controlled empty/absent graph: `COMPLETE`, no AttackPaths, no Findings.
- Synthetic golden graph: exactly 8 nodes and 8 edges, one InfluencePath, one AuthorityPath, one ACTIVE AttackPath, same-scan Evidence, and stable cross-scan fingerprint.
- Proven blocked authority: one BLOCKED AttackPath and zero active paths.
- ASK/unknown and bounded-limit cases remain unresolved/limited and produce no positive persisted AttackPath.
- Secret-sentinel persistence test: PASS; sentinel absent from normalized graph and persisted state.
- Analysis persistence: `scan_analyses`, `attack_paths`, ordered edge references, and ordered evidence references round-trip through SQLite schema version 3.
- Analysis performed no network requests, provider mutation requests, or raw credential persistence.

Architecture pressure test: PASS for provider-neutral graph analysis, deterministic Resource/Scan/Observation modeling, same-scan Evidence, bounded traversal, and no plugin framework. Finding, severity, confidence, remediation, explanation UX, and Sprint 009 functionality remain intentionally absent.

Roadmap decision: `EXTEND v0.1`; the Finding and controlled-dogfood gates remain future authorized work.

---

# 39. Commit Policy

If and only if Sprint 008 is fully verified, stage only Sprint 008 changes,
inspect the staged diff, and commit with:

```text
feat(analysis): identify the first golden-path attack path
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not
begin Sprint 009.

The authoring-only document may be committed separately with:

```text
docs(sprints): define Sprint 008 attack-path analysis
```

---

# 40. Final Report Contract

Report:

```text
Sprint
SPRINT-008 — First Attack Path — Deterministic Golden-Path Analysis

Status
COMPLETE or BLOCKED

Baseline
<verified SHA>

Implementation commit
<SHA + message>

Analysis contract
<scan scope, influence, authority, boundaries, outcomes, determinism>

Implementation
<analysis boundary, traversal, joins, persistence, ScanService, CLI>

Verification
<tests and all required checks>

Analysis result
Influence Paths: <count>
Authority Paths: <count>
Potentially Active AttackPaths: <count>
Blocked AttackPaths: <count>
Unresolved Candidates: <count>
Findings: 0

Golden path
Source: <canonical identity>
Actor: <canonical identity>
Sink: <canonical identity>
Disposition: ACTIVE | BLOCKED | UNRESOLVED | NONE
Evidence-complete: YES | NO

Currentness
Cross-scan leakage: NO
Same-scan Evidence only: YES
Analysis version: <version>

Safety
Network required by analysis tests: NO
Provider mutation requests: 0
Raw credentials persisted: NO
Secret sentinel persisted or emitted: NO

Scope
Finding implemented: NO
Severity implemented: NO
Product confidence implemented: NO
Remediation implemented: NO
Explanation UX implemented: NO
Pico MCP implemented: NO
Sprint 009 functionality implemented: NO

Architecture pressure test
<PASS / FAIL for every question>

Repository
Branch: <branch>
HEAD: <SHA>
origin/main: <SHA>
Ahead/behind: <state>
Working tree: <state>

Follow-ups
<only genuine observations for Slice 8 / Sprint 009>
```

Do not report UNRESOLVED as active or blocked. Do not report an AttackPath as
exploited, observed at runtime, or verified by write action.

---

# 41. Sprint Exit

Sprint 008 ends when Pico can reliably say:

> **I analyzed this scan's graph and determined whether its golden path is
> active, blocked, absent, or unresolved, with exact evidence for every
> conclusion.**

It does not yet answer:

> **What security Finding should the developer act on, how severe is it, and
> where should the path be cut?**

That belongs to the next explicitly authorized Finding sprint.

Do not begin Sprint 009.

Wait for explicit authorization.
