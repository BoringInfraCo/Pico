# Pico — Sprint 010: First Explanation — Finding Navigation

**Status:** COMPLETE
**Sprint:** 010
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `29cccdf`
**Depends on:** Sprint 009 — First Finding — Untrusted to Production
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Turn Pico's first persisted Finding into a complete, deterministic, evidence-
backed CLI explanation that a developer can navigate and act on.

Sprint 009 established:

> **Pico can turn an active path to explicitly classified production authority
> into a stable `UNTRUSTED_TO_PRODUCTION` Finding with transparent severity,
> confidence, Evidence, reasons, and remediation cut points.**

Sprint 010 must establish:

> **Pico can retrieve that persisted Finding and explain what exists, why it
> matters, how the path works, how Pico knows, what uncertainty remains, what
> enforced boundary is absent, and where the path can be broken.**

The primary flow is:

```text
Persisted COMPLETE Scan
        ↓
Persisted Finding + AttackPaths
        ↓
Historical scan-scoped graph projection
        ↓
Evidence + Reasons + Boundaries + Remediations
        ↓
Application explanation DTOs
        ↓
pico findings
pico finding <id>
```

This sprint answers:

> **Can a developer understand and navigate Pico's first security conclusion
> without knowing Pico's internal schema or security engine?**

It does not add a new security conclusion, rerun analysis, or implement the
agent-native interface.

---

# 2. Roadmap Position

Sprint 010 implements Architecture Slice 9:

```text
pico findings
pico finding <id>
```

Architecture Slice 8 is complete:

```text
UNTRUSTED_TO_PRODUCTION
severity
confidence
evidence aggregation
remediation cut points
```

Architecture Slice 10 remains future work:

```text
minimal Pico MCP exposure
same application services
no duplicate scanner
```

Sprint 010 advances the v0.1 usability exit criterion:

> A developer unfamiliar with the internals can explain what the path is, why
> it matters, how Pico knows, what remains uncertain, and at least one practical
> cut point.

Completing this implementation does not by itself prove that criterion with a
real developer. Controlled real-environment dogfood and developer-comprehension
validation remain separate gates.

Expected roadmap decision after this sprint:

```text
EXTEND v0.1
```

Do not advance to v0.2 solely because fixture-backed explanation works.

---

# 3. Required Product Claim

At completion, Pico must be able to present semantically:

```text
CRITICAL · HIGH confidence
External content can reach production mutation authority

Externally controlled content can reach an autonomous coding environment with
authority capable of changing an explicitly classified production resource.

Path
  External GitHub Content
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

Boundary
  No proven enforced boundary in this scan interrupts this path.

Recommended cuts
  1. Enforce Bash approval or deny.
  2. Remove agent credential reachability.
  3. Restrict external retrieval.
  4. Scope mutation authority away from production.
```

The claim must remain narrower than:

```text
The path was exploited.
The external content is malicious.
The agent is compromised.
No security boundary exists anywhere.
The environment is globally safe when no Finding is listed.
Pico validated the path by performing a write.
Pico applied a remediation.
```

The explanation describes a potential exposure established from one persisted
Scan. It is not a runtime incident verdict.

---

# 4. Explanation UX Contract

The required command surface is exactly:

```text
pico findings
pico finding <id>
```

`pico findings` answers:

```text
What Findings exist in the newest COMPLETE Scan?
How severe and well-supported are they?
Which Finding ID should I inspect?
Is a newer incomplete or failed scan attempt present?
```

`pico finding <id>` answers:

```text
WHAT did Pico find?
WHY does it matter?
HOW does the path work?
HOW does Pico know?
WHAT did Pico establish about boundaries and uncertainty?
HOW can the path be broken?
```

Both commands are read-only projections of persisted authoritative results.
They must not create a Scan, rerun discovery, rebuild a Finding, or update
SQLite state.

---

# 5. Application Query Boundary

Maintain:

```text
CLI
 ↓
FindingQueryService / ExplanationService
 ↓
Persistence + historical graph projection
 ↓
Application-level DTOs
 ↓
CLI rendering
```

The exact service naming may remain small, for example:

```text
src/application/findings.rs

FindingQueryService::list_latest(workspace)
FindingQueryService::get(workspace, finding_id)
```

The application layer owns:

```text
database opening
scan selection and freshness context
same-scan integrity validation
historical graph reconstruction
Finding composition
fixed reason narration
boundary narration
stable DTO ordering
```

The query path must add or use an explicit `SQLITE_OPEN_READ_ONLY` database
open path, validate that schema version 4 is supported, and never run
migrations, DDL, or `user_version` updates. A schema mismatch is a clear
compatibility error, not permission to mutate state from a query command.

Compose each command inside one coherent SQLite read transaction/snapshot.
Scan selection, freshness state, historical graph inputs, Finding children,
integrity checks, and DTO materialization must not mix rows observed before and
after a concurrent Scan update.

The CLI owns only:

```text
argument parsing
terminal layout
safe error presentation through the existing boundary
```

The CLI must not contain SQL, inspect Observation JSON, evaluate path
eligibility, recompute severity or confidence, interpret provider metadata, or
call adapters.

---

# 6. Latest COMPLETE Scan Selection

`pico findings` defaults to the newest Scan whose status is exactly:

```text
COMPLETE
```

Use deterministic ordering:

```text
completed_at DESC
started_at DESC
id DESC
```

Select the newest scan attempt independently using:

```text
started_at DESC
id DESC
```

Use that same `(started_at, id)` tuple to decide whether an attempt is newer
than the selected COMPLETE Scan. This ordering works for RUNNING Scans that do
not yet have `completed_at`.

`PARTIAL`, `FAILED`, and `RUNNING` Scans are not authoritative sources of
positive Findings and must not replace the selected COMPLETE Scan.

However, Pico must also inspect the newest scan attempt. If it is newer than
the selected COMPLETE Scan by `(started_at, id)` and its status is `RUNNING`,
`PARTIAL`, or `FAILED`, render a visible freshness warning:

```text
Freshness: A newer scan <scan-id> is PARTIAL.
Showing the last COMPLETE scan; these results may not describe current state.
```

Equivalent messages are required for `FAILED` and `RUNNING`.

This rule prevents two failures:

```text
newer PARTIAL scan hides all useful prior results

older COMPLETE result is silently presented as current after a newer failed or
incomplete attempt
```

Do not fall back to the newest terminal Scan without reporting its status. Do
not treat `completed_at IS NOT NULL` as equivalent to `status == COMPLETE`.

---

# 7. `pico findings` Contract

The list command must present:

```text
selected Scan ID
selected Scan completion time
selected Scan status
freshness state
Finding count
one deterministic summary per Finding
```

Each summary includes at least:

```text
Finding ID
Finding class
title
severity
confidence
status
AttackPath count
affected production Sink count
```

Conceptual output:

```text
Pico Findings

Scan: scan_...
Status: COMPLETE
Completed: 2026-08-25T...
Freshness: LATEST COMPLETE
Findings: 1

CRITICAL · HIGH confidence
External content can reach production mutation authority
Class: UNTRUSTED_TO_PRODUCTION
Status: OPEN
Paths: 1
Affected production resources: 1
ID: finding_scan_...:...

Run:
  pico finding finding_scan_...:...
```

The exact spacing may evolve during implementation. The semantic content and
ordering may not.

The minimal `pico scan` navigation hint must print every generated Finding ID
in the same deterministic order used by `pico findings`. Do not print only the
first ID when a Scan contains multiple Findings.

---

# 8. Finding List DTO and Ordering

Introduce stable application DTOs rather than returning database records to the
CLI, for example:

```text
FindingList {
  selected_scan
  newest_scan_attempt
  freshness
  findings[]
}

FindingSummary {
  id
  finding_class
  status
  title
  severity
  confidence
  attack_path_count
  affected_sink_count
  fingerprint
}
```

The DTO is an application contract. It must not expose SQLite rows or raw JSON
metadata as the interface model.

List Findings in this order:

```text
severity descending:
  CRITICAL, HIGH, MEDIUM, LOW, INFO

then confidence descending:
  HIGH, MEDIUM, LOW

then title ascending
then fingerprint ascending
then id ascending
```

Even though Sprint 010 has one Finding class and only eligible HIGH-confidence
Findings, define and test the complete ordering vocabulary already present in
the domain. Do not add new Finding classes to exercise it.

---

# 9. Empty and No-Scan States

The command must distinguish:

```text
Pico is not initialized
Pico is initialized but has no Scans
Scans exist but none is COMPLETE
latest COMPLETE Scan has zero Findings
latest COMPLETE Scan has Findings
```

Required semantics:

```text
not initialized
  → existing safe error
  → non-zero exit
  → instruct the user to run pico init

no Scans
  → successful empty state
  → instruct the user to run pico scan

no COMPLETE Scan
  → successful non-authoritative state
  → report newest attempt and status
  → do not imply an all-clear

COMPLETE Scan with zero Findings
  → report zero Findings within Pico's supported scan scope
  → do not say the environment is safe
```

Recommended zero-Finding language:

```text
No Findings were produced for this COMPLETE scan within Pico's supported
scope.
```

Avoid:

```text
No risk found.
Your environment is secure.
No attack paths exist.
```

---

# 10. `pico finding <id>` Contract

The detail command accepts one exact full Finding ID.

It may retrieve a Finding from any retained Scan, not only the newest COMPLETE
Scan. The view must label whether the Finding belongs to:

```text
LATEST_COMPLETE
HISTORICAL
```

These states are independent:

```text
Finding Scan == selected newest COMPLETE Scan
  → LATEST_COMPLETE

a later COMPLETE Scan exists
  → HISTORICAL
  → identify the newer COMPLETE Scan

newest attempt is later than the newest COMPLETE Scan and is
RUNNING, PARTIAL, or FAILED
  → also show the incomplete-attempt freshness warning from pico findings
```

An equivalent fingerprint in a later Scan does not turn the older scan-scoped
Finding ID into `LATEST_COMPLETE`.

The detail command presents these sections in deterministic order:

```text
Finding
What Pico found
Why it matters
Path or Paths
Severity and Confidence
Evidence
Boundaries and Uncertainty
Recommended cuts
Scope note
```

Do not implement prefix lookup, fuzzy lookup, interactive selection, or
fallback to another Finding. An unknown exact ID returns a clear non-zero
error.

---

# 11. Finding Detail DTO

The application layer should produce a composed DTO, conceptually:

```text
FindingDetail {
  id
  fingerprint
  finding_version
  scan
  currentness
  freshness_warning
  finding_class
  status
  title
  summary
  severity
  confidence
  reasons[]
  paths[]
  evidence[]
  boundary_summary
  remediations[]
  created_at
}

ExplainedPath {
  id
  fingerprint
  disposition
  source_trust
  influence_strength
  capability
  authority_resolution
  sink_impact
  steps[]
  boundaries[]
}

PathStep {
  position
  phase
  traversal
  relationship_id
  relationship_kind
  from_resource
  to_resource
  relationship_state
  evidence_ids[]
}

EvidenceView {
  id
  class
  source_type
  safe_source_locator
  subject
  observation
  captured_at
  freshness
  sensitivity
  support_roles[]
}
```

Names are illustrative. Preserve the separation between persisted facts,
application explanation, and terminal formatting.

---

# 12. What and Why Narrative

Use the persisted Finding title and summary as authoritative `WHAT` and `WHY`
content.

Do not regenerate them from provider names, resource names, Evidence text, or
an LLM.

Always include a fixed scope statement equivalent to:

```text
This Finding describes a potential exposure established from the recorded
scan. It does not establish exploitation, malicious content, or compromise.
```

The application layer may map stable Finding and reason codes to fixed,
provider-neutral explanatory prose. It must not modify Finding eligibility or
upgrade the persisted claim.

---

# 13. Path Explanation

For every linked AttackPath, show the complete ordered path from source to
Sink.

The golden path must render in security traversal order:

```text
External GitHub Content
        ↓
GitHub MCP Tool
        ↓
OpenCode
        ↓
Bash
        ↓
Cloudflare Credential
        ↓
Cloudflare Worker
```

For each path also present:

```text
disposition
source trust
influence strength
capability
authority resolution
sink impact
```

Every rendered path step must identify its exact same-scan supporting Evidence
IDs. Render the minimized Evidence details once in the Evidence section and use
IDs to connect each edge to its provenance without duplicating or overstating
reason-level support.

The Finding view must use persisted AttackPaths. It must not run graph
traversal again to discover a more attractive path, omit a linked path, or
construct a new path from current Relationships.

All grouped AttackPaths must remain inspectable.

---

# 14. Traversal and Historical Resource Resolution

AttackPath edges store both:

```text
relationship direction
AttackPath traversal direction: FORWARD or REVERSE
```

The rendered path must honor `traversal`. A naïve `from_resource_id →
to_resource_id` rendering may reverse the external-influence segment or create
a disconnected explanation.

Historical integrity is mandatory.

Stable `resources` and `relationships` rows may be updated by later Scans.
Therefore detail rendering must reconstruct the Finding's historical graph
from:

```text
Finding.scan_id
scan-scoped Observations
versioned Resource snapshots
versioned Relationship snapshots
same-scan Evidence
stable rows used only as identity anchors
```

Reuse the existing graph projection and snapshot validation path, or extract a
small read-only application helper around it. Do not hand-parse Observation
JSON in the CLI and do not read current stable row labels as historical truth.

If the historical projection cannot be reconstructed safely, fail the detail
query. Do not silently borrow state from a newer Scan.

---

# 15. Evidence Explanation

Render the exact ordered Evidence links persisted for the Finding.

Each Evidence item may display only the minimized fields required to explain
provenance:

```text
Evidence ID
class
source type
normalized safe source locator, or a deterministic redacted label
subject
observation
captured time
freshness, or UNKNOWN when absent
sensitivity label
support role or roles
```

Do not render:

```text
raw Evidence metadata
raw provider responses
authorization headers
credential values
environment values
raw OpenCode configuration
arbitrary source files
raw or full source locators when they may expose machine paths or sensitive
context
```

A source locator may be shown only when the persisted value is already
normalized and passes the existing secret/output-safety boundary. Otherwise
render a stable redacted provenance label. Provenance must remain inspectable
without exposing a credential or unnecessary absolute path.

The query layer performs no source reread. It explains what was persisted in
the Finding's Scan.

Every Evidence ID must resolve and belong to `Finding.scan_id`. Missing or
foreign-scan Evidence is an integrity error, not an omitted bullet.

Accept only the current Finding Evidence support roles:

```text
SUPPORTING
SINK_CLASSIFICATION
```

Unknown support roles are compatibility or integrity errors.

Finding v1's broad reason Evidence union can also make a persisted
`SINK_CLASSIFICATION` role broader than one uniquely scoped production proof.
Render it as a persisted support label, not as a claim that every Evidence item
with that label independently establishes production.

---

# 16. Reasons

Render all persisted structured reasons in stored position order:

```text
EXTERNAL_INFLUENCE_SOURCE
AGENT_RETRIEVABLE_CONTENT
AUTONOMOUS_EXECUTION_CAPABILITY
REACHABLE_CREDENTIAL_AUTHORITY
PRODUCTION_MUTATION_AUTHORITY
NO_ENFORCED_BOUNDARY
```

Map each reason code to fixed, provider-neutral human text. Unknown reason
codes fail explicitly; do not display them as a trusted explanation.

Sprint 009 currently persists the same broad supporting Resource,
Relationship, AttackPath, and Evidence union for each reason. Sprint 010 must
not falsely present those broad references as uniquely proving an individual
reason.

Use this honest boundary:

```text
reason code + fixed explanation

shared Finding Evidence shown once in the Evidence section
```

Only show reason-specific supporting references when the persisted reason
contract actually narrows them. Do not change Finding generation merely to make
the explanation appear more precise.

---

# 17. Severity and Confidence

Display severity and confidence separately and explain their distinct meaning:

```text
Severity
  What could happen if the established path is usable.

Confidence
  How strongly Pico established that this Finding exists.
```

Read both values from the persisted Finding.

Do not:

```text
recompute severity
recompute confidence
average Evidence
upgrade or downgrade the Finding
combine both values into an opaque score
```

For the golden fixture:

```text
Severity: CRITICAL
Confidence: HIGH
```

Also explain the recorded basis without recalculating either value:

```text
CRITICAL severity basis
  persisted PUBLIC_EXTERNAL or OPEN_WORLD source trust on an otherwise
  eligible active production-mutation path

HIGH severity basis
  persisted AUTHENTICATED_EXTERNAL source trust on an otherwise eligible
  active production-mutation path

HIGH confidence basis
  persisted CONFIRMED/DERIVED security-critical Relationships
  + non-INFERRED same-scan supporting and production Evidence
  + exact authority, or scoped authority with exact target inclusion
```

Use the exact persisted path facts in the DTO. Fixed prose may explain why
those facts matter, but it must not contain a second severity/confidence rule
engine.

---

# 18. Boundaries and Uncertainty Narrative

Decode each linked AttackPath's persisted, typed boundary evaluations and
present them in deterministic order.

For an active Sprint 009 Finding, the safe conclusion is:

```text
No proven enforced boundary recorded for this scan interrupts this path.
```

It is not:

```text
No boundary exists.
Approval can never occur.
The path is guaranteed exploitable.
```

If a boundary evaluation says `DOES_NOT_INTERRUPT`, identify the kind and the
recorded decision without overstating its scope. A persisted `INTERRUPTS` or
security-critical `UNRESOLVED` evaluation linked to an active Finding violates
Sprint 009 eligibility and must fail detail composition.

Missing, malformed, or internally inconsistent boundary metadata is an
integrity error. Do not manufacture a confident no-boundary narrative from an
unreadable record.

The uncertainty section must state at least:

```text
this is observed potential reachability, not runtime use or exploitation
the conclusion is limited to Pico's supported scan scope
the Finding reflects its originating Scan and may be historical
Evidence freshness is UNKNOWN wherever no freshness value was persisted
```

Do not say that no uncertainty exists globally merely because the emitted
Finding has `HIGH` confidence.

Blocked AttackPaths do not produce Findings. A general blocked-path browser is
not part of Sprint 010.

---

# 19. Remediation Cut Points

Render all persisted remediations in stored position order.

Each cut includes:

```text
rule ID
title
description
security effect
cut phase
target Resources
target Relationships
```

Resolve target display names from the same historical graph used for path
rendering. Preserve full normalized IDs where they help auditability.

Always state:

```text
Recommendations only. Pico did not apply these changes.
```

Do not reprioritize remediations, infer operational cost, edit configuration,
revoke credentials, scope tokens, or enforce approval.

---

# 20. Grouped Paths and Affected Sinks

One Finding may contain multiple AttackPaths and production Sinks.

The list view reports exact counts. The detail view displays every persisted
path and identifies every affected Sink.

```text
Finding
  Path 1 → Worker A
  Path 2 → Worker B
```

Do not collapse multiple Sinks into an unnamed count in the detail view. Do not
duplicate a shared path in a way that changes its meaning. Do not imply that
one displayed path is the only route when the Finding contains more.

`affected production resources` is the number of unique Sink Resource IDs
across the Finding's linked ACTIVE paths whose persisted `sink_impact` is
`PRODUCTION`. Two paths to one Sink count once. A linked non-production path is
an integrity error for `UNTRUSTED_TO_PRODUCTION`, not an affected production
resource.

Persisted state must remain compatible with the versioned Sprint 009 generation
contract. Define an explicit bounded read budget for Findings, paths, path
edges, Evidence, reasons, and remediations. If persisted state exceeds that
budget or cannot be composed completely, fail instead of silently truncating.
Do not claim that the concrete generation limits were persisted in schema
version 4.

---

# 21. Identity, Lookup, and Integrity Semantics

Finding identity remains:

```text
finding_<scan-id>:<fingerprint-digest>
```

`pico finding <id>` performs exact lookup within the current workspace's Pico
database.

Required outcomes:

```text
exact existing ID
  → complete detail DTO

unknown ID
  → clear not-found error
  → non-zero exit

empty ID
  → CLI parse error

prefix or ambiguous ID
  → not found; no fuzzy matching

broken path, Evidence, Resource, Relationship, Observation, or Scan link
  → integrity error
  → non-zero exit
  → no partial explanation
```

Validate at least:

```text
Finding belongs to its Scan
Finding version is supported
owning Scan is COMPLETE and has completed_at
owning analysis exists, is COMPLETE, and has a supported version
Finding has at least one linked AttackPath
each linked AttackPath belongs to that Scan
each linked AttackPath is ACTIVE and has a supported analysis version
each linked AttackPath has persisted sink_impact PRODUCTION
each linked Evidence row belongs to that Scan
each AttackPath Evidence row resolves, is same-scan, and is represented by the
  Finding Evidence set
path endpoints exist in the historical graph
ordered path edges resolve
reason Resource, Relationship, AttackPath, and Evidence references resolve
  within the Finding's historical graph and supporting sets
remediation targets resolve when presented as exact cut points
boundary metadata is valid and compatible with an active Finding
owning Scan declares a supported graph_snapshot_version
every Observation snapshot version is supported and agrees with the Scan
```

Additionally require:

```text
all ordered collections use zero-based contiguous positions
path edges form one connected source-to-actor-to-Sink chain when traversal is
  applied
INFLUENCE edges precede AUTHORITY edges and the phase transition occurs at the
  declared Actor
boundary affected Resources, Relationships, and Evidence resolve on the same
  path and Scan
every enum-like stored string uses the supported Finding-v1 vocabulary
remediation rule IDs are one of the four Sprint 009 rules
remediation cut phases are INFLUENCE or AUTHORITY
remediation target Relationships are linked path edges in the declared phase
remediation target Resources are endpoints of those target Relationships
```

---

# 22. Determinism

Equivalent persisted state must produce equivalent DTOs and terminal output.

Never depend on:

```text
hash-map iteration order
unordered SQL results
current wall-clock time
filesystem enumeration order
current mutable Resource or Relationship labels
provider response order
terminal width auto-reflow
```

Preserve stored positions for:

```text
Finding paths
path edges
Finding Evidence
reasons
remediations
```

Use explicit tie-breakers for all derived collections. Repeated queries must
not mutate access times or database rows.

Apply bounded row-count, JSON-array, string-length, and total rendered-byte
limits before materializing untrusted or corrupted persisted state. Exceeding a
query budget is an explicit error; never allocate or print without bounds and
never silently truncate a security explanation.

---

# 23. Secret and Output Safety

Explanation increases the amount of security metadata shown to a user. It must
not weaken Pico's secret boundary.

The application DTOs and CLI output must exclude:

```text
raw credentials
secret environment values
authorization headers
raw configuration
raw provider bodies
unsafe metadata dumps
unnecessary absolute machine paths
```

Use at least:

```text
TEST_SECRET_SHOULD_NOT_PERSIST
Authorization: Bearer TEST_AUTH_HEADER_SHOULD_NOT_APPEAR
```

Verify zero occurrences in:

```text
stdout
stderr
application DTO serialization used by tests
SQLite
logs and diagnostics
```

An integrity error must identify the broken normalized reference without
printing the unsafe row payload.

All persisted strings are terminal-untrusted, including titles, Resource
names, Evidence source/subject/observation text, remediation text, and error
diagnostics. Apply one deterministic terminal-safety policy that escapes or
rejects ANSI escape sequences, CR/LF, tabs, and other control characters before
stdout or stderr. Persisted text must not spoof headings, colors, or additional
terminal lines.

---

# 24. Network and Mutation Safety

Both Sprint 010 query commands perform:

```text
new Scans: 0
discovery calls: 0
filesystem discovery reads: 0
environment reads: 0
network requests: 0
provider operations: 0
database writes: 0
system mutations: 0
remediations applied: 0
```

Opening the existing workspace database and reading `.pico/pico.db` is the
only required workspace I/O.

Use a read-only SQLite connection, validate the supported schema version, and
do not call `migrate`. Do not reuse `ScanService` for explanation. Do not
instantiate adapters or a provider client.

---

# 25. Scope and Explicit Non-Goals

Sprint 010 includes only:

```text
provider-neutral Finding query/explanation service
historical scan selection and freshness context
historical graph reconstruction through the existing projection contract
application DTOs
pico findings
pico finding <id>
minimal pico scan Finding-ID navigation hint
fixed reason and boundary narration
deterministic terminal rendering
fixtures and tests
```

Sprint 010 does not include:

```text
new Finding classes
Finding eligibility or grouping changes
severity or confidence changes
Finding lifecycle, suppression, assignment, or comments
blocked-path browsing or a new blocked Finding
pico graph
pico resources
pico agents
pico status
pico explain
pico history or pico diff
filters, pagination, or interactive selection
--json or another machine-readable contract
exports, SARIF, or reports
CI thresholds or exit-code policy
Pico MCP or Architecture Slice 10
LLM-generated explanation
new adapters or providers
new provider calls
runtime monitoring
automatic remediation or enforcement
hosted services
controlled live Cloudflare dogfood without separate authorization
Sprint 011 functionality
```

No schema migration is expected. If the required explanation cannot be
implemented safely from schema version 4, STOP and report the exact missing
fact before changing persistence.

---

# 26. Baseline

Expected implementation baseline:

```text
Branch: main
HEAD: 29cccdffd8888e7f02552e89e162dae4d5103824
origin/main: 29cccdffd8888e7f02552e89e162dae4d5103824
Ahead/behind: 0/0
Sprint 009 implementation: 4c642216f08c62d85ff2dd640a0c8d043c7fd8f2
Schema version: 4
Finding version: 1
Tests: 145 passed, 0 failed
```

The authoring inspection found one unrelated untracked file:

```text
.DS_Store
```

Preserve it and do not include it in Sprint 010's diff or commit.

Before implementation verify the baseline. The expected authoring artifact may
be this document alone. If HEAD materially differs, Sprint 009 is not complete,
or the tree contains additional unexplained changes, STOP and report them.

---

# 27. Canonical Reading Order

Before implementation read:

1. `docs/internal/PRODUCT_DEFINITION.md`
2. `docs/internal/TECHNICAL.md`
3. `docs/internal/ARCHITECTURE.md`
4. `docs/internal/ROADMAP.md`
5. `docs/internal/sprints/SPRINT-009.md`
6. `docs/internal/sprints/SPRINT-010.md`

Treat them as authoritative. Do not rewrite Canon to make implementation
easier. Stop for founder review if the required slice contradicts Canon.

---

# 28. Baseline Architecture to Inspect

Inspect at minimum:

```text
src/application/mod.rs
src/application/scan.rs
src/cli/mod.rs
src/findings/model.rs
src/findings/engine.rs
src/analysis/model.rs
src/graph/projection.rs
src/persistence/repos.rs
src/persistence/analysis.rs
src/persistence/findings.rs
src/persistence/db.rs
tests/integration/sprint008_analysis_test.rs
tests/integration/sprint009_finding_test.rs
tests/persistence/analysis_test.rs
tests/persistence/findings_test.rs
```

Confirm:

```text
CLI currently exposes only init and scan
application currently exposes only InitService and ScanService
FindingRepo supports exact get and per-Scan ordered list
Finding child records preserve positions
AttackPaths and Finding Evidence are scan-scoped
Observation snapshots preserve historical graph state
graph projection already validates historical snapshots and same-scan Evidence
AttackPath edges preserve FORWARD and REVERSE traversal
Finding reasons currently share a broad supporting reference union
Finding metadata is currently empty
pico scan does not yet expose the Finding ID
schema version is 4
```

---

# 29. Implementation Plan Requirement

Before code changes produce a concise plan covering:

```text
latest COMPLETE Scan selection and freshness warning
read-only historical graph loading/projection
Finding list and detail DTOs
same-scan and reference integrity validation
traversal-aware path composition
reason, Evidence, boundary, and remediation presentation
CLI subcommands and scan navigation hint
empty and error states
determinism and secret safety
fixtures and tests
```

Call out genuine architecture friction, especially:

```text
mutable stable Resource and Relationship rows
reverse traversal of influence edges
broad per-reason reference unions
empty Finding metadata
historical or stale-result presentation after a newer incomplete Scan
```

Do not solve these by duplicating graph projection, adding provider logic to
the CLI, recomputing Findings, or dumping raw metadata.

---

# 30. Required Fixtures and Tests

Add sanitized deterministic fixtures for:

1. No Scans.
2. Scans exist but none is COMPLETE.
3. Latest COMPLETE Scan with zero Findings.
4. Latest COMPLETE Scan with one golden Finding.
5. Newer RUNNING Scan after a COMPLETE Scan.
6. Newer PARTIAL Scan after a COMPLETE Scan.
7. Newer FAILED Scan after a COMPLETE Scan.
8. Exact historical Finding lookup.
9. Historical Finding followed by a newer COMPLETE Scan.
10. Unknown Finding ID.
11. One Finding grouping multiple paths and multiple Sinks.
12. Two paths reaching the same Sink.
13. A path containing REVERSE traversal.
14. Disconnected, phase-invalid, or position-gapped ordered records.
15. Later Scan updating stable Resource or Relationship state.
16. Missing linked AttackPath or path edge.
17. Missing or foreign-scan Evidence.
18. Missing historical Observation snapshot.
19. Malformed or inconsistent boundary metadata.
20. Secret and authorization-header sentinels.
21. ANSI escape, CR/LF, tab, and control-character strings.
22. Unsupported older and newer schema versions.
23. Unsupported Finding, analysis, and Observation snapshot versions.

At minimum test:

```text
newest COMPLETE selection is deterministic
newer incomplete attempts produce visible freshness warnings
zero Findings is scoped and never presented as global safety
list ordering follows the exact severity/confidence/title/fingerprint/id rule
exact IDs resolve and unknown IDs fail
an older Finding is HISTORICAL after a newer COMPLETE Scan
historical detail uses the originating Scan snapshot
later stable-row updates do not rewrite historical explanation
FORWARD and REVERSE traversal render a connected source-to-Sink path
every path step links to exact same-scan supporting Evidence IDs
all grouped paths and Sinks remain visible
two paths to one production Sink produce an affected-Sink count of one
path edges are connected, phase-valid, and position-contiguous
all six reasons render in stored order with fixed text
reason Evidence is not overstated as uniquely scoped
Finding Evidence support roles are not overstated as unique proof
severity and confidence are displayed separately and never recomputed
Evidence fields are minimized and same-scan
boundary wording says no proven enforced boundary interrupts the path
all four remediations preserve stored order and exact targets
broken references fail closed
unsupported schema and record versions fail without migration or writes
repeated reads produce identical output and zero writes
secret sentinels never appear
terminal control strings cannot alter the output structure
network and provider call counts remain zero
```

No fixture may contain a real credential.

---

# 31. Required Integration Results

Through the controlled application and CLI seams verify:

```text
golden COMPLETE scan:
  selected Scan is the expected COMPLETE Scan
  Findings 1
  class UNTRUSTED_TO_PRODUCTION
  severity CRITICAL
  confidence HIGH
  paths 1
  affected production resources 1

golden detail:
  complete ordered source-to-Sink path
  six reasons
  exact same-scan Evidence
  honest no-interrupting-boundary narrative
  four ordered remediation cut points
  potential-exposure scope note

newer PARTIAL scan:
  older COMPLETE result may remain queryable
  freshness warning is visible
  older result is not labeled current

historical update case:
  historical names, kinds, endpoints, states, and safe metadata come from the
  historical scan projection
  no Evidence from a later Scan appears

query behavior:
  Scan count unchanged
  Finding count unchanged
  all row counts unchanged
  provider calls 0
  network requests 0
```

For a multi-Finding controlled Scan, verify that `pico scan` prints every exact
Finding ID in the same deterministic order as `pico findings`.

Inspect SQLite before and after the commands and prove no write occurred.

---

# 32. Controlled Manual Verification

Using a temporary initialized workspace and the controlled golden fixture:

1. Produce one completed production Finding through the existing injected
   provider seam.
2. Run `pico findings`.
3. Copy the exact displayed Finding ID.
4. Run `pico finding <id>`.
5. Verify the complete path, Evidence, boundaries, and four remediations.
6. Record SQLite row counts.
7. Repeat both queries and verify stable output and unchanged row counts.
8. Add a newer PARTIAL fixture Scan and verify the freshness warning.
9. Query the historical Finding again and verify its originating snapshot.
10. Search stdout, stderr, and SQLite for both secret sentinels.

Expected semantic list output:

```text
Status: COMPLETE
Findings: 1
Class: UNTRUSTED_TO_PRODUCTION
Severity: CRITICAL
Confidence: HIGH
Paths: 1
Affected production resources: 1
ID: finding_...
```

Expected semantic detail output includes:

```text
Potential exposure, not exploitation
External GitHub Content → GitHub MCP Tool → OpenCode → Bash
  → Cloudflare Credential → Cloudflare Worker
No proven enforced boundary recorded for this scan interrupts this path
Recommendations only; no change was applied
```

Controlled live Cloudflare dogfood remains a roadmap follow-up. Do not obtain
credentials or perform a write operation for this sprint.

---

# 33. Developer Comprehension Check

Before completion, ask a developer who did not implement the feature to inspect
the controlled output and answer:

1. What externally controlled source begins the path?
2. Which autonomous Actor joins influence to authority?
3. What production capability is reachable?
4. Why is the Finding severe?
5. Why is Pico confident?
6. Which Evidence supports the conclusion?
7. What did Pico establish about enforced boundaries?
8. Name at least one practical cut point.
9. Did Pico prove exploitation?
10. Did Pico apply a remediation?

Record whether the check ran and what was unclear. A fixture author may not be
the sole comprehension participant.

If no independent developer is available, record the gate as `NOT RUN`. Do not
claim the roadmap comprehension criterion is complete.

---

# 34. Architecture Pressure Test

Before completion answer:

1. Do both commands call an application service rather than query SQLite from
   the CLI?
2. Does `pico findings` deterministically select the newest COMPLETE Scan?
3. Is a newer incomplete or failed attempt always visible?
4. Can an empty result be mistaken for a global all-clear?
5. Does exact Finding lookup preserve its originating Scan?
6. Are historical Resources and Relationships reconstructed from Observation
   snapshots rather than current mutable rows?
7. Does path rendering honor FORWARD and REVERSE traversal?
8. Are all grouped paths and affected Sinks visible?
9. Are severity, confidence, eligibility, and grouping read rather than
   recomputed?
10. Does every linked AttackPath and Evidence row belong to the Finding's Scan?
11. Do broken references fail closed rather than produce a partial explanation?
12. Are reason narratives fixed and provider-neutral?
13. Does broad per-reason support remain honestly labeled?
14. Does boundary wording avoid claiming that no boundary exists?
15. Are remediations presented without being executed?
16. Are raw metadata, credentials, headers, and unsafe paths absent from output?
17. Do explanation commands perform zero network and provider calls?
18. Do explanation commands perform zero database writes?
19. Does one coherent read snapshot back each composed result?
20. Are all persisted strings terminal-safe before rendering?
21. Did the implementation avoid a schema migration unless explicitly reviewed?
22. Did Pico MCP and all Sprint 011+ functionality remain absent?

If any answer is NO, do not hide it. Fix only if clearly within Sprint 010;
otherwise STOP and report it.

---

# 35. Definition of Done

Sprint 010 is complete only when:

- [ ] Baseline `29cccdf` is verified and unrelated `.DS_Store` is preserved.
- [ ] `pico findings` exists and delegates through the application layer.
- [ ] `pico finding <id>` exists and delegates through the application layer.
- [ ] Latest COMPLETE Scan selection is deterministic.
- [ ] Newer RUNNING, PARTIAL, or FAILED attempts produce visible freshness
      warnings.
- [ ] No-scan, no-COMPLETE-scan, and zero-Finding states are distinct.
- [ ] Empty output never claims global safety.
- [ ] Finding summaries include exact identity, severity, confidence, status,
      path count, and affected Sink count.
- [ ] Exact Finding IDs resolve; unknown and prefix-only IDs fail safely.
- [ ] Historical details use the originating Scan's Observation snapshots.
- [ ] Path rendering honors stored traversal and produces a connected path.
- [ ] Every security-critical path step identifies its supporting same-scan
      Evidence IDs.
- [ ] All grouped paths and affected Sinks remain visible.
- [ ] Affected production Sink counts deduplicate exact Sink Resource IDs.
- [ ] Ordered child positions are contiguous and every path is connected and
      phase-valid.
- [ ] All persisted reasons render with fixed provider-neutral explanations.
- [ ] Broad reason references are not overstated as uniquely scoped Evidence.
- [ ] Severity and confidence remain separate persisted decisions.
- [ ] Evidence is same-scan, minimized, ordered, and complete.
- [ ] Severity, confidence, and remaining uncertainty have deterministic
      explanation without a second scoring engine.
- [ ] Boundary and uncertainty narration is accurate and non-absolute.
- [ ] Remediations preserve order and exact cut targets.
- [ ] Output states that the Finding is a potential exposure, not exploitation.
- [ ] Output states that recommendations were not applied.
- [ ] Missing, malformed, and cross-scan associations fail closed.
- [ ] Unsupported schema, Finding, analysis, and snapshot versions fail closed.
- [ ] Schema mismatch does not change `user_version`, run migrations, or write
      rows.
- [ ] Repeated queries are deterministic and perform zero database writes.
- [ ] Secret sentinels have zero output and persistence occurrences.
- [ ] ANSI and control-character sentinels cannot spoof terminal output.
- [ ] Query commands perform zero network/provider operations.
- [ ] Each query composes from one coherent read transaction/snapshot.
- [ ] `pico scan` provides every exact Finding ID needed for navigation in
      deterministic order.
- [ ] Full verification passes.
- [ ] Final diff contains no MCP or Sprint 011+ functionality.
- [ ] Developer comprehension check is recorded honestly.
- [ ] This document records completion evidence.

---

# 36. Full Verification

After implementation run:

```text
cargo test
cargo check
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

Report exact totals. Run controlled CLI/SQLite checks, output determinism checks,
secret-sentinel searches, and the architecture pressure test. Do not declare
completion from focused tests alone.

---

# 37. Final Diff Inspection

Review for:

```text
accidental files or .DS_Store
build artifacts or .pico state
real credentials or machine paths
raw metadata rendering
SQL or security logic in CLI
duplicate snapshot interpretation
recomputed Finding semantics
provider-specific application DTOs
unordered output
current-state leakage into historical detail
cross-scan Evidence
silent partial explanations
absolute no-boundary or global-safety claims
database writes during queries
network or provider calls
schema changes
new Finding classes
blocked-path browser
JSON, filters, exports, or CI policy
Pico MCP or Sprint 011+ functionality
unnecessary dependencies
```

Do not perform unrelated refactoring.

---

# 38. Stop Conditions

Stop and report if:

```text
baseline is materially unexpected
the worktree contains unexplained changes beyond the known .DS_Store
Canon contradicts the required UX
historical graph state cannot be reconstructed from Observation snapshots
path traversal cannot be rendered without recomputing analysis
same-scan Finding, path, and Evidence integrity cannot be validated
safe Evidence explanation requires raw metadata or source rereads
boundary metadata cannot support an honest narrative
implementation requires changing Finding security semantics
implementation requires a schema migration not reviewed in the plan
the query path cannot open and validate SQLite without migrations or writes
query commands require discovery, network access, or provider calls
persisted text cannot be rendered safely in the terminal
linked path edges cannot be proven connected and phase-valid
```

Do not silently weaken integrity or explanation precision to make the fixture
pass.

---

# 39. Completion Evidence

When implementation and verification pass, set `Status: COMPLETE` and record:

```text
completion date and verified baseline
implementation commit
repository state
test totals and Rust checks
schema and Finding versions
list and detail command results
latest COMPLETE and freshness-warning results
historical snapshot and traversal results
reason, Evidence, boundary, and remediation results
empty, not-found, and corrupt-link results
determinism and database-write counts
secret-sentinel results
network/provider mutation counts
architecture pressure-test answers
developer comprehension result
controlled-real-environment status
roadmap decision
```

Do not claim the full v0.1 exit gate if controlled dogfood or independent
developer comprehension remains incomplete.

---

# 40. Commit Policy

The authoring-only document may be committed separately with:

```text
docs(sprints): define Sprint 010 finding explanation
```

If and only if Sprint 010 is fully verified, stage only Sprint 010
implementation changes, inspect the staged diff, and commit with:

```text
feat(cli): explain persisted findings
```

Record completion evidence in a separate documentation commit if needed.

Do not amend previous commits. Do not push unless explicitly instructed. Do
not begin Sprint 011.

---

# 41. Final Report Contract

Report:

```text
Sprint: SPRINT-010 — First Explanation — Finding Navigation
Status: COMPLETE or BLOCKED
Baseline: <verified SHA>
Implementation commit: <SHA + message>

Commands:
pico findings: PASS | FAIL
pico finding <id>: PASS | FAIL
pico scan navigation hint: PASS | FAIL

Golden explanation:
Class: UNTRUSTED_TO_PRODUCTION
Severity: CRITICAL
Confidence: HIGH
Paths shown: <count>
Affected production Sinks shown: <count>
Reasons shown: <count>
Evidence complete: YES | NO
Boundary narrative: <result>
Remediation cut points shown: <count>

Selection and history:
Latest COMPLETE selected deterministically: YES | NO
Newer incomplete Scan warning: YES | NO
Historical snapshot preserved: YES | NO
Reverse traversal rendered correctly: YES | NO

Negative and integrity cases:
No Scan: <result>
No COMPLETE Scan: <result>
Zero Findings: <result>
Unknown Finding ID: <result>
Broken link: <result>
Cross-scan Evidence: <result>

Safety:
New Scans created by query commands: 0
Database writes: 0
Network requests: 0
Provider operations: 0
Secret sentinel persisted or emitted: NO
Automatic remediation performed: NO

Scope:
Finding security semantics changed: NO
Additional Finding classes: NO
Schema migration: NO
JSON/filters/history UX implemented: NO
Blocked-path browser implemented: NO
Pico MCP implemented: NO
Sprint 011 functionality implemented: NO

Verification:
<tests and all required checks>

Developer comprehension:
<PASS, FAIL, or NOT RUN with notes>

Repository:
Branch: <branch>
HEAD: <SHA>
origin/main: <SHA>
Ahead/behind: <state>
Working tree: <state, including preserved unrelated .DS_Store>

Follow-ups:
<only genuine controlled-dogfood, comprehension, or Slice 10 observations>
```

Do not call a potential exposure exploited. Do not call zero Findings an all-
clear. Do not call a historical result current when a newer scan attempt
exists.

---

# 42. Sprint Exit

Sprint 010 ends when a developer can run:

```text
pico findings
pico finding <id>
```

and Pico can reliably answer:

> **This is the persisted Finding, this is the complete path, this is why it
> matters, this is the Evidence behind it, this is what Pico established about
> boundaries and uncertainty, and these are the exact places where the path can
> be broken.**

It does not yet answer through an AI-agent interface:

> **Ask Pico for the same Finding through MCP.**

That belongs to the next explicitly authorized agent-native interface sprint.

Do not begin Sprint 011.

Wait for explicit authorization.

---

# 43. Completion Evidence

**Sprint:** SPRINT-010 — First Explanation — Finding Navigation
**Status:** COMPLETE
**Completion date:** 2026-08-25
**Baseline verified:** `29cccdffd8888e7f02552e89e162dae4d5103824` (main, 0/0 ahead/behind; unrelated `.DS_Store` preserved)
**Schema version:** 4 (unchanged)
**Finding version:** 1
**Analysis version:** 1
**Graph snapshot version:** 1

**Implementation commits:**
- `feat(cli): explain persisted findings` — Sprint 010 implementation.
- `docs(sprints): define Sprint 010 finding explanation` — this document with completion evidence.

**Commands:**
- `pico findings`: PASS
- `pico finding <id>`: PASS
- `pico scan` navigation hint: PASS (prints every Finding ID in §8 order via `finding_navigation_ids`)

**Golden explanation (controlled provider seam):**
- Class: UNTRUSTED_TO_PRODUCTION
- Severity: CRITICAL
- Confidence: HIGH
- Paths shown: 1 (5 steps; 6 historical nodes; REVERSE×2 → FORWARD×3; connected source-to-Sink chain; phase transition lands on the declared Actor)
- Affected production Sinks shown: 1 (deduped; multi-path fixtures prove 2 paths → 1 Sink counts once)
- Reasons shown: 6 in stored order with fixed provider-neutral text
- Evidence complete: YES (minimized, same-scan, safe locators)
- Boundary narrative: "No proven enforced boundary recorded for this scan interrupts this path."
- Remediation cut points shown: 4 in stored order with resolved historical targets

**Selection and history:**
- Latest COMPLETE selected deterministically: YES (`completed_at DESC, started_at DESC, id DESC`)
- Newer incomplete Scan warning: YES (RUNNING/PARTIAL/FAILED exact wording)
- Historical snapshot preserved: YES (originating Scan Observations; later stable-row rename does not rewrite history)
- Reverse traversal rendered correctly: YES

**Negative and integrity cases:** no-Scan guidance; no-COMPLETE non-authoritative state; zero-Findings scoped language; unknown/prefix/empty ID errors; missing path link; foreign-scan Evidence; unsupported schema 3/5 without migration; unsupported Finding version; NULL/malformed/INTERRUPTS/UNRESOLVED boundary metadata; gapped positions; disconnected edges; remediation targeting unlinked relationship; non-production sink impact; missing Observation snapshot — all fail closed.

**Safety:**
- New Scans created by query commands: 0
- Database writes: 0 (SQLITE_OPEN_READ_ONLY; byte-identical DB hash across repeated queries)
- Network requests: 0
- Provider operations: 0
- Secret sentinel persisted or emitted: NO (`TEST_SECRET_SHOULD_NOT_PERSIST`, `TEST_AUTH_HEADER_SHOULD_NOT_APPEAR`)
- Automatic remediation performed: NO

**Scope:** Finding security semantics unchanged; no additional Finding classes; no schema migration; no JSON/filters/history UX; no blocked-path browser; no Pico MCP; no Sprint 011 functionality.

**Verification:**
- `cargo test`: 189 passed, 0 failed (61 unit + 30 domain + 60 integration + 38 persistence)
- `cargo check`: clean
- `cargo clippy --all-targets -- -D warnings`: clean
- `cargo fmt --check`: clean
- `cargo build --release`: clean
- Controlled CLI checks: `pico init` / `pico scan` / `pico findings` / `pico finding <id>` exercised on a temporary workspace; repeated queries byte-identical and zero-write; unknown ID exits non-zero.

**Developer comprehension:** NOT RUN — no independent developer was available; the roadmap comprehension gate is not claimed.

**Controlled live Cloudflare dogfood:** NOT RUN — fixture-backed explanation only; remains a roadmap follow-up.

**Roadmap decision:** EXTEND v0.1 (fixture-backed explanation works; real-developer comprehension and controlled dogfood remain separate gates).
