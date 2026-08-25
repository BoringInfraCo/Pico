# Pico — Sprint 009: First Finding — Untrusted to Production

**Status:** COMPLETE
**Sprint:** 009
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `8f2987a`
**Depends on:** Sprint 008 — First Attack Path — Deterministic Golden-Path Analysis
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Convert Pico's first deterministic active AttackPath into one useful,
evidence-backed security Finding.

Sprint 008 established:

> **Pico can determine whether the observed golden path is active, blocked,
> absent, or unresolved, with exact evidence for the conclusion.**

Sprint 009 must establish:

> **Pico can turn a qualifying active path to explicitly classified production
> authority into a stable `UNTRUSTED_TO_PRODUCTION` Finding with transparent
> severity, confidence, evidence aggregation, and practical remediation cut
> points.**

The pipeline is:

```text
Current completed Scan
        ↓
SecurityGraph
        ↓
AnalysisResult
        ↓
ACTIVE AttackPath[]
        ↓
Finding eligibility and grouping
        ↓
Severity + Confidence
        ↓
Evidence + Reasons + Remediation cut points
        ↓
UNTRUSTED_TO_PRODUCTION Finding
        ↓
SQLite + pico scan summary
```

This sprint answers:

> **What should the developer care about when Pico proves the golden path?**

It does not yet implement the complete explanation experience or new Finding
navigation commands.

---

# 2. Roadmap Position

Sprint 009 implements Architecture Slice 8:

```text
UNTRUSTED_TO_PRODUCTION
severity
confidence
evidence aggregation
remediation cut points
```

Architecture Slice 7 is complete:

```text
InfluencePath
AuthorityPath
BoundaryEvaluation
AttackPath
```

Architecture Slice 9 remains future work:

```text
pico findings
pico finding <id>
full path explanation
reason-by-reason evidence presentation
unknown and boundary narrative
remediation detail UX
```

Sprint 009 may extend the existing `pico scan` summary enough to prove that the
Finding exists. It must not implement the Slice 9 commands or a second scanner.

Completing Sprint 009 does not by itself complete v0.1. Controlled real-
environment dogfood, developer comprehension, and any separately authorized
explanation or MCP gates remain open.

Expected roadmap decision after this sprint:

```text
EXTEND v0.1
```

Do not advance to v0.2 solely because the first Finding exists in fixtures.

---

# 3. Required Product Claim

At completion, Pico must be able to say:

```text
Finding: UNTRUSTED_TO_PRODUCTION
Severity: CRITICAL
Confidence: HIGH

Externally controlled content can reach an autonomous coding environment with
explicitly classified production mutation authority.
```

The claim must remain narrower than:

```text
The path was exploited.
The content is malicious.
The agent is compromised.
The Worker is production because its name looks production-like.
Pico verified mutation by performing a write.
```

The Finding describes a potential exposure established from current scan
evidence. It is not a runtime incident or exploitation verdict.

---

# 4. Golden Finding Contract

The one Finding class in scope is:

```text
UNTRUSTED_TO_PRODUCTION
```

The required path remains:

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
Cloudflare Worker classified as PRODUCTION
```

The Finding is provider-neutral at the domain and rule-engine boundary even
though the first controlled fixture uses GitHub, OpenCode, and Cloudflare.

No provider adapter may create a Finding.

---

# 5. Production Classification Is Mandatory

Sprint 008 intentionally recorded this pressure point:

> **Consequential does not mean production.**

The current Cloudflare Worker normalization uses:

```text
consequential_sink: true
environment: UNKNOWN
```

That state may form an active AttackPath to a consequential sink, but it must
not produce `UNTRUSTED_TO_PRODUCTION`.

```text
consequential_sink = true
sink_impact = UNKNOWN
→ active AttackPath may exist
→ UNTRUSTED_TO_PRODUCTION Finding = NO
```

```text
consequential_sink = true
sink_impact = PRODUCTION
production classification has same-scan authoritative Evidence
→ Finding eligibility may continue
```

Production classification must come from an explicit supported signal. It
must not come from:

```text
resource names containing prod or production
Worker presence alone
account names alone
credential breadth alone
hard-coded provider assumptions
test file names
arbitrary user files
LLM judgment
```

If the existing bounded Cloudflare API cannot authoritatively distinguish
production from staging, production remains `UNKNOWN` in normal scans. The
controlled provider seam may inject a sanitized explicit `PRODUCTION`
classification and supporting Evidence for deterministic tests.

The implementation may add the smallest normalized environment/sink-impact
field required to carry that fact. Unknown remains the production default.

Do not invent live compatibility behavior or broaden provider network calls to
solve this classification.

---

# 6. Finding Eligibility Rule

Generate `UNTRUSTED_TO_PRODUCTION` only when all conditions are true:

```text
Scan.status == COMPLETE
Analysis.status == COMPLETE
AttackPath.disposition == ACTIVE
source_trust IN {PUBLIC_EXTERNAL, OPEN_WORLD, AUTHENTICATED_EXTERNAL}
influence_strength IN {
  AGENT_RETRIEVABLE,
  AUTOMATICALLY_INJECTED,
  INSTRUCTION_BEARING
}
capability IN {EXECUTE, ADMIN}
authority_resolution IN {EXACT, SCOPED}
sink_impact == PRODUCTION
no BoundaryEvaluation == INTERRUPTS
no security-critical UNKNOWN state
all path and production-classification Evidence belongs to the current Scan
```

`SCOPED` is eligible only when the exact target is proven within the observed
scope. A broad or ambiguous scope is unresolved and cannot qualify.

The rule must be ordinary deterministic Rust code. Do not use an LLM,
probabilistic classifier, remote scoring service, or mutable rule download.

---

# 7. Non-Eligibility Rules

The following produce zero `UNTRUSTED_TO_PRODUCTION` Findings:

```text
no AttackPath
BLOCKED AttackPath
UNRESOLVED candidate
LIMITED analysis
FAILED analysis
PARTIAL Scan
sink_impact UNKNOWN
sink_impact STAGING
sink_impact LOCAL_DEV
authority_resolution UNKNOWN
authority_resolution BEHAVIORAL_READ_ONLY
unknown or unsupported capability
unknown source trust
manual-only or metadata-only influence
missing same-scan Evidence
inconsistent scan ownership
```

Blocked paths remain persisted analysis results. They do not become active
Findings merely to explain that a boundary exists. Sprint 010 may present
blocked-path explanation.

---

# 8. Finding Domain

Introduce provider-neutral Finding types outside adapters, for example:

```text
src/findings/
  mod.rs
  model.rs
  engine.rs
  severity.rs
  confidence.rs
  remediation.rs
```

An equivalently small organization is acceptable.

Conceptual types:

```text
Finding
FindingClass
FindingStatus
Severity
Confidence
FindingReason
Remediation
RemediationCutPoint
FindingResult
```

Do not add provider-specific Finding types, dynamic plugins, arbitrary rule
scripting, or remote rule loading. Adapters produce facts; the Finding engine
produces security stories.

---

# 9. Finding Shape

The first Finding should contain at least:

```text
Finding {
  id
  scan_id
  fingerprint
  finding_version
  finding_class
  status
  title
  summary
  severity
  confidence
  source_resource_ids[]
  actor_resource_ids[]
  sink_resource_ids[]
  attack_path_ids[]
  evidence_ids[]
  reasons[]
  remediations[]
  created_at
}
```

Use normalized resource, path, relationship, and evidence identifiers. Do not
persist copied raw configuration or provider responses in the Finding.

Initial fixed values:

```text
finding_class: UNTRUSTED_TO_PRODUCTION
status: OPEN
```

Lifecycle transitions such as resolved, accepted, suppressed, or reopened are
future work.

---

# 10. Title, Summary, and Reasons

Use stable deterministic templates.

Recommended title:

```text
External content can reach production mutation authority
```

Recommended summary:

```text
Externally controlled content can reach an autonomous coding environment with
authority capable of changing an explicitly classified production resource.
```

Create a small structured reason vocabulary:

```text
EXTERNAL_INFLUENCE_SOURCE
AGENT_RETRIEVABLE_CONTENT
AUTONOMOUS_EXECUTION_CAPABILITY
REACHABLE_CREDENTIAL_AUTHORITY
PRODUCTION_MUTATION_AUTHORITY
NO_ENFORCED_BOUNDARY
```

Each reason references exact Resources, Relationships, AttackPaths, and
Evidence. Reasons are structured facts, not generated prose or Explanation UX.

Do not interpolate raw source locators, credentials, provider responses, or
secret-like metadata into title, summary, or reasons.

---

# 11. Severity Contract

Severity answers:

> **What could happen if the proven path is usable?**

Define:

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

Only the bounded rules needed for the first class must be implemented.

```text
PUBLIC_EXTERNAL or OPEN_WORLD
+ AGENT_RETRIEVABLE / AUTOMATICALLY_INJECTED / INSTRUCTION_BEARING
+ EXECUTE or ADMIN
+ PRODUCTION
+ ACTIVE path
= CRITICAL
```

```text
AUTHENTICATED_EXTERNAL
+ AGENT_RETRIEVABLE / AUTOMATICALLY_INJECTED / INSTRUCTION_BEARING
+ EXECUTE or ADMIN
+ PRODUCTION
+ ACTIVE path
= HIGH
```

No numeric risk score is required. Severity must not increase because
confidence is high. Severity and confidence remain independent.

---

# 12. Confidence Contract

Confidence answers:

> **How strongly can Pico establish that this Finding exists?**

Define:

```text
LOW
MEDIUM
HIGH
```

For the first emitted Finding, `HIGH` requires:

```text
COMPLETE Scan
COMPLETE analysis
ACTIVE AttackPath
all security-critical Relationships CONFIRMED or DERIVED
all supporting Evidence DIRECT, DECLARED, or DERIVED
no INFERRED Evidence in a security-critical claim
EXACT authority, or SCOPED authority with exact target inclusion
explicit PRODUCTION classification with current-scan Evidence
no unresolved boundary
```

The weakest security-critical fact constrains confidence. Do not average or
vote away a weaker fact.

Sprint 008 does not persist inferred active AttackPaths. Sprint 009 must not
reconstruct them to manufacture a MEDIUM-confidence Finding. `MEDIUM` and
`LOW` remain in the vocabulary for future supported Finding contracts. If the
`HIGH` rule is not satisfied, emit no `UNTRUSTED_TO_PRODUCTION` Finding.

---

# 13. Evidence Aggregation

The Finding evidence set is the sorted union of:

```text
all supporting Evidence for grouped AttackPaths
all boundary-evaluation Evidence relevant to the active conclusion
the Evidence establishing sink_impact == PRODUCTION
```

Requirements:

```text
every Evidence ID resolves
every Evidence row belongs to Finding.scan_id
no duplicate Evidence IDs
deterministic ordering
no raw secret material
no evidence from historical scans
```

Evidence aggregation fails closed. If a security-critical Evidence reference
is absent, foreign, or malformed, do not persist the Finding. Persist links;
do not copy full Evidence observations into Finding metadata.

---

# 14. Finding Grouping

AttackPath and Finding are not one-to-one.

Group paths only when they represent the same security story:

```text
same finding class
same source security identity or source class
same autonomous Actor identity
same authority mechanism
same production classification contract
same severity
same confidence
```

Multiple production sinks may belong to one Finding when the same source,
Actor, capability chain, and authority mechanism reach them.

```text
Issue → OpenCode → Credential → Worker A
Issue → OpenCode → Credential → Worker B

→ one UNTRUSTED_TO_PRODUCTION Finding
→ two AttackPath links
→ two affected Sink resources
```

Do not group across different Actors or materially different authority
mechanisms. Use the smallest grouping rule that satisfies the golden fixture;
do not build a generic correlation framework.

---

# 15. Finding Identity

Finding identity must be stable across equivalent scans and scan-scoped in
persistence.

```text
id = finding_<scan-id>:<fingerprint-digest>
fingerprint = sha256(canonical finding input)
```

Canonical fingerprint input includes deterministic, unambiguous values for:

```text
finding_version
finding_class
sorted source canonical keys
sorted Actor canonical keys
sorted Sink canonical keys
sorted AttackPath fingerprints
severity
confidence
sorted remediation rule identifiers
```

It excludes:

```text
Scan ID
Finding ID
AttackPath IDs
Evidence IDs
timestamps
database row order
absolute machine paths
raw secret values
```

Two equivalent scans produce two scan-scoped Finding rows, two distinct IDs,
and one stable fingerprint. Security-significant changes to affected sinks,
paths, severity, confidence, or remediation change the fingerprint predictably.

---

# 16. Remediation Cut Points

Pico remains read-only.

For each Finding derive candidate cuts from exact path edges:

```text
RESTRICT_EXTERNAL_RETRIEVAL
ENFORCE_BASH_APPROVAL_OR_DENY
REMOVE_AGENT_CREDENTIAL_REACHABILITY
SCOPE_PRODUCTION_MUTATION_AUTHORITY
```

Each remediation contains:

```text
rule_id
title
description
security_effect
cut_phase
target_resource_ids[]
target_relationship_ids[]
```

Suggested deterministic presentation order:

1. Restrict the exact external retrieval capability for the privileged Actor.
2. Require technically enforced, non-bypassable approval or deny for Bash.
3. Remove the credential from the Actor-reachable execution environment.
4. Scope mutation authority away from the affected production target.

This order is stable, not an operational-risk optimizer. Do not implement
credential revocation, policy mutation, configuration edits, or enforcement.

---

# 17. Finding Engine Boundary

Maintain:

```text
CLI
 ↓
Application
 ↓
Discovery / Adapters
 ↓
Domain + Persistence
 ↓
Graph
 ↓
Analysis
 ↓
Finding Engine
 ↓
Persistence
```

The Finding engine consumes normalized current-scan graph and analysis
results. It must not read configurations or environment variables, call
providers, inspect raw payloads, perform discovery, or use historical facts to
complete a current claim.

Provider-specific knowledge remains outside the Finding domain.

---

# 18. ScanService Integration

Run Finding generation only after:

```text
discovery completed
normalized state persisted
graph projection succeeded
analysis completed without limits or integrity failure
AttackPath persistence succeeded
```

Required semantics:

```text
COMPLETE scan + eligible path → Finding generation
COMPLETE scan + no eligible path → zero Findings
PARTIAL scan → zero positive Findings
LIMITED analysis → zero positive Findings
FAILED analysis → Scan FAILED, no Finding
Finding integrity/persistence failure → Scan FAILED, safe error
```

Persist Findings before completing the Scan so persistence failure cannot
leave a false success. Finding generation must not upgrade PARTIAL or LIMITED.

---

# 19. SQLite Persistence

Add one append-oriented migration after schema version 3.

Recommended tables:

```text
findings
finding_paths
finding_evidence
finding_reasons
finding_remediations
```

Core queryable fields must not be hidden in one opaque JSON blob.

Minimum `findings` fields:

```text
id TEXT PRIMARY KEY
scan_id TEXT NOT NULL REFERENCES scans(id)
fingerprint TEXT NOT NULL
finding_version TEXT NOT NULL
finding_class TEXT NOT NULL
title TEXT NOT NULL
summary TEXT NOT NULL
severity TEXT NOT NULL
confidence TEXT NOT NULL
status TEXT NOT NULL
metadata TEXT
created_at TEXT NOT NULL
UNIQUE(scan_id, fingerprint)
```

`finding_paths` preserves deterministic position and references persisted
AttackPaths. `finding_evidence` preserves deterministic position and
references same-scan Evidence. Remediations preserve order and exact cut-point
references.

Use foreign keys, checks, uniqueness constraints, and indexes consistent with
existing persistence style. Do not add lifecycle history, suppression,
assignment, comments, or remote sync.

---

# 20. CLI Contract

Extend `pico scan` only enough to prove the first Finding.

Eligible golden fixture output should include semantically:

```text
Status: COMPLETE
Analysis: COMPLETE
Potentially Active AttackPaths: 1
Findings: 1
Finding: UNTRUSTED_TO_PRODUCTION
Severity: CRITICAL
Confidence: HIGH
```

Unknown production classification remains honest:

```text
Potentially Active AttackPaths: 1
Findings: 0
Production Classification: UNKNOWN
```

Blocked, unresolved, partial, and empty cases retain `Findings: 0`.

Do not implement `pico findings`, `pico finding <id>`, filters, pagination,
history UX, rich explanation rendering, exports, SARIF, or MCP Finding tools.

---

# 21. Determinism and Limits

Eligibility, grouping, severity, confidence, reasons, evidence ordering,
remediation ordering, fingerprints, and CLI ordering must be deterministic.

Never depend on hash-map iteration order, unordered database rows, runtime
IDs, timestamps, evidence insertion timing, or machine paths.

Define explicit limits for:

```text
maximum AttackPaths examined
maximum groups
maximum paths per Finding
maximum Evidence links per Finding
maximum reasons per Finding
maximum remediations per Finding
maximum emitted Findings
```

If limits prevent complete evaluation:

```text
Finding generation: LIMITED
Scan: PARTIAL
positive Findings from incomplete evaluation are not persisted
```

Do not truncate silently.

---

# 22. Safety

Finding generation performs:

```text
network requests: 0
provider operations: 0
filesystem reads: 0
environment reads: 0
system mutation: 0
```

The controlled integration fixture may use the existing injected provider
seam. It must not use real credentials or provider mutation.

No Finding field may contain credentials, authorization headers, secret
environment values, raw OpenCode configuration, or raw provider responses.

Use `TEST_SECRET_SHOULD_NOT_PERSIST` and authorization-header sentinels to
verify database and CLI output remain clean.

---

# 23. Scope

Sprint 009 includes only:

```text
one Finding class
deterministic severity and confidence
Finding grouping
evidence aggregation
structured reasons
remediation cut points
SQLite persistence
minimal pico scan summary
fixtures and tests
```

Sprint 009 does not include:

```text
additional Finding classes
Finding lifecycle or suppression
severity overrides
user-authored policies
generic rule DSL
LLM Finding generation
new adapters or providers
new cloud API calls
write validation
automatic remediation or enforcement
pico findings
pico finding <id>
full explanation UX
Pico MCP
runtime monitoring
CI gates or alerts
Sprint 010 functionality
```

Architect for extension. Implement only this slice.

---

# 24. Baseline

Expected implementation baseline:

```text
Branch: main
HEAD: 8f2987a7e040b6ee2ad19075eb2256e6e6c76403
origin/main: 6d379a7de5f4a84c20f7c518f58d943625d4ed75
Ahead/behind: ahead 18, behind 0
Working tree before this document: clean
Schema version: 3
Tests: 132 passed, 0 failed
cargo check: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo fmt --check: PASS
cargo build --release: PASS
```

Before implementation verify this baseline. The expected authoring artifact
may be this document alone. If HEAD materially differs, the tree contains
unexplained changes, or Sprint 008 is not complete, STOP and report it.

---

# 25. Canonical Reading Order

Before implementation read:

1. `docs/internal/PRODUCT_DEFINITION.md`
2. `docs/internal/TECHNICAL.md`
3. `docs/internal/ARCHITECTURE.md`
4. `docs/internal/ROADMAP.md`
5. `docs/internal/sprints/SPRINT-008.md`
6. `docs/internal/sprints/SPRINT-009.md`

Treat them as authoritative. Do not rewrite Canon to make implementation
easier. Stop for founder review if the required slice contradicts Canon.

---

# 26. Baseline Architecture to Inspect

Inspect at minimum:

```text
src/analysis/model.rs
src/analysis/attack_path.rs
src/application/scan.rs
src/cli/mod.rs
src/graph/model.rs
src/persistence/analysis.rs
src/persistence/db.rs
tests/integration/sprint008_analysis_test.rs
tests/persistence/analysis_test.rs
```

Confirm AttackPaths are scan-scoped, fingerprints are stable, ACTIVE and
BLOCKED are distinct, partial/limited analysis cannot persist positive paths,
same-scan Evidence exists, Worker sink impact is currently UNKNOWN, Finding
count is hard-coded to zero, and schema version is 3.

---

# 27. Implementation Plan Requirement

Before code changes produce a concise plan covering:

```text
production-classification normalization
Finding domain and engine
eligibility and grouping
severity and confidence
evidence aggregation and reasons
remediation cut points
identity and persistence
ScanService and CLI
fixtures and tests
```

Call out genuine architectural friction, especially inability to classify
production authoritatively. If the only signal is a resource name, STOP. Do
not implement a name heuristic.

---

# 28. Required Fixtures and Tests

Add sanitized deterministic fixtures for:

1. Active golden path with explicit `PRODUCTION` classification.
2. Same active path with `sink_impact: UNKNOWN`.
3. Same active path with `sink_impact: STAGING`.
4. Proven blocked path.
5. Unresolved authority or influence.
6. Partial Scan.
7. Limited Finding evaluation.
8. Two production paths grouped into one Finding.
9. Same story through materially different Actors, producing separate
   Findings.
10. Repeated equivalent scans.
11. Missing or foreign-scan Evidence.
12. Secret and authorization-header sentinels.

At minimum test:

```text
explicit production is required
UNKNOWN and STAGING produce no production Finding
BLOCKED and UNRESOLVED produce no active Finding
PARTIAL and LIMITED produce no positive Finding
public/open golden path is CRITICAL
authenticated-external eligible path is HIGH
severity and confidence are independent
weakest Evidence constrains or rejects confidence
equivalent sinks group; distinct Actors do not
reasons and remediations reference exact facts and edges
fingerprints are stable across equivalent scans
security-significant scope changes alter fingerprints
Evidence union is sorted, unique, and same-scan
limits fail closed
```

Persistence tests must cover schema version 4, idempotent migration, Finding
round-trip, ordered path/evidence/reason/remediation links, foreign keys,
validation checks, duplicate scan fingerprints, and stable fingerprints across
separate scan rows.

No fixture may contain a real credential.

---

# 29. Required Integration Results

Through the controlled application seam verify:

```text
complete production fixture:
  Scan COMPLETE
  Analysis COMPLETE
  Potentially Active AttackPaths 1
  Findings 1
  class UNTRUSTED_TO_PRODUCTION
  severity CRITICAL
  confidence HIGH

current UNKNOWN Worker environment:
  Potentially Active AttackPaths 1
  Findings 0

blocked fixture:
  Blocked AttackPaths 1
  Findings 0

repeated production scans:
  two Scans
  two AttackPaths
  two Findings
  one stable AttackPath fingerprint
  one stable Finding fingerprint
```

Inspect SQLite for exact associations and zero secret-sentinel occurrences.

---

# 30. Controlled Manual Verification

Run a controlled fixture-backed scan with explicit production classification.

Expected semantic output:

```text
Status: COMPLETE
Security Graph: PROJECTED
Analysis: COMPLETE
Influence Paths: 1
Authority Paths: 1
Potentially Active AttackPaths: 1
Blocked AttackPaths: 0
Unresolved Candidates: 0
Findings: 1
Finding: UNTRUSTED_TO_PRODUCTION
Severity: CRITICAL
Confidence: HIGH
```

Inspect SQLite for one Scan, one analysis summary, one ACTIVE AttackPath, one
OPEN Finding, exact path/evidence/resource links, and exact remediation cut
edges. Repeat the fixture and verify stable fingerprints with separate
scan-scoped rows. Then verify UNKNOWN, STAGING, blocked, absent, partial, and
sentinel cases.

Live Cloudflare dogfood remains a roadmap follow-up unless an explicitly
authorized controlled environment provides trustworthy production
classification. Do not obtain credentials or perform a write operation.

---

# 31. Architecture Pressure Test

Before completion answer:

1. Did Finding generation consume only completed current-scan analysis?
2. Could an active consequential path with `sink_impact: UNKNOWN` accidentally
   become `UNTRUSTED_TO_PRODUCTION`?
3. Is production classification backed by explicit same-scan Evidence?
4. Are severity and confidence separate deterministic decisions?
5. Does the weakest security-critical fact constrain confidence?
6. Can one Finding group equivalent AttackPaths without hiding affected Sinks?
7. Do different Actors or authority mechanisms remain separate?
8. Is Finding identity stable across equivalent scans?
9. Can every claim resolve exact Evidence and AttackPath references?
10. Do remediations identify real graph cuts without applying changes?
11. Did provider-specific knowledge remain outside the Finding domain?
12. Did implementation avoid a generic rules or plugin framework?
13. Did Finding generation perform zero network/provider operations?
14. Did secret-like values remain absent from persistence and output?
15. Did Sprint 010 Explanation UX remain absent?

If any answer is NO, do not hide it. Fix only if clearly within Sprint 009;
otherwise STOP and report it.

---

# 32. Definition of Done

Sprint 009 is complete only when:

- [x] Baseline `8f2987a` is verified.
- [x] Finding generation consumes only completed current-scan analysis.
- [x] `UNTRUSTED_TO_PRODUCTION` is the only Finding class implemented.
- [x] Explicit production classification is required.
- [x] UNKNOWN and STAGING sinks do not produce the production Finding.
- [x] ACTIVE, BLOCKED, UNRESOLVED, PARTIAL, and LIMITED remain distinct.
- [x] Severity is deterministic and independent from confidence.
- [x] Confidence is deterministic and weakest-fact constrained.
- [x] Evidence aggregation is same-scan, sorted, unique, and complete.
- [x] Finding grouping is deterministic and bounded.
- [x] Finding fingerprints are stable across equivalent scans.
- [x] Equivalent paths may group without losing affected resources.
- [x] Structured reasons reference exact security facts.
- [x] Remediations reference exact graph cut points.
- [x] No remediation is applied.
- [x] SQLite persistence and foreign-key behavior are verified.
- [x] `pico scan` reports the first useful Finding.
- [x] Repeated scans preserve stable fingerprints and history.
- [x] Secret sentinels have zero persistence and output occurrences.
- [x] Finding generation performs zero network/provider operations.
- [x] Full verification passes.
- [x] Final diff contains no Sprint 010+ functionality.
- [x] This document records completion evidence.

---

# 33. Full Verification

After implementation run:

```text
cargo test
cargo check
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

Report exact totals. Run controlled CLI/SQLite checks and the architecture
pressure test. Do not declare completion from focused tests alone.

---

# 34. Final Diff Inspection

Review for accidental files, build artifacts, `.pico` state, real credentials,
machine paths, name-based production heuristics, provider-specific Finding
logic, unordered grouping, cross-scan Evidence, partial positive Findings,
opaque scoring, automatic remediation, new Finding classes, Explanation UX,
Sprint 010+ functionality, and unnecessary dependencies.

Do not perform unrelated refactoring.

---

# 35. Stop Conditions

Stop and report if:

```text
baseline is materially unexpected
the worktree contains unexplained changes
Canon contradicts the required rule
production can only be inferred from names
same-scan production Evidence cannot be represented safely
Finding generation would require live provider mutation
confidence cannot be derived without overstating Evidence
exact path/evidence links cannot be retained
implementation requires a generic rule engine or plugin framework
```

Do not silently weaken eligibility to make the golden fixture pass.

---

# 36. Completion Evidence

When implementation and verification pass, set `Status: COMPLETE` and record:

```text
completion date and verified baseline
implementation commit
repository state
test totals and Rust checks
finding and schema versions
golden class, severity, and confidence
production-classification signal and Evidence
negative-case results
grouping and fingerprint results
evidence and remediation results
secret-sentinel results
network/provider mutation counts
architecture pressure-test answers
controlled-real-environment status
roadmap decision
```

Do not claim the full v0.1 exit gate while controlled dogfood and explanation
comprehension gates remain incomplete.

## Recorded completion evidence

- Completion date: 2026-08-25.
- Verified baseline: `8f2987a7e040b6ee2ad19075eb2256e6e6c76403` on `main`; origin/main
  remained `6d379a7de5f4a84c20f7c518f58d943625d4ed75`.
- Implementation commit: `4c642216f08c62d85ff2dd640a0c8d043c7fd8f2`
  (`feat(findings): generate untrusted-to-production finding`).
- Schema version: 4; Finding version: 1.
- Verification: 145 tests passed (55 library, 30 domain, 41 integration, 19
  persistence); `cargo check`, Clippy with `-D warnings`, `cargo fmt --check`,
  and `cargo build --release` passed.
- Golden controlled fixture: one `UNTRUSTED_TO_PRODUCTION` Finding with
  `CRITICAL` severity, `HIGH` confidence, one active AttackPath, explicit
  same-scan `PRODUCTION` sink Evidence, six structured reasons, and four
  deterministic remediation cut points.
- Negative cases: UNKNOWN, unsupported, STAGING, LOCAL_DEV, blocked,
  unresolved, partial, limited, absent, and incomplete scans produced zero
  Findings. Repeated equivalent scans preserved one stable Finding fingerprint
  per scan with scan-scoped history.
- Persistence and safety: Finding, path, Evidence, reason, and remediation
  links were persisted with same-scan foreign-key enforcement. The synthetic
  sentinel `TEST_SECRET_SHOULD_NOT_PERSIST` was absent from persisted state and
  output. No network or provider mutation was performed and no real credentials
  or raw configuration were persisted.
- Architecture pressure test: PASS. Production requires explicit same-scan
  classification; severity and confidence remain separate deterministic
  decisions; exact path/Evidence references and stable grouping worked; the
  Finding domain remained provider-neutral; no plugin/rules framework or
  Sprint 010 explanation UX was introduced.
- Controlled-real-environment status: not run; no credentials or write access
  were obtained. The production fixture used the bounded sanitized provider
  seam required for deterministic testing.
- Roadmap decision: `EXTEND v0.1`.

---

# 37. Commit Policy

If and only if Sprint 009 is fully verified, stage only Sprint 009 changes,
inspect the staged diff, and commit with:

```text
feat(findings): generate untrusted-to-production finding
```

Do not amend previous commits. Do not push unless explicitly instructed. Do
not begin Sprint 010.

The authoring-only document may be committed separately with:

```text
docs(sprints): define Sprint 009 finding generation
```

---

# 38. Final Report Contract

Report:

```text
Sprint: SPRINT-009 — First Finding — Untrusted to Production
Status: COMPLETE or BLOCKED
Baseline: <verified SHA>
Implementation commit: <SHA + message>

Finding contract:
<eligibility, production classification, grouping, severity, confidence>

Verification:
<tests and all required checks>

Golden Finding:
Class: UNTRUSTED_TO_PRODUCTION
Severity: <level>
Confidence: <level>
AttackPaths: <count>
Affected production Sinks: <count>
Evidence-complete: YES | NO
Remediation cut points: <count>

Negative cases:
UNKNOWN production Finding: 0
STAGING production Finding: 0
BLOCKED Finding: 0
UNRESOLVED Finding: 0
PARTIAL Finding: 0
LIMITED Finding: 0

Safety:
Network required by Finding tests: NO
Provider mutation requests: 0
Real secrets persisted: NO
Secret sentinel persisted or emitted: NO
Automatic remediation performed: NO

Scope:
Additional Finding classes: NO
pico findings implemented: NO
pico finding <id> implemented: NO
Explanation UX implemented: NO
Pico MCP implemented: NO
Sprint 010 functionality implemented: NO

Repository:
Branch: <branch>
HEAD: <SHA>
origin/main: <SHA>
Ahead/behind: <state>
Working tree: <state>

Follow-ups:
<only genuine controlled-dogfood or Sprint 010 observations>
```

Do not call an UNKNOWN-environment Worker production. Do not call a potential
exposure exploited.

---

# 39. Sprint Exit

Sprint 009 ends when Pico can reliably say:

> **Externally controlled content can reach explicitly classified production
> mutation authority through this autonomous actor; here is the deterministic
> severity, confidence, evidence, and the exact places where the path can be
> broken.**

It does not yet answer through a complete interactive experience:

> **Show me every Finding, walk me through each reason, and let me navigate the
> full evidence-backed explanation.**

That belongs to the next explicitly authorized Explanation UX sprint.

Do not begin Sprint 010.

Wait for explicit authorization.
