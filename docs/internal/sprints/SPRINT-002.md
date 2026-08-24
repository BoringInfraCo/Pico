# Pico — Sprint 002: First Autonomous Actor — OpenCode

**Status:** COMPLETE
**Sprint:** 002
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `2e3f3d4`
**Depends on:** Sprint 001 — Local Foundation
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Teach Pico to observe its first real autonomous actor.

At the end of Sprint 002, Pico must be capable of discovering a supported local OpenCode installation/configuration and representing that actor as evidence-backed Pico domain state.

The core question for this sprint is:

> **Can Pico discover a locally configured OpenCode autonomous actor and prove what it observed with evidence?**

Conceptually:

```text
Local Environment
        ↓
OpenCode Discovery
        ↓
Normalization
        ↓
Agent Resource
        ├── Evidence
        └── Observation
        ↓
SQLite
```

Sprint 001 proved:

> Pico can remember.

Sprint 002 must prove:

> **Pico can observe.**

---

# 2. Sprint Principle

> **Discover the actor. Do not analyze its power.**

This distinction is critical.

Sprint 002 answers:

```text
Does OpenCode exist here?

What observed configuration establishes that?

How does Pico represent the actor?

What evidence supports the observation?
```

Sprint 002 does NOT answer:

```text
What can OpenCode execute?

Can OpenCode use Bash?

What MCP servers can OpenCode reach?

Can OpenCode reach GitHub?

Can OpenCode access credentials?

Can OpenCode reach production?

Is OpenCode dangerous?
```

Those belong to later slices.

---

# 3. Expected User Experience

Given a supported local OpenCode environment:

```bash
pico scan
```

Pico should discover OpenCode and complete successfully.

Conceptual output:

```text
Pico scan complete

Status: COMPLETE

Agents:         1
Resources:      1
Relationships:  0
Evidence:       1+
Findings:       0
```

The exact CLI presentation may vary according to the existing application contract.

The important behavior is:

```text
OpenCode discovered
        ↓
normalized Resource created
        ↓
supporting Evidence created
        ↓
Observation created
        ↓
all associated with the Scan
        ↓
persisted locally
```

If OpenCode is not present:

```bash
pico scan
```

must still be a valid successful scan.

Conceptually:

```text
Pico scan complete

Status: COMPLETE

Agents:         0
Resources:      0
Relationships:  0
Evidence:       0
Findings:       0
```

Absence of OpenCode is not an error.

---

# 4. Scope

Sprint 002 includes only the minimum functionality required to observe OpenCode as Pico's first autonomous actor.

## Required

Implement:

```text
discovery module boundary

first agent adapter:
  OpenCode

supported local OpenCode detection

safe OpenCode configuration inspection

OpenCode actor normalization

Agent Resource creation

supporting Evidence creation

Observation creation

Scan association

SQLite persistence

scan-result count integration

fixture-based tests

end-to-end scan tests
```

---

# 5. Discovery Architecture

Sprint 002 introduces Pico's first real discovery path.

Preferred conceptual flow:

```text
CLI
 ↓
ScanService
 ↓
Discovery
 ↓
OpenCode Adapter
 ↓
Observed Facts
 ↓
Normalization
 ↓
Resource
Evidence
Observation
 ↓
Persistence
```

The CLI must not know how OpenCode is discovered.

`ScanService` must not contain OpenCode-specific parsing logic.

The generic Pico domain must not import OpenCode-specific types.

---

# 6. First Adapter Boundary

OpenCode-specific knowledge belongs behind an adapter boundary.

Conceptually:

```text
adapters/
└── agents/
    └── opencode/
```

The exact Rust module structure should follow the repository's established conventions.

The adapter owns knowledge such as:

```text
where supported OpenCode configuration may exist

how supported OpenCode configuration is represented

what minimum facts establish the presence of OpenCode

how those facts are safely read
```

The adapter does NOT decide:

```text
severity

risk

attack paths

authority

influence

findings
```

Adapters produce facts.

Pico's later analysis engine will interpret security meaning.

---

# 7. Discovery Boundary

Introduce only enough discovery orchestration to support the OpenCode adapter.

Do not create a generalized plugin framework.

Do not create dynamic adapter loading.

Do not create arbitrary provider registration.

A simple internal discovery mechanism is sufficient.

Conceptually:

```text
DiscoveryService
      ↓
OpenCodeAdapter
      ↓
ObservedActor
```

or an equivalent structure consistent with the existing Rust architecture.

The implementation should remain easy to extend later without prematurely implementing that extension system.

---

# 8. Supported Detection

Pico should use documented/stable OpenCode configuration or installation signals where practical.

The implementation agent must verify the current OpenCode configuration model before locking detection behavior.

Detection should prioritize deterministic local evidence.

Examples of acceptable evidence classes may include:

```text
supported configuration file

supported project configuration

supported user configuration

known OpenCode metadata
```

Do not treat arbitrary fuzzy filesystem clues as authoritative merely because they contain the word `opencode`.

For example, the existence of:

```text
random-folder/opencode-notes.txt
```

must not establish an autonomous actor.

---

# 9. Configuration Precedence

If OpenCode supports multiple configuration layers, Pico must not casually invent configuration-precedence semantics.

Sprint 002 needs only enough configuration understanding to establish that OpenCode is present as a supported actor.

If determining actor identity requires precedence resolution, follow documented OpenCode behavior.

If effective permission/capability resolution becomes necessary:

> **STOP.**

That belongs to the capability sprint.

Do not accidentally turn Sprint 002 into OpenCode policy analysis.

---

# 10. Resource Normalization

A discovered OpenCode actor must normalize into Pico's generic `Resource` domain.

Conceptually:

```text
Resource {
  canonical_key
  kind
  provider
  name
  metadata
  first_observed_at
  last_observed_at
}
```

The normalized representation should identify the resource as an autonomous/agent actor using the vocabulary already established by Pico's canonical architecture.

Do not introduce:

```text
OpenCodeResource
```

into the generic domain.

OpenCode-specific parsing structures may exist inside the adapter.

They must not become Pico's core model.

---

# 11. Stable Identity

Repeated scans of the same OpenCode actor should resolve to the same canonical Resource identity.

Conceptually:

```text
Scan A
  ↓
OpenCode
  ↓
Resource pico-resource-X

Scan B
  ↓
same OpenCode actor
  ↓
Resource pico-resource-X
```

Expected behavior:

```text
Resource count in database:
1 stable Resource

Observations:
2 scan-specific observations

Evidence:
scan-specific evidence as appropriate
```

The second scan must not create a duplicate Resource merely because it occurred later.

This is the first real pressure test of Sprint 001's stable identity model.

---

# 12. Evidence

A discovered actor must be evidence-backed.

Pico must be able to answer:

> **How do you know OpenCode exists here?**

Evidence should use the generic `Evidence` domain established in Sprint 001.

Conceptually:

```text
Evidence
  scan_id
  class
  source_type
  source_locator
  subject
  observation
  captured_at
  freshness
  sensitivity
  metadata
```

Evidence should describe the observed fact without unnecessarily copying complete source configuration into Pico.

Prefer:

```text
source locator
normalized observation
safe metadata
```

over:

```text
entire raw configuration dump
```

---

# 13. Evidence Safety

OpenCode configuration may contain or reference sensitive values.

Pico must not assume configuration is safe merely because it is local.

Do not persist arbitrary raw configuration.

Do not persist:

```text
API keys
tokens
passwords
credentials
environment values containing secrets
authorization headers
private keys
```

If OpenCode configuration contains unrelated sensitive fields, Pico should extract only the minimum information required for this sprint.

Sprint 002 should establish a pattern of:

> **observe minimally, normalize safely, persist intentionally.**

---

# 14. Observation

Each successful detection should create an `Observation` associated with the current Scan.

Conceptually:

```text
Observation

scan:
  current scan

subject:
  OpenCode Resource

observation_type:
  actor observed

observed_at:
  current observation time

source:
  OpenCode adapter
```

Exact enum/string vocabulary should follow the domain conventions established in the repository.

Do not create a giant generic observation taxonomy in this sprint.

---

# 15. Scan Semantics

`pico scan` now performs actual discovery.

Conceptually:

```text
ScanService.run()
      ↓
create Scan
      ↓
RUNNING
      ↓
run supported discovery
      ↓
OpenCode adapter
      ↓
normalize result
      ↓
persist Resource
      ↓
persist Evidence
      ↓
persist Observation
      ↓
COMPLETE
```

For supported normal states:

```text
OpenCode found     → COMPLETE
OpenCode not found → COMPLETE
```

Discovery absence is not failure.

---

# 16. Failure Semantics

Sprint 002 must distinguish:

```text
NOT FOUND
```

from:

```text
DISCOVERY FAILED
```

Examples:

OpenCode configuration absent:

```text
not found
→ valid
→ scan can COMPLETE
```

Supported OpenCode configuration exists but cannot be safely parsed:

```text
discovery problem
```

The architecture already supports:

```text
COMPLETE
PARTIAL
FAILED
```

Do not invent complex failure policy without need.

Use the simplest semantics consistent with `ARCHITECTURE.md`.

If the canonical docs do not sufficiently define whether a specific adapter failure should produce `PARTIAL` or `FAILED`, document the ambiguity and choose the smallest defensible behavior rather than creating a broad policy framework.

---

# 17. Relationship Scope

Sprint 002 should create no security relationships merely because an OpenCode actor exists.

Expected:

```text
Relationships: 0
```

Do not create speculative relationships such as:

```text
OpenCode
  → uses Bash

OpenCode
  → uses MCP

OpenCode
  → accesses filesystem

OpenCode
  → accesses GitHub
```

Those require separate evidence and later sprint authorization.

---

# 18. No Capability Analysis

The adapter may encounter fields related to:

```text
permissions
tools
Bash
commands
MCP
models
providers
environment
```

Do not normalize those into security capability state in Sprint 002.

Reading enough structure to safely identify OpenCode is allowed.

Analyzing its authority is not.

If the implementation naturally exposes those fields during parsing, ignore them unless they are strictly required to establish actor identity.

---

# 19. No Finding Generation

A discovered OpenCode actor is not inherently a security problem.

Sprint 002 produces:

```text
Resource
Evidence
Observation
```

It does NOT produce:

```text
AttackPath
Finding
Severity
Confidence
Remediation
```

Expected:

```text
Findings: 0
```

---

# 20. Filesystem Safety

Discovery must be bounded.

Do not recursively search the user's entire filesystem for OpenCode.

Use known/documented configuration locations and the current Pico workspace where appropriate.

Avoid:

```text
/
~/ recursively
all mounted volumes
arbitrary home-directory crawling
```

Pico should know where to look rather than rummaging through the machine.

---

# 21. Network Boundary

Sprint 002 should require no network access.

OpenCode actor detection should be based on local state.

Do not:

```text
contact OpenCode services
contact model providers
contact GitHub
contact package registries
contact telemetry endpoints
```

The sprint should remain fully fixture-testable offline.

---

# 22. Test Fixtures

Add sanitized OpenCode fixtures sufficient to represent:

```text
OpenCode present

OpenCode absent

valid supported configuration

malformed supported configuration

configuration containing irrelevant fields

configuration containing secret-like values
```

Fixtures must not contain real credentials.

Secret-safety fixtures may use clearly synthetic sentinel values.

Example:

```text
TEST_SECRET_SHOULD_NOT_PERSIST
```

After scanning such a fixture, verify that the sentinel does not appear in persisted Pico state.

---

# 23. Required Tests

## Adapter tests

Verify:

```text
supported OpenCode state is detected

absent state returns not found

malformed state is handled deterministically

irrelevant files do not trigger detection

adapter produces expected normalized facts
```

---

## Resource tests

Verify:

```text
OpenCode normalizes into generic Resource

canonical identity is deterministic

repeated observation does not duplicate Resource

first_observed_at remains stable

last_observed_at advances appropriately
```

---

## Evidence tests

Verify:

```text
detection creates supporting Evidence

Evidence belongs to current Scan

Evidence identifies its source

raw configuration is not unnecessarily persisted

secret-like fixture values do not enter persisted Evidence
```

---

## Observation tests

Verify:

```text
detection creates Observation

Observation belongs to current Scan

Observation references discovered Resource

second scan creates a new Observation
```

---

## Integration tests

From a temporary Pico workspace with a supported OpenCode fixture:

```text
pico init
   ↓
pico scan
```

Verify:

```text
Scan = COMPLETE

Agent count = 1

Resource count = 1

Relationship count = 0

Evidence count >= 1

Finding count = 0
```

Run a second scan.

Verify:

```text
Scans = 2

OpenCode Resources = 1

OpenCode Observations = 2

Resource identity unchanged
```

---

## Absence integration test

With no OpenCode state:

```text
pico scan
```

Verify:

```text
COMPLETE

Agents = 0

Resources = 0

Relationships = 0

Evidence = 0

Findings = 0
```

---

## Secret persistence regression

Inject a synthetic secret-like sentinel into irrelevant OpenCode configuration.

After scan, inspect Pico's persistent state.

Expected:

```text
sentinel occurrences = 0
```

Search at minimum the persisted fields Pico controls.

Do not rely only on CLI output.

---

# 24. Definition of Done

Sprint 002 is COMPLETE only when all of the following are true:

- [ ] Pico has a bounded discovery layer.
- [ ] Pico has its first agent adapter.
- [ ] The adapter supports OpenCode.
- [ ] Supported OpenCode local state can be detected.
- [ ] OpenCode absence is handled successfully.
- [ ] OpenCode normalizes into a generic Pico Resource.
- [ ] Resource identity is stable across scans.
- [ ] Detection produces supporting Evidence.
- [ ] Detection produces a scan-scoped Observation.
- [ ] Resource, Evidence, and Observation persist in SQLite.
- [ ] Repeated scans do not duplicate the Resource.
- [ ] Repeated scans create new scan-scoped observations.
- [ ] Relationships remain zero for this slice.
- [ ] Findings remain zero.
- [ ] No Bash capability analysis exists.
- [ ] No MCP discovery exists.
- [ ] No GitHub integration exists.
- [ ] No Cloudflare integration exists.
- [ ] No credential discovery exists.
- [ ] No Security Graph exists.
- [ ] No AttackPath logic exists.
- [ ] No network access is required.
- [ ] No credentials are required.
- [ ] Raw OpenCode configuration is not indiscriminately persisted.
- [ ] Synthetic secret-like fixture values do not enter Pico persistence.
- [ ] Full tests pass.
- [ ] `cargo check` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` passes.
- [ ] `cargo fmt --check` passes.
- [ ] `cargo build --release` passes.
- [ ] Working-tree diff contains only Sprint 002 work.

---

# 25. Manual Verification

Using a controlled local fixture/environment representing supported OpenCode configuration:

```bash
pico init
pico scan
```

Verify equivalent behavior:

```text
Pico scan complete

Status: COMPLETE

Agents:         1
Resources:      1
Relationships:  0
Evidence:       >=1
Findings:       0
```

Inspect SQLite.

Verify:

```text
one OpenCode Resource

supporting Evidence

one Observation

all expected Scan associations
```

Run:

```bash
pico scan
```

again.

Verify:

```text
two completed Scans

one stable OpenCode Resource

two scan-specific Observations

new scan-specific Evidence as designed
```

Then test a workspace/environment with no supported OpenCode state.

Verify:

```text
scan COMPLETE

Agents: 0
```

No error should occur solely because OpenCode is absent.

---

# 26. Stop Conditions

STOP implementation if Sprint 002 appears to require:

```text
effective Bash permission resolution

tool capability analysis

MCP server discovery

MCP tool inspection

GitHub integration

Cloudflare integration

credential inspection

provider API calls

Security Graph

InfluencePath

AuthorityPath

BoundaryEvaluation

AttackPath

Finding

severity calculation

LLM security reasoning

runtime monitoring

automatic remediation
```

Document the dependency.

Do not solve it in Sprint 002.

---

# 27. Architectural Questions to Pressure-Test

Sprint 002 is intentionally our first real test of Pico's architecture.

During implementation, pay attention to:

### Q1 — Resource identity

Can a real autonomous actor be represented with the existing canonical identity model?

### Q2 — Evidence

Can Pico explain why it believes the actor exists without storing excessive source configuration?

### Q3 — Observation

Does the Scan + Resource + Observation model cleanly represent repeated sightings?

### Q4 — Adapter boundary

Can OpenCode-specific knowledge remain outside the generic domain?

### Q5 — Secret safety

Can Pico inspect agent configuration without turning its database into a copy of sensitive configuration?

### Q6 — Discovery orchestration

Can the first adapter be introduced without prematurely building a plugin framework?

If any answer is materially **NO**, report it.

Do not hide architectural friction behind adapter-specific hacks.

---

# 28. Sprint Deliverables

Expected deliverables:

```text
bounded discovery orchestration

OpenCode agent adapter

OpenCode actor detection

generic Resource normalization

Evidence generation

Observation generation

ScanService discovery integration

SQLite persistence integration

sanitized fixtures

adapter tests

domain/persistence tests as needed

integration tests

README update only if user-facing behavior changed enough to require it

SPRINT-002.md completion evidence
```

---

# 29. Completion Evidence

When implementation is complete, record:

```text
Baseline:
2e3f3d4

Implementation commit:
<sha>

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

OpenCode-present scan:
<result>

OpenCode-absent scan:
<result>

Repeated scan identity:
<result>

Evidence persistence:
<result>

Observation persistence:
<result>

Secret-sentinel persistence check:
<result>

Relationships:
0

Findings:
0

Network required:
NO

Credentials required:
NO

Sprint 003+ functionality implemented:
NO
```

## Completion Record

Baseline:
`2e3f3d4`

Implementation commit:
`7d4fd40 feat(discovery): observe OpenCode actor`

Tests:
`81 passed / 0 failed`

`cargo check`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, and `cargo build --release`:
PASS

OpenCode-present controlled scan:
COMPLETE — 1 Agent, 1 Resource, 0 Relationships, 1 Evidence, 0 Findings.

OpenCode-absent controlled scan:
COMPLETE — 0 Agents, 0 Resources, 0 Relationships, 0 Evidence, 0 Findings.

Repeated controlled scan:
2 completed Scans, 1 stable `agent:opencode` Resource, 2 scan-specific Observations, and 2 scan-specific Evidence records.

Evidence and Observation persistence:
PASS — SQLite records reference their respective Scan IDs; the Observation references the stable Resource.

Secret-sentinel persistence check:
PASS — `TEST_SECRET_SHOULD_NOT_PERSIST` occurred 0 times in Pico-controlled persisted state.

Relationships:
0

Findings:
0

Network required:
NO

Credentials required:
NO

Sprint 003+ functionality implemented:
NO

Architecture pressure test:

- Resource identity: PASS
- Evidence model: PASS
- Observation model: PASS
- Adapter boundary: PASS
- Secret safety: PASS
- No premature plugin framework: PASS

The current OpenCode docs also describe configuration used by later capability work. Sprint 002 intentionally records only actor presence; effective permission, Bash, and MCP interpretation remain follow-up work.

---

# 30. Sprint Exit

Sprint 002 proves:

> **Pico can observe a real autonomous actor and preserve evidence of what it observed.**

That is the entire milestone.

Sprint 002 does not establish whether that actor is safe or dangerous.

Once this sprint is complete, Pico should have:

```text
OpenCode
   │
   ├── Resource
   ├── Evidence
   └── Observation
```

The next architectural question becomes:

> **What can this actor actually do?**

That is a separate sprint.

Do not begin it here.
