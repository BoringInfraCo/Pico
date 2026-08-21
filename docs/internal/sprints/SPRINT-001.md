# Pico — Sprint 001: Local Foundation

**Status:** COMPLETE  
**Sprint:** 001  
**Phase:** v0.1 — Golden Path Proof  
**Type:** Implementation  
**Depends on:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Establish Pico's smallest working local application and persistence foundation.

At the end of Sprint 001, Pico must be capable of:

```text
initialize local Pico state
        ↓
create/open SQLite
        ↓
start a Scan
        ↓
persist the Scan
        ↓
complete the Scan
        ↓
report an empty successful result
```

The sprint proves that Pico's core local lifecycle works before any security discovery is introduced.

The goal is **not** to find security problems yet.

The goal is to establish the trustworthy foundation that future discovery and analysis will use.

---

# 2. Sprint Principle

> **Build the foundation. Do not build discovery.**

Pico's architecture rule remains:

> **Architect for extension. Implement only the golden path.**

For Sprint 001, the golden path is even narrower:

```text
CLI
 ↓
Application Service
 ↓
Domain
 ↓
SQLite
```

No external system should be required.

No network access should be required.

---

# 3. Required User Experience

The minimum expected workflow is:

```bash
pico init
```

Expected conceptual result:

```text
Pico initialized.

.pico/
  pico.db
```

Then:

```bash
pico scan
```

Expected conceptual result:

```text
Pico scan complete

Scan: <scan-id>
Status: COMPLETE

Resources:     0
Relationships: 0
Evidence:      0
Findings:      0
```

Exact wording may vary.

The behavior may not.

---

# 4. Scope

Sprint 001 includes:

## CLI foundation

Implement:

```text
pico
pico init
pico scan
```

The root command may expose basic help/version information as appropriate.

---

## Local Pico state

Create and manage:

```text
.pico/
.pico/pico.db
```

Pico must safely initialize an environment without destroying existing state.

`pico init` must be idempotent.

---

## SQLite foundation

Implement:

```text
database connection
schema initialization
migration mechanism
transaction helpers where appropriate
```

SQLite is Pico's canonical V0 persistent store.

Do not introduce another database.

---

## Core observed-domain types

Implement the minimum domain representations for:

```text
Scan
Resource
Relationship
Evidence
Observation
```

These should follow `ARCHITECTURE.md`.

Do not implement provider-specific domain types.

Examples of prohibited domain objects:

```text
OpenCodeAgent
GitHubMCPTool
CloudflareWorker
```

Those systems will later normalize into Pico's generic domain.

---

## Scan lifecycle

Implement:

```text
RUNNING
COMPLETE
PARTIAL
FAILED
```

Sprint 001 only needs the successful empty lifecycle to operate end-to-end:

```text
Create Scan
   ↓
RUNNING
   ↓
Persist
   ↓
No discovery work
   ↓
COMPLETE
   ↓
Persist completion
```

The model must support `PARTIAL` and `FAILED` for future sprints.

---

## Persistence

Persist the minimum architecture-defined state necessary for:

```text
scans
resources
relationships
evidence
observations
```

The exact SQL schema may evolve during implementation if necessary.

However, it must preserve the architecture invariants defined in `ARCHITECTURE.md`.

---

## Stable identity

Resources and Relationships must support stable canonical identity.

Conceptually:

```text
Resource
  id
  canonical_key

Relationship
  id
  canonical_key
```

Sprint 001 does not need real discovered Resources or Relationships.

The persistence model and tests must support them.

---

## Diagnostics

Implement enough structured error handling that Pico can distinguish:

```text
initialization failure

database failure

migration failure

scan failure
```

Do not build a generalized observability framework.

---

# 5. Explicit Non-Scope

Sprint 001 MUST NOT implement:

```text
OpenCode discovery

Claude Code discovery

Codex discovery

Cursor discovery

MCP discovery

GitHub integration

Cloudflare integration

Vercel integration

credential discovery

environment-secret discovery

provider API calls

Integration Intelligence

integrations.sh

Security Graph

Influence Analysis

Authority Analysis

Boundary Evaluation

AttackPath

Finding generation

remediation

Pico MCP server

Slack

hosted services

telemetry

continuous monitoring

runtime monitoring

automatic remediation

enforcement
```

If implementation reaches one of these areas:

> **STOP.**

It belongs to a later sprint.

---

# 6. Architectural Constraints

Sprint 001 must preserve the following Pico invariants.

## Local-first

All functionality works locally.

No Pico account or hosted service is required.

---

## Offline

Sprint 001 requires no network access.

Running:

```bash
pico init
pico scan
```

must work offline.

---

## Modular monolith

Do not create:

```text
microservices
background workers
remote queues
remote databases
separate deployable services
```

Pico begins as one local application with clear internal module boundaries.

---

## Interface separation

CLI commands must call application services.

Do not implement domain or persistence logic directly inside CLI handlers.

Preferred:

```text
CLI
 ↓
Application
 ↓
Domain / Persistence
```

Avoid:

```text
CLI
 ↓
raw SQL
```

---

## Domain independence

The core domain must not depend on:

```text
CLI framework
SQLite driver
OpenCode
GitHub
Cloudflare
MCP
provider SDKs
```

---

## Secret safety

Sprint 001 should not encounter real credentials.

However, the architecture must not introduce obvious paths where arbitrary secrets are expected to become domain state.

Do not build credential handling prematurely.

---

# 7. Proposed Repository Shape

Follow the repository's existing language/tooling conventions where they already exist.

If Pico is a new/empty repository, prefer a structure consistent with:

```text
src/
├── cli/
├── application/
├── domain/
├── persistence/
├── security/
└── shared/

tests/
├── domain/
├── persistence/
└── integration/
```

Do not create empty directories merely to mirror the future architecture.

Create modules only when Sprint 001 actually needs them.

Future directories such as:

```text
graph/
analysis/
discovery/
adapters/
mcp/
```

should wait until the sprint that needs them.

---

# 8. Core Domain Requirements

## Scan

Minimum conceptual fields:

```text
id
started_at
completed_at
status
trigger
scope
pico_version
environment_fingerprint
metadata
```

Sprint 001 may keep optional fields empty when appropriate.

Initial trigger:

```text
MANUAL
```

---

## Resource

Minimum conceptual fields:

```text
id
canonical_key
kind
provider
name
metadata
first_observed_at
last_observed_at
```

---

## Relationship

Minimum conceptual fields:

```text
id
canonical_key
from_resource_id
to_resource_id
kind
state
metadata
first_observed_at
last_observed_at
```

Supported states:

```text
CONFIRMED
DERIVED
INFERRED
UNKNOWN
BLOCKED
```

---

## Evidence

Minimum conceptual fields:

```text
id
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

Evidence should be append-oriented.

---

## Observation

Minimum conceptual fields:

```text
id
scan_id
subject_type
subject_id
observation_type
observed_at
source
metadata
```

---

# 9. Database Requirements

The database must support the architecture-defined tables necessary for:

```text
scans
resources
relationships
observations
evidence
relationship_evidence
```

Analysis tables such as:

```text
attack_paths
findings
finding_paths
```

do not need to be implemented in Sprint 001 unless the migration strategy strongly benefits from defining empty schema now.

Default preference:

> Do not create unused implementation surface.

Implement what this sprint needs.

---

# 10. Migration Requirements

Pico must have an explicit schema version/migration mechanism.

Requirements:

```text
fresh database can initialize

existing initialized database can reopen

running pico init again is safe

migration state can be determined

future schema migrations are possible
```

Do not overbuild a custom migration framework if the chosen stack already provides a simple reliable mechanism.

---

# 11. `pico init`

`pico init` should:

```text
resolve Pico workspace

create .pico if missing

apply restrictive permissions where supported

create/open pico.db

apply migrations

report success
```

If already initialized:

```text
pico init
```

should succeed safely.

It must not reset or delete the database.

---

# 12. `pico scan`

Sprint 001's scan implementation intentionally performs no discovery.

Conceptually:

```text
ScanService.run()
     ↓
create Scan
     ↓
status = RUNNING
     ↓
persist
     ↓
discovery result = empty
     ↓
status = COMPLETE
     ↓
completed_at = now
     ↓
persist
     ↓
return ScanResult
```

The resulting scan should contain:

```text
Resources:     0
Relationships: 0
Evidence:      0
Findings:      0
```

This is a valid successful Pico scan.

---

# 13. Scan Result Contract

The application layer should return a structured result.

Conceptually:

```text
ScanResult {
  scan_id
  status
  started_at
  completed_at

  resource_count
  relationship_count
  evidence_count
  finding_count
}
```

The CLI renders this result.

The CLI should not calculate security/application state itself.

---

# 14. Testing Requirements

Sprint 001 must establish Pico's testing baseline.

Required coverage should include:

## Domain

Test:

```text
valid Scan creation

valid Scan state transitions

invalid Scan transitions where applicable

Resource canonical identity

Relationship endpoint requirements

Relationship state validation
```

---

## Persistence

Test:

```text
fresh database initialization

migration execution

database reopen

Scan persistence

Scan completion update

Resource persistence

Relationship persistence

Evidence persistence

Observation persistence
```

---

## Init

Test:

```text
first pico init succeeds

second pico init succeeds

existing database is preserved
```

---

## Empty scan

Integration test:

```text
initialize temporary Pico workspace
        ↓
run ScanService
        ↓
persist RUNNING scan
        ↓
complete scan
        ↓
reload from SQLite
```

Assert:

```text
status == COMPLETE

started_at exists

completed_at exists

resource_count == 0

relationship_count == 0

evidence_count == 0
```

---

## Offline guarantee

Sprint 001 tests must not require:

```text
internet
provider credentials
GitHub
Cloudflare
OpenCode
MCP
```

---

# 15. Definition of Done

Sprint 001 is COMPLETE only when all of the following are true:

- [ ] Pico has a working CLI entrypoint.
- [ ] `pico init` works.
- [ ] `pico init` is idempotent.
- [ ] `.pico/` is created safely.
- [ ] `.pico/pico.db` is created.
- [ ] SQLite schema initialization works.
- [ ] A migration mechanism exists.
- [ ] `Scan` is implemented.
- [ ] `Resource` is implemented.
- [ ] `Relationship` is implemented.
- [ ] `Evidence` is implemented.
- [ ] `Observation` is implemented.
- [ ] Scan statuses support `RUNNING`, `COMPLETE`, `PARTIAL`, and `FAILED`.
- [ ] `pico scan` creates a persisted Scan.
- [ ] The Scan transitions from `RUNNING` to `COMPLETE`.
- [ ] The completed Scan can be read back from SQLite.
- [ ] Empty scan counts are correct.
- [ ] CLI handlers do not contain raw persistence/domain logic.
- [ ] Core domain does not depend on provider-specific code.
- [ ] Tests pass.
- [ ] Typecheck/lint/build checks pass as applicable.
- [ ] No network access is required.
- [ ] No credentials are required.
- [ ] No Sprint 002+ discovery functionality was implemented.

---

# 16. Manual Verification

From a clean temporary workspace:

```bash
pico init
```

Verify:

```text
.pico/
└── pico.db
```

Run again:

```bash
pico init
```

Verify:

```text
no data loss
no reset
no failure
```

Then:

```bash
pico scan
```

Verify output equivalent to:

```text
Pico scan complete

Status: COMPLETE

Resources:     0
Relationships: 0
Evidence:      0
Findings:      0
```

Inspect persisted state and verify:

```text
one completed Scan exists

started_at exists

completed_at exists

status = COMPLETE
```

Run:

```bash
pico scan
```

again.

Verify:

```text
a second Scan is created

the first Scan remains intact
```

Pico now has scan history.

---

# 17. Stop Conditions

Stop implementation immediately if completing Sprint 001 appears to require:

```text
OpenCode integration

MCP discovery

GitHub API access

Cloudflare API access

credential discovery

security graph implementation

AttackPath logic

Finding rules

LLM integration

hosted infrastructure
```

Do not solve future sprint problems preemptively.

Document the dependency or architectural question instead.

---

# 18. Sprint Deliverables

Expected deliverables:

```text
working Pico local application

CLI entrypoint

pico init

pico scan

SQLite persistence

initial migration

core observed-domain model

ScanService

tests

updated README usage if appropriate
```

And this document updated with completion evidence.

---

# 19. Completion Evidence

When implementation is complete, record:

```text
Commit:
b09897d — feat(core): establish Pico local foundation
(HEAD; parent 134b9c2f7a5ee4bebdf46fd25519d771dcc345c1; single commit)

Tests:
75 passed, 0 failed
  - 31 lib unit tests (domain, persistence, application)
  - 26 tests/domain integration tests
  - 13 tests/persistence integration tests
  - 5 tests/integration tests (empty scan flow, init idempotency,
    scan history, offline smoke)

Typecheck:
PASS (cargo check, no warnings)

Lint:
PASS (cargo clippy --all-targets -- -D warnings; cargo fmt --check)

Build:
PASS (cargo build --release)

pico_version consistency check:
RESOLVED — Scan::start now validates pico_version with
`pico_version.trim().is_empty()`, matching the blank-value invariant
used by every other Sprint 001 domain constructor (Resource::new,
Relationship::new, Evidence::new, Observation::new). Previously
Scan::start used `is_empty()` only, so a whitespace-only value such as
"   " passed Scan::start while being rejected elsewhere. The existing
test `empty_pico_version_is_rejected` was extended to also assert that
a whitespace-only value is rejected. No generalized validation
abstraction was introduced; the change is a one-line alignment.

Manual pico init:
PASS — created .pico/ (0700) and .pico/pico.db (0600) in a clean
temporary workspace; schema migrated to version 1.

Manual second pico init:
PASS — idempotent; no reset, no data loss, schema version unchanged.

Manual pico scan:
PASS — created Scan, transitioned RUNNING -> COMPLETE, reported
Resources: 0, Relationships: 0, Evidence: 0, Findings: 0.

Persisted scan verified:
PASS — SQLite contains the completed Scan with started_at and
completed_at set and status COMPLETE; a second scan created a second
record and the first remained intact (scan history confirmed).

Scan-before-init safety:
PASS — `pico scan` in an uninitialized workspace fails with a clear
diagnostic ("no Pico state at .../.pico/pico.db (run `pico init`
first)") and a non-zero exit, without contacting any external system.

Network required:
NO

Credentials required:
NO

Out-of-scope functionality added:
NO
```

---

# 20. Sprint Exit

Sprint 001 proves:

> Pico can exist as a trustworthy local application, preserve its own state, and record a coherent security scan lifecycle.

It does **not** prove that Pico can discover an AI agent.

That is intentional.

Once Sprint 001 is complete and verified, Pico may proceed to the next roadmap slice:

> **Discover the first real autonomous actor.**

Do not begin that work as part of Sprint 001.

---

# Sprint 001 Status

**IMPLEMENTED — COMPLETE**

Verification summary:

```text
pico init       PASS (idempotent, safe, restrictive permissions)
pico scan       PASS (persisted RUNNING -> COMPLETE lifecycle)
SQLite          PASS (schema v1, migrations, reopen, 6 tables)
Domain types    PASS (Scan, Resource, Relationship, Evidence, Observation)
Tests           PASS (75 passed, 0 failed)
Typecheck       PASS
Lint            PASS (clippy -D warnings, fmt --check)
Build           PASS (cargo build --release)
Network         NONE required
Credentials     NONE required
Out-of-scope    NONE added
```

Completion evidence recorded in §19 above.

**Next (NOT STARTED):** Sprint 002 — discover the first real autonomous actor (OpenCode discovery).
```