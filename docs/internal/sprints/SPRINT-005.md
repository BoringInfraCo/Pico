# Pico — Sprint 005: First Credential Reachability — Cloudflare

**Status:** COMPLETE
**Sprint:** 005
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `9feb704`
**Depends on:** Sprint 004 — First Influence Surface: GitHub MCP
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Teach Pico to observe its first credential-reachability edge without becoming
a credential store.

At the end of Sprint 005, Pico must be able to discover a supported Cloudflare
credential reference in a bounded local environment, determine whether the
observed OpenCode Bash capability can reach that credential under the supported
environment contract, and persist only safe identity and reachability facts.

The core question is:

> **Can OpenCode's effective Bash capability reach a supported Cloudflare credential, and can Pico prove that without persisting the credential value?**

Conceptually:

```text
OpenCode
   ↓ can_execute
Bash
   ↓ can_access
Cloudflare Credential
   ├── Evidence
   └── Observations
        ↓
      SQLite
```

Sprint 001 proved:

> Pico can remember.

Sprint 002 proved:

> Pico can observe an autonomous actor.

Sprint 003 proved:

> Pico can resolve one actor capability.

Sprint 004 proved:

> Pico can observe one external influence surface.

Sprint 005 must prove:

> **Pico can observe credential reachability without retaining credential material.**

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

Sprint 005 implements only this slice:

```text
OpenCode
   ↓
Bash
   ↓
Cloudflare Credential
```

This is `ARCHITECTURE.md` Slice 4 — Cloudflare credential reachability.

Sprint 005 does not determine what the credential authorizes.

Cloudflare verification, permission introspection, account/resource scope,
Worker discovery, and mutation authority belong to Sprint 006 or a later
explicitly authorized slice.

Sprint 005 does not create an AttackPath or Finding.

---

# 3. Sprint Principle

> **Establish reachability. Do not infer authority.**

Sprint 005 answers:

```text
Is a supported Cloudflare credential reference present?

What bounded source exposed the reference?

What supported credential type does the reference represent?

Can the observed Bash execution environment reach it?

What effective Bash state applies?

What stable, non-secret identity can Pico persist?

How does Pico prove every claim?
```

Sprint 005 does NOT answer:

```text
Is the credential valid?

Is the credential active or expired?

Which Cloudflare account or zone does it reach?

Which permission groups does it contain?

Can it write Workers?

Can it mutate production?

Has OpenCode used the credential?

Has any command read or exfiltrated it?

Does a complete attack path exist?
```

The distinction is foundational:

```text
CREDENTIAL_REACHABLE
is not
CREDENTIAL_USED
is not
CREDENTIAL_VALID
is not
WRITE_AUTHORITY
```

---

# 4. Required Reachability Claim

Sprint 005 should establish the smallest defensible claim:

> **A supported Cloudflare credential reference is present in a bounded environment that the supported Bash capability can access under the observed execution contract.**

The claim must preserve:

```text
credential type
source type
source locator
presence
safe identity
reachability state
effective Bash permission
runtime uncertainty
secret_stored: false
```

If environment inheritance cannot be established, Pico must record:

```text
reachability: UNKNOWN
```

or decline to create a positive `can_access` edge.

Credential presence alone must never be promoted to agent accessibility.

---

# 5. Expected User Experience

Given:

```text
supported OpenCode actor
effective Bash permission ALLOW or ASK
supported Cloudflare credential reference
supported evidence that the Bash environment can reach the reference
```

then:

```bash
pico scan
```

should complete and expose the new credential slice.

Conceptually:

```text
Pico scan complete

Status: COMPLETE

Agents:         1
Resources:      existing resources + 1 credential
Relationships:  existing relationships + 1 credential reachability edge
Evidence:       supporting records
Findings:       0

Cloudflare Credential: OBSERVED
Credential Reachability: REACHABLE | APPROVAL_GATED | BLOCKED | UNKNOWN
Credential Value Stored: NO
```

If no supported credential reference exists:

```text
Status: COMPLETE
Cloudflare Credential: NOT OBSERVED
Findings: 0
```

Absence is valid and is not a scan failure.

If the credential is present but Bash is denied:

```text
Cloudflare Credential: OBSERVED
Credential Reachability: BLOCKED
```

Pico must not erase credential presence merely because the path to it is
blocked.

---

# 6. Scope

Sprint 005 includes only the minimum implementation required to observe the
first supported local credential-reachability edge.

## Required

Implement:

```text
authoritative Cloudflare local credential contract research

bounded credential-reference discovery

one supported Cloudflare credential type

one supported agent-accessible environment contract

safe credential identity or fingerprint

transient credential handle boundary

credential Resource normalization

Bash → can_access → Cloudflare Credential Relationship

reachability states derived from effective Bash and environment evidence

Evidence generation and linkage

Observation generation

ScanService and persistence integration

CLI/result summary

secret-safety validation

sanitized fixtures and tests
```

## Explicitly excluded

Do not implement:

```text
Cloudflare API calls

token verification

token policy introspection

permission-group discovery

account discovery

zone discovery

Worker discovery

Worker write-authority resolution

provider operation allowlists beyond what future authority work needs

GitHub credential discovery

generic secret scanning

recursive dotfile crawling

shell-history inspection

keychain inspection

browser-session inspection

credential rotation or revocation

credential export

Security Graph traversal

Authority Analysis

Boundary Evaluation

AttackPath construction

Finding generation

severity or remediation

runtime monitoring

enforcement

Sprint 006 functionality
```

---

# 7. Required Research Before Implementation

Sprint 005 is Pico's first credential adapter slice.

Do not implement credential detection based on guesses.

Before changing code, verify from authoritative Cloudflare and supported tool
documentation/source:

```text
the current supported Cloudflare API-token environment variable names

the exact credential types represented by those names

whether legacy global API key + email pairs remain supported

the current Wrangler/OpenCode environment behavior relevant to detection

which configuration locations, if any, are authoritative for local presence

which sources are references versus raw credential material

whether the supported agent Bash environment inherits each source

minimum token format facts needed for type classification

safe validation that does not contact Cloudflare
```

Use authoritative primary material:

```text
Cloudflare developer documentation

Wrangler documentation and source where necessary

OpenCode documentation/source for execution-environment behavior

the repository's canonical documents
```

Research only what Sprint 005 needs.

Do not research or implement:

```text
effective Cloudflare permissions

token verification endpoints

Worker APIs

resource scopes

write operations

production classification
```

If authoritative behavior contradicts this sprint's assumptions, stop before
implementation and report the contradiction.

Do not silently invent compatibility behavior.

---

# 8. Baseline and Preflight

Expected baseline:

```text
9feb704
```

Before implementation, report:

```text
branch
HEAD SHA
origin/main SHA
ahead/behind
working-tree state
repository structure
current Rust architecture
current discovery result contracts
current OpenCode adapter boundary
current Bash capability semantics
current ScanService persistence flow
current Resource/Relationship/Evidence/Observation contracts
current SQLite schema/migrations
current test count
cargo check
clippy
fmt
release build
```

If the repository is dirty or HEAD materially differs from the expected
baseline:

```text
STOP
```

Report the difference before building on it.

---

# 9. Architecture Boundary

Maintain:

```text
CLI
 ↓
Application / ScanService
 ↓
Credential Discovery / Cloudflare Adapter
 ↓
Normalization
 ↓
Secret-Safety Boundary
 ↓
Generic Domain
 ↓
Persistence
```

Provider-specific knowledge must remain outside Pico's generic domain.

Do not add:

```text
CloudflareCredentialResource

Cloudflare-specific fields to Resource

Cloudflare parsing in CLI handlers

environment enumeration in persistence code

secret values in DiscoveryResult

dynamic provider loading

a plugin framework
```

Architect for later provider authority resolution.

Implement only credential presence and reachability now.

---

# 10. Discovery Ordering

Credential discovery depends on earlier facts.

The bounded plan is:

```text
OpenCode discovered
        ↓
effective Bash state resolved
        ↓
supported environment boundary established
        ↓
Cloudflare credential reference discovered
        ↓
reachability normalized
```

Do not scan the entire machine for credentials.

Do not begin Cloudflare provider discovery merely because a credential exists.

Provider authority is a later dependent stage.

---

# 11. Supported Credential Source Boundary

Support the smallest deterministic source required for the golden path.

Candidate source classes must be verified before implementation:

```text
agent-accessible environment variable

explicit environment reference in supported agent configuration

supported provider-session reference
```

The implementation contract selected after research is intentionally limited
to:

```text
CLOUDFLARE_API_TOKEN in the scan environment

the exact project-root `.env` entry CLOUDFLARE_API_TOKEN
```

The project-root `.env` path is a single bounded file, not a recursive dotenv
search. Cloudflare documents it as a supported local Wrangler source. A
non-empty entry establishes presence and, when Bash has the supported project
filesystem boundary, a reachable file reference; it does not establish token
validity or authority.

Sprint 005 should prefer one exact source contract.

It must not recursively inspect:

```text
the home directory

arbitrary .env files

shell profiles

shell history

editor state

browser storage

keychains

password managers

unrelated process environments

container environments
```

An arbitrary file containing `CLOUDFLARE_API_TOKEN` is not authoritative
credential evidence.

---

# 12. Presence Versus Value

Pico needs to know that credential material is present.

Pico does not need to retain that material.

The discovery boundary may transiently observe:

```text
whether a supported source has a non-empty value

the credential type implied by the verified source contract

the minimum bytes needed to calculate a safe identity
```

The normalized output must contain only:

```text
provider
credential_type
source_type
source_locator
safe_fingerprint or safe source identity
presence
secret_stored: false
```

It must never contain:

```text
raw value
prefix + suffix previews
token length when unnecessarily identifying
authorization header
shell assignment
complete environment map
debug representation of the handle
```

---

# 13. Transient Credential Handle

Introduce the smallest internal boundary that prevents secret material from
entering normalized adapter output.

Conceptually:

```text
Credential Source
      ↓
Transient Credential Handle
      ├── provider
      ├── credential type
      ├── safe source locator
      └── tightly scoped access to value
      ↓
Safe normalization
```

The handle must:

```text
not implement Serialize

not expose the secret through Debug

avoid unnecessary clones

remain short-lived

never enter Resource metadata

never enter Evidence

never enter Observation

never enter diagnostics or logs
```

Sprint 005 does not need a general secret-management framework.

The handle only needs to support safe identity derivation and future bounded
provider-client use.

---

# 14. Safe Credential Identity

The Credential Resource needs stable identity across scans without placing a
secret in its canonical key.

Conceptually:

```text
credential:cloudflare:<safe-fingerprint>
```

The fingerprint construction must be:

```text
one-way
domain-separated
deterministic for the same credential
different for different credential values
non-authenticating
non-reversible under the expected credential entropy
free of raw token substrings
```

Do not use:

```text
the raw token
the first or last token characters
base64 of the token
reversible encryption as identity
the environment variable name alone when it would merge rotated credentials
```

If a safe fingerprint cannot be justified for the supported credential type,
use the smallest honest source-scoped identity and document the loss of
credential-rotation precision.

Do not invent cryptography. Use a reviewed standard construction and document
its threat assumptions.

---

# 15. Credential Resource

Normalize the credential into the existing generic `Resource` domain.

Conceptually:

```text
Resource
  kind: credential
  provider: cloudflare
  canonical_key: credential:cloudflare:<safe-fingerprint>
  name: Cloudflare API Token
  metadata:
    credential_type
    source_type
    source_locator
    presence: PRESENT
    validity: UNKNOWN
    authority_resolution: UNKNOWN
    secret_stored: false
```

Do not persist:

```text
credential material
token preview
authorization header
account identifier inferred from token contents
permission claims
Worker claims
```

Two scans observing the same credential must resolve to one stable Resource.

A rotated credential should become a distinct Resource when the safe identity
contract supports that distinction.

---

# 16. Reachability Model

Use the existing generic `Relationship` domain.

The new relationship is:

```text
Bash
  → can_access → Cloudflare Credential
```

The complete observed slice becomes:

```text
OpenCode
  → can_execute → Bash

Bash
  → can_access → Cloudflare Credential
```

Do not create:

```text
OpenCode → uses_credential → Credential
```

unless actual use is directly observed in a later authorized sprint.

Do not create:

```text
Credential → authorizes → Worker
```

in Sprint 005.

---

# 17. Reachability State

Relationship state and effective permission metadata remain separate.

Conceptually:

```text
credential present
+
supported environment inheritance established
+
Bash ALLOW
→ can_access DERIVED
→ reachability REACHABLE

credential present
+
supported environment inheritance established
+
Bash ASK
→ can_access DERIVED
→ reachability APPROVAL_GATED
→ runtime mode UNKNOWN unless observed

credential present
+
Bash DENY
→ can_access BLOCKED
→ reachability BLOCKED

credential present
+
Bash UNKNOWN or bounded/mixed
→ can_access UNKNOWN
→ reachability UNKNOWN

credential present
+
environment inheritance UNKNOWN
→ can_access UNKNOWN or absent
```

`ASK` must not be described as automatic credential access.

A blocked edge remains useful state because it records an enforced interruption
of this specific path.

---

# 18. Environment Inheritance

Environment inheritance is security-critical evidence.

Pico must distinguish:

```text
credential exists in Pico's own process

credential exists in a developer shell

credential is configured for an agent process

credential is available to Bash invoked by the supported actor
```

These are not automatically equivalent.

Implementation must define one supported deterministic inheritance contract.

If the current local scanner cannot prove that the scanned process environment
is the OpenCode Bash environment, the implementation must preserve that
uncertainty rather than creating a positive edge.

Controlled fixtures may supply an explicit synthetic execution-environment
projection for deterministic testing.

The production scanner must not claim stronger evidence than the real source
supports.

---

# 19. Evidence

Every claim must answer:

```text
How does Pico know the credential reference exists?

How does Pico know its credential type?

How does Pico know which environment exposes it?

How does Pico know Bash can or cannot reach it?

How does Pico know the persisted identity is not credential material?
```

Evidence may safely include:

```text
source type
source locator or variable name
presence: true
credential type
safe fingerprint algorithm/version
effective Bash permission
capability scope
runtime mode
environment-inheritance result
reachability classification
secret_stored: false
```

Evidence must not include:

```text
raw value
token preview
full environment dump
secret-bearing exception
secret-bearing command
secret-bearing configuration fragment
```

Expected evidence classes:

```text
DIRECT
  supported source reference/presence was directly observed

DECLARED
  authoritative configuration declares environment exposure

DERIVED
  reachability combines credential presence, environment inheritance,
  and effective Bash capability

INFERRED
  incomplete evidence suggests reachability but cannot establish it
```

Evidence remains scan-scoped and append-oriented.

---

# 20. Observations

Create scan-scoped Observations for:

```text
Credential Resource presence

Bash → can_access → Credential Relationship state
```

Observation metadata may include only safe normalized facts.

Repeated scans must preserve:

```text
one stable Credential Resource for the same credential

one stable reachability Relationship for the same endpoints

scan-specific Evidence

scan-specific Observations
```

Credential rotation must preserve history rather than rewriting the old
credential into the new one.

---

# 21. Secret-Safety Boundary

Sprint 005 must establish an explicit validation boundary before persistence.

Conceptually:

```text
Credential Adapter
      ↓
Safe Normalized Candidate
      ↓
Secret-Safety Validation
      ↓
Resource / Relationship / Evidence / Observation
```

At minimum, validate all credential-derived:

```text
canonical keys
names
source locators
observations
metadata
diagnostics
```

The validator must reject or redact prohibited secret material before a write.

Do not rely solely on fixture assertions after persistence.

The persistence-wide sentinel check remains mandatory as defense in depth.

---

# 22. Diagnostics and Failure Safety

Errors are a common secret-leak path.

Diagnostics must identify the safe source without rendering its value.

Good:

```text
unsupported Cloudflare credential value in environment:CLOUDFLARE_API_TOKEN
```

Bad:

```text
invalid token TEST_SECRET_SHOULD_NOT_PERSIST
```

Malformed, empty, or unsupported credential state should produce:

```text
COMPLETE with absence
```

or:

```text
PARTIAL with a secret-safe diagnostic
```

according to the verified source contract.

It must never panic, dump the environment, or persist the rejected value.

---

# 23. Network and Process Safety

Sprint 005 requires no network access.

Do not:

```text
contact api.cloudflare.com

verify the token

enumerate accounts, zones, or Workers

execute wrangler

execute OpenCode

launch a shell

run a command to test credential access

source shell profiles

load arbitrary environment files

perform an authentication probe
```

Credential reachability must be established from bounded local evidence.

No credential is required to implement or test this sprint.

---

# 24. ScanService Integration

Extend the existing scan pipeline without moving provider logic into the
application service.

Conceptually:

```text
DiscoveryResult
  actors
  bash_capabilities
  mcp_servers
  github_surfaces
  credential_references
  credential_reachability
  problems
```

The application service should:

```text
upsert the generic Credential Resource

resolve the existing Bash Resource

upsert the can_access Relationship

persist safe Evidence

link Evidence to the Relationship

persist scan-scoped Observations

report safe summary fields
```

Do not let `ScanService` parse environment variables or fingerprint secrets.

---

# 25. CLI Result

Add only the smallest useful output.

Conceptually:

```text
Cloudflare Credential: OBSERVED | NOT OBSERVED
Credential Reachability: REACHABLE | APPROVAL_GATED | BLOCKED | UNKNOWN
Credential Value Stored: NO
```

Do not display:

```text
token value
token preview
fingerprint unless explicitly needed for safe disambiguation
Cloudflare validity
Cloudflare permission
Worker authority
```

Findings remain:

```text
0
```

---

# 26. Fixtures

Use only synthetic credentials.

Required fixtures should cover:

```text
supported credential present

credential absent

empty supported source

OpenCode absent

Bash capability absent

unsupported Cloudflare-like variable

irrelevant file containing the supported variable name

same credential repeated across scans

credential rotation

Bash ALLOW

Bash ASK

Bash DENY

Bash UNKNOWN / bounded

environment inheritance confirmed

environment inheritance unknown

malformed supported source state
```

Use synthetic values such as:

```text
TEST_CLOUDFLARE_TOKEN_ALPHA_SHOULD_NOT_PERSIST

TEST_CLOUDFLARE_TOKEN_BETA_SHOULD_NOT_PERSIST
```

No real credentials may exist in fixtures, test output, or committed state.

---

# 27. Required Tests

At minimum test:

```text
supported Cloudflare credential presence

credential absence

unsupported source does not trigger detection

irrelevant files do not trigger detection

empty source is not a usable credential

OpenCode absence does not create credential reachability

Bash capability absence does not create credential reachability

credential Resource normalization

canonical key contains no raw secret substring

safe identity is deterministic

different credentials receive different safe identities

same credential preserves one Resource across scans

credential rotation preserves separate historical identity

ALLOW produces reachable state when inheritance is established

ASK produces approval-gated state

DENY produces blocked state

UNKNOWN Bash produces unknown state

unknown inheritance does not produce a positive reachability claim

Evidence generation and Relationship linkage

Observation generation

repeated scans create separate Observations

no provider authority Relationship

no Worker Resource

no Finding

partial credential-source failure retains trustworthy earlier-sprint state

no network access

no shell or subprocess execution

raw credential does not enter DiscoveryResult

raw credential does not enter Resource

raw credential does not enter Relationship

raw credential does not enter Evidence

raw credential does not enter Observation

raw credential does not enter diagnostics

raw credential does not enter CLI output

raw credential does not enter SQLite
```

The test suite must search every Pico-controlled persisted text field for both
synthetic sentinels.

---

# 28. Repeated Scans and Rotation

For the same credential observed twice:

```text
2 Scans
1 Credential Resource
1 stable can_access Relationship
2 credential Observations
2 reachability Observations
scan-specific Evidence
```

For credential A followed by credential B:

```text
2 Scans
2 Credential Resources when fingerprinting distinguishes them
historical Evidence for A remains intact
new Evidence for B is appended
no secret value is persisted for either
```

Do not delete the historical Credential Resource merely because it is not
observed in the newest scan.

Do not overwrite A's evidence with B's facts.

---

# 29. Expected Security State

Sprint 005 adds one authority-adjacent Resource and one reachability edge.

Expected new state:

```text
Resource:
Cloudflare Credential

Relationship:
Bash → can_access → Cloudflare Credential
```

Expected absent state:

```text
Cloudflare authority Relationships: 0
Cloudflare Worker Resources: 0
AttackPaths: 0
Findings: 0
```

The Credential Resource has:

```text
validity: UNKNOWN
authority_resolution: UNKNOWN
secret_stored: false
```

---

# 30. Scope Guardrails

Sprint 005 ends at:

```text
OpenCode
   ↓ can_execute
Bash
   ↓ can_access
Cloudflare Credential
```

It must not continue to:

```text
Cloudflare Account

Cloudflare Zone

Cloudflare Worker

Workers Scripts write

production classification

AttackPath

Finding
```

Encountering a real token does not authorize Pico to contact Cloudflare.

Encountering a Worker-related variable does not authorize Worker discovery.

Do not begin Sprint 006.

---

# 31. Architecture Pressure Test

Before completion, explicitly answer:

1. Can Pico represent a credential without persisting its value?
2. Is the credential identity stable without containing recoverable secret material?
3. Does the transient handle keep secrets out of normalized adapter output?
4. Can Pico distinguish credential presence from Bash reachability?
5. Does `ASK` remain approval-gated rather than automatic?
6. Does `DENY` create a truthful blocked edge?
7. Does unknown environment inheritance remain `UNKNOWN`?
8. Do repeated scans and rotation preserve correct history?
9. Does provider-specific parsing remain outside the generic domain?
10. Does the design avoid requiring a general secret scanner or provider framework?

If any answer is `NO`, do not hide it.

Fix only friction clearly within Sprint 005 scope.

Otherwise stop and report it for review.

---

# 32. Definition of Done

Sprint 005 is complete only when:

```text
the authoritative supported credential contract is documented

one bounded credential source is implemented

one Cloudflare credential type is normalized

the raw credential remains transient

safe identity is stable across scans

same-credential and rotation history are correct

Bash reachability is represented honestly

ALLOW / ASK / DENY / UNKNOWN remain distinct

unknown inheritance does not become positive reachability

Evidence explains presence, type, identity, and reachability

Observations are scan-scoped

no provider API is contacted

no command is executed

no authority is inferred

no Worker is discovered

no AttackPath or Finding is created

all secret-sentinel checks pass

all required verification passes

the final diff is clean and scoped
```

---

# 33. Verification

Run:

```bash
cargo test

cargo check

cargo clippy --all-targets -- -D warnings

cargo fmt --check

cargo build --release
```

Then manually verify controlled environments for:

```text
credential present + Bash ALLOW

credential present + Bash ASK

credential present + Bash DENY

credential absent

credential rotated

environment inheritance unknown
```

Inspect SQLite after every security-significant scenario.

Verify:

```text
stable Resources and Relationships

scan-specific Evidence and Observations

correct Relationship states

no credential material

no Cloudflare authority

no Worker Resource

no Findings
```

Search the complete Pico-controlled workspace and database representation for
the synthetic sentinels.

Expected matches:

```text
0
```

outside the fixture source files themselves.

---

# 34. Final Diff Inspection

Inspect the entire Sprint 005 diff.

Check for:

```text
raw credentials

secret previews

synthetic sentinel leakage outside fixtures/tests

environment dumps

secret-bearing debug output

accidental .pico state

build artifacts

machine-specific paths

unnecessary dependencies

home-directory crawling

subprocess execution

network code

Cloudflare API calls

Worker logic

AttackPath or Finding logic

speculative abstractions

unrelated refactoring
```

Stage only Sprint 005 changes.

---

# 35. Stop Conditions

Stop before implementation if:

```text
the baseline is unexpected

the working tree is dirty

the supported credential source cannot be established authoritatively

environment inheritance cannot support a truthful positive reachability edge

safe fingerprinting would retain recoverable credential material

the implementation requires scanning unrelated machine state

the implementation requires network access

the implementation requires executing a shell or provider CLI

the current domain cannot distinguish presence, reachability, and authority

canonical documents contradict the proposed slice
```

Do not silently weaken the product's secret-safety promise to complete the
sprint.

---

# 36. Deliverables

Expected deliverables:

```text
verified Cloudflare credential-source contract

verified execution-environment reachability contract

bounded credential adapter

transient credential handle

safe credential identity/fingerprint

generic Credential Resource normalization

Bash → can_access → Credential Relationship

reachability state normalization

Evidence generation and linkage

Observation generation

secret-safety validation

ScanService integration

CLI/result update

sanitized fixtures

unit, integration, persistence, rotation, and secret-leakage tests

SPRINT-005.md completion evidence
```

Do not modify Sprints 001–004.

Do not rewrite canonical documents unless implementation uncovers a genuine
contradiction requiring founder review.

---

# 37. Completion Evidence

When implementation is complete, set:

```text
Status: COMPLETE
```

Record:

```text
Baseline:
9feb704

Implementation commit:
<sha>

Authoritative Cloudflare credential contract:
<summary and sources>

Supported environment/reachability contract:
<summary and sources>

Safe fingerprint contract:
<summary>

Transient handle contract:
<summary>

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

Credential-present scan:
<result>

Credential-absent scan:
<result>

ALLOW reachability:
<result>

ASK reachability:
<result>

DENY reachability:
<result>

UNKNOWN reachability:
<result>

Unknown-inheritance behavior:
<result>

Repeated-scan identity:
<result>

Credential-rotation history:
<result>

Evidence persistence:
<result>

Observation persistence:
<result>

Secret-sentinel persistence check:
<result>

Network requests:
0

Subprocesses executed for discovery:
0

Cloudflare provider calls:
0

Cloudflare Worker Resources:
0

AttackPaths:
0

Findings:
0

Real credentials required:
NO

Raw credentials persisted:
NO

Sprint 006+ functionality implemented:
NO
```

Also record the architecture pressure-test results and only genuine follow-ups.

---

# 38. Commit

If and only if Sprint 005 is fully implemented and verified:

```text
stage only Sprint 005 changes

inspect the staged diff

commit with:

feat(discovery): observe Cloudflare credential reachability
```

Do not amend previous commits.

Do not push unless explicitly authorized at implementation time.

Do not begin Sprint 006.

---

# 39. Sprint Exit

Sprint 005 proves:

> **Pico can establish that OpenCode's Bash capability can reach a supported Cloudflare credential without retaining the credential value.**

At sprint exit, Pico should represent:

```text
OpenCode
   ↓ can_execute
Bash
   ↓ can_access
Cloudflare Credential

Credential value persisted:
NO

Credential validity:
UNKNOWN

Credential authority:
UNKNOWN
```

It does not yet establish:

```text
token validity

Cloudflare permissions

account or zone scope

Worker discovery

production mutation authority

a complete AttackPath

a Finding
```

The next roadmap question is:

> **What Cloudflare authority does the reachable credential have over which Worker resources, based only on safe read-only provider evidence?**

That belongs to Sprint 006.

Do not begin it here.

---

# 40. Completion Record

**Baseline:** `9feb704`

**Implementation commit:** `396de75 feat(discovery): observe Cloudflare credential reachability`

**Authoritative Cloudflare credential contract:** Sprint 005 supports only the
non-empty `CLOUDFLARE_API_TOKEN` source. Cloudflare documents `CF_API_TOKEN` as
deprecated and treats `CLOUDFLARE_API_KEY` plus `CLOUDFLARE_EMAIL` as a separate
legacy credential type. No local token grammar, prefix, or length validation is
performed; validity remains `UNKNOWN`. Sources: [Wrangler system environment
variables](https://developers.cloudflare.com/workers/wrangler/system-environment-variables/),
[local environment variables](https://developers.cloudflare.com/workers/local-development/environment-variables/),
and the deferred [Verify Token API](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/).

**Supported reachability contract:** A non-empty exact project-root `.env`
entry is a bounded file reference available to the supported project Bash
boundary and can produce derived reachability when Bash is unrestricted. A
token observed only in Pico's own process environment produces credential
presence but `UNKNOWN` reachability unless a caller explicitly supplies the
same-launch environment contract. No shell profiles, history, keychains,
plugins, or unrelated files are inspected.

**Safe identity:** A domain-separated SHA-256 digest is persisted as a
non-authenticating fingerprint. Raw values and previews never enter the
normalized discovery result, domain, persistence, diagnostics, or CLI output.

**Transient handling:** Raw values are consumed only inside the OpenCode
adapter long enough to determine non-empty presence and derive the safe
fingerprint. `ObservedCredential` contains no value field and is not a secret
handle or credential export.

**Tests:** `cargo test` — 99 passed / 0 failed.

**cargo check:** PASS

**clippy:** PASS (`--all-targets -- -D warnings`)

**fmt:** PASS (`cargo fmt --check`)

**release build:** PASS

**Credential-present scan:** PASS — stable Cloudflare Credential Resource,
`Bash → can_access → Credential`, safe evidence, and scan observations.

**Credential-absent scan:** PASS — no credential Resource or reachability edge.

**ALLOW reachability:** PASS — `REACHABLE` when the explicit environment
contract is proven.

**ASK reachability:** PASS — `APPROVAL_GATED`, never automatic access.

**DENY reachability:** PASS — `BLOCKED` relationship.

**UNKNOWN reachability:** PASS — unknown Bash or unknown environment remains
`UNKNOWN`.

**Unknown inheritance behavior:** PASS — current-process presence alone does
not become a positive reachability claim.

**Repeated-scan identity:** PASS — one stable Credential Resource and one
stable `can_access` Relationship with scan-specific Evidence and Observations.

**Credential rotation:** PASS — different safe fingerprints create distinct
historical Credential Resources without rewriting prior evidence.

**Evidence persistence:** PASS — direct presence evidence and derived
reachability evidence are persisted and linked safely.

**Observation persistence:** PASS — credential and relationship sightings are
scan-scoped.

**Secret-sentinel persistence:** PASS — synthetic sentinels have zero matches
in persisted Resources, Relationships, Evidence, or Observations.

**Network requests:** `0`

**Subprocesses executed for discovery:** `0`

**Cloudflare provider calls:** `0`

**Cloudflare Worker Resources:** `0`

**AttackPaths:** `0`

**Findings:** `0`

**Real credentials required:** `NO`

**Raw credentials persisted:** `NO`

**Sprint 006+ functionality implemented:** `NO`

## Architecture pressure test

- Credential without value: **PASS**
- Stable non-secret identity: **PASS**
- Transient adapter boundary: **PASS**
- Presence versus reachability: **PASS**
- ASK approval semantics: **PASS**
- DENY blocked semantics: **PASS**
- Unknown inheritance honesty: **PASS**
- Repeated-scan and rotation history: **PASS**
- Provider-specific knowledge outside generic domain: **PASS**
- No broad secret scanner or provider framework: **PASS**

## Genuine follow-ups

- Sprint 006 may use Cloudflare's read-only token verification and authority
  introspection; Sprint 005 intentionally makes no validity or authority claim.
- Legacy/plugin-injected environment variables remain unsupported and are kept
  `UNKNOWN` rather than discovered through broad machine inspection.
- A future runtime integration may establish a same-launch process contract
  for environment variables observed outside project `.env`.

## Validation tooling note

`vet` was invoked after each logical code unit but could not run its model
review because no Anthropic API credential is configured. Agent CI was invoked,
but this repository has no `.github/workflows` directory and the launcher
produced no workflow result before timeout. Rust verification and deterministic
integration tests passed independently.
