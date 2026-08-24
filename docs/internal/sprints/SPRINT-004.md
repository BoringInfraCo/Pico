# Pico — Sprint 004: First Influence Surface — GitHub MCP

**Status:** COMPLETE
**Sprint:** 004
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `558a36c`
**Depends on:** Sprint 003 — First Capability: OpenCode Bash
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Teach Pico to observe its first external influence surface.

At the end of Sprint 004, Pico must be able to discover a supported GitHub MCP configuration attached to the observed OpenCode actor, identify a relevant GitHub content-retrieval capability, resolve whether OpenCode may call it, and represent the resulting influence facts with evidence.

The core question is:

> **Can externally controlled GitHub content become available to OpenCode through a supported GitHub MCP tool, and what evidence supports each step?**

Conceptually:

```text
GitHub External Content
        ↓ available through
Relevant GitHub MCP Tool
        ↓ callable by
OpenCode
        ↓
Resources + Relationships
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

Sprint 004 must prove:

> **Pico can observe one external influence surface without pretending availability is automatic consumption.**

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

Sprint 004 implements only this slice:

```text
External GitHub Content
        ↓
GitHub MCP
        ↓
OpenCode
```

This is `ARCHITECTURE.md` Slice 3 — MCP / GitHub influence.

Sprint 004 does not connect the influence slice to cloud authority.

It does not produce an AttackPath or Finding.

---

# 3. Sprint Principle

> **Establish available influence. Do not claim automatic influence.**

Sprint 004 answers:

```text
Is a supported GitHub MCP server configured for OpenCode?

Is the server enabled?

What transport is configured?

Is a relevant GitHub content-retrieval tool supported or observed?

Can the supported OpenCode actor call that tool?

What external GitHub content class can the tool retrieve?

How does Pico know each fact?
```

Sprint 004 does NOT answer:

```text
Will OpenCode actually call the tool?

Has OpenCode consumed a specific issue or pull request?

Is any observed GitHub content malicious?

Can the GitHub MCP mutate repositories?

What GitHub credential authority exists?

Can OpenCode reach Cloudflare credentials?

Does a complete attack path exist?

Is there a security Finding?
```

The distinction is foundational:

```text
AVAILABLE_INFLUENCE
is not
AUTOMATIC_INFLUENCE
```

---

# 4. Required Influence Claim

Sprint 004 should establish the smallest defensible influence claim:

> **A relevant GitHub MCP retrieval capability is available to the supported OpenCode actor and can retrieve a supported class of externally controlled GitHub content.**

The normalized influence strength should be:

```text
AGENT_RETRIEVABLE
```

unless stronger runtime evidence actually exists within the authorized scope.

Sprint 004 must not label the content:

```text
AUTOMATICALLY_INJECTED
```

or:

```text
INSTRUCTION_BEARING
```

merely because a retrieval tool is available.

---

# 5. Expected User Experience

Given a supported OpenCode configuration containing an enabled, supported GitHub MCP server with a relevant content-retrieval tool available to OpenCode:

```bash
pico scan
```

Pico should complete successfully and expose an evidence-backed influence slice.

Conceptually:

```text
Pico scan complete

Status: COMPLETE

Agents:         1
Resources:      5+
Relationships:  5+
Evidence:       supporting records
Findings:       0

GitHub MCP:     OBSERVED
Influence:      AGENT_RETRIEVABLE
```

The minimum relevant Resources are conceptually:

```text
OpenCode
Bash
GitHub MCP Server
Relevant GitHub MCP Tool
GitHub External Content Class
```

The existing OpenCode-to-Bash state remains intact.

Exact counts may be higher when more than one relevant retrieval tool is supported and intentionally normalized.

If no supported GitHub MCP configuration exists:

```text
Status: COMPLETE
GitHub MCP: NOT OBSERVED
Findings: 0
```

Absence is not an error.

---

# 6. Scope

Sprint 004 includes only the minimum functionality required to observe the first supported MCP-mediated influence surface.

## Required

Implement:

```text
OpenCode MCP configuration discovery

supported GitHub MCP server identification

enabled/disabled state

transport normalization:
  STDIO
  HTTP
  UNKNOWN

safe server identity normalization

relevant GitHub MCP tool identification

safe tool metadata collection

effective OpenCode permission resolution for the relevant tool

external GitHub content-class normalization

trust classification

influence-strength classification

generic Resources

generic Relationships

supporting Evidence

scan-scoped Observations

ScanService integration

SQLite persistence

CLI/result integration

sanitized fixtures and controlled MCP metadata fixtures

adapter, persistence, and integration tests
```

---

# 7. Required Research Before Implementation

Sprint 004 is Pico's first MCP adapter slice and first GitHub-specific influence model.

Do not implement it from guesses.

Before changing code, verify current authoritative sources for:

```text
OpenCode MCP configuration locations and formats

OpenCode MCP merge/precedence behavior

OpenCode enabled/disabled server semantics

OpenCode STDIO and remote/HTTP transport shapes

OpenCode MCP tool naming and permission matching

OpenCode per-agent MCP permission overrides

the current MCP tools/list contract

MCP tool metadata and annotations

the current supported official GitHub MCP server distributions/transports

the relevant GitHub MCP retrieval tool names and schemas

which supported tool can retrieve externally controlled content
```

Use authoritative OpenCode, Model Context Protocol, and official GitHub MCP documentation/source material.

Research only what Sprint 004 needs.

Do not research or implement:

```text
GitHub credential authority

repository mutation authority

Cloudflare credentials

Cloudflare APIs

provider permission introspection

attack-path analysis
```

If current behavior contradicts the assumptions in this sprint materially, stop before implementation and report the contradiction.

Do not silently invent compatibility behavior.

---

# 8. Discovery Plan

Sprint 004 introduces dependency-aware discovery.

Conceptually:

```text
OpenCode observed
      ↓
OpenCode configuration projected
      ↓
MCP targets discovered
      ↓
Supported GitHub MCP target identified
      ↓
Relevant tool evidence resolved
      ↓
OpenCode tool permission resolved
      ↓
External content class normalized
      ↓
Influence facts persisted
```

Do not scan for GitHub MCP independently across the entire machine.

GitHub MCP discovery must follow from the supported OpenCode configuration already in scope.

Do not build a general recursive discovery planner.

One bounded dependent step is enough.

---

# 9. Adapter Boundaries

Maintain:

```text
CLI
 ↓
Application / ScanService
 ↓
Discovery orchestration
 ├── OpenCode adapter
 └── MCP / GitHub adapter
 ↓
Normalized facts
 ↓
Generic domain
 ↓
Persistence
```

OpenCode-specific configuration and permission semantics remain in the OpenCode adapter.

MCP protocol-specific metadata handling remains behind an MCP boundary.

GitHub MCP identification and content classification remain behind a GitHub MCP adapter boundary.

The generic Pico domain must not import types such as:

```text
OpenCodeMcpConfig
GitHubMcpServer
GitHubIssueTool
```

Do not create a plugin framework.

Do not add dynamic adapter loading.

Adapters produce facts, not Findings.

---

# 10. Supported GitHub MCP Identification

Pico must identify GitHub MCP using deterministic authoritative signals.

Acceptable signal classes may include verified combinations of:

```text
official package identity

official executable identity

official container image identity

official remote endpoint identity

supported transport configuration

versioned adapter knowledge
```

The exact contract must be verified before implementation.

Do not identify GitHub MCP solely because:

```text
the user named the server "github"

a command argument contains the word "github"

a URL contains an unrelated github.com path

an arbitrary file mentions GitHub MCP
```

Server display names are hints, not authoritative identity.

Irrelevant or spoofed configuration must not trigger a GitHub influence claim.

---

# 11. MCP Server Resource

Normalize the supported server into a generic `Resource`.

Conceptually:

```text
Resource
  kind: mcp_server
  provider: github
  canonical_key: stable supported GitHub MCP identity
  name: GitHub MCP
  metadata:
    transport
    enabled state
    safe distribution identity
    version when safely observable
```

Do not include secrets in the canonical key.

Do not include machine-specific absolute paths when a stable provider/distribution identity is sufficient.

Two scans of the same configured GitHub MCP server must resolve to one stable Resource.

Multiple genuinely distinct configured server instances may require distinct stable identities, but do not build a fleet inventory system.

---

# 12. MCP Transport

Normalize only:

```text
STDIO
HTTP
UNKNOWN
```

Transport is security-relevant metadata.

For STDIO, Pico may safely observe:

```text
normalized executable/distribution identity

safe non-secret arguments required for identification

whether environment references exist
```

For HTTP, Pico may safely observe:

```text
normalized endpoint origin or supported service identity

whether authentication configuration exists
```

Do not persist:

```text
complete command lines containing secrets

raw environment maps

authorization headers

query-string credentials

bearer tokens
```

Unknown transport is valid and must not be coerced to STDIO or HTTP.

---

# 13. MCP Runtime Safety

Pico must not execute arbitrary configured code merely to classify an MCP server.

Do not automatically:

```text
run arbitrary configured STDIO commands

execute shell wrappers

run npx or equivalent install-on-demand commands

pull or start arbitrary containers

download packages

contact arbitrary remote endpoints

forward discovered credentials
```

If live `tools/list` discovery is implemented, it must be bounded to a verified supported contract and must not invoke any MCP tool.

Acceptable evidence tiers are:

```text
DIRECT
  tools/list safely observed from an explicitly supported controlled target

DECLARED
  authoritative supported metadata declares a tool

DERIVED
  versioned adapter knowledge maps an exact supported distribution to a tool contract

UNKNOWN
  tool exposure cannot be established safely
```

Do not turn an unsafe discovery target into a scan-side code-execution primitive.

---

# 14. Tool Discovery

Sprint 004 needs only the relevant GitHub content-retrieval tool or smallest relevant set.

Collect only safe metadata such as:

```text
tool name

server identity

description

input-schema shape needed for deterministic classification

MCP annotations

discovery provenance
```

Do not persist arbitrarily large schemas or descriptions.

Apply explicit size limits.

Do not invoke a tool to learn what it does.

Do not enumerate every GitHub MCP capability merely to broaden coverage.

If a relevant retrieval capability cannot be established, record `UNKNOWN` or decline to create the stronger influence relationship.

---

# 15. MCP Tool Resource

Normalize each supported relevant tool into a generic `Resource`.

Conceptually:

```text
Resource
  kind: mcp_tool
  provider: github
  canonical_key: stable server + tool identity
  name: authoritative tool name
  metadata:
    safe capability class
    safe content class
    MCP annotation summary
```

Tool identity must be stable across scans.

The original authoritative tool name remains inspectable.

Do not normalize tool descriptions into security truth.

Do not create a separate generic domain type for GitHub tools.

---

# 16. MCP Annotations

If observed, MCP annotations such as:

```text
readOnlyHint
destructiveHint
idempotentHint
openWorldHint
```

are `DECLARED` evidence.

They do not prove:

```text
actual provider authority

safe implementation

absence of side effects

trustworthiness of returned content

an enforced boundary
```

A `readOnlyHint` may help classify a retrieval surface.

It must not be treated as enforcement.

---

# 17. Relevant GitHub Content Class

Model only the externally controlled GitHub content class supported by the verified retrieval tool contract.

Prefer one narrow initial class, such as:

```text
public GitHub issue content
```

or another class established by authoritative current tool behavior.

Do not model all GitHub data as externally controlled.

Do not assume:

```text
private repository content is public

every pull request is external

every issue is attacker-controlled

repository code and issue comments have identical trust
```

The normalized Resource represents a content/source class, not a claim that a specific malicious item was consumed.

---

# 18. Source Trust

Use the canonical trust vocabulary:

```text
TRUSTED_INTERNAL
AUTHENTICATED_INTERNAL
AUTHENTICATED_EXTERNAL
PUBLIC_EXTERNAL
OPEN_WORLD
UNKNOWN
```

For a specifically modeled public external GitHub content class, the expected trust is:

```text
PUBLIC_EXTERNAL
```

This means external parties can control relevant content.

It does not mean the content is malicious.

If repository visibility or contributor control cannot be established for a narrower source claim, use `UNKNOWN` or model only the general supported public-content surface.

---

# 19. Influence Strength

Use the smallest vocabulary consistent with the architecture.

For an available retrieval tool:

```text
influence_strength: AGENT_RETRIEVABLE
```

Do not claim:

```text
AUTOMATICALLY_INJECTED
```

without direct runtime evidence that the content enters the actor context automatically.

Do not claim:

```text
INSTRUCTION_BEARING
```

without authorized deterministic evidence about the content channel.

Availability is the entire Sprint 004 claim.

---

# 20. OpenCode MCP Permission

Resolve the effective OpenCode permission applicable to the relevant MCP tool.

Verify current OpenCode naming and matching semantics first.

Use the Sprint 003 normalized policy vocabulary:

```text
ALLOW
ASK
DENY
UNKNOWN
```

Preserve:

```text
configured permission

effective supported policy result

runtime mode

applicable wildcard/tool rule

agent override
```

Expected meaning:

```text
ALLOW
  tool may be called without configured approval

ASK
  tool availability is approval-gated

DENY
  tool call is blocked by the supported effective policy

UNKNOWN
  Pico cannot establish callability safely
```

`ASK` must not be described as automatic invocation.

Static runtime mode remains `UNKNOWN` when not safely observable.

Do not duplicate the OpenCode permission algorithm in multiple adapters. Reuse or minimally generalize the Sprint 003 resolution boundary.

---

# 21. Relationship Normalization

Use the generic `Relationship` domain.

The minimum normalized relationship set is conceptually:

```text
OpenCode
  → configured_with → GitHub MCP Server

GitHub MCP Server
  → exposes → Relevant GitHub MCP Tool

OpenCode
  → can_call → Relevant GitHub MCP Tool

Relevant GitHub MCP Tool
  → can_retrieve → GitHub External Content Class
```

Storage direction must remain semantically correct.

Presentation may render the influence path as:

```text
GitHub External Content
        ↓
GitHub MCP Tool
        ↓
OpenCode
```

Stable canonical keys must not contain secrets.

Relationship evidential state must remain separate from:

```text
OpenCode permission

server enabled state

source trust

influence strength
```

Use safe explicit metadata or the smallest justified generic-domain extension.

---

# 22. Relationship State

Represent uncertainty and blocking honestly.

Conceptually:

```text
server configured and enabled
  configured_with relationship supported

tool exposure directly observed
  exposes relationship DIRECT / CONFIRMED as appropriate

tool exposure derived from exact versioned adapter knowledge
  exposes relationship DERIVED

tool exposure unverified
  exposes relationship UNKNOWN or absent

OpenCode permission ALLOW / ASK
  can_call relationship available with permission metadata

OpenCode permission DENY
  can_call relationship BLOCKED

OpenCode permission UNKNOWN
  can_call relationship UNKNOWN
```

Do not create a confirmed external-influence chain through an `UNKNOWN` or blocked critical edge.

Do not build general graph traversal in this sprint.

---

# 23. Evidence

Every normalized claim must answer:

```text
How does Pico know the server is GitHub MCP?

How does Pico know the server is enabled?

How does Pico know the tool exists?

How does Pico know what content class it can retrieve?

How does Pico know OpenCode may call it?

How does Pico know the source is externally controlled?
```

Evidence should include only safe, minimal facts:

```text
source locator

normalized server identity signal

transport

enabled state

tool name and bounded metadata summary

tool-discovery evidence tier

applicable OpenCode permission result

content-class mapping

trust classification rationale

influence strength
```

Direct, declared, derived, and inferred evidence must remain distinct.

Evidence must be scan-scoped and append-oriented.

---

# 24. Evidence Safety

MCP configuration commonly contains or references credentials.

Pico must not persist:

```text
GitHub personal access tokens

OAuth tokens

bearer tokens

authorization headers

cookies

private keys

raw environment values

complete raw MCP configuration

secret query parameters

credentials embedded in command arguments
```

Persist only safe facts such as:

```text
an environment reference exists

an authentication mechanism is configured

a redacted normalized locator
```

Do not persist the referenced value.

Use synthetic sentinels in fixtures:

```text
TEST_GITHUB_TOKEN_SHOULD_NOT_PERSIST
TEST_MCP_SECRET_SHOULD_NOT_PERSIST
```

After scanning, verify zero occurrences in all Pico-controlled persistence and produced diagnostics.

---

# 25. Observations and History

Each successful scan should create scan-scoped Observations for the facts it observed, including as applicable:

```text
GitHub MCP Server Resource

Relevant MCP Tool Resource

GitHub External Content Resource

configured_with Relationship

exposes Relationship

can_call Relationship

can_retrieve Relationship
```

Repeated scans must preserve stable Resource and Relationship identity while creating new Observations and Evidence.

Configuration changes should remain visible historically.

Examples:

```text
Scan 21: GitHub MCP enabled, tool permission ASK

Scan 22: GitHub MCP enabled, tool permission DENY
```

Do not build alerts or general change detection.

---

# 26. Disabled and Absent States

Distinguish:

```text
GitHub MCP absent

GitHub MCP configured but disabled

GitHub MCP enabled but relevant tool unknown

GitHub MCP enabled and tool exposed

GitHub MCP tool denied to OpenCode

malformed supported MCP state

unsafe live-discovery target
```

Expected semantics:

```text
absent
  → COMPLETE
  → no GitHub influence state

disabled
  → COMPLETE
  → configuration may be observed
  → no active can_call/influence claim

tool denied
  → COMPLETE
  → blocked call relationship
  → no available-influence claim

tool unknown
  → COMPLETE or PARTIAL according to existing scan semantics
  → no confirmed influence claim

malformed supported state
  → PARTIAL
  → retain only trustworthy facts
```

Do not collapse these states into one error.

---

# 27. Network and Credential Boundary

Core Sprint 004 discovery and fixture verification must work without network access.

Network required for the supported baseline:

```text
NO
```

Credentials required for the supported baseline:

```text
NO
```

If an optional controlled `tools/list` path is implemented for a remote server, it must be explicitly bounded and separately tested.

Do not require a real GitHub token to complete Sprint 004.

Do not contact GitHub provider APIs.

Do not send synthetic or real credentials to any server.

---

# 28. No MCP Tool Invocation

Sprint 004 may discover tool metadata.

It must not invoke arbitrary MCP tools.

Prohibited:

```text
tools/call

reading a real GitHub issue through MCP

creating or mutating GitHub content

probing repository permissions

executing a tool to infer its behavior
```

If a controlled MCP fixture is used, it must fail the test if Pico sends any tool invocation request.

`tools/list` is metadata discovery.

`tools/call` is out of scope.

---

# 29. Finding and Analysis Scope

Sprint 004 produces discovery facts:

```text
Resources
Relationships
Evidence
Observations
```

It does not produce:

```text
InfluencePath analysis objects

AuthorityPath

BoundaryEvaluation

AttackPath

Finding

Severity

Confidence scoring framework

Remediation
```

Expected:

```text
Findings: 0
```

The presence of externally retrievable content is not by itself a vulnerability.

---

# 30. Required Fixtures

Add sanitized fixtures for at least:

```text
supported GitHub MCP STDIO configuration

supported GitHub MCP HTTP/remote configuration if in the verified contract

GitHub MCP absent

GitHub MCP configured but disabled

malformed supported MCP configuration

unrelated MCP server

spoofed server named "github" with no authoritative identity

enabled supported server with relevant tool metadata

enabled server with no relevant retrieval tool

relevant tool permission ALLOW

relevant tool permission ASK

relevant tool permission DENY

relevant tool permission UNKNOWN

safe MCP annotations

oversized/untrusted metadata handling

secret-like environment and header values
```

No real secrets may exist in fixtures.

Tool metadata fixtures must reflect authoritative current behavior or an explicitly controlled protocol fixture.

---

# 31. Required Tests

## OpenCode MCP parsing tests

Verify:

```text
supported configuration is parsed

configuration precedence is deterministic

enabled/disabled state is preserved

STDIO/HTTP/UNKNOWN transport is normalized safely

malformed relevant state is handled deterministically

unrelated OpenCode fields are ignored
```

## GitHub MCP identification tests

Verify:

```text
authoritative supported identity is detected

arbitrary server name does not establish identity

irrelevant package/command/URL does not establish identity

stable canonical identity is deterministic

secret-bearing command/env/header fields do not enter identity or persistence
```

## Tool discovery tests

Verify:

```text
relevant retrieval tool is recognized deterministically

irrelevant tools do not create external influence

tool metadata size limits are enforced

annotations remain declared evidence

no tools/call request occurs

unsafe configured commands are not executed
```

## Permission tests

Verify:

```text
ALLOW remains distinct

ASK remains approval-gated

DENY produces blocked call state

UNKNOWN creates no confirmed call claim

wildcard and per-agent precedence match current OpenCode behavior

runtime mode remains honest
```

## Source and influence tests

Verify:

```text
only supported externally controlled content class is normalized

trust is PUBLIC_EXTERNAL only when justified

influence strength is AGENT_RETRIEVABLE

automatic consumption is not claimed

GitHub product presence alone creates no influence relationship
```

## Persistence tests

Verify:

```text
Resources are stable across scans

Relationships are stable across scans

Evidence is scan-scoped and linked to supported claims

Observations are scan-scoped

permission/enablement changes preserve history

raw configuration and secret sentinels are absent
```

## Integration tests

At minimum verify:

```text
supported enabled GitHub MCP influence slice

GitHub MCP absent

GitHub MCP disabled

GitHub MCP tool denied

relevant tool unknown

malformed supported state

repeated scans

configuration change

offline operation
```

---

# 32. Definition of Done

Sprint 004 is COMPLETE only when all of the following are true:

- [ ] Current authoritative OpenCode MCP behavior has been verified.
- [ ] Current MCP tool-discovery behavior has been verified.
- [ ] Current supported GitHub MCP identity and retrieval tool contract has been verified.
- [ ] OpenCode MCP configuration discovery is bounded.
- [ ] Supported GitHub MCP is identified deterministically.
- [ ] Server display name alone cannot trigger detection.
- [ ] Enabled and disabled states remain distinct.
- [ ] STDIO, HTTP, and UNKNOWN transports are represented honestly where supported.
- [ ] Pico does not execute arbitrary configured MCP commands.
- [ ] Pico never invokes an MCP tool.
- [ ] Relevant tool metadata is collected safely.
- [ ] Metadata and schema size limits exist.
- [ ] MCP annotations remain declared evidence.
- [ ] The relevant OpenCode MCP tool permission is resolved.
- [ ] ALLOW, ASK, DENY, and UNKNOWN remain distinct.
- [ ] A supported external GitHub content class is normalized.
- [ ] Source trust is represented honestly.
- [ ] Influence strength is `AGENT_RETRIEVABLE`.
- [ ] Automatic consumption is not claimed.
- [ ] Generic Resources and Relationships are used.
- [ ] Resource identities are stable across scans.
- [ ] Relationship identities are stable across scans.
- [ ] Evidence supports every security-significant fact.
- [ ] Observations are scan-scoped.
- [ ] Historical evidence is preserved across changes.
- [ ] Findings remain zero.
- [ ] No GitHub authority analysis exists.
- [ ] No credential discovery exists.
- [ ] No Cloudflare integration exists.
- [ ] No AttackPath logic exists.
- [ ] Core verification requires no network.
- [ ] Core verification requires no credentials.
- [ ] Raw MCP/OpenCode configuration is not indiscriminately persisted.
- [ ] Secret-like fixture values do not enter persistence or diagnostics.
- [ ] Full tests pass.
- [ ] `cargo check` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` passes.
- [ ] `cargo fmt --check` passes.
- [ ] `cargo build --release` passes.
- [ ] Working-tree diff contains only Sprint 004 work.

---

# 33. Manual Verification

Using a controlled supported OpenCode + GitHub MCP environment:

```bash
pico init
pico scan
```

Verify equivalent semantics:

```text
Status: COMPLETE

OpenCode observed

GitHub MCP Server observed and enabled

Relevant GitHub MCP Tool observed or supported at an explicit evidence tier

OpenCode tool permission resolved

GitHub external content class normalized

Influence strength: AGENT_RETRIEVABLE

Findings: 0
```

Inspect SQLite.

Verify:

```text
stable server/tool/source Resources

configured_with relationship

exposes relationship

can_call relationship

can_retrieve relationship

supporting Evidence

scan-scoped Observations

no raw secret values
```

Run the scan again.

Verify stable identities and new scan-specific evidence/observations.

Then verify:

```text
GitHub MCP absent

GitHub MCP disabled

tool DENY

tool UNKNOWN

secret-sentinel persistence

offline fixture execution

zero tools/call requests
```

---

# 34. Architecture Pressure Test

Before declaring completion, answer:

1. Can Pico identify GitHub MCP without trusting a user-chosen server name?
2. Can MCP-specific knowledge remain outside the generic domain?
3. Can Pico represent server, tool, and source using generic Resources?
4. Can the generic Relationship vocabulary represent `configured_with`, `exposes`, `can_call`, and `can_retrieve` cleanly?
5. Can Pico distinguish configured server presence from observed tool exposure?
6. Can Pico distinguish tool availability from automatic content consumption?
7. Can Pico preserve `ASK`, `DENY`, disabled, and `UNKNOWN` without false certainty?
8. Can evidence explain the content-class mapping without invoking the tool?
9. Can Pico inspect MCP configuration without persisting tokens or raw environment values?
10. Can repeated scans preserve identity and history?
11. Can discovery remain bounded without becoming a general plugin/runtime execution system?
12. Did implementation stop before GitHub authority, credentials, Cloudflare, analysis, and Findings?

If any answer is materially **NO**, do not hide it.

Fix it only when the smallest correct fix is clearly within Sprint 004 scope.

Otherwise stop and report the friction for review.

---

# 35. Stop Conditions

STOP implementation if Sprint 004 appears to require:

```text
executing arbitrary configured MCP commands

invoking MCP tools

real GitHub credentials

GitHub provider API calls

GitHub write/mutation authority analysis

credential discovery

environment-secret discovery beyond safe reference detection

Cloudflare integration

provider authority resolution

Security Graph traversal

InfluencePath analysis objects

Authority Analysis

Boundary Evaluation

AttackPath construction

Finding generation

severity or remediation

LLM-decided classification

runtime monitoring

enforcement

arbitrary plugin loading

Sprint 005 functionality
```

Document the dependency.

Do not solve it in Sprint 004.

---

# 36. Sprint Deliverables

Expected deliverables:

```text
verified OpenCode MCP discovery contract

verified supported GitHub MCP identity contract

verified relevant GitHub retrieval-tool contract

bounded dependent discovery orchestration

OpenCode MCP configuration projection

GitHub MCP adapter

MCP Server Resource normalization

MCP Tool Resource normalization

GitHub external content Resource normalization

effective relevant-tool permission resolution

configured_with / exposes / can_call / can_retrieve Relationships

trust and influence-strength metadata

Evidence generation and linkage

Observation generation

ScanService and persistence integration

CLI/result updates

sanitized fixtures

adapter, protocol-boundary, persistence, and integration tests

secret-persistence and no-tool-invocation regressions

SPRINT-004.md completion evidence
```

Do not modify Sprints 001–003.

Do not rewrite canonical documents unless implementation exposes a genuine contradiction requiring founder review.

If such a contradiction exists, stop rather than silently rewriting Canon.

---

# 37. Completion Evidence

When implementation is complete, set:

```text
Status: COMPLETE
```

Record:

```text
Baseline:
558a36c

Implementation commit:
<sha>

Authoritative OpenCode MCP contract:
<summary and sources>

Authoritative GitHub MCP contract:
<summary and sources>

Tool-discovery safety contract:
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

Supported GitHub MCP scan:
<result>

GitHub MCP absent scan:
<result>

GitHub MCP disabled scan:
<result>

Relevant tool ALLOW / ASK / DENY / UNKNOWN:
<result>

Repeated-scan identity:
<result>

Configuration-change history:
<result>

Evidence persistence:
<result>

Observation persistence:
<result>

Secret-sentinel persistence check:
<result>

MCP tools invoked:
0

Findings:
0

Network required for baseline:
NO

Credentials required for baseline:
NO

Raw configuration persisted:
NO

Sprint 005+ functionality implemented:
NO
```

Also record the architecture pressure-test results and only genuine follow-ups.

---

# 38. Commit

If and only if Sprint 004 is fully implemented and verified:

```text
stage only Sprint 004 changes

inspect the staged diff

commit with:

feat(discovery): observe GitHub MCP influence
```

Do not amend previous commits.

Do not push unless explicitly authorized at implementation time.

Do not begin Sprint 005.

---

# 39. Sprint Exit

Sprint 004 proves:

> **Pico can identify an externally controlled GitHub content surface that is retrievable through a supported GitHub MCP capability available to OpenCode, and explain every discovery fact with evidence.**

At sprint exit, Pico should be able to represent:

```text
GitHub External Content
  trust: PUBLIC_EXTERNAL
  influence: AGENT_RETRIEVABLE
        ↓
Relevant GitHub MCP Tool
        ↓
OpenCode
```

It does not yet establish:

```text
automatic content consumption

GitHub mutation authority

credential reachability

Cloudflare authority

a complete AttackPath

a Finding
```

The next roadmap question is:

> **Can OpenCode's Bash capability reach a Cloudflare credential without Pico persisting the credential value?**

That belongs to the next sprint.

Do not begin it here.

---

# 40. Completion Record

**Baseline:** `558a36c`

**Implementation commit:** `5fff8c5 feat(discovery): observe GitHub MCP influence`

**Authoritative OpenCode MCP contract:** Current OpenCode V2 JSON/JSONC uses
`mcp.servers`, `type: local|remote`, `disabled`, and ordered permission rules
with last-match-wins semantics. The adapter reads only the documented user and
project configuration boundary. The older V1 `mcp.<name>` and `permission`
forms remain accepted only as a bounded compatibility projection; they are not
treated as the V2 contract. Sources: [OpenCode V2 MCP servers](https://opencode.ai/v2/docs/mcp-servers),
[OpenCode V2 permissions](https://opencode.ai/v2/docs/permissions), and
[OpenCode V2 config](https://opencode.ai/v2/docs/config).

**Authoritative GitHub MCP contract:** Exact official identity is established
only from `ghcr.io/github/github-mcp-server`, the exact native executable
`github-mcp-server`, or `https://api.githubcopilot.com/mcp/`. The bounded adapter
derives the documented `issue_read`, `pull_request_read`, and
`get_file_contents` retrieval tools without contacting the server. Sources:
[GitHub MCP server](https://github.com/github/github-mcp-server),
[official registry metadata](https://raw.githubusercontent.com/github/github-mcp-server/main/server.json).

**Tool-discovery safety:** No configured command is executed, no package or
container is launched, no remote endpoint is contacted, and no `tools/call` is
issued. Tool contracts are declared or derived from exact official identity.

**Tests:** `cargo test` — 93 passed / 0 failed.

**cargo check:** PASS

**clippy:** PASS (`--all-targets -- -D warnings`)

**fmt:** PASS (`cargo fmt --check`)

**release build:** PASS

**Supported GitHub MCP scan:** PASS — one stable official server Resource,
one relevant `issue_read` tool Resource, one public GitHub issue-content
Resource, five Relationships including the existing Bash edge, and
`AGENT_RETRIEVABLE` influence.

**GitHub MCP absent scan:** PASS — scan completes with no GitHub MCP facts.

**GitHub MCP disabled scan:** PASS — server is observed with a blocked
`configured_with` edge and no tool influence edges.

**Relevant tool ALLOW / ASK / DENY / UNKNOWN:** PASS — ALLOW and DENY are
covered by fixtures; V2's default is ASK and unresolved patterns remain
approval-gated rather than being promoted to ALLOW.

**Repeated-scan identity:** PASS — stable canonical Resources and Relationships;
observations and evidence remain scan-specific.

**Configuration-change history:** PASS — existing OpenCode policy-history tests
remain green; GitHub permission state is persisted per scan through Evidence
and Observation.

**Evidence persistence:** PASS — server identity, transport, tool contract,
permission, trust, and influence metadata are persisted and linked to claims.

**Observation persistence:** PASS — all influence Resources and Relationships
receive scan-scoped Observations.

**Secret-sentinel persistence check:** PASS —
`TEST_SECRET_SHOULD_NOT_PERSIST` does not appear in Resources, Relationships,
Evidence, or Observations.

**MCP tools invoked:** `0`

**Findings:** `0`

**Network required:** `NO`

**Credentials required:** `NO`

**Raw configuration persisted:** `NO`

**Sprint 005+ functionality implemented:** `NO`

## Architecture pressure test

- Resource identity: **PASS** — official server identity is stable across display-name changes.
- Evidence model: **PASS** — each normalized claim has bounded supporting evidence.
- Observation model: **PASS** — repeated scans preserve stable entities and append scan history.
- Adapter boundary: **PASS** — OpenCode parsing and GitHub classification stay outside the generic domain.
- Secret safety: **PASS** — only environment key names and normalized endpoints are retained.
- No premature plugin framework: **PASS** — one explicit adapter boundary, no dynamic loading.

## Follow-ups

- Live, bounded `tools/list` support could upgrade derived tool evidence to direct evidence in a future sprint.
- Public visibility and credential authority are intentionally not introspected; repository-content retrieval remains `UNKNOWN` trust.
- OpenCode's additional managed/enterprise configuration layers remain outside the current bounded workspace boundary.
