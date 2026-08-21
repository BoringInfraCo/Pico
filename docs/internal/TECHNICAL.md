# Pico --- Technical Model

**File:** `TECHNICAL.md`\
**Status:** Canonical technical-definition handoff\
**Research verdict:** PASS\
**Date:** August 18, 2026\
**Stage:** Technical Feasibility → Architecture

------------------------------------------------------------------------

## 1. Purpose

This document defines the technical model Pico will use to discover,
represent, evaluate, and explain agent security exposure.

Pico is a local-first, read-only developer security product for
AI-native engineering environments.

Its core thesis is:

> **Agent security risk emerges where untrusted influence intersects
> autonomous authority.**

Pico's first job is not to detect an active attacker, classify prompts
as malicious, or block an agent. Its first job is to answer a narrower
question with evidence:

> **How can something untrusted reach something consequential through my
> agents?**

The core product object is the **Attack Path**.

Pico must be able to explain every meaningful edge in that path and
distinguish what it directly knows from what it derives, infers, or
cannot establish.

------------------------------------------------------------------------

## 2. Technical Feasibility Verdict

### Verdict: PASS

Research indicates that Pico's V0 security primitive is technically
feasible.

Modern coding-agent environments expose enough observable configuration
and permission state to establish meaningful portions of an agent attack
graph without executing an attack.

Examples include:

-   coding-agent configuration and permission rules;
-   MCP server configuration;
-   MCP tool discovery and tool metadata;
-   local shell and filesystem permissions;
-   credential presence and source metadata;
-   provider resource inventory;
-   provider permission and authorization metadata where available;
-   explicit approval, deny, sandbox, and isolation controls;
-   public/external content surfaces such as GitHub issues and pull
    requests.

The primary technical limitation is not whether Pico can construct
useful attack paths.

The limitation is **authority resolution precision**.

Different providers expose different levels of credential and
authorization introspection. Pico therefore MUST NOT treat all providers
or credential types as equally knowable.

Pico's architecture must support graded authority resolution and graded
evidence.

------------------------------------------------------------------------

## 3. Technical Invariants

The following are foundational rules.

### 3.1 Evidence before conclusions

Pico MUST NOT create a high-confidence relationship merely because two
resources coexist.

Every security-significant edge must have evidence.

### 3.2 Severity and confidence are separate

A path may be:

-   `CRITICAL` severity and `LOW` confidence;
-   `HIGH` severity and `HIGH` confidence.

Severity describes consequence.

Confidence describes how strongly Pico can establish the path.

### 3.3 Potential exposure is not exploitation

V0 discovers **potential attack paths**.

Pico MUST NOT claim:

-   compromise occurred;
-   malicious content propagated;
-   an agent was exploited;
-   an operation was executed;

unless future runtime evidence actually establishes those facts.

### 3.4 Read-only by default

Pico V0 MUST NOT:

-   mutate infrastructure;
-   invoke destructive provider APIs;
-   rotate credentials;
-   revoke credentials;
-   modify agent configuration;
-   automatically change permissions;
-   deploy code;
-   attempt exploitation;
-   perform destructive authorization probes.

### 3.5 Secret values are not product data

Pico cares about credential **presence, identity, scope, authority,
provenance, and accessibility**.

It does not need the credential value as persisted product state.

Pico MUST NOT persist raw:

-   API tokens;
-   passwords;
-   private keys;
-   OAuth access tokens;
-   refresh tokens;
-   session cookies;
-   secret environment values.

### 3.6 A hint is not enforcement

Descriptions, README instructions, prompts, MCP annotations, model
instructions, and policy prose do not automatically constitute security
boundaries.

Pico distinguishes **declared intent** from **enforced control**.

------------------------------------------------------------------------

## 4. Core Security Equation

Pico models two primary flows.

### Influence

Influence asks:

> What information can reach this actor?

Example:

``` text
External GitHub Issue
        ↓
GitHub MCP
        ↓
Coding Agent
```

### Authority

Authority asks:

> What consequential action can this actor perform?

Example:

``` text
Coding Agent
      ↓
Shell
      ↓
Cloud Credential
      ↓
Production Resource
```

### Intersection

The meaningful security condition is:

``` text
UNTRUSTED INFLUENCE
        ×
AUTONOMOUS AUTHORITY
        =
AGENT ATTACK SURFACE
```

An Attack Path exists when Pico can establish a sufficiently continuous
chain connecting those two flows.

------------------------------------------------------------------------

## 5. Attack Path Definition

An **Attack Path** is:

> An evidence-backed chain in which relevant influence can reach an
> autonomous actor, the actor can exercise capabilities that lead to
> consequential authority, and no adequate enforced trust boundary
> interrupts the chain.

A path should normally establish four properties.

### 5.1 Influence reachability

Can information from the source actually reach the actor?

### 5.2 Capability reachability

Can the actor actually invoke the relevant tool or capability?

### 5.3 Authority reachability

Does that capability or credential authorize an operation against a
consequential resource?

### 5.4 Boundary continuity

Is there an enforced control that prevents the influence-to-authority
chain from continuing automatically?

If Pico cannot establish one of these properties, it must lower
confidence, mark the edge unknown/inferred, or decline to make the
stronger claim.

------------------------------------------------------------------------

## 6. Security Graph

Pico should maintain one normalized security graph rather than separate
incompatible models for agents, MCP, credentials, and providers.

The graph contains:

``` text
Resources
+
Relationships
+
Evidence
+
Capabilities
+
Trust Boundaries
+
Security Roles
```

Influence and authority are graph interpretations over this common
model.

------------------------------------------------------------------------

## 7. Resource Model

A resource is an observed entity in the environment.

Conceptual shape:

``` text
Resource {
  id
  kind
  provider
  name
  location?
  metadata
  security_roles[]
  first_observed_at
  last_observed_at
}
```

Possible `kind` values:

``` text
agent
mcp_server
mcp_tool
repository
issue
pull_request
shell
filesystem
credential
provider_account
project
deployment
worker
database
environment
approval_gate
sandbox
external_source
```

Security roles are overlays rather than mutually exclusive resource
types:

``` text
source
actor
capability
sink
boundary
```

One resource may hold multiple roles.

------------------------------------------------------------------------

## 8. Relationship Model

Conceptual shape:

``` text
Relationship {
  id
  from_resource_id
  to_resource_id
  kind
  state
  confidence
  evidence_ids[]
  metadata
  observed_at
}
```

Initial relationship vocabulary may include:

``` text
configured_with
exposes
can_call
can_read
can_write
can_execute
can_access
can_retrieve
consumes
receives_from
uses_credential
authenticates_to
authorizes
can_deploy
can_mutate
scoped_to
protected_by
requires_approval
isolated_by
denied_by
```

The vocabulary should stay small and security-meaningful.

------------------------------------------------------------------------

## 9. Relationship State

A relationship should not be only true/false.

Recommended state:

### `CONFIRMED`

Pico has sufficient direct or declared authoritative evidence.

### `DERIVED`

Pico deterministically derives the relationship from multiple stronger
facts.

### `INFERRED`

Evidence suggests the relationship, but Pico cannot prove it.

### `UNKNOWN`

Pico lacks sufficient evidence.

### `BLOCKED`

An enforced control prevents the relationship under the observed
configuration.

`BLOCKED` is important because the graph must represent security
boundaries, not merely positive reachability.

------------------------------------------------------------------------

## 10. Evidence Model

Evidence is first-class.

Conceptual shape:

``` text
Evidence {
  id
  class
  source_type
  source_location
  subject
  observation
  captured_at
  freshness
  sensitive
  metadata
}
```

### 10.1 Evidence classes

#### DIRECT

Pico directly observes configuration or provider/API state.

Examples:

-   an MCP server exists in a config file;
-   an agent permission rule allows Bash;
-   a credential variable name is present in an agent-accessible
    environment;
-   a provider API returns a resource.

#### DECLARED

An authoritative system declares a capability or permission.

Examples:

-   an agent configuration explicitly allows a tool;
-   a provider returns a role or permission;
-   an MCP server advertises a tool.

Declared evidence is stronger when the declaring source controls the
capability.

#### DERIVED

Pico deterministically combines stronger evidence.

Example:

``` text
Agent can execute shell
+
credential is available to that shell
=
agent can access credential
```

#### INFERRED

Pico has suggestive but incomplete evidence.

Example:

A provider token successfully reads project metadata, but the provider
does not expose enough introspection to prove whether it can perform a
production mutation.

------------------------------------------------------------------------

## 11. Evidence Strength and Confidence

Confidence should be calculated from the weakest security-significant
edge, evidence freshness, contradictions, and source authority.

A conceptual starting point:

``` text
DIRECT + DIRECT       → HIGH / CONFIRMED
DIRECT + DECLARED     → HIGH / CONFIRMED
DIRECT + DERIVED      → HIGH
DIRECT + INFERRED     → MEDIUM
INFERRED + INFERRED   → LOW
UNKNOWN               → path incomplete
```

This is not the final scoring formula.

The important rule is:

> **Pico never silently upgrades uncertainty.**

------------------------------------------------------------------------

## 12. Evidence Freshness

Security state changes.

Evidence therefore requires freshness metadata.

Examples:

-   local configuration: valid until changed;
-   active process/session state: short-lived;
-   token verification: short-lived;
-   provider permissions: refresh periodically;
-   provider resources: refresh on scan;
-   MCP tool inventory: refresh when server/config changes.

A finding based on stale authority evidence should show reduced
confidence or request refresh.

------------------------------------------------------------------------

## 13. Agent Discovery

Pico should use explicit adapters for supported coding agents.

Initial candidates:

1.  OpenCode
2.  Claude Code
3.  Codex
4.  Cursor later if evidence quality is sufficient

### 13.1 OpenCode

Current OpenCode configuration exposes explicit permission rules for
tools such as:

-   `bash`;
-   `edit`;
-   `read`;
-   `webfetch`;
-   `websearch`;
-   `external_directory`;
-   custom tools;
-   MCP tools.

Rules resolve to:

``` text
allow
ask
deny
```

OpenCode also supports granular Bash patterns and per-agent overrides.

This is strong evidence for capability reachability.

Important nuance:

OpenCode's auto mode can automatically approve requests that would
otherwise be `ask`, while explicit `deny` remains enforced.

Therefore Pico cannot interpret `ask` without also considering
runtime/launch mode.

### 13.2 Claude Code

Claude Code exposes configuration across user, project, local, managed,
and command-line scopes.

It has explicit:

``` text
allow
ask
deny
```

permission semantics, MCP configuration, permission modes, sandbox
controls, managed MCP restrictions, and protected-path behavior.

This gives Pico a strong technical basis for identifying:

-   available tools;
-   automatically allowed tools;
-   approval-gated tools;
-   denied tools;
-   MCP servers;
-   MCP tool permissions;
-   sandbox boundaries;
-   project/worktree restrictions.

Important nuance:

Pico must evaluate effective configuration, not merely one settings
file.

### 13.3 Codex

Codex should receive its own adapter only after Pico verifies the
current effective configuration, sandbox, approval, MCP, and
tool-discovery surfaces against current Codex documentation/behavior.

Pico should not assume that OpenCode or Claude semantics transfer
directly to Codex.

------------------------------------------------------------------------

## 14. MCP Discovery

MCP is a major Pico surface because it creates both influence and
authority edges.

An MCP server may expose:

-   resources;
-   prompts;
-   tools;
-   external data;
-   destructive operations;
-   open-world interactions.

Pico should discover:

``` text
Agent
  ↓ configured_with
MCP Server
  ↓ exposes
MCP Tool
```

and separately classify the security meaning of each tool.

------------------------------------------------------------------------

## 15. MCP Tool Annotations

Current MCP tool annotations include:

``` text
readOnlyHint
destructiveHint
idempotentHint
openWorldHint
```

These are extremely useful to Pico as a **risk vocabulary**.

They are NOT authoritative security guarantees.

The MCP specification explicitly treats them as hints and warns clients
not to make security decisions based on annotations from untrusted
servers.

Therefore Pico MUST model them as:

``` text
Evidence class: DECLARED
Trust: server-dependent
Authority: insufficient alone
Boundary: never
```

Examples:

`openWorldHint = true` may strengthen evidence that a tool interacts
with external/untrusted entities.

`destructiveHint = true` may strengthen evidence that a tool has
consequential side effects.

But neither proves exact behavior.

------------------------------------------------------------------------

## 16. MCP Authorization

MCP authorization also matters to Pico.

For HTTP transports, MCP defines OAuth-oriented authorization behavior.

For STDIO transports, the specification states that credentials should
instead be obtained from the environment.

This creates an especially important local attack-surface pattern:

``` text
Coding Agent
     ↓
STDIO MCP Server
     ↓
Inherited Environment
     ↓
Provider Credential
```

Pico should therefore inspect MCP launch configuration and credential
*references/presence* without persisting credential values.

------------------------------------------------------------------------

## 17. Integration Intelligence

Pico should distinguish **integration intelligence** from **security
evidence**.

A service such as integrations.sh can accelerate discovery by describing
integration surfaces such as:

-   REST/OpenAPI;
-   MCP;
-   GraphQL;
-   CLI;
-   authentication mechanisms;
-   credential names and request placement.

This is valuable for answering:

> What surfaces might exist, and how are they normally connected?

It is NOT sufficient for answering:

> Does this specific credential have this specific authority in this
> specific environment?

Therefore:

``` text
integrations.sh / schemas / catalogs
        ↓
DISCOVERY INTELLIGENCE

provider/local observations
        ↓
SECURITY EVIDENCE
```

Pico may use integration intelligence to guide adapters and discovery,
but high-confidence findings must ultimately rely on
environment-specific evidence.

------------------------------------------------------------------------

## 18. Credential Model

Pico should represent a credential without persisting its secret.

Conceptual model:

``` text
Credential {
  id
  provider
  credential_type
  source_type
  source_location
  fingerprint?
  validity
  authority_resolution
  last_verified_at?
  secret_stored: false
}
```

Possible `source_type`:

``` text
environment
config_reference
keychain_reference
agent_runtime
mcp_runtime
provider_session
unknown
```

Pico should prefer opaque IDs/fingerprints and metadata.

------------------------------------------------------------------------

## 19. Credential Accessibility

Credential existence does not equal agent accessibility.

Pico must establish a chain such as:

``` text
Agent
  ↓ can_execute
Shell
  ↓ can_access
Credential
```

Potential evidence:

-   agent Bash permission;
-   environment inheritance;
-   MCP process configuration;
-   explicit environment mappings;
-   sandbox/environment restrictions.

Pico should not assume every credential on a machine is accessible to
every agent.

------------------------------------------------------------------------

## 20. Authority Resolution Tiers

Provider capability varies enough that Pico needs explicit
authority-resolution tiers.

### Tier A --- Exact

Pico can establish:

``` text
credential
+
permission
+
resource scope
+
target resource
```

and deterministically conclude whether the credential can perform a
class of action.

### Tier B --- Scoped

Pico can establish broad role/scope and resource reach, but not every
operation.

### Tier C --- Behavioral Read-Only Evidence

Pico can safely establish that the credential can access a resource or
API, but cannot introspect exact mutation authority.

This may establish read reachability but MUST NOT be upgraded into write
authority.

### Tier D --- Unknown

Credential exists, but Pico cannot safely establish effective authority.

Pico should say so.

------------------------------------------------------------------------

## 21. Cloudflare Authority Research

Cloudflare is a strong first authority provider.

Cloudflare API token permissions are segmented by resource scope,
including:

-   user;
-   account;
-   zone;
-   other product-specific resource scopes.

Cloudflare exposes permission groups and their scopes.

Cloudflare also provides token verification endpoints that establish
token validity/status.

Account-owned and user token APIs expose token-management surfaces when
the caller has the corresponding token-read permissions.

### Important limitation

A token being valid does NOT establish its complete authority.

`verify` establishes validity/status, not the full effective permission
graph.

Therefore Pico should resolve Cloudflare authority using the strongest
available combination of:

1.  token identity/status;
2.  token details/policy metadata where authorized;
3.  permission group IDs and scopes;
4.  explicit resource scopes;
5.  discovered target resources.

If Pico cannot read the token's policy/details with the credential
available, it must lower the authority-resolution tier.

### V0 decision

**Cloudflare is the preferred first infrastructure authority adapter.**

It provides enough explicit permission vocabulary to make the
golden-path prototype meaningful while still forcing Pico to handle
incomplete introspection honestly.

------------------------------------------------------------------------

## 22. GitHub Authority Research

GitHub provides strong authorization semantics for several modern
credential types.

Fine-grained personal access tokens have explicit permission categories
tied to API operations.

GitHub App installation tokens are especially attractive for Pico
because installation access can be constrained by:

-   repository selection;
-   installation permissions;
-   token permissions.

GitHub documentation states that installation-token creation responses
include permissions and accessible repositories when applicable.

GitHub also provides endpoints to list repositories accessible to an
installation.

### Important limitation

Not every GitHub credential type exposes authority equally cleanly.

Classic PATs, OAuth tokens, fine-grained PATs, GitHub App installation
tokens, and ephemeral workflow tokens have different semantics.

### V0 decision

Pico should model GitHub credential types separately rather than
creating one generic `github_token` authority model.

GitHub App and fine-grained-token semantics should receive stronger
authority resolution than credential types Pico cannot introspect
precisely.

------------------------------------------------------------------------

## 23. Vercel Authority Research

Vercel has increasingly granular RBAC.

Current role/permission concepts include:

-   team roles;
-   project roles;
-   extended permissions;
-   production deployment authority;
-   environment management;
-   environment-variable management;
-   deployment-protection management.

This is useful for reasoning about human/team authority.

However, Vercel's newer access-token permission model is documented as
private beta.

### V0 decision

Vercel MAY be useful for resource discovery in V0, but Pico should not
initially promise Cloudflare-equivalent exact token-authority
resolution.

Vercel should enter the authority graph at the precision supported by
observable evidence.

If exact token-to-operation authority cannot be established:

``` text
authority_resolution = SCOPED / UNKNOWN
```

not `EXACT`.

------------------------------------------------------------------------

## 24. External Influence Model

A source is not untrusted merely because it is external, and it is not
trusted merely because it is internal.

Pico should initially use a conservative source-trust model.

Potential categories:

``` text
TRUSTED_INTERNAL
AUTHENTICATED_INTERNAL
AUTHENTICATED_EXTERNAL
PUBLIC_EXTERNAL
OPEN_WORLD
UNKNOWN
```

Examples:

``` text
checked-in project config      → TRUSTED_INTERNAL
team-authored private issue    → AUTHENTICATED_INTERNAL
external contributor PR        → AUTHENTICATED_EXTERNAL
public GitHub issue            → PUBLIC_EXTERNAL
web search result              → OPEN_WORLD
unknown MCP response source    → UNKNOWN
```

These are source characteristics, not claims that content is malicious.

------------------------------------------------------------------------

## 25. Influence Reachability

Pico must distinguish:

``` text
source exists
```

from:

``` text
agent can receive source content
```

A strong influence edge requires evidence that the agent can retrieve,
automatically receive, or otherwise consume the source.

Example:

``` text
Public GitHub Issue
       ↓ can_retrieve
GitHub MCP Tool
       ↓ can_call
Coding Agent
```

The mere presence of a GitHub MCP server does not prove that every
GitHub content type can reach the agent.

Tool inventory and permissions should narrow the edge.

------------------------------------------------------------------------

## 26. Trust Boundary Definition

A **Trust Boundary** in Pico is:

> An enforced control that materially interrupts influence propagation,
> capability reachability, or authority reachability.

The word **enforced** is critical.

### Valid boundary examples

#### Hard deny

``` text
Agent
  ↓
Bash: DENY
```

If effective configuration guarantees Bash cannot be invoked, that edge
is blocked.

#### Sandbox isolation

A sandbox that technically prevents filesystem, network, environment, or
process access relevant to the next edge.

#### Credential scoping

A credential that lacks authority over the target resource.

#### Resource isolation

The actor cannot reach the target network/resource because of an
enforced technical boundary.

#### Mandatory approval

A human approval gate can be a boundary when the system technically
prevents the operation until an independent human approves it.

### Not a boundary

The following are not hard trust boundaries by themselves:

-   system prompts;
-   `AGENTS.md`;
-   `CLAUDE.md`;
-   README instructions;
-   "do not deploy" text;
-   model alignment;
-   naming conventions;
-   MCP tool annotations;
-   documentation;
-   warnings;
-   expected user behavior.

These may be evidence of intended policy, but they do not technically
interrupt the path.

------------------------------------------------------------------------

## 27. Approval Gates

Approval needs special handling.

An approval prompt does not eliminate the attack path.

It changes the path.

Example:

``` text
External Source
      ↓
Agent
      ↓
Shell
      ↓
Human Approval
      ↓
Production
```

This should normally reduce autonomous-risk severity because the path is
no longer fully autonomous.

But Pico should consider:

-   whether the approval is mandatory;
-   whether auto/bypass mode disables it;
-   whether prior persistent approval covers the operation;
-   whether the agent can use an alternate capability that bypasses it.

An approval that can be trivially bypassed is not a strong boundary.

------------------------------------------------------------------------

## 28. Agent Runtime Modes Matter

Static configuration is insufficient when runtime modes can change
effective permissions.

Examples found during research:

-   OpenCode auto mode automatically approves requests that otherwise
    require `ask`, while explicit denies remain enforced.
-   Claude Code supports permission modes with different approval
    behavior, including modes that can reduce or bypass prompts.
-   Claude Code's managed configuration can disable bypass modes and
    enforce MCP/tool restrictions.

Therefore Pico should model:

``` text
configured_permission
+
effective_runtime_mode
=
effective_capability
```

If runtime mode is unknown, Pico should preserve uncertainty rather than
assuming the safest state.

------------------------------------------------------------------------

## 29. Risk Model Inputs

V0 risk analysis should remain deterministic.

Initial dimensions:

### Source Trust

How externally controllable is the influence source?

### Influence Strength

How directly can content enter agent context?

Possible levels:

``` text
metadata_only
manual_retrieval
agent_retrievable
automatically_injected
instruction_bearing
```

### Capability

What can the actor do?

``` text
read
write
execute
admin
```

### Authority

What consequential provider/resource authority exists?

### Sink Impact

Potential levels:

``` text
local_dev
repository
staging
production
secrets
iam
billing
external_side_effect
```

### Boundary Strength

Examples:

``` text
none
soft_policy
approval
scoped_credential
sandbox
hard_deny
isolation
```

### Confidence

Calculated separately from severity.

------------------------------------------------------------------------

## 30. Finding Generation

Pico should generate findings from meaningful exposure stories rather
than every graph traversal.

Example raw paths:

``` text
Issue → Agent → Shell → Token → Worker A
Issue → Agent → Shell → Token → Worker B
Issue → Agent → Shell → Token → Worker C
```

Preferred finding:

``` text
CRITICAL EXPOSURE

External GitHub content can reach a coding agent
with Cloudflare production mutation authority.

Affected resources: 3 Workers
```

This reduces alert fatigue and makes findings actionable.

------------------------------------------------------------------------

## 31. Finding Classes for V0

Keep the initial set small.

Candidate classes:

``` text
UNTRUSTED_TO_PRODUCTION
UNTRUSTED_TO_SECRET
UNTRUSTED_TO_SHELL
UNTRUSTED_TO_DATABASE_MUTATION
UNBOUNDED_MCP_CAPABILITY
SHARED_PRIVILEGED_CREDENTIAL
```

V0 should prioritize 4--6 excellent rules over a large generic rule
catalog.

------------------------------------------------------------------------

## 32. Remediation Model

Pico remains read-only but should identify where a path can be broken.

For each path, identify candidate cut points:

``` text
Source
  ↓
Agent
  ↓
Capability
  ↓
Credential
  ↓
Sink
```

Possible remediation:

-   reduce source reachability;
-   deny a tool;
-   require an enforced approval;
-   enable sandbox isolation;
-   remove credential exposure;
-   scope credential authority;
-   isolate production resources.

Pico should explain the security effect of each recommendation.

------------------------------------------------------------------------

## 33. Golden Path Prototype

The first technical prototype should support exactly one high-quality
path.

Recommended golden path:

``` text
PUBLIC / EXTERNAL GITHUB CONTENT
             ↓
          GITHUB MCP
             ↓
          OPENCODE
             ↓
            BASH
             ↓
     CLOUDFLARE CREDENTIAL
             ↓
     CLOUDFLARE RESOURCE
```

### Why OpenCode first

OpenCode exposes explicit permission configuration with `allow`, `ask`,
and `deny`, granular Bash patterns, MCP tool rules, and per-agent
overrides.

This provides strong local evidence.

### Why GitHub

GitHub provides a realistic external-input surface and explicit
permission/resource models.

### Why Cloudflare

Cloudflare provides explicit permission groups, resource scopes, token
validity checks, and inspectable infrastructure resources.

This makes it a strong first authority adapter.

------------------------------------------------------------------------

## 34. Golden Path Proof Requirements

Pico must establish each edge separately.

### Edge 1

``` text
External GitHub content
→ GitHub MCP tool
```

Evidence:

-   relevant GitHub MCP capability exists;
-   tool can retrieve the relevant content class;
-   source trust is externally controllable/public.

### Edge 2

``` text
GitHub MCP tool
→ OpenCode
```

Evidence:

-   MCP server configured;
-   tool exposed;
-   effective OpenCode permission permits or approval-gates invocation.

### Edge 3

``` text
OpenCode
→ Bash
```

Evidence:

-   effective permission rule;
-   runtime mode;
-   applicable command scope.

### Edge 4

``` text
Bash
→ Cloudflare credential
```

Evidence:

-   credential reference/presence is visible in the execution
    environment;
-   no boundary prevents access;
-   secret value is not persisted.

### Edge 5

``` text
Cloudflare credential
→ Cloudflare authority
```

Evidence:

-   token validity;
-   strongest safely obtainable token policy/permission metadata;
-   permission group scope;
-   authority-resolution tier.

### Edge 6

``` text
Cloudflare authority
→ target resource
```

Evidence:

-   target resource discovered;
-   permission scope covers resource;
-   action class is compatible with permission.

### Boundary check

Evaluate:

-   `deny`;
-   approval;
-   auto/bypass mode;
-   sandbox;
-   credential scope;
-   resource scope;
-   other enforced isolation.

------------------------------------------------------------------------

## 35. Golden Path Success Output

A successful prototype should be able to produce something like:

``` text
CRITICAL ATTACK PATH

External GitHub Issue
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

Severity:   CRITICAL
Confidence: HIGH

Evidence
────────────────────────
✓ External issue content is retrievable through the configured MCP surface
✓ MCP capability is available to OpenCode
✓ Bash execution is effectively allowed
✓ Cloudflare credential is available to the shell environment
✓ Credential authority includes relevant Cloudflare write capability
✓ Authority scope covers the target resource
✓ No enforced boundary interrupts the autonomous path

Why this matters
────────────────────────
Externally controlled content can reach an autonomous
execution environment with authority capable of changing
a consequential Cloudflare resource.

This is a potential exposure path.
Pico has not observed exploitation.
```

If authority cannot be fully resolved:

``` text
Severity:   CRITICAL
Confidence: MEDIUM

Authority:
Potential production write authority detected,
but exact token policy could not be introspected.

Pico will not claim confirmed production mutation authority.
```

That honesty is part of the product.

------------------------------------------------------------------------

## 36. Provider Adapter Contract

Each provider authority adapter should eventually implement a contract
similar to:

``` text
discover_resources()

identify_credential_type()

verify_credential_status()

resolve_authority()

resolve_resource_scope()

collect_evidence()
```

`resolve_authority()` should return:

``` text
AuthorityResolution {
  tier
  permissions[]
  resource_scopes[]
  evidence_ids[]
  unknowns[]
}
```

Providers are allowed to return incomplete authority.

That is preferable to fabricated precision.

------------------------------------------------------------------------

## 37. Agent Adapter Contract

Each agent adapter should eventually expose:

``` text
detect()

discover_config()

discover_mcp_servers()

discover_tools()

resolve_permissions()

resolve_runtime_mode()

discover_boundaries()

collect_evidence()
```

The adapter's job is to calculate **effective** capability, not merely
parse files.

------------------------------------------------------------------------

## 38. Integration Intelligence Adapter

A separate intelligence layer may use sources such as integrations.sh
and machine-readable integration specifications.

Conceptual contract:

``` text
lookup_service()

discover_surfaces()

discover_auth_patterns()

discover_cli()

discover_mcp()

discover_openapi()

discover_graphql()
```

This layer must not directly produce high-confidence authority edges.

Its purpose is discovery acceleration and adapter enrichment.

------------------------------------------------------------------------

## 39. Local Storage

V0 should use a local persistent store.

The exact implementation belongs in `ARCHITECTURE.md`, but the technical
model requires durable local storage for:

-   resources;
-   relationships;
-   evidence metadata;
-   findings;
-   scans;
-   confidence;
-   timestamps;
-   provider metadata.

Raw secret values MUST NOT enter this store.

------------------------------------------------------------------------

## 40. Scan Semantics

A scan should be an evidence collection event.

Conceptually:

``` text
Scan
  ↓
Local discovery
  ↓
Agent discovery
  ↓
MCP discovery
  ↓
Provider discovery
  ↓
Evidence normalization
  ↓
Graph update
  ↓
Influence analysis
  ↓
Authority analysis
  ↓
Boundary evaluation
  ↓
Finding generation
```

A scan should not execute attack paths.

------------------------------------------------------------------------

## 41. Security of Pico Itself

Pico is a security product inspecting privileged environments.

It therefore must minimize its own authority.

Principles:

-   read-only provider permissions where possible;
-   no long-lived secret persistence;
-   no unnecessary outbound telemetry;
-   local-first storage;
-   explicit network operations;
-   narrow filesystem discovery;
-   no arbitrary recursive home-directory scanning;
-   clear evidence provenance;
-   deterministic core risk engine;
-   safe failure when provider introspection is incomplete.

Pico must not become a new privileged execution layer merely to inspect
existing privileged execution layers.

------------------------------------------------------------------------

## 42. Claims Pico May Make

With sufficient evidence:

> "OpenCode has Bash capability."

> "This GitHub MCP tool is available to OpenCode."

> "This environment exposes a Cloudflare credential to the shell."

> "This credential is valid."

> "This credential's observed policy includes a write permission scoped
> to these resources."

> "This attack path has no observed enforced boundary."

> "External GitHub content has a potential path to production
> authority."

------------------------------------------------------------------------

## 43. Claims Pico Must Not Make Without Stronger Evidence

> "This prompt is malicious."

> "This agent is compromised."

> "An attacker exploited this path."

> "This token can delete production" when exact authority is unknown.

> "This MCP tool is safe" because `readOnlyHint` says so.

> "Human approval protects this operation" when auto/bypass mode may
> remove the approval.

> "This credential is inaccessible" merely because Pico did not find it.

Absence of evidence is not always evidence of absence.

------------------------------------------------------------------------

## 44. Open Technical Questions

The Technical Feasibility Sprint is a PASS, but implementation should
investigate:

1.  Exact Codex effective-permission and runtime discovery.
2.  Whether Cloudflare token policy/details can be safely resolved for
    the current token across common user/account token configurations.
3.  How Pico identifies production vs staging resources across providers
    without relying solely on naming conventions.
4.  How to represent session-specific permission changes.
5.  How to fingerprint credentials without retaining recoverable secret
    material.
6.  How to detect environment inheritance accurately for STDIO MCP
    servers.
7.  How to model chained MCP/tool-to-tool authority.
8.  How to distinguish user-triggered retrieval from automatically
    injected influence.
9.  How evidence expiration should affect existing findings.
10. How to export the graph without leaking sensitive metadata.

These are architecture/implementation questions, not blockers to the
product primitive.

------------------------------------------------------------------------

## 45. V0 Technical Scope

### MUST

-   local-first;
-   read-only;
-   discover at least one supported coding agent;
-   discover effective tool permissions;
-   discover configured MCP servers/tools;
-   identify external influence surfaces;
-   detect credential presence without persisting values;
-   resolve at least one provider's authority with meaningful precision;
-   discover consequential resources;
-   represent enforced trust boundaries;
-   construct influence paths;
-   construct authority paths;
-   identify intersections;
-   generate evidence-backed findings;
-   separate severity and confidence;
-   explain every finding;
-   represent unknown/inferred edges honestly.

### SHOULD NOT

-   execute attacks;
-   classify malicious prompts;
-   intercept agent traffic;
-   proxy all MCP traffic;
-   mutate infrastructure;
-   automatically remediate;
-   rotate/revoke credentials;
-   require cloud control plane;
-   support every provider;
-   support every agent;
-   use an LLM as the authoritative risk engine.

------------------------------------------------------------------------

## 46. Technical Definition of Done

The technical model is validated when Pico can inspect a real local
environment and safely produce an evidence-backed path such as:

``` text
External Source
      ↓
MCP Capability
      ↓
Coding Agent
      ↓
Execution Capability
      ↓
Credential
      ↓
Privileged Resource
```

and answer, for every edge:

1.  **What is this relationship?**
2.  **How does Pico know?**
3.  **How fresh is the evidence?**
4.  **How confident is Pico?**
5.  **What boundary interrupts it, if any?**
6.  **What would break the path?**

Pico must be able to say **unknown** when evidence is insufficient.

If Pico can do this reliably for the golden path, the core technical
thesis is proven.

------------------------------------------------------------------------

## 47. Research Conclusions

The research produced several important decisions.

### Decision 1 --- The graph is feasible

Modern coding agents expose enough configuration and permission state to
construct useful security relationships.

### Decision 2 --- MCP is both an opportunity and a risk surface

MCP provides structured capability discovery, but its annotations are
hints rather than security guarantees.

### Decision 3 --- Provider authority must be tiered

Cloudflare, GitHub, Vercel, and future providers do not expose identical
credential introspection.

Pico must model this difference explicitly.

### Decision 4 --- Runtime mode matters

Static permission files alone do not establish effective agent
authority.

### Decision 5 --- Trust boundaries must be enforced

Instructions and intent are not equivalent to technical isolation.

### Decision 6 --- integrations.sh is intelligence, not proof

It can dramatically accelerate integration discovery without becoming
Pico's source of truth for environment-specific authority.

### Decision 7 --- Cloudflare is the preferred first authority adapter

Its permission-group and resource-scope model is a strong fit for Pico's
first prototype.

### Decision 8 --- OpenCode is the preferred first agent adapter

Its explicit permission model makes it a strong golden-path environment.

### Decision 9 --- Security honesty is a feature

Pico's ability to distinguish `CONFIRMED`, `DERIVED`, `INFERRED`, and
`UNKNOWN` is central to trust.

------------------------------------------------------------------------

## 48. Final Technical Thesis

Pico does not need to know whether content is malicious in order to
identify dangerous architecture.

It needs to establish:

``` text
Who can influence the agent?
        ↓
What can the agent invoke?
        ↓
What authority can those capabilities reach?
        ↓
What consequential resources are reachable?
        ↓
What enforced boundaries interrupt the path?
```

That produces the core Pico primitive:

> **An evidence-backed map of where untrusted influence can intersect
> autonomous authority.**

V0 discovers and explains those intersections.

Future versions can observe them at runtime.

Later versions can detect anomalous propagation.

Eventually Pico can control and contain them.

``` text
DISCOVER
   ↓
MAP
   ↓
EXPLAIN
   ↓
OBSERVE
   ↓
DETECT
   ↓
CONTROL
   ↓
CONTAIN
```

------------------------------------------------------------------------

# 49. Sprint Decision

## Technical Feasibility & Evidence Research: PASS

The core Pico product claim is technically credible enough to proceed.

The next canonical artifact should be:

# `ARCHITECTURE.md`

That document should turn this technical model into concrete
implementation boundaries:

-   package/module layout;
-   local database schema;
-   adapter interfaces;
-   discovery pipeline;
-   evidence persistence;
-   graph representation;
-   path-analysis algorithm;
-   risk-engine boundary;
-   CLI boundary;
-   MCP/agent interface;
-   secret-handling implementation;
-   provider networking;
-   testing strategy;
-   golden-path implementation plan.

The architecture must follow this technical model rather than weaken its
evidence requirements.

------------------------------------------------------------------------

# 50. Research Sources

Primary sources consulted during the Technical Feasibility Sprint:

-   Model Context Protocol specification --- Tool Annotations and
    security/trust guidance
    -   https://modelcontextprotocol.io/specification/2025-11-25/schema
    -   https://modelcontextprotocol.io/specification/2025-11-25
    -   https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
    -   https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/
-   OpenCode documentation --- Agents and permissions
    -   https://opencode.ai/docs/agents/
    -   https://opencode.ai/docs/permissions
-   Claude Code documentation --- permissions, settings, MCP,
    sandbox/security
    -   https://code.claude.com/docs/en/permissions
    -   https://code.claude.com/docs/en/settings
    -   https://code.claude.com/docs/en/security
    -   https://code.claude.com/docs/en/mcp
    -   https://code.claude.com/docs/en/permission-modes
-   Cloudflare documentation --- API token permissions and token APIs
    -   https://developers.cloudflare.com/fundamentals/api/reference/permissions/
    -   https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/
    -   https://developers.cloudflare.com/api/go/resources/user/subresources/tokens/
    -   https://developers.cloudflare.com/api/go/resources/accounts/subresources/tokens/
-   GitHub documentation --- fine-grained token permissions and GitHub
    App installations
    -   https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens
    -   https://docs.github.com/en/rest/apps/installations
    -   https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
-   Vercel documentation --- RBAC and access-token permission model
    -   https://vercel.com/docs/rbac/access-roles
    -   https://vercel.com/docs/rbac/access-roles/extended-permissions
    -   https://vercel.com/docs/sign-in-with-vercel/scopes-and-permissions
-   integrations.sh --- integration surface discovery
    -   https://integrations.sh/
    -   https://integrations.sh/publishing/

------------------------------------------------------------------------

**Canonical decision:** Pico proceeds to Architecture.
