# Pico — Sprint 006: First Provider Authority — Cloudflare Worker

**Status:** COMPLETE
**Sprint:** 006
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** b52559d
**Depends on:** Sprint 005 — First Credential Reachability — Cloudflare
**Canonical docs:** PRODUCT_DEFINITION.md, TECHNICAL.md, ARCHITECTURE.md, ROADMAP.md

---

# 1. Objective

Teach Pico to resolve its first provider authority without exercising that
authority.

At the end of Sprint 006, Pico must be able to use a reachable, supported
Cloudflare API token transiently, perform only explicitly allowlisted
read/introspection requests, discover the Cloudflare account and Worker
resources that the provider exposes, and determine whether the token has
Workers script mutation authority over each observed Worker.

The core question is:

> **Can the reachable Cloudflare credential mutate an observed Cloudflare
> Worker, and can Pico prove that from read-only authorization evidence?**

Conceptually:

~~~text
Cloudflare Credential
        ↓ transient authentication
Safe Cloudflare Provider Client
        ↓ read-only introspection
Token Status + Token Policy + Resource Scope + Worker Inventory
        ↓ deterministic resolution
Cloudflare Credential
        ↓ can_mutate
Cloudflare Worker
        ├── Evidence
        └── Observations
             ↓
           SQLite
~~~

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

Sprint 006 must prove:

> **Pico can resolve consequential provider authority without using it.**

---

# 2. Roadmap Position

The v0.1 golden path is:

~~~text
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
~~~

Sprint 006 implements only:

~~~text
Cloudflare Credential
        ↓
Cloudflare Worker
~~~

This is ARCHITECTURE.md Slice 5 — Cloudflare authority.

Sprint 006 completes discovery of the individual resource and relationship
facts required by the golden path. It does not project those facts into the
Security Graph, traverse the complete path, evaluate every boundary, or
produce an AttackPath or Finding.

Those remain later roadmap slices.

---

# 3. Sprint Principle

> **Prove authority from policy. Never probe authority with a mutation.**

Sprint 006 answers:

~~~text
Is the supported Cloudflare credential active?

Which token identity did Cloudflare verify?

Which supported token policy metadata can Pico read?

Does that policy contain Workers Scripts Write?

Which account resources does the policy cover?

Which Workers exist in those accounts?

Does the permission and resource scope cover each Worker?

What authority-resolution tier supports the conclusion?

What remains unknown?

How does Pico prove every claim?
~~~

Sprint 006 does not answer:

~~~text
Has OpenCode used the credential?

Has the token ever changed a Worker?

Is a Worker production merely because of its name?

Can external GitHub content traverse the complete golden path?

Does an enforced boundary interrupt that path?

Is there an AttackPath?

Is there a Finding?
~~~

The distinction is foundational:

~~~text
TOKEN_ACTIVE
is not
WORKER_WRITE_AUTHORITY

WORKER_LIST_SUCCEEDED
is not
WORKER_WRITE_AUTHORITY

WORKERS_WRITE_PERMISSION
without matching resource scope
is not
TARGET_WORKER_WRITE_AUTHORITY

TARGET_WORKER_WRITE_AUTHORITY
is not
AUTHORITY_USED
~~~

---

# 4. Required Authority Claim

The strongest supported claim is:

> **Cloudflare reports that the active token policy grants Workers Scripts
> Write over the account containing this observed Worker.**

That claim requires all of:

~~~text
supported credential type

credential reachable under Sprint 005 semantics

successful token verification

active token status

token policy details attributable to the verified token

authoritative mapping of the permission-group identifier
to Workers Scripts Write

allow policy effect

resource scope covering the target account

target Worker observed in that account

fresh, scan-scoped evidence for every input
~~~

If any required input is unavailable, Pico must lower the resolution tier,
emit the unknown reason, and avoid claiming confirmed Worker mutation
authority.

---

# 5. Authoring Research Contract

This design is based on the current official Cloudflare API contract verified
when this sprint was authored.

Current read/introspection surfaces relevant to Sprint 006 are:

~~~text
GET /user/tokens/verify
  verifies a user API token and returns token ID and status metadata

GET /user/tokens/{token_id}
  returns token details, including policies, permission groups, resources,
  status, and conditions when the caller has API Tokens Read or Write

GET /user/tokens/permission_groups
  returns current permission-group IDs, names, and scopes when authorized

GET /accounts
  lists accounts accessible to the caller

GET /accounts/{account_id}/workers/scripts
  lists uploaded Workers for an account
~~~

Cloudflare currently documents:

~~~text
Workers Scripts Read
  grants read access to Worker scripts

Workers Scripts Write
  grants write access to Worker scripts

Worker listing accepts at least one of:
  Workers Tail Read
  Workers Scripts Read
  Workers Scripts Write
~~~

Therefore:

~~~text
a successful Worker list request proves behavioral read access

it does not distinguish Workers Scripts Read from Workers Scripts Write

token verification proves token status

it does not expose the full effective permission graph

token policy and resource-scope metadata are required for an EXACT
target-specific mutation claim
~~~

Authoritative references:

~~~text
https://developers.cloudflare.com/api/resources/user/subresources/tokens/

https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/get/

https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/permission_groups/methods/list/

https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/list/

https://developers.cloudflare.com/fundamentals/api/reference/permissions/
~~~

Before implementation, re-verify those contracts. Cloudflare API surfaces and
permission names are external behavior and may change.

If current authoritative behavior contradicts this document:

~~~text
STOP
~~~

Report the contradiction. Do not silently invent compatibility behavior or
rewrite Canon.

---

# 6. Supported Credential Boundary

Sprint 006 initially supports only the API-token credential class established
by Sprint 005:

~~~text
CLOUDFLARE_API_TOKEN
credential_type: api_token
provider: cloudflare
~~~

The first exact introspection path is the current user-owned API-token surface:

~~~text
GET /user/tokens/verify
GET /user/tokens/{verified_token_id}
~~~

Account-owned API tokens expose separate account token endpoints. They are not
automatically equivalent to user-owned tokens. If Pico cannot deterministically
identify and safely introspect an account-owned token under this sprint's
bounded contract, it must report:

~~~text
authority_resolution: UNKNOWN
unknown_reason: UNSUPPORTED_TOKEN_OWNERSHIP_OR_INTROSPECTION
~~~

Do not infer token ownership from token shape.

Do not add support for:

~~~text
Global API Key + email
Origin CA keys
service tokens
OAuth tokens
Wrangler login/session files
browser sessions
account-owned token management unless explicitly verified in scope
~~~

Additional credential types belong to later authority-depth work.

---

# 7. Baseline and Preflight

Expected baseline:

~~~text
b52559d
~~~

Before implementation, report:

~~~text
branch
HEAD SHA
origin/main SHA
ahead/behind
working-tree state
repository structure
existing Rust architecture
current DiscoveryResult contract
current transient credential boundary
current Cloudflare credential Resource
current Bash → can_access Relationship
current ScanService persistence flow
current Resource/Relationship/Evidence/Observation contracts
current SQLite schema and migrations
current test count
cargo check
clippy
fmt
release build
~~~

If the repository is dirty or HEAD materially differs from the expected
baseline:

~~~text
STOP
~~~

Report the difference before building on it.

---

# 8. Known Baseline Architecture Friction

Sprint 005 intentionally keeps the transient credential private inside the
OpenCode discovery adapter and emits only a safe fingerprint through
DiscoveryResult.

That was correct for local reachability, but Sprint 006 needs the provider
client to consume the raw token transiently.

The bounded Sprint 006 refactor is:

~~~text
Supported Credential Source
        ↓
Transient Credential Handle
        ├── safe normalized identity projection
        └── tightly scoped provider-client access
              ↓
        Cloudflare introspection
~~~

Required properties:

~~~text
the raw token never enters DiscoveryResult

the raw token never enters a generic domain type

the raw token never enters ScanService persistence input

the provider client receives access only for a bounded request

safe local credential discovery remains provider-neutral at its output

OpenCode-specific configuration parsing remains outside the provider adapter
~~~

This is a scoped repair to the credential-handle boundary, not permission to
build a general secret manager, dependency-injection framework, or plugin
system.

---

# 9. Architecture Boundary

Maintain:

~~~text
CLI
 ↓
Application / Discovery Plan
 ↓
Credential Source Boundary
 ↓
Transient Credential Handle
 ↓
Cloudflare Provider Adapter
 ↓
Allowlisted Cloudflare Provider Client
 ↓
Safe Normalization
 ↓
Generic Domain
 ↓
Persistence
~~~

Cloudflare-specific knowledge must remain in the Cloudflare provider boundary.

Do not add:

~~~text
CloudflareWorkerResource

CloudflareAuthorityRelationship

Cloudflare-specific fields to Resource or Relationship

HTTP calls in CLI handlers

Cloudflare JSON parsing in ScanService

credential values in adapter result types

arbitrary provider URLs

dynamic provider loading

a plugin framework
~~~

Architect for later providers. Implement only Cloudflare.

---

# 10. Dependency-Aware Discovery Ordering

Provider discovery must run only when its prerequisites exist.

~~~text
OpenCode observed
        ↓
Bash capability resolved
        ↓
Cloudflare credential observed
        ↓
Bash → can_access → Credential resolved
        ↓
credential reachability permits or gates access
        ↓
Cloudflare provider introspection
~~~

Required behavior:

~~~text
no credential
→ do not run the provider adapter

credential BLOCKED
→ do not send it to Cloudflare
→ preserve blocked local reachability

credential UNKNOWN
→ do not silently treat it as reachable
→ provider introspection is skipped unless an explicit controlled scan
  contract proves safe access

credential REACHABLE
→ provider adapter may run

credential APPROVAL_GATED
→ static scan must not bypass the approval
→ provider introspection is skipped or explicitly represented as gated
~~~

Do not recursively trigger arbitrary adapters from provider responses.

---

# 11. Safe Provider Client

Introduce the smallest Cloudflare HTTP client required by this sprint.

The client must expose semantic operations, not an arbitrary request primitive:

~~~text
verify_user_token()

read_verified_user_token_details(token_id)

list_user_token_permission_groups(filter)

list_accessible_accounts()

list_worker_scripts(account_id)
~~~

The adapter must not accept:

~~~text
arbitrary method
arbitrary URL
arbitrary path
arbitrary body
arbitrary headers
~~~

Use an injected transport or equivalent narrow test seam so integration tests
can run against deterministic synthetic responses without internet access or
real credentials.

Do not build a generic HTTP SDK.

---

# 12. Explicit Operation Allowlist

Sprint 006 allows only these HTTP operations, subject to implementation-time
verification:

~~~text
GET /user/tokens/verify

GET /user/tokens/{verified_token_id}

GET /user/tokens/permission_groups

GET /accounts

GET /accounts/{validated_account_id}/workers/scripts
~~~

The exact allowlist must be represented in code and tested.

Every other operation is denied before network dispatch.

Explicitly forbidden:

~~~text
POST
PUT
PATCH
DELETE

Worker upload
Worker delete
Worker version upload
Worker deployment creation
route creation or modification
secret creation, reading, or modification
KV write
D1 write
R2 write
DNS modification
token creation
token update
token rotation
token deletion
permission modification
~~~

No write request may be used to prove write authority.

---

# 13. Network Safety

Production provider requests must enforce:

~~~text
HTTPS only

exact API origin:
https://api.cloudflare.com/client/v4

no caller-supplied origin

no cross-origin redirects

bounded redirect behavior, preferably no redirects

validated token IDs and account IDs before path interpolation

connection timeout

request timeout

response-body size limit

bounded pagination

bounded total requests per scan

safe user agent
~~~

The initial implementation should use conservative constants and document
them.

Provider unavailability must not hang the scan indefinitely.

---

# 14. Authentication Safety

The provider client may place the token only in the outbound Cloudflare
Authorization header.

The header must never enter:

~~~text
Debug
Display
logs
diagnostics
request snapshots
test failure output
Evidence
Observations
Resource metadata
Relationship metadata
SQLite
CLI output
exports
panic messages
~~~

The transient credential handle must:

~~~text
not implement Serialize

have redacted Debug behavior

avoid unnecessary clones

limit value access to provider request construction

be released promptly

retain Sprint 005's best-effort memory clearing behavior
~~~

Do not persist raw Cloudflare responses indiscriminately. A provider response
may contain sensitive operational metadata even when it does not contain the
input token.

---

# 15. Credential Verification

Token verification establishes only:

~~~text
verified token ID
status: active | disabled | expired
not-before when present
expiration when present
verification timestamp
~~~

Verification does not establish:

~~~text
Workers Scripts Write
account scope
target Worker scope
production scope
effective mutation authority
~~~

Normalize status conceptually as:

~~~text
ACTIVE
INACTIVE
UNKNOWN
~~~

Mapping:

~~~text
Cloudflare active
→ ACTIVE

Cloudflare disabled or expired
→ INACTIVE

authentication failure, malformed response, or unavailable verification
→ UNKNOWN unless Cloudflare directly establishes invalidity
~~~

Do not overwrite the stable credential fingerprint with the Cloudflare token
ID. The safe fingerprint remains the local cross-scan identity established by
Sprint 005. The provider token ID is safe provider metadata and may be stored
only when necessary for provenance.

---

# 16. Token Policy Introspection

When the verified token is active, Pico may request details for the exact token
ID returned by verification.

Extract only:

~~~text
token ID
status
policy effect
permission-group IDs
permission-group names when returned
resource selectors required for account scope
request-IP condition presence and bounded normalized state
validity timestamps required for authority evaluation
~~~

Do not persist:

~~~text
raw response body
token value fields
unrelated permission groups
unrelated resource metadata
token name unless required for safe user explanation
last-used operational history
raw CIDR collections
~~~

If token details require permissions the token does not possess, that is an
expected partial-introspection case, not a reason to probe with a write.

---

# 17. Permission-Group Resolution

Permission-group IDs are the authoritative policy identifiers.

Pico should resolve the current Cloudflare meaning of the relevant ID through
the allowlisted permission-group metadata endpoint where authorized.

The only action permission relevant to Sprint 006 is:

~~~text
Workers Scripts Write
scope: com.cloudflare.api.account
~~~

Cloudflare documentation may render the write label as Write or Edit during
terminology transitions. Do not match arbitrary substrings or silently equate
labels.

Implementation must use the current authoritative permission-group ID/name
mapping verified during the sprint and preserve the evidence source.

Do not normalize unrelated Cloudflare permissions into Pico security state.

If the mapping cannot be authoritatively established:

~~~text
authority_resolution cannot be EXACT
~~~

---

# 18. Resource-Scope Resolution

Workers Scripts Write is account-scoped. Pico must evaluate both permission
and resource selection.

Supported scope inputs are explicit account selectors in the verified token
policy and account IDs returned by bounded account discovery.

Pico must distinguish:

~~~text
one explicit account included
multiple explicit accounts included
all accounts included
account explicitly excluded
unsupported nested or conditional resource selector
scope unavailable
~~~

Allow and deny/exclude semantics must not be flattened into a string contains
check.

For each account, resolve:

~~~text
IN_SCOPE
OUT_OF_SCOPE
UNKNOWN
~~~

If a selector cannot be parsed using verified Cloudflare semantics, use
UNKNOWN.

Do not infer account scope from token verification or an account name.

---

# 19. Account Resource

Normalize observed accounts using the generic Resource domain.

~~~text
Resource
  kind: account
  provider: cloudflare
  canonical_key: cloudflare:account:<account-id>
  name: <safe account display name or Cloudflare Account>
  metadata:
    account_id
    account_type when safely observed
    environment: UNKNOWN
    source: cloudflare_api
~~~

Do not persist account settings unrelated to authority resolution.

Account names do not establish environment classification.

---

# 20. Worker Resource Enumeration

For each bounded, relevant account, use only:

~~~text
GET /accounts/{account_id}/workers/scripts
~~~

Extract only:

~~~text
account ID
Worker script ID/name
immutable Worker tag when present
safe timestamps when useful for provenance
minimum metadata required for identity
~~~

Do not download:

~~~text
Worker source code
Worker module contents
Worker secrets
Worker bindings
environment variables
deployment payloads
logs
tail data
~~~

Do not enumerate unrelated Cloudflare products.

Pagination and total Worker count must be bounded.

---

# 21. Worker Resource Identity

Normalize each Worker through the generic Resource domain.

Preferred identity:

~~~text
cloudflare:worker:<account-id>:<immutable-worker-tag>
~~~

If the API omits an immutable tag, use the documented fallback:

~~~text
cloudflare:worker:<account-id>:name:<normalized-script-id>
identity_precision: NAME_SCOPED
~~~

Worker metadata may include:

~~~text
account_id
worker_tag when present
identity_precision
environment: UNKNOWN
consequential_sink: true
~~~

Do not infer production, staging, or development from a Worker name, route,
hostname, or tag.

---

# 22. Generic Relationship Model

Use the existing generic Relationship domain and vocabulary.

Required provider relationships are:

~~~text
Cloudflare Credential
        ↓ scoped_to
Cloudflare Account

Cloudflare Credential
        ↓ can_mutate
Cloudflare Worker
~~~

The account scope relationship may be omitted when scope is entirely unknown.

Do not create provider-specific relationship kinds such as
cloudflare_worker_edit.

Worker mutation metadata should contain only safe normalized facts:

~~~text
capability: WORKERS_SCRIPTS_WRITE
authority_resolution
credential_status
permission_state
account_scope_state
target_observation_state
unknown_reasons[]
~~~

---

# 23. Authority Resolution Tiers

Use Canon's existing vocabulary exactly:

~~~text
EXACT
SCOPED
BEHAVIORAL_READ_ONLY
UNKNOWN
~~~

## EXACT

Use only when Pico has:

~~~text
active verified token
+
verified token policy
+
authoritative Workers Scripts Write permission-group mapping
+
allow effect
+
account resource scope covering the target account
+
observed target Worker in that account
+
no unresolved condition that could invalidate the claim
~~~

Result:

~~~text
Credential → can_mutate → Worker
state: DERIVED
authority_resolution: EXACT
capability: WRITE
~~~

## SCOPED

Use when Pico can establish broad Workers write permission and account scope,
but cannot bind the authority to a specifically enumerated Worker or cannot
fully resolve a target-level condition.

SCOPED does not justify an EXACT target-specific edge.

## BEHAVIORAL_READ_ONLY

Use when a safe request demonstrates access to account or Worker metadata but
policy introspection cannot distinguish read from write.

This tier must never be upgraded into write authority.

## UNKNOWN

Use when credential presence exists but effective provider authority cannot be
safely established.

Every non-EXACT result must preserve explicit unknown reasons.

---

# 24. Relationship State

Authority precision and relationship state remain distinct.

~~~text
EXACT write authority
→ can_mutate DERIVED

policy directly excludes the target account or lacks Workers Scripts Write
and the target Worker is otherwise observed
→ can_mutate BLOCKED

Worker observed but mutation authority cannot be resolved
→ can_mutate UNKNOWN

behavioral list access only
→ can_read CONFIRMED or DERIVED as supported
→ can_mutate UNKNOWN

inactive token
→ no active can_mutate edge
→ retain credential status evidence
~~~

Pico must not use CONFIRMED merely because a derived policy calculation has
all inputs. The provider facts may be direct; the cross-fact authority
relationship is derived.

---

# 25. Conditions and Effective Authority

Token policy may include conditions such as request-IP restrictions or
validity windows.

Sprint 006 must not silently ignore a condition that can change whether the
credential is usable from Pico's observed environment.

Minimum behavior:

~~~text
expired, disabled, or not-yet-valid token
→ no active mutation authority

request-IP condition present and effective match cannot be safely established
→ authority resolution lower than EXACT
→ unknown reason preserved

unsupported condition
→ UNKNOWN or SCOPED as justified
~~~

Do not call an external IP-echo service to evaluate request-IP conditions.

---

# 26. Evidence

Every security-relevant fact must answer:

~~~text
How does Pico know the token is active?

How does Pico know the policy belongs to this verified token?

How does Pico know the relevant permission-group meaning?

How does Pico know the account is in scope?

How does Pico know the Worker exists in that account?

How does Pico derive or refuse the mutation claim?

What remains unknown?
~~~

Expected evidence classes:

~~~text
DIRECT
  token verification projection
  token-detail projection
  permission-group metadata projection
  account metadata projection
  Worker listing projection

DECLARED
  token policy permission and resource selectors

DERIVED
  account scope evaluation
  Worker mutation authority resolution

INFERRED
  incomplete provider behavior that cannot justify write authority
~~~

Safe Evidence may include:

~~~text
operation identifier from the local allowlist
Cloudflare API origin
HTTP status class
provider response success
verified token ID
normalized token status
relevant permission-group ID and canonical name
normalized resource selector
account ID
Worker stable ID and display name
authority-resolution tier
unknown reason codes
observed_at
~~~

Evidence must not include:

~~~text
Authorization header
raw token
token preview
raw response body
unrelated account settings
Worker source
Worker secret or binding values
unsafe provider error payloads
~~~

---

# 27. Observations and History

Create scan-scoped Observations for:

~~~text
Credential verification status
Cloudflare Account Resource presence
Cloudflare Worker Resource presence
Credential → scoped_to → Account state
Credential → can_mutate → Worker state
~~~

Repeated scans must preserve:

~~~text
one stable Credential Resource for the same token
one stable Account Resource per Cloudflare account ID
one stable Worker Resource per stable Worker identity
one stable Relationship per endpoint and kind
scan-specific Evidence
scan-specific Observations
authority changes across time
~~~

If a permission is revoked, a token expires, an account moves out of scope, or
a Worker disappears, Pico must not rewrite historical Observations.

---

# 28. Failure and Partial-Scan Semantics

Provider failure is expected and must preserve useful facts.

~~~text
credential absent
→ COMPLETE
→ provider adapter not run

credential locally blocked
→ COMPLETE
→ provider adapter not run

token verification says disabled or expired
→ COMPLETE
→ credential status INACTIVE
→ no active Worker mutation edge

401 or 403 during token details
→ PARTIAL if verification succeeded
→ authority UNKNOWN or BEHAVIORAL_READ_ONLY as supported

Worker listing forbidden
→ PARTIAL
→ retain verified token and policy evidence
→ no invented Worker Resource

429
→ PARTIAL
→ safe rate-limit diagnostic

timeout, DNS, TLS, or network failure
→ PARTIAL
→ retain local credential facts

malformed or oversized response
→ PARTIAL
→ reject response safely

one account fails while another succeeds
→ PARTIAL
→ retain successful account and Worker evidence
~~~

A provider error must never delete earlier valid facts or convert uncertainty
into certainty.

---

# 29. ScanService Integration

Extend the bounded Discovery Plan without moving provider knowledge into the
application service.

~~~text
Local Discovery Result
  actors
  capabilities
  MCP surfaces
  credential references
  credential reachability
        ↓
Provider Discovery Result
  credential verification
  accounts
  Workers
  permission projections
  scope projections
  authority projections
  problems
~~~

The application service should only:

~~~text
upsert generic Account and Worker Resources
upsert generic scoped_to and can_mutate Relationships
persist safe Evidence
link Evidence to subjects
persist scan-scoped Observations
aggregate provider problems into COMPLETE or PARTIAL status
report safe summary counts
~~~

ScanService must not construct Authorization headers, parse Cloudflare JSON,
interpret permission IDs, evaluate Cloudflare selectors, classify Worker
authority, or retain credential bytes.

---

# 30. CLI Result

Add only the smallest useful summary.

~~~text
Cloudflare Credential: OBSERVED | NOT OBSERVED
Credential Reachability: REACHABLE | APPROVAL_GATED | BLOCKED | UNKNOWN
Credential Status: ACTIVE | INACTIVE | UNKNOWN
Cloudflare Accounts: <N>
Cloudflare Workers: <N>
Worker Mutation Authority: CONFIRMED | BLOCKED | UNKNOWN
Authority Resolution: EXACT | SCOPED | BEHAVIORAL_READ_ONLY | UNKNOWN
Credential Value Stored: NO
Findings: 0
~~~

If multiple Workers produce different results, summarize counts without
discarding per-Worker evidence.

Do not print raw tokens, previews, Authorization headers, raw policies, raw
responses, Worker source, or unsupported production labels.

---

# 31. Fixtures

Use a deterministic fake transport and sanitized Cloudflare response fixtures.

Required cases:

~~~text
active user API token
disabled token
expired token
not-yet-valid token
token verification unavailable
token details readable
token details forbidden
Workers Scripts Write permission
Workers Scripts Read only
unrelated permission only
permission-group mapping available
permission-group mapping unavailable
explicit account include
all-accounts include
explicit account exclusion
unsupported resource selector
one Worker
multiple Workers
no Workers
Worker list forbidden
Worker list succeeds without policy detail
paginated accounts
bounded pagination overflow
401
403
429
5xx
timeout
malformed JSON
oversized response
redirect
wrong origin
~~~

All IDs and names must be synthetic.

No real Cloudflare account, token, Worker, hostname, route, or credential may
exist in fixtures.

---

# 32. Secret-Sentinel Validation

Use synthetic canaries:

~~~text
TEST_SECRET_SHOULD_NOT_PERSIST
TEST_AUTHORIZATION_HEADER_SHOULD_NOT_PERSIST
TEST_PROVIDER_SECRET_RESPONSE_FIELD_SHOULD_NOT_PERSIST
~~~

Place canaries in the synthetic credential, Authorization header, an
irrelevant sensitive response field, and a provider error body.

After scanning, verify zero occurrences in:

~~~text
SQLite
CLI output
captured diagnostics
logs
Debug output
test snapshots
exported state if any
~~~

No real secret may be used in tests.

---

# 33. Required Tests

At minimum test:

## Provider-client safety

~~~text
only allowlisted GET operations dispatch
all write methods are rejected before dispatch
arbitrary paths and origins are rejected
cross-origin redirects are rejected
IDs are validated before interpolation
timeouts are enforced
response size is bounded
pagination is bounded
total request count is bounded
~~~

## Verification

~~~text
active token maps to ACTIVE
disabled and expired map to INACTIVE
verification alone does not create mutation authority
malformed verification remains safe
~~~

## Permission and scope

~~~text
Workers Scripts Write resolves by authoritative permission-group mapping
Workers Scripts Read does not become write
unrelated permissions do not become write
explicit matching account is IN_SCOPE
explicit exclusion is OUT_OF_SCOPE
unsupported selectors are UNKNOWN
conditions lower resolution when unresolved
~~~

## Resource normalization

~~~text
stable account identity
stable Worker identity using immutable tag
documented name-scoped fallback
same Worker repeated across scans remains one Resource
same Worker name in two accounts remains two Resources
Worker rename with immutable tag preserves identity
~~~

## Authority

~~~text
active token + Workers Write + matching account + observed Worker
→ EXACT
→ can_mutate DERIVED

Workers Read only
→ no positive mutation claim

Worker list success without policy introspection
→ BEHAVIORAL_READ_ONLY
→ mutation UNKNOWN

write permission and account scope without target enumeration
→ SCOPED at most

excluded account
→ can_mutate BLOCKED when target otherwise exists

inactive token
→ no active mutation edge
~~~

## Persistence and history

~~~text
Evidence generation
Observation generation
Evidence links to credential, account, Worker, and relationship subjects
repeated scans preserve stable Resources and Relationships
repeated scans create separate Observations and Evidence
permission removal preserves earlier scan history
Worker removal preserves earlier scan history
~~~

## Safety and scope

~~~text
credential not in SQLite or errors
Authorization header not in SQLite or diagnostics
irrelevant sensitive response field not persisted
raw response not persisted
no mutation request emitted
no real network required by tests
AttackPaths = 0
Findings = 0
no production classification inferred from names
~~~

---

# 34. Controlled Manual Verification

Automated verification must not require a real credential.

If a controlled, non-production Cloudflare environment and explicitly supplied
test token are available, manually verify:

~~~text
pico init
pico scan
~~~

Use separate disposable tokens for:

~~~text
Workers Scripts Read only

Workers Scripts Write + API Tokens Read for exact introspection
~~~

Expected exact semantic result:

~~~text
Status: COMPLETE or PARTIAL with explained provider limitations
Cloudflare Credential: OBSERVED
Credential Reachability: REACHABLE
Credential Status: ACTIVE
Cloudflare Accounts: >= 1
Cloudflare Workers: >= 1
Worker Mutation Authority: CONFIRMED
Authority Resolution: EXACT
Credential Value Stored: NO
AttackPaths: 0
Findings: 0
~~~

Inspect SQLite for stable Resources, scan-scoped Evidence and Observations, and
zero credential or Authorization-header occurrences. Run the scan again and
verify stable identity plus separate history.

If exact policy introspection is unavailable, report the real result as
SCOPED, BEHAVIORAL_READ_ONLY, or UNKNOWN. Do not weaken the sprint contract to
force an EXACT live result.

---

# 35. Expected Security State

Sprint 006 may add provider-scope and Worker-authority Relationships.

~~~text
Resources:
  existing resources
  + Cloudflare Account Resources
  + Cloudflare Worker Resources

Relationships:
  existing relationships
  + Credential → scoped_to → Account where supported
  + Credential → can_mutate → Worker for resolved or explicitly unknown state

Evidence:
  provider verification, policy, scope, inventory, and authority evidence

Observations:
  scan-scoped provider resource and relationship observations

AttackPaths:
  0

Findings:
  0
~~~

Sprint 006 establishes authority facts. It does not combine them with the
external-influence chain.

---

# 36. Scope Guardrails

Do not implement:

~~~text
credential discovery beyond Sprint 005's supported API token
Global API Key support
account-owned token support without explicit verified scope
Cloudflare Worker writes or deployment
Worker source download
Worker secret or binding discovery
Worker route mutation
KV, D1, R2, DNS, Pages, Access, or other product authority
production classification based on names
provider plugin framework
additional cloud providers
Security Graph projection
graph traversal
Influence Analysis
AuthorityPath construction
Boundary Evaluation
AttackPath construction
Finding generation
severity
remediation
Pico MCP
runtime monitoring
enforcement
Sprint 007 functionality
~~~

Do not perform unrelated refactoring.

---

# 37. Architecture Pressure Test

Before declaring completion, explicitly answer:

~~~text
1. Could the Sprint 005 transient credential boundary safely serve a provider
   client after a bounded refactor?

2. Did the provider client make operations outside the read-only allowlist
   structurally unavailable?

3. Could token status remain separate from effective authority?

4. Could successful Worker listing remain separate from write authority?

5. Could permission, resource scope, and target Resource combine into an EXACT
   claim without a mutation probe?

6. Could partial introspection produce honest SCOPED,
   BEHAVIORAL_READ_ONLY, or UNKNOWN results?

7. Did the existing Resource identity model work for Cloudflare accounts and
   Workers across repeated scans?

8. Did the existing Relationship model represent target-specific mutation
   authority without provider-specific domain types?

9. Did Evidence explain authority without raw response persistence?

10. Did provider knowledge remain outside the generic domain and ScanService?

11. Did Pico avoid persisting tokens, Authorization headers, and unrelated
    sensitive response fields?

12. Did one provider adapter avoid requiring a plugin framework?
~~~

If any answer is NO, do not hide it. Fix it only when clearly inside Sprint
006. Otherwise stop and report the architectural friction.

---

# 38. Definition of Done

Sprint 006 is complete only when:

~~~text
baseline is verified
current Cloudflare behavior is re-verified from authoritative sources
transient credential handoff safely supports provider-client use
provider client has a tested explicit GET-only operation allowlist
network, request, response, and pagination bounds are enforced
token verification is implemented
token policy introspection is implemented where authorized
Workers Scripts Write permission is resolved authoritatively
account resource scope is resolved deterministically
Cloudflare accounts and Workers are generic Resources
target-specific mutation authority has an explicit tier
successful read behavior never becomes a write claim
uncertainty and partial failure remain explicit
Evidence and Observations persist safely
stable identity and history work across repeated scans
secret canaries have zero persistence and diagnostic occurrences
no mutating request can be emitted
AttackPaths remain 0
Findings remain 0
all automated verification passes
final diff is clean and scoped
~~~

---

# 39. Full Verification

After implementation run:

~~~bash
cargo test

cargo check

cargo clippy --all-targets -- -D warnings

cargo fmt --check

cargo build --release
~~~

Also run any repository-local validation required by policy.

Report:

~~~text
tests: X passed / X failed
cargo check
clippy
fmt
release build
fake-transport exact-authority scan
fake-transport read-only scan
fake-transport unknown-authority scan
credential-absent scan
locally blocked credential scan
repeated-scan identity
authority history
partial-provider failure
operation-allowlist proof
no-mutation proof
secret-sentinel persistence check
~~~

---

# 40. Final Diff Inspection

Review the entire Sprint 006 diff for:

~~~text
accidental files
build artifacts
.pico state
real credentials
Authorization headers
real Cloudflare account IDs or Worker names
machine-specific paths
raw provider fixtures
unnecessary dependencies
debug logging
generic arbitrary HTTP request surfaces
write-capable HTTP methods
speculative abstractions
plugin infrastructure
unrelated refactors
Sprint 007+ functionality
~~~

Remove any accidental state before completion.

---

# 41. Stop Conditions

Stop and report before implementation if:

~~~text
the baseline is unexpected or dirty
current Cloudflare behavior contradicts this sprint
the supported token type cannot be identified honestly
the credential must enter normalized or persisted state
required evidence can only be obtained through a write
the HTTP stack cannot enforce the operation/origin allowlist
the token policy/resource schema cannot be interpreted deterministically
tests would require production credentials
implementation would require a provider plugin framework
Canon would need silent revision
~~~

Partial provider introspection is not itself a blocker. It is an expected
result that must be modeled honestly.

---

# 42. Deliverables

Required deliverables:

~~~text
bounded transient credential handoff
Cloudflare provider adapter
safe allowlisted Cloudflare provider client
token verification projection
token-policy and permission-group projection
account resource-scope resolver
account and Worker Resource normalization
scoped_to and can_mutate Relationship normalization
authority-resolution tiers and unknown reasons
Evidence and Observation generation
ScanService integration
CLI summary
sanitized fake-provider fixtures
unit and integration tests
secret-sentinel checks
completion evidence in this document
~~~

Do not modify Sprint 001–005 completion records.

Do not rewrite canonical product or architecture documents unless a genuine
contradiction requires founder review. In that case, stop instead.

---

# 43. Completion Evidence

When implementation and verification pass, set:

~~~text
Status: COMPLETE
~~~

Record:

~~~text
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
Cloudflare API contract verification date
supported credential ownership/type
exact operation allowlist
network limits
authority-resolution cases
account and Worker identities
repeated-scan history result
provider partial-failure result
no-mutation proof
secret-sentinel result
architecture pressure-test answers
~~~

State whether live controlled Cloudflare verification was performed. Fixture
verification remains mandatory either way.

## Completion Record

~~~text
Completion date: 2026-08-25
Verified baseline: b52559d
Implementation commit: 67c5e86 feat(authority): resolve Cloudflare Worker authority
Automated tests: 109 passed / 0 failed
cargo check: PASS
cargo clippy --all-targets -- -D warnings: PASS
cargo fmt --check: PASS
cargo build --release: PASS
Fake transport exact authority: PASS
Fake transport read-only authority: PASS
Unknown and partial authority handling: PASS
Repeated identity/history: PASS
Secret sentinel persistence: PASS
Mutation requests emitted: 0
Live controlled Cloudflare verification: NOT PERFORMED
~~

The provider client and normalization path are implemented and verified with
sanitized fake transports. Live Cloudflare verification remains a follow-up
requiring an explicitly supplied controlled credential and environment.

---

# 44. Commit

If and only if Sprint 006 is fully implemented and verified:

~~~text
stage only Sprint 006 changes
inspect the staged diff
commit with:

feat(authority): resolve Cloudflare Worker authority
~~~

Do not amend previous commits.

Do not push unless explicitly instructed by repository policy or the user.

Do not begin Sprint 007.

---

# 45. Final Report Contract

Report:

~~~text
Sprint
SPRINT-006 — First Provider Authority — Cloudflare Worker

Status
COMPLETE or BLOCKED

Baseline
<verified SHA>

Implementation commit
<SHA + message>

Cloudflare authority contract
<verification, policy, permission, scope, and Worker signals>

Implementation
<credential handoff, provider client, adapter, normalization, persistence>

Verification
<tests and all required checks>

Authority results
<EXACT / SCOPED / BEHAVIORAL_READ_ONLY / UNKNOWN cases>

Operation safety
Allowlisted GET operations: <list>
Mutation requests emitted: 0

Secret safety
Raw credential persisted: NO
Authorization header persisted: NO
Raw provider responses indiscriminately persisted: NO

Expected security state
AttackPaths: 0
Findings: 0

Architecture pressure test
<PASS / FAIL for every required question>

Scope
<explicit NO list for Sprint 007+ features>

Repository
<branch, HEAD, origin/main, ahead/behind, working tree>

Follow-ups
<genuine observations only; do not implement them>
~~~

---

# 46. Sprint Exit

Sprint 006 ends when Pico can reliably say:

> **I observed this Cloudflare Worker, and read-only policy evidence proves—or
> cannot yet prove—that this reachable credential can mutate it.**

Sprint 006 does not yet say:

> **External GitHub content has an active path to this Worker.**

That requires the Security Graph and later analysis slices.

Do not begin Sprint 007 without explicit authorization.
