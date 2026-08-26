# Pico — Sprint 011: First Agent Interface — Minimal MCP Exposure

**Status:** COMPLETE
**Sprint:** 011
**Phase:** v0.1 — Golden Path Proof
**Type:** Implementation
**Baseline:** `13bc5e9`
**Depends on:** Sprint 010 — First Explanation — Finding Navigation
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Expose Pico's first persisted Finding to a coding agent through a minimal,
read-only MCP interface backed entirely by the existing application services.

Sprint 010 established:

> **Pico can retrieve a persisted Finding and explain what exists, why it
> matters, how the path works, how Pico knows, what uncertainty remains, what
> enforced boundary is absent, and where the path can be broken — through the
> CLI.**

Sprint 011 must establish:

> **A coding agent can ask Pico, through MCP, for exactly the same Findings
> and the same Finding detail visible through `pico findings` and
> `pico finding <id>` — with no second scanner, no new security logic, no
> database writes, and no new privileged execution surface.**

The primary flow is:

```text
Coding agent
        ↓
MCP client session (stdio)
        ↓
pico mcp
        ↓
MCP protocol boundary (JSON-RPC)
        ↓
FindingQueryService (unchanged)
        ↓
Read-only SQLite + historical graph projection
        ↓
Application explanation DTOs
        ↓
Structured tool results
```

This sprint answers:

> **Can a coding agent consume Pico's security conclusions without Pico
> duplicating any scan, analysis, or explanation logic — and without becoming
> another privileged execution layer?**

It does not add new security conclusions, new CLI commands beyond one launch
verb, a scan trigger, an enforcement surface, or a hosted service.

---

# 2. Roadmap Position

Sprint 011 implements Architecture Slice 10:

```text
Implement minimal Pico MCP exposure over existing application services.
Success:
A coding agent can ask Pico for the same Finding visible through the CLI.
No duplicate scanner exists.
```

Roadmap ordering constraint:

```text
Minimal read-only Pico MCP access over the same application services,
only after the CLI path works.
```

The CLI path works: Sprints 001–010 are COMPLETE. Sprint 010's exit required
explicit authorization to begin this slice; that authorization has been given
by commissioning this document.

Locked decisions that bind this sprint:

```text
AD-027
  CLI and MCP use the same application services and security engine.

ROADMAP §3.8 — One engine, multiple interfaces
  CLI, MCP, and future surfaces must call the same application services
  and security engine; interfaces must not develop independent scan or
  risk logic.

PRODUCT_DEFINITION §27-28
  There must not be separate CLI and agent scanners or separate security
  logic; the agent-facing interface is read-only in V0 and Pico must not
  become another privileged execution surface simply because it is
  callable by an agent.

TECHNICAL.md §41
  Pico must not become a new privileged execution layer merely to inspect
  existing privileged execution layers.
```

With Slice 10 complete, every defined architecture slice (1–10) is built. The
remaining v0.1 gates are unchanged and remain outside this sprint:

```text
controlled live-environment dogfood
independent developer comprehension validation
```

Expected roadmap decision after this sprint:

```text
EXTEND v0.1
```

Do not advance to v0.2 merely because an agent can list Findings. v0.2 entry
requires proven golden-path results in controlled dogfood and a growing corpus
of sanitized real cases.

---

# 3. Required Product Claim

At completion, a coding agent connected over MCP must be able to establish,
semantically:

```text
list_findings
  → Pico reports which Findings exist in the newest COMPLETE Scan,
    with class, severity, confidence, status, path count, affected
    production resource count, exact IDs, and freshness state.

get_finding <id>
  → Pico returns the same composed explanation the CLI renders:
    summary, ordered paths with traversal-aware steps and supporting
    Evidence IDs, reasons, severity and confidence bases, boundary
    narrative, uncertainties, remediation cut points, and the
    potential-exposure scope note.
```

The claim must remain narrower than:

```text
The agent understands the Finding without reading Pico output.
Pico trusts the agent's interpretation.
The MCP interface can trigger a scan.
The MCP interface can remediate anything.
An agent-visible empty result means the environment is safe globally.
Pico validated anything by serving it to an agent.
```

Pico remains authoritative about the security facts. The agent may summarize
or discuss results; Pico's DTOs and fixed narration are the source of truth.

---

# 4. Architecture Position and Layering

The mandated position:

```text
Coding Agent → Pico MCP → Application Services → Pico Core → SQLite
```

Binding rules:

```text
The MCP server does not implement separate security reasoning.
The MCP layer contains no SQL, no Observation JSON parsing, no eligibility
evaluation, no severity or confidence recomputation, no provider metadata
interpretation, and no adapter calls.
CLI and MCP surfaces call the same FindingQueryService.
Modularity is achieved through code boundaries, not network boundaries.
```

Concretely:

```text
src/mcp/            new module: protocol framing and dispatch only;
                    calls crate::application::findings
src/application/    unchanged behavior; extended only where a genuine gap
                    is found
src/cli/mod.rs      gains exactly one launch subcommand and no MCP logic
```

If any required capability appears missing from `FindingQueryService`, extend
the application layer there — never inside the MCP module. If extending the
application layer would change Finding semantics, STOP and report.

---

# 5. Transport and Process Model

The only transport is MCP over stdio:

```text
launch command:  pico mcp
workspace:       the current directory is the Pico workspace
stdin:           newline-delimited JSON-RPC 2.0 messages
stdout:          newline-delimited JSON-RPC 2.0 responses only
stderr:          bounded human-readable diagnostics
lifetime:        one session per process; exit cleanly on stdin EOF
```

Required properties:

```text
single process, foreground, no daemon
no TCP, HTTP, WebSocket, or Unix-socket listener
no background worker or async runtime requirement
sequential request processing; responses preserve request order
process startup performs no database work until the first tool call
process shutdown closes SQLite cleanly and writes nothing (read-only)
```

`pico mcp` must fail safely when the workspace is not initialized: it still
serves the protocol handshake and answers tool calls with the established
not-initialized error, mirroring CLI behavior. It must never create `.pico/`,
create the database, or migrate.

---

# 6. Protocol Surface

Implement the minimal MCP subset required for a tool server:

```text
initialize                  negotiate protocolVersion; advertise tools
                            capability; report serverInfo name "pico" and
                            the running PICO_VERSION
notifications/initialized   acknowledge silently (no response frame)
ping                        reply with an empty result
tools/list                  the two tool descriptors with inputSchema and
                            readOnlyHint annotations
tools/call                  dispatch by tool name; never execute anything else
```

Protocol rules:

```text
Respond to every request with its exact id.
Never respond to notifications.
Unknown method → JSON-RPC error -32601 with a safe message.
Malformed JSON → error -32700; the session continues.
Invalid request envelope → -32600; invalid params → -32602.
Application failures (not initialized, unsupported schema, unknown Finding
ID, integrity errors) → JSON-RPC error results whose messages equal the
existing PicoError display text, containing no row payloads.
Protocol-version negotiation follows the MCP specification revision being
implemented; record the negotiated version in completion evidence.
Unsupported requested version → respond per spec with the server's
supported version, or a clear error where the spec requires it.
```

Anything beyond this subset — resources, prompts, sampling, roots, logging
frames, completions — returns `-32601` rather than being improvised.

---

# 7. Tool Surface

The tool surface is exactly:

```text
1. list_findings
2. get_finding
```

`list_findings` takes no arguments.

`get_finding` takes:

```text
{ "id": "<exact Finding ID>" }
```

A missing, empty, or whitespace-only `id` is invalid parameters (-32602),
mirroring the CLI Usage error.

Each descriptor declares:

```text
name
description   one or two sentences, provider-neutral
inputSchema   JSON Schema object
annotations   readOnlyHint = true
```

No tool may declare a destructive or environment-mutating hint. There are
exactly two tools; adding a third requires a new authorized sprint.

---

# 8. Explicitly Deferred Capabilities

PRODUCT_DEFINITION permits an agent-facing surface to eventually support:

```text
get_status, scan, get_security_context
```

Sprint 011 deliberately defers all of them:

```text
scan                 an agent-triggered scan performs discovery and provider
                     operations; authorizing that through MCP needs its own
                     safety review and is not required by Slice 10's success
                     criterion. An authorized agent can still run `pico scan`
                     itself through its own execution tools.
get_status           no StatusService exists; inventing one here would grow
                     the surface without a Slice 10 requirement.
get_security_context depends on status and richer projections; deferred.
fix / revoke / enforce family
                     permanently out of scope for V0 by product decision;
                     Pico must not become another privileged execution
                     surface simply because it is callable by an agent.
```

Deferral is a scope decision, not a judgment that these are unsafe forever.
Record it in the final report follow-ups.

---

# 9. Application Query Boundary

Maintain exactly the Sprint 010 boundary:

```text
MCP module
 ↓
FindingQueryService::list_latest(workspace)
FindingQueryService::get(workspace, finding_id)
 ↓
Read-only SQLite open + schema version 4 gate
 ↓
One coherent read transaction per call
 ↓
Historical graph projection from scan-scoped Observations
 ↓
Application DTOs
```

The MCP layer owns only:

```text
protocol framing and validation
tool dispatch
DTO-to-tool-result shaping
error mapping
```

The query path continues to use `Database::open_read_only`, validates schema
version 4, runs no migrations or DDL, and composes each call inside one
coherent read snapshot. Repeated tool calls must not mutate rows.

---

# 10. `list_findings` Contract

`list_findings` returns a structured result semantically identical to
`pico findings`:

```text
selected_scan         id, status, completed_at (or null)
newest_scan_attempt   id, status, completed_at (or null)
freshness             LATEST_COMPLETE | NEWER_INCOMPLETE_ATTEMPT
freshness_warning     the exact warning text when present, else null
findings[]            id, finding_class, status, title, severity, confidence,
                      attack_path_count, affected_sink_count, fingerprint
state                 NO_SCANS | NO_COMPLETE_SCAN | RESULTS_AVAILABLE
guidance              fixed, provider-neutral sentence(s) for the state
```

Required state semantics:

```text
NO_SCANS
  → successful empty result; guidance instructs running `pico scan`;
    never implies safety.

NO_COMPLETE_SCAN
  → successful result naming the newest attempt and its status; guidance
    states no authoritative scan exists; never implies safety.

RESULTS_AVAILABLE with zero Findings
  → guidance uses the scoped sentence:
    "No Findings were produced for this COMPLETE scan within Pico's
    supported scope."
    Never implies global safety.

RESULTS_AVAILABLE with Findings
  → every Finding summary appears in the same deterministic order used
    by `pico findings`.
```

Ordering, freshness computation, counts, and integrity validation come from
`FindingQueryService`; none may be reimplemented in the MCP layer.

---

# 11. `get_finding` Contract

`get_finding` accepts one exact Finding ID and returns the composed detail
equivalent to `pico finding <id>`:

```text
id, fingerprint, finding_version
scan (id, status, completed_at)
currentness           LATEST_COMPLETE | HISTORICAL { newer_complete_scan_id }
freshness_warning     when present
finding_class, status, title, summary, severity, confidence
scope_note, severity_basis, confidence_basis
reasons[]             position, code, fixed explanation
paths[]               disposition, source_trust, influence_strength,
                      capability, authority_resolution, sink_impact,
                      steps[] (position, phase, traversal, relationship_id,
                      relationship_kind, from_resource, to_resource,
                      relationship_state, evidence_ids), boundaries[]
evidence[]            minimized EvidenceView fields only
boundary_summary
uncertainties[]
remediations[]        stored order, resolved targets
remediation_note
created_at
```

Lookup semantics inherited unchanged:

```text
unknown ID            clear not-found failure
prefix or fuzzy ID    not found; no fallback matching
empty ID              invalid parameters (-32602)
broken references     integrity error; no partial explanation
unsupported versions  integrity error; no migration, no writes
```

Historical details must continue to resolve names, kinds, states, and safe
metadata from the originating Scan's Observation snapshots. Current-state
leakage into a historical detail is a defect.

---

# 12. Result Shaping and Structured Content

Tool results are returned as MCP text content whose payload is UTF-8 JSON:

```text
content: [ { type: "text", text: "<deterministic pretty-printed JSON>" } ]
```

Shaping rules:

```text
Serialize the application DTOs with serde; do not rebuild parallel
structures inside the MCP layer.
Field names equal the DTO definitions; optional fields serialize as null.
Persisted strings pass through the existing terminal-safety policy before
serialization so control characters cannot spoof downstream consumers.
Evidence remains minimized: no raw metadata, provider bodies, credentials,
authorization headers, unsafe locators, or absolute machine paths.
Redacted locators serialize as null; presenting labels belongs to the
consumer.
JSON key order follows struct declaration order, which is stable.
Pretty-printing settings are fixed constants.
```

The JSON payload is a machine contract. Do not embed ANSI styling, terminal
tables, or CLI layout artifacts.

---

# 13. Empty, Error, and Freshness Semantics

All Sprint 010 semantics carry over verbatim:

```text
not initialized       existing safe error text mentioning `pico init`
no Scans              NO_SCANS state; instructive, non-authoritative
no COMPLETE Scan      NO_COMPLETE_SCAN state; newest attempt named
zero Findings         scoped sentence; never an all-clear
newer RUNNING/PARTIAL/FAILED attempt
                      freshness_warning present with the exact wording:
                      "Freshness: A newer scan <scan-id> is <STATUS>."
                      "Showing the last COMPLETE scan; these results may
                      not describe current state."
historical Finding    HISTORICAL with newer_complete_scan_id
```

An MCP consumer must never receive a successful-looking empty answer that
could be read as global safety. The state enum plus guidance strings exist to
disambiguate; do not drop them for brevity.

---

# 14. Read-Only and Mutation Safety

Across an entire session, `pico mcp` performs:

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
file creations: 0
```

Opening `.pico/pico.db` read-only is the only workspace I/O. `ScanService`
must never be constructed or called from the MCP path. No adapter or provider
client may be instantiated.

Verify zero-write by hashing the database file around a scripted session.

---

# 15. Secret and Content Safety

Explanation increases exposed metadata; Pico's secret boundary must hold:

```text
Excluded always:
raw credentials, secret environment values, authorization headers,
raw configuration, raw provider bodies, unsafe metadata dumps,
unnecessary absolute machine paths.
```

Requirements:

```text
Reuse the DTO-layer locator safety policy unchanged.
TEST_SECRET_SHOULD_NOT_PERSIST and TEST_AUTH_HEADER_SHOULD_NOT_APPEAR must
appear nowhere in any tool result for the golden fixture.
Integrity errors identify broken normalized references without printing
unsafe row payloads.
Every persisted string passes the shared terminal-safety policy before
entering a tool result, so ANSI escapes, CR/LF, tabs, and other control
characters cannot spoof the JSON envelope or downstream rendering.
stderr diagnostics never echo request payloads or row payloads.
```

---

# 16. Protocol Safety and Bounds

Untrusted input arrives on stdin; bound everything:

```text
maximum accepted request line length — at least 1 MiB, documented;
longer lines yield one protocol error and are discarded, never buffered
without bound
one request processed at a time; no concurrency
a request that fails validation never touches SQLite
EOF on stdin ends the session with exit code 0
unrecoverable stdout write failure ends the session with a diagnostic
the process must not panic on malformed input; map to protocol errors
no request may terminate the process except EOF or unrecoverable IO
```

Fuzz-shaped inputs — truncated JSON, oversized lines, binary noise, wrong
types, unknown fields, duplicate ids, notifications with ids — must produce
protocol errors or safe application errors, never panics, partial results, or
writes.

---

# 17. Determinism

Equivalent persisted state must produce byte-identical tool results across
sessions and repeated calls:

```text
no hash-map iteration order in output
stored positions preserved for paths, edges, evidence, reasons,
remediations
no wall-clock time in results except echoing persisted timestamps
no filesystem enumeration order dependence
no randomness in ids, framing, or formatting
stable serde serialization with fixed pretty-printer settings
```

Repeated identical tool calls within one session and across sessions return
identical bytes and perform zero writes.

---

# 18. Dependency and Runtime Policy

Default expectation:

```text
implement the minimal stdio JSON-RPC/MCP subset in-repo using existing
dependencies (serde, serde_json, chrono, rusqlite, clap)
synchronous blocking IO; no async runtime
```

Policy:

```text
Any new dependency (including an official MCP SDK or tokio) requires
justification in the implementation plan: what it buys, its transitive
weight, its maintenance posture, and why the hand-rolled subset is
insufficient.
Network listeners, daemons, service installers, and privilege escalation
are forbidden regardless of dependency choice.
No MCP configuration system is added in this sprint.
```

If the handshake cannot be implemented faithfully against the MCP
specification without a new dependency, stop at the plan stage and present
the trade-off instead of improvising protocol behavior.

---

# 19. Scope and Explicit Non-Goals

Sprint 011 includes only:

```text
`pico mcp` stdio server launch verb
minimal JSON-RPC/MCP subset: initialize, initialized notification, ping,
tools/list, tools/call
two read-only tools: list_findings, get_finding
deterministic structured JSON result shaping over existing DTOs
protocol error mapping and bounded framing
fixtures and tests through in-process and scripted-client seams
```

Sprint 011 does not include:

```text
scan triggering over MCP
get_status or get_security_context tools
resources, prompts, sampling, roots, logging, completions primitives
HTTP, SSE, WebSocket, or Unix-socket transports
daemon or service mode
authentication, authorization, or multi-tenant behavior
an MCP configuration file
pagination, filtering, or query parameters beyond get_finding's id
--json flags on CLI commands
new Finding classes, eligibility, severity, or confidence changes
writes of any kind to SQLite or the filesystem
LLM-generated explanation
new adapters or providers; any provider call from the MCP path
automatic remediation or enforcement
hosted services
controlled live dogfood without separate authorization
Sprint 012 functionality
```

No schema migration and no Finding-semantics change are expected. If serving
the required tools faithfully appears to require either, STOP and report the
exact missing fact before changing persistence or security semantics.

---

# 20. Baseline

Expected implementation baseline:

```text
Branch: main
HEAD: 13bc5e912ca9ada72ac0c7fca7d09f6fcfe48054
origin/main: 29cccdffd8888e7f02552e89e162dae4d5103824
Ahead/behind: 2/0 (Sprint 010 commits intentionally unpushed per its commit
policy)
Working tree: clean except the known unrelated untracked .DS_Store
Schema version: 4
Finding version: 1
Analysis version: 1
Graph snapshot version: 1
Tests: 189 passed, 0 failed (61 unit + 30 domain + 60 integration +
38 persistence)
cargo check / clippy --all-targets -- -D warnings / fmt --check /
build --release: PASS
```

The authoring artifact may be this document alone. Preserve `.DS_Store`; do
not include it in Sprint 011's diff or commit. Before implementation verify
the baseline. If HEAD materially differs, Sprint 010 is not complete, or the
tree contains additional unexplained changes, STOP and report them.

---

# 21. Canonical Reading Order

Before implementation read:

1. `docs/internal/PRODUCT_DEFINITION.md`
2. `docs/internal/TECHNICAL.md`
3. `docs/internal/ARCHITECTURE.md`
4. `docs/internal/ROADMAP.md`
5. `docs/internal/sprints/SPRINT-010.md`
6. `docs/internal/sprints/SPRINT-011.md`

Treat them as authoritative. Do not rewrite Canon to make implementation
easier. Stop for founder review if the required slice contradicts Canon.

---

# 22. Baseline Architecture to Inspect

Inspect at minimum:

```text
src/application/findings.rs      FindingQueryService DTO surface
src/application/mod.rs           service exports
src/cli/mod.rs                   command enum and dispatch
src/cli/render.rs                terminal rendering contract
src/shared/mod.rs                PicoError classes, terminal_safe, version
src/persistence/db.rs            open_read_only, require_schema_version
tests/integration/sprint010_cli_test.rs        golden fixture seam
tests/integration/sprint010_finding_query_test.rs
tests/persistence/finding_query_integrity_test.rs
tests/persistence/finding_query_multi_test.rs
Cargo.toml                       existing dependency set
```

Confirm:

```text
CLI exposes init, scan, findings, finding only
application exposes InitService, ScanService, FindingQueryService
query path opens SQLITE_OPEN_READ_ONLY and gates schema version 4
DTOs derive serde Serialize and are stable under repeated serialization
freshness, empty-state, currentness, and integrity semantics live in the
application layer, not the CLI renderer
terminal_safe escapes C0/C1 control characters deterministically
schema version is 4; no migrations run on the query path
```

---

# 23. Implementation Plan Requirement

Before code changes produce a concise plan covering:

```text
stdio framing loop and shutdown semantics
JSON-RPC envelope validation and error mapping
initialize handshake and protocol-version handling
tools/list descriptors and annotations
list_findings and get_finding dispatch into FindingQueryService
state/guidance shaping for empty and no-COMPLETE states
result JSON shaping and terminal-safety application
workspace resolution matching the CLI (`current_dir`)
bounds, EOF handling, and panic containment
fixtures and tests, including parity against CLI DTOs
```

Call out genuine friction, especially:

```text
guidance strings currently live only in the CLI renderer; decide whether
they move into shared application constants rather than duplicating text
in the MCP layer
Freshness/Currentness enums serialize as tags; confirm the exact JSON
shape before freezing the machine contract
error taxonomy mapping PicoError variants to JSON-RPC codes without
leaking internals
bounded line reading without unbounded buffering
```

Do not solve friction by duplicating query logic, adding provider access,
recomputing explanations, or widening the tool surface.

---

# 24. Required Fixtures and Tests

Add sanitized deterministic fixtures for:

1. Golden COMPLETE Scan with one Finding (existing provider seam).
2. Newer RUNNING attempt after a COMPLETE Scan.
3. Newer PARTIAL attempt after a COMPLETE Scan.
4. Newer FAILED attempt after a COMPLETE Scan.
5. Initialized workspace with no Scans.
6. Scans exist but none is COMPLETE.
7. Latest COMPLETE Scan with zero Findings.
8. Historical Finding followed by a newer COMPLETE Scan.
9. Unknown Finding ID; prefix-only ID; empty id parameter.
10. Uninitialized workspace.
11. Unsupported schema version database.
12. Malformed JSON-RPC frames (truncated, non-object, binary noise).
13. Unknown method; unknown tool; notifications; ping.
14. Oversized request line beyond the documented bound.
15. Secret and authorization-header sentinels.
16. ANSI escape, CR/LF, tab, and control-character strings inside persisted
   fields surfaced through both tools.
17. Two paths reaching one Sink (affected_sink_count = 1) surfaced through
   list_findings.

At minimum test:

```text
initialize handshake returns pico serverInfo and a negotiated version
tools/list exposes exactly two tools, both readOnlyHint
list_findings mirrors FindingQueryService::list_latest exactly
get_finding mirrors FindingQueryService::get exactly, including HISTORICAL
currentness and freshness warnings
empty and no-COMPLETE states carry explicit non-all-clear guidance
zero Findings uses the scoped sentence
unknown IDs fail with safe messages and no partial data
malformed input yields protocol errors and the session continues
oversized lines are rejected within bounds
repeated identical calls produce byte-identical results and zero writes
database bytes are unchanged across a full scripted session
sentinels never appear in any tool result or stderr
control characters cannot break the JSON envelope
ScanService is unreachable from the MCP dispatch path (compile-level
assertion or equivalent structural test)
process exits cleanly on EOF with exit code 0
```

No fixture may contain a real credential.

---

# 25. Required Integration Results

Through the controlled seams verify:

```text
golden session:
  initialize → tools/list → list_findings → get_finding <id>
  list result equals the serialized FindingList DTO plus state/guidance
  detail result equals the serialized FindingDetail DTO
  six reasons, five ordered steps, four remediations present
  boundary narrative and scope note present

freshness:
  newer PARTIAL/RUNNING/FAILED attempts surface freshness_warning verbatim

history:
  first-scan Finding reports HISTORICAL with newer_complete_scan_id
  names come from the originating snapshot

behavior:
  Scan count unchanged; Finding count unchanged; all row counts unchanged
  database file hash identical before and after the session
  provider calls 0; network requests 0
  repeated calls byte-identical
```

For a multi-Finding controlled Scan, verify list_findings orders summaries in
the same deterministic order as `pico findings`.

---

# 26. Controlled Manual Verification

Using a temporary initialized workspace and the controlled golden fixture:

1. Produce one completed production Finding through the injected provider
   seam.
2. Launch `pico mcp` under a small scripted stdio client.
3. Complete the initialize handshake; record the negotiated protocolVersion.
4. Call tools/list; verify exactly two read-only tools.
5. Call list_findings; copy the exact displayed Finding ID.
6. Call get_finding with that ID; verify path, Evidence, boundaries, and four
   remediations match the CLI output semantically.
7. Record SQLite row counts and the database file hash.
8. Repeat both tool calls; verify byte-identical results and unchanged hash.
9. Inject a newer PARTIAL fixture Scan; call list_findings again; verify the
   freshness warning.
10. Search all captured stdout, stderr, and SQLite for both secret sentinels.
11. Send malformed and oversized frames; verify safe errors and continued
    session; close stdin and verify exit code 0.

Controlled live agent-session dogfood remains a roadmap follow-up. Do not
obtain credentials or perform any write for this sprint.

---

# 27. Architecture Pressure Test

Before completion answer:

1. Does every tool call flow through FindingQueryService rather than new
   query code?
2. Is the MCP layer free of SQL, graph logic, and security reasoning?
3. Are exactly two tools exposed, both declared read-only?
4. Can any tool result be mistaken for a global all-clear?
5. Does get_finding preserve exact-ID lookup and originating-scan history?
6. Are freshness warnings carried verbatim into results?
7. Are results byte-deterministic across sessions?
8. Do sessions perform zero writes, verified by file hash?
9. Do sessions perform zero network and provider operations?
10. Are sentinels and unsafe locators provably absent from results?
11. Are control characters neutralized before serialization?
12. Do malformed inputs fail safely without panics or termination?
13. Is ScanService structurally unreachable from the MCP path?
14. Did the implementation avoid schema migrations and semantic changes?
15. Are deferred capabilities (scan, status, security context) absent?

If any answer is NO, do not hide it. Fix only if clearly within Sprint 011;
otherwise STOP and report it.

---

# 28. Definition of Done

Sprint 011 is complete only when:

- [ ] Baseline `13bc5e9` is verified and unrelated `.DS_Store` is preserved.
- [ ] `pico mcp` launches a stdio MCP session.
- [ ] The initialize handshake negotiates a protocol version and advertises
      the tools capability.
- [ ] tools/list exposes exactly list_findings and get_finding, both
      readOnlyHint.
- [ ] list_findings reproduces `pico findings` semantics including ordering,
      counts, freshness, and distinct empty states.
- [ ] get_finding reproduces `pico finding <id>` semantics including exact
      lookup, HISTORICAL labeling, and fail-closed integrity.
- [ ] Results are deterministic JSON shaped from application DTOs.
- [ ] Every persisted string passes the terminal-safety policy before
      serialization.
- [ ] Query commands perform zero network/provider operations and zero
      database writes.
- [ ] Each tool call composes from one coherent read snapshot.
- [ ] Malformed, oversized, and unknown protocol input fails safely and the
      session survives.
- [ ] Secret sentinels have zero occurrences in results, stderr, and SQLite.
- [ ] Repeated queries are byte-identical and write nothing.
- [ ] Full verification passes.
- [ ] Final diff contains no scan trigger, no extra tools, no daemon, and no
      Sprint 012+ functionality.
- [ ] This document records completion evidence.

---

# 29. Full Verification

After implementation run:

```text
cargo test
cargo check
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

Report exact totals. Run controlled scripted-session checks, determinism
checks, zero-write hash checks, secret-sentinel searches, and the architecture
pressure test. Do not declare completion from focused tests alone.

---

# 30. Final Diff Inspection

Review for:

```text
accidental files or .DS_Store
build artifacts or .pico state
real credentials or machine paths
raw metadata rendering
SQL or security logic in the MCP module
duplicate snapshot interpretation or duplicated explanation logic
recomputed Finding semantics
unordered or nondeterministic output
current-state leakage into historical detail
cross-scan Evidence
silent partial explanations
absolute no-boundary or global-safety claims
database writes during sessions
network listeners, daemons, or provider calls
schema changes
extra tools or write-capable surfaces
unnecessary dependencies or async runtimes
Pico configuration systems
Sprint 012+ functionality
```

Do not perform unrelated refactoring.

---

# 31. Stop Conditions

Stop and report if:

```text
baseline is materially unexpected
the worktree contains unexplained changes beyond the known .DS_Store
Canon contradicts the required interface posture
the MCP subset cannot be implemented faithfully without forbidden
dependencies or improvised protocol behavior
serving the tools requires writes, migrations, or provider access
tool results cannot be made deterministic and sentinel-free
malformed input cannot be contained without panics
the query layer cannot back both CLI and MCP without semantic drift
deferred capabilities appear required by Slice 10 (they do not)
```

Do not silently weaken integrity, determinism, or safety guarantees to make a
fixture pass. Report blockers rather than inventing compatibility or security
truth.

---

# 32. Completion Evidence

When implementation and verification pass, set `Status: COMPLETE` and record:

```text
completion date and verified baseline
implementation commit
repository state
test totals and Rust checks
negotiated MCP protocolVersion and serverInfo
tools/list contents
list_findings and get_finding golden results
freshness-warning and historical results
empty, not-found, and corrupt-link results
determinism and database-write counts
secret-sentinel results
network/provider mutation counts
architecture pressure-test answers
scripted-agent comprehension observation if any independent reviewer is
available; otherwise record NOT RUN honestly
controlled-real-environment status
roadmap decision
```

Do not claim the full v0.1 exit gate while controlled dogfood or independent
developer comprehension remains incomplete.

## Recorded completion evidence — 2026-08-25

- **Verified baseline:** `13bc5e912ca9ada72ac0c7fca7d09f6fcfe48054`; working
  tree clean except preserved untracked `.DS_Store`.
- **Implementation commit:** `936a421 feat(mcp): serve persisted findings to coding agents`.
- **Schema version:** 4 (unchanged). Finding/analysis/snapshot versions: 1.
- **Verification totals:** 222 passed, 0 failed (77 unit + 30 domain +
  77 integration + 38 persistence). `cargo check`, `cargo clippy --all-targets
  -- -D warnings`, `cargo fmt --check`, `cargo build --release`: all clean.
- **Protocol:** transport stdio; supported versions
  `2025-06-18 | 2025-03-26 | 2024-11-05`; requested supported versions echoed,
  otherwise fallback `2025-06-18`; scripted session negotiated `2025-03-26`;
  serverInfo `pico` + `PICO_VERSION`.
- **Tools/list:** exactly `list_findings` and `get_finding`, both
  `readOnlyHint: true`, stable order, JSON Schema input contracts.
- **Golden session (provider seam):** list payload deep-equals the serialized
  `FindingList` plus state/guidance (`RESULTS_AVAILABLE`,
  `LATEST_COMPLETE`); detail deep-equals serialized `FindingDetail` with six
  ordered reasons, five traversal-aware steps (REVERSE×2 → FORWARD×3),
  connected chain, per-step Evidence IDs, boundary narrative, scope note, and
  four ordered remediations. CLI/MCP parity asserted by DTO equality.
- **Freshness and history:** RUNNING/PARTIAL/FAILED attempts surface
  `NEWER_INCOMPLETE_ATTEMPT` with verbatim warning text (newline sanitized to
  `\x0A` per the terminal-safety contract); historical finding reports
  HISTORICAL with `newer_complete_scan_id` and keeps originating-snapshot
  names despite later stable-row renames.
- **Negative cases:** unknown tool → `-32602`; unknown method → `-32601`;
  malformed frame → `-32700` with session continuation; oversized line → one
  bounded error then continued session; uninitialized workspace → safe
  `pico init` guidance; unknown/prefix/empty Finding IDs fail closed.
- **Determinism and zero-write:** repeated calls byte-identical; database file
  hash identical across full sessions (release binary and in-process).
- **Secret sentinels:** zero occurrences in any frame, stderr, or SQLite.
- **Mutation counts:** new Scans 0; database writes 0; network requests 0;
  provider operations 0; remediations applied 0.
- **Architecture pressure test:** all 15 answers YES (two tools read-only;
  no SQL/security logic in MCP; ScanService structurally unreachable from the
  MCP path; no daemon/listener; no schema change).
- **Independent review / agent-session dogfood:** NOT RUN — remains a roadmap
  follow-up.
- **Roadmap decision:** EXTEND v0.1 (all architecture slices 1–10 built;
  controlled dogfood and developer comprehension gates remain open).

---

# 33. Commit Policy

The authoring-only document may be committed separately with:

```text
docs(sprints): define Sprint 011 minimal MCP exposure
```

If and only if Sprint 011 is fully verified, stage only Sprint 011
implementation changes, inspect the staged diff, and commit with:

```text
feat(mcp): serve persisted findings to coding agents
```

Record completion evidence in a separate documentation commit if needed.
Do not amend previous commits. Do not push unless explicitly instructed.
Do not begin Sprint 012.

---

# 34. Final Report Contract

Report:

```text
Sprint: SPRINT-011 — First Agent Interface — Minimal MCP Exposure
Status: COMPLETE or BLOCKED
Baseline: <verified SHA>
Implementation commit: <SHA + message>

Commands:
pico mcp: PASS | FAIL
tools/list: PASS | FAIL
list_findings: PASS | FAIL
get_finding <id>: PASS | FAIL

Protocol:
Transport: stdio
Negotiated protocolVersion: <value>
Server info reported: <name + version>
Tools exposed: 2
Read-only hints declared: YES | NO

Golden session:
list_findings matches CLI semantics: YES | NO
get_finding matches CLI semantics: YES | NO
Paths shown: <count>
Reasons shown: <count>
Evidence complete: YES | NO
Remediation cut points shown: <count>
Scope note present: YES | NO

Selection and history:
Freshness warning surfaced: YES | NO
HISTORICAL currentness surfaced: YES | NO

Negative cases:
Unknown tool: <result>
Malformed frame: <result>
Oversized frame: <result>
Uninitialized workspace: <result>
Unknown Finding ID: <result>

Safety:
New Scans created by sessions: 0
Database writes: 0
Network requests: 0
Provider operations: 0
Secret sentinel emitted: NO
Automatic remediation performed: NO

Scope:
Scan trigger implemented: NO
Status/security-context tools implemented: NO
Daemon/listener implemented: NO
Schema migration: NO
Finding semantics changed: NO
Sprint 012 functionality implemented: NO

Verification:
<tests and all required checks>

Independent review: PASS, FAIL, or NOT RUN with notes

Repository:
Branch: <branch>
HEAD: <SHA>
origin/main: <SHA>
Ahead/behind: <state>
Working tree: <state, including preserved .DS_Store>

Follow-ups:
<only genuine dogfood, comprehension, or post-v0.1 observations>
```

Do not report an agent-readable Finding as a validated environment. Do not
report deferred capabilities as delivered.

---

# 35. Sprint Exit

Sprint 011 ends when a coding agent can run:

```text
initialize → tools/list → list_findings → get_finding <id>
```

and receive exactly what the CLI would have told a developer:

> **This is the persisted Finding, this is the complete path, this is why it
> matters, this is the Evidence behind it, this is what Pico established about
> boundaries and uncertainty, and these are the exact places where the path can
> be broken — served read-only, deterministically, with no second scanner.**

It does not yet prove:

> **A real developer's comprehension of these conclusions, or Pico's value in
> a controlled live environment.**

Those remain the v0.1 gates. They belong to explicitly authorized follow-up
work.

Do not begin Sprint 012.

Wait for explicit authorization.

