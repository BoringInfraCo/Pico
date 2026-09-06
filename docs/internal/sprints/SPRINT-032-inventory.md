# Sprint 032 — attribution inventory checkpoint

**Status:** DRAFT CHECKPOINT — source inventory and proposed decisions;
not an approved implementation spec and not Sprint 032 completion.
**Baseline:** `178a8ed` (S031). **Date:** 2026-09-05.
**Authority:** [v0.4 closeout plan](V0.4-CLOSEOUT-PLAN.md), §4.

## 1. S031 verification

Source review confirms an immediate transaction precedes scan loading,
RUNNING refusal, planning, and both health gates; post-health precedes commit.
Prune requires the supported schema without migrating. Dangling diagnostics
carry structural locations and counts rather than cell text or unresolved IDs.

Rerun: 528 tests pass (222 lib, 30 domain, 226 integration, 50 persistence),
one pre-existing ignored; fmt and clippy pass. MCP diff between the S031 spec
and implementation commits is empty. No new blocking defect was identified
in the reviewed correction paths.

Evidence limitation: R5 tests SQLite's immediate-transaction mechanism and
the service's pre-existing RUNNING refusal separately. It does not inject a
writer between actual service checkpoints. Correct service placement is
supported by source review; do not describe R5 as an end-to-end interleaving
regression that would fail on S030.

## 2. What the current data can establish

| Persisted surface | Current producer/consumer | Attribution consequence |
| --- | --- | --- |
| Resource/relationship observation snapshots | `src/application/scan.rs`; `src/domain/observation.rs`; `src/application/graph_diff.rs::sets_for_scan` | Use these scan-local values for before/after state. Global resource and relationship rows are mutable identities, not historical state. |
| Evidence class, source type, locator, subject, observation, captured time, freshness, sensitivity, metadata | `src/domain/evidence.rs`; evidence creation in `scan.rs` | Enough to retain separate side provenance, but free-form prose is not a causal rule and source type alone does not prove a specific field. Export only a safe projection. |
| Relationship evidence and finding/path evidence links | Persistence repos; scan-local filtering in `src/graph/projection.rs` | Prefer explicit same-scan links. Global relationships accumulate evidence across scans; filter by operand scan. Validate subject/field applicability as well as existence. |
| Scan status, timestamps | `Scan::start` and finalization in `scan.rs` | Status describes run success, not equal coverage. PARTIAL/FAILED/RUNNING remain non-operands. |
| `scans.scope`, `environment_fingerprint` | `src/domain/scan.rs` initializes both to `None`; production scan path does not populate them | Neither is an existing coverage proof or environment-change detector. No legacy backfill can infer their missing contents. |
| Comparison tuple in scan metadata and analysis record | `scan.rs`; `src/application/compare_contract.rs` | S029 must run first. Missing/incompatible contracts stay NotComparable, with no normal attribution. |
| Provider diagnostics | `src/findings/diagnostics.rs`; `scan.rs::build_provider_statuses` | Reachable is constructed from absence of reported problems. No exhaustive attempted/not-attempted, target-scope, or enumeration-completeness manifest exists here. Missing provider entry is not a successful empty inventory. |
| Suppressed candidates and confidence notes | `ScanDiagnostics` | Explain evidence limitations and freshness penalties. Do not infer a changed permission from a changed confidence score. |
| Finding full/family fingerprints and lifecycle deltas | `src/application/diff.rs` | Stable matching already exists; weakened/strengthened/uncertain pairs need observed attribution in addition to rating movement. |
| Existing cause | `src/application/cause.rs` | Attached only to appeared/disappeared findings. Evidence source types are merged across sides; `evidence_types` uses equality OR substring subject matching. This is explanatory context, insufficient for strict field-level proof. |

## 3. Complete current graph-field inventory

This table covers all 26 `METADATA_KEYS` plus top-level diff fields in
`src/application/graph_diff.rs`. Categories are proposed interpretation rules,
not classifications already implemented. An environment candidate requires
comparable support on both sides; the field name alone never determines it.

| Fields | Meaning and producer | Proposed treatment |
| --- | --- | --- |
| `effective_permission`, `effective_state`, `scope`, `runtime_mode`, `boundary_kind` | Normalized Bash capability and approval/sandbox posture from agent adapters, persisted on `can_execute` with matching evidence metadata | Known supported value to known supported value can establish observed configuration change. Unknown/unresolved values or a change in inspected config layers require evidence/coverage qualification. |
| `enabled`, `transport` | Static supported GitHub MCP configuration from OpenCode/Claude discovery | Observed configuration change with comparable config provenance. Does not prove live MCP connectivity or server capability negotiation. |
| `permission`, `permission_pattern` | Normalized MCP tool permission and matching rule | Environment candidate with known effective config on both sides. Pattern text alone may change without changing authority; separate rule change from security effect. |
| `influence_strength`, `trust`, `content_class`, `consequential_sink` | Supported tool/content classifications and sink projection | Derived semantics. Check input evidence and S029 before attribution; a changed classification alone is not a changed environment. |
| `authority_resolution`, `permission_state`, `account_scope_state` | Normalized GitHub/Cloudflare authority and permission knowledge | Exact supported policy changes may be environment changes; known-to-unknown and unknown-to-known may be evidence loss/recovery. Evaluate supporting facts, not enum direction. |
| `credential_status`, `validity` | Provider verification knowledge/status | UNKNOWN or failed observation does not establish revocation. Require comparable affirmative verification facts for claims about validity changing. See snapshot caveat below. |
| `unknown_reasons` | Structured authority uncertainty reasons | Evidence/uncertainty context; never environment change by itself. Normalize ordering of set-like reasons. |
| `granted_permissions`, `zone_scoped` | Cloudflare policy facts attached to authority edges | Environment candidate only when both policy observations are supported and comparable; unavailable fields are not empty grants. Normalize set-like grants. |
| `sink_impact` | Worker impact normalized from provider-result input; unknown remains unknown | Requires provenance of impact declaration/observation. Worker names do not establish production status. Known/unknown movement alone is evidence movement. |
| `credential_type` | Safe credential classification | Type change may also change canonical identity. Do not infer secret rotation or authority change solely from this field. |
| `environment_reachability` | Credential execution-environment reachability knowledge | Distinguish observed exposure from changed ability to establish exposure. Missing/unknown is not confirmed isolation. |
| `presence` | Credential positive observation, currently set to PRESENT | Positive evidence exists; absence from the next snapshot does not establish removal without collection coverage. |
| `identity_precision` | Worker identity quality (e.g. stable tag versus fallback) | Evidence/identity qualification; do not turn identity churn into resource creation/remediation. |
| `kind`, `provider` (resource); `kind` (relationship) | Canonical subject classification | Usually identity/contract context. Unexpected movement under the same key needs explicit handling, not automatic causal attribution. |
| `name` | Resource display label | May be an observed rename but is not itself a security-significant cause. |
| `state` (relationship) | OBSERVED/DERIVED/UNKNOWN-style relationship knowledge | Interpretation depends on supporting facts and edge kind. State transition alone does not establish gained/lost authority. |

## 4. Gaps that affect the design

1. **Coverage is not persisted as a comparable contract.** Provider-level
   absence of errors cannot justify absence of a subject. Define scoped
   coverage for config layers, credential discovery environment, and bounded
   provider operations/targets. Distinguish inspected, not attempted,
   incomplete, unsupported, and unknown; define completeness within each
   supported boundary, not as a global all-clear.
2. **Diff values lose type and presence information.** `field_text` merges
   missing and JSON null; `GraphDelta` renders absence as an em dash and
   stringifies values. Attribution must read typed operand snapshots before
   rendering rather than parse these display strings. Set-like arrays need
   semantic normalization so ordering alone is not a security change.
3. **Some useful metadata is outside the current diff allowlist.** MCP
   `discovery_tier`, Cloudflare account/`scoped_to` `scope_state`, and credential
   source/fingerprint metadata are persisted but not compared by those keys.
   Audit relevance and safety before adding fields; do not dump metadata.
4. **Global state can differ from the recorded snapshot.** Cloudflare
   verification updates global credential `validity` after the initial
   credential observation; that update path does not itself record a fresh
   credential snapshot. Authority-edge `credential_status` is a separate
   scan-local source. Do not read the current global validity as old evidence.
5. **Field-level causal joins need tightening.** Replace substring evidence
   matching for attribution with exact canonical subjects or validated
   explicit links, filtered by side. Missing or ambiguous support remains
   unattributed, with both sides' provenance kept separate.
6. **Scope loss must affect claims, not just add a footnote.** Today graph
   and finding set differences can reach disappeared buckets before an
   attribution layer exists. S032 must suppress or qualify unsupported
   disappearance at the application-result level so later JSON/MCP consumers
   cannot interpret it as remediation. Preserve first-seen as retained-window
   observation history, not proof of actual creation time.

## 5. Recommended contract direction

Retain the closeout's proposed `observed_environment_change`,
`evidence_change`, `mixed`, and `unattributed` outcomes, with stable reasons.
Use `mixed` only when both components are supported; ambiguity is
`unattributed`. Contract mismatch remains outside these outcomes.

Implement attribution over typed persisted observations and validated
same-scan evidence. Attach it to graph changes and all relevant finding
lifecycle entries. Separate the observed change from the security effect;
where several causes fit, report ambiguity instead of inventing one cause.

Legacy snapshots can support paired affirmative observations where their
provenance is sufficient. They cannot prove exhaustive negative coverage.
Missing coverage must remain explicit and cannot be backfilled from COMPLETE
or current discovery. Pruned history also cannot establish negative facts.

Prefer a versioned, safe coverage payload in an existing scan-local JSON
surface if it satisfies validation and lifecycle requirements; schema v6 is
possible, not yet promised. Freeze the producer, atomic persistence point,
validation, and legacy behavior before selecting storage. Review the S029
comparison contract explicitly when changing supported diff semantics.

## 6. Next spec checkpoints and acceptance matrix

The inventory identifies why S032 is the largest slice. Execute it in staged
checkpoints, without treating this draft as authorization to implement:

1. Freeze coverage producers and storage, typed attribution inputs, unknown
   fallback, compatibility/version policy, and the disappearance result shape.
2. Add producer/legacy fixtures and prove coverage is persisted safely before
   writing the classifier. Exercise real discovery paths, not only seeded DTOs.
3. Implement shared attribution and lifecycle integration; then render it.
4. Validate combined semantics and document only delivered behavior.

Required cases: unchanged repeat; Bash allow/ask/deny and supported sandbox;
MCP disabled/enabled versus unobserved; known scope/permission changes;
provider failure and recovery; UNKNOWN authority transitions; reduced scope
with COMPLETE operands; unattempted operation; identity precision change;
display-only rename; grant/reason reordering; missing/null/value distinction;
multiple causes; exact versus substring subject collisions; legacy absence
of coverage; newer incomplete attempt; S029 mismatch; post-prune window.

For each case assert the attribution, safe side provenance, lifecycle result,
and absence of unsupported disappearance/remediation. Keep read-only digests,
secret sweeps, S024–S031 regressions, schema compatibility, and MCP byte
compatibility (new MCP tools remain S034). No production source changed in
this inventory checkpoint; S032 remains unimplemented.
