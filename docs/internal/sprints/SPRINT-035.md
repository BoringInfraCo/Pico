# Pico — Sprint 035: v0.4 Evidence and Independent Comprehension

**Status:** PARTIAL — controlled capture harness executed; scenario gaps and independent gate pending.
**Phase:** v0.4 — Security Memory and Change Detection
**Depends on:** S031 retention correctness, S032 attribution, S033 public JSON,
S034 MCP history/diff; final implementation contracts take precedence over
proposed names in the closeout plan.
**Authority:** [ROADMAP §8](../ROADMAP.md#8-v04--security-memory-and-change-detection),
[v0.4 closeout §7](V0.4-CLOSEOUT-PLAN.md#7-s035--evidence-and-independent-comprehension).

## 1. Purpose and scope

Demonstrate that the delivered implementation lets a developer distinguish an
observed environment change, a change in evidence, and an invalid comparison.
Record controlled end-to-end evidence and administer an uncoached independent
comprehension check against the final build. A prepared protocol or successful
automated suite does not establish human comprehension.

This sprint adds no providers, continuous observation, notifications, policy
thresholds, remediation, or infrastructure mutation. Exercise read-only queries
and explicit local pruning only in a disposable fixture workspace. Synthetic
provider observations must be identified as synthetic; they do not establish
live-provider correctness or human usefulness.

## 2. Build and capture contract

Record the following in `docs/internal/dogfood/evidence-v0.4.md` when executed:

- Exact commit and dirty-tree status, patch digest if uncommitted, binary SHA-256,
  `pico --version`, build command, platform, and public output/schema versions.
- Fixture source and deterministic setup, observation timestamps and opaque scan
  IDs, supported agents/providers exercised, and which operations are real scans
  versus seeded persisted snapshots. Do not present a seeded scan as a live run.
- Commands, exit codes, separate stdout/stderr, full JSON responses, and MCP
  requests/responses. Store captures as `transcripts-v0.4/df35-<scenario>-<surface>.*`.
- Read-only before/after whole-database content digests covering all tables, plus
  retained-unit digests for pruning. Account for SQLite sidecars if byte digests
  are used. Record the digest method; a file hash and a logical content digest
  prove different properties.
- Sanitization manifest and secret/control-byte sweep result. Generate synthetic
  credentials, never borrow ambient credentials. Do not print secret matches in
  failure diagnostics. Keep an original private capture only if needed to verify
  sanitization; committed output must already be safe.

For each scenario capture human CLI, CLI JSON, and decoded MCP query payloads
where supported. Compare the shared public payload structurally, preserving array
order and all fields. MCP framing is excluded from semantic equality. Repeated
reads of the same snapshot must produce equal payloads; never normalize away an
unexpected difference to obtain a pass. Human output must preserve the same
limitations even when its wording differs.

## 3. Controlled scenario matrix

| ID | Setup and action | Required observed result |
| --- | --- | --- |
| E1 | Empty initialized workspace; history and diff; first COMPLETE scan | Empty history and insufficient comparison history are explicit, successful typed query outcomes; no all-clear implied. |
| E2 | Repeat an unchanged supported local configuration with equivalent coverage | No security-significant diff; timestamps/evidence row identity alone do not invent an environment change. |
| E3 | Change OpenCode Bash allow → ask → deny in separate scans; repeat equivalent supported Claude posture changes | Typed before/after values and relevant evidence support the reported permission/boundary change. No claim of executed remediation; cut points describe observed configuration. |
| E4 | Separately vary supported credential scope, resource scope, MCP availability, and authority in controlled fixtures | Each supported field produces its expected deterministic delta and defensible attribution; unrelated evidence cannot serve as its cause. Mark any unsupported field or missing provenance explicitly. |
| E5 | Keep configuration fixed while collection fails or access/coverage is lost, then restore collection | Missing evidence is never described as confirmed removal or remediation. Newer incomplete attempts remain freshness context, not comparison operands. Recovery does not invent first-ever exposure. |
| E6 | Use COMPLETE snapshots with reduced coverage, identity churn, or legacy provenance absent | COMPLETE alone does not justify environmental disappearance; uncertainty and attribution limits remain explicit. |
| E7 | Produce supported rating movement and an ambiguous multiple-change case | Weakened/strengthened/uncertain entries use supporting before/after evidence. Rating movement alone does not prove environmental change; ambiguous causes are not presented as a unique cause. |
| E8 | Compare snapshots with mismatched analysis/graph/finding contracts | Explicit not-comparable outcome, no ordinary environment/lifecycle conclusions; history and provenance identify the limitation. |
| E9 | Retain enough COMPLETE scans to prune; `prune --keep 2`; rerun it; query retained and removed pairs | Whole-unit deletion, retained provenance unchanged, second prune no-op, retained pair comparable, removed IDs explicitly unavailable. First-seen claims remain scoped to retained history. |
| E10 | Query invalid/missing IDs, reversed and incomplete pairs, unsupported schema, and malformed MCP arguments | Documented typed outcome/error and exit behavior, no database writes, no raw secret/control-byte leakage. Preserve parser-error policy from S033. |
| E11 | Inspect a supported influence-to-authority path and findings using CLI and existing MCP tools | Existing finding payloads remain compatible; source, actor, authority, evidence, uncertainty, boundaries, and cut points are understandable. This supplies the carried v0.3 comprehension packet. |

E3/E4 require product-level captures plus field-specific automated assertions.
If a fixture cannot support a positive environment attribution, record that
limitation and do not substitute a plausible narrative. E5/E6 must include
negative assertions against false disappearance/remediation. Real local scan
captures and seeded edge-case regression evidence are separate evidence classes.

## 4. ROADMAP §8 exit evidence map

| Exit criterion | Required evidence |
| --- | --- |
| Unchanged environments have no significant diff | E2 repeated real local scans and deterministic regression results |
| Permission/approval/scope/MCP/authority changes have expected diffs | E3–E4 captures and per-field S032 acceptance evidence |
| First appearance and smallest observed cause | E4/E7 exact subject/field evidence; E9 retained-window limits; no unique cause invented for ambiguous changes |
| Failure/reduced scope never means remediation | E5–E6 negative assertions and independent safety questions |
| Stable lifecycle across scans/upgrades | E2/E7 lifecycle assertions, E8 comparison-contract refusal, migration/legacy results |
| Usable secret-safe retained history | E9 health/digest/secret evidence and participant retention answers |
| Developer distinguishes environment/evidence/analysis | Independent E3/E5/E6/E8 answers under the protocol; automated labels alone cannot close this criterion |
| Stable machine diffs without SQLite API | S033 schema/goldens, E1–E10 parsed CLI/MCP parity, S034 old-tool compatibility |

## 5. Independent comprehension

Administer [comprehension-v0.4.md](../dogfood/comprehension-v0.4.md) only after
final captures exist. The developer must not have implemented the feature or
authored its fixtures. Give only product output and ordinary user-facing help;
withhold the rubric, expected answers, source, SQLite inspection, and coaching.
Record verbatim answers before any explanation. An agent proxy may test packet
readiness but cannot pass the independent gate.

The carried v0.3 gate is separate: record Set B's independent path comprehension
result explicitly. Do not rewrite historic proxy results or silently infer that
new diff comprehension closes the earlier path-comprehension requirement.

## 6. Release review checklist and decision

- [ ] E1–E11 executed with actual results, artifact links, limitations, and
  provenance of synthetic versus real observations.
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --all-targets`, and `git diff --check` pass on the recorded build.
  List ignored tests and whether they were separately executed; do not count
  ignored live tests as passes.
- [ ] S031 rollback/refusal/no-op, S029 comparison guard, schema/legacy behavior,
  S032 attribution, S033 output schema, and S034 parity/compatibility verified.
- [ ] Secret sweeps and read-only/retained-row digest evidence attached.
- [ ] Independent v0.4 comprehension PASS and carried v0.3 result separately
  recorded; all safety-critical distinctions correct.
- [ ] Learning answers recorded: urgent versus noisy change, useful retention,
  manual triggers, analysis-version messaging, and trusted future notification
  threshold. These inform later planning, not authorization to build v0.5.
- [ ] ROADMAP/architecture reflect delivered contracts, including COMPLETE-only
  operands and partial-attempt context. Cargo/CLI version naming is explicitly
  decided at release review, not automatically bumped by this sprint.

Decision values: **HOLD** (missing evidence or any failing gate), **REWORK**
(reproducible defect or misleading output requires correction), or **ADVANCE**
(all technical and independent gates satisfied). Record decision owner, date,
exact build, open issues, and supporting artifacts. Until an actual independent
participant has passed, v0.4 remains IN PROGRESS even if implementation is done.

## 7. Current execution record

Protocol and scenario design: PREPARED. Controlled execution: two automated
end-to-end tests PASS, with actual captures and exact build record in
[evidence-v0.4.md](../dogfood/evidence-v0.4.md). That record identifies incomplete
scenario variants and distinguishes real local discovery from synthetic provider
injection. Independent participant: NONE. v0.4 comprehension: NOT RUN. Carried
v0.3 independent gate: NOT RUN. Release decision: HOLD pending remaining scenario
evidence and independent validation. Automated success does not close this sprint.
