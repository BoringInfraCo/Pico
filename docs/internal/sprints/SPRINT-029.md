# Pico — Sprint 029: Comparison Contract Guard (v0.4 slice 6)

**Status:** DONE

**Sprint:** 029
**Phase:** v0.4 — Security Memory and Change Detection
**Type:** Implementation (sixth slice)
**Baseline:** `5a1e9e4` (post-Sprint-028 finding lifecycle)
**Depends on:** Sprint 008 (persisted analysis), Sprint 024/025 (diff pair selection), Sprint 026/027 (graph and causes), Sprint 028 (finding lifecycle)

---

# 1. Purpose

S024–S028 compare the persisted conclusions of two COMPLETE scans without
first proving that the same comparison contracts produced both sides. Pico
already versions three independent semantic layers:

- observation graph snapshots (`GRAPH_SNAPSHOT_VERSION`);
- analysis/AttackPaths (`ANALYSIS_VERSION`);
- Findings and fingerprints (`FINDING_VERSION`).

Today, a change to any one can surface as an ordinary graph or Finding
movement and be mistaken for an environment change.

Sprint 029 proves a **comparison contract guard**:

> **`pico diff` computes Finding, graph, lifecycle, and Cause changes only
> when both COMPLETE scans declare the same comparison-contract tuple and
> that tuple is supported by the running Pico build. Missing legacy
> provenance, a changed tuple, or an unsupported tuple produces an explicit
> non-comparable result. Pico never converts those states into empty buckets,
> ordinary appeared/disappeared movement, or an all-clear.**

The guard establishes whether this Pico build may compare the two persisted
conclusions. It does not prove that an observed change came from the external
environment rather than collection/evidence changes.

This is not v0.4 complete. Environment-versus-evidence attribution,
retention, MCP diff/history, stable public machine output, and the independent
comprehension gate remain later work.

---

# 2. Scope

- Define a composite comparison tuple:
  `comparison_contract_version + graph_snapshot_version + analysis_version + finding_version`.
- New scans declare `comparison_contract_version` and `finding_version` in
  safe Scan metadata. The existing `graph_snapshot_version` declaration
  remains. The persisted `scan_analyses.analysis_version` remains the
  authoritative analysis version.
- Load and validate both sides' provenance inside the existing read-only diff
  snapshot, after COMPLETE/chronology validation and before any comparison.
- Cross-check declarations against persisted rows:
  - observation snapshot versions equal the scan graph version;
  - every AttackPath version equals its scan analysis summary;
  - all Finding versions agree and equal the declared/derived scan version.
- Current, equal tuple: preserve every S024–S028 comparison rule, ordering,
  conservation invariant, freshness rule, graph bucket, and Cause rule.
- Valid tuples differ: return `NotComparable(ContractChanged)` before loading
  Finding/graph comparison inputs or attaching causes.
- Equal valid tuple unsupported by the current binary: return
  `NotComparable(ContractUnsupported)`.
- Required legacy provenance cannot be derived: return
  `NotComparable(ProvenanceUnavailable)`, not a corruption error.
- Malformed or internally contradictory persisted provenance fails closed as
  a database integrity error.
- Apply the same guard to implicit latest-two and explicit-pair diffs.
- Render supported provenance and a dedicated non-comparable explanation.
- Make analysis summaries immutable once their parent Scan is COMPLETE.
- Schema remains v6. No data migration or historical re-analysis.
- MCP remains exactly `list_findings` and `get_finding`.

---

# 3. Non-goals

- Claiming that a contract mismatch caused every underlying difference.
- Distinguishing an environment change from an evidence/collector change.
- Populating or defining `Scan.environment_fingerprint`.
- Hashing or comparing raw Evidence IDs, capture timestamps, source locators,
  or observation metadata as an evidence-change classifier.
- Re-analyzing, rewriting, or backfilling old scans.
- Treating a `pico_version` change alone as a contract mismatch. Package
  version is reported provenance; the composite tuple is the guard key.
- Mapping non-comparability to S028 `uncertain` or emitting zero-valued change
  counts that could be mistaken for no change.
- MCP `what_changed`, `pico diff --json`, CI/notification contracts.
- Retention, pruning, database repair, or deletion.
- Claiming v0.4 complete or advancing to v0.5.

---

# 4. Validation Matrix

```text
R1  Equal current tuple: existing S024–S028 Ready result and all
    Finding/graph/lifecycle/Cause semantics remain intact; provenance names
    all four contract components.
    → NEW-FIXTURE (current_contract_pair_is_comparable)

R2  Equal current tuple, different Pico package versions: comparison remains
    Ready; package-version drift alone is not the guard key.
    → NEW-FIXTURE (pico_version_change_alone_does_not_block)

R3  Different analysis, finding, or graph component (one case each):
    NotComparable(ContractChanged); no Finding/GraphDiff is constructed, no
    Cause is attached, and render says comparison was skipped and this is not
    an all-clear.
    → NEW-FIXTURE (changed_contract_component_blocks_comparison)

R4  Both sides declare the same well-formed but unsupported tuple:
    NotComparable(ContractUnsupported), never Ready.
    → NEW-FIXTURE (equal_unsupported_contract_is_not_comparable)

R5  A valid upgraded database with legacy COMPLETE scans whose required
    provenance cannot be derived returns
    NotComparable(ProvenanceUnavailable), never corruption or an empty diff.
    → NEW-FIXTURE (legacy_missing_provenance_is_explicit)

R6  Blank/invalid declarations, conflicting row versions, a non-COMPLETE
    analysis summary on a COMPLETE scan, or a mutable-summary rewrite after
    completion fails closed as a database integrity error.
    → NEW-FIXTURE (contradictory_provenance_fails_closed)

R7  Latest-two and explicit-pair paths select the same pair, provenance, and
    guard decision. Their intentional Compared/Freshness context differences
    remain. A newer incomplete attempt never becomes a side; a reversed
    explicit pair is still rejected even when contract tuples differ.
    → NEW-FIXTURE (latest_and_explicit_guard_decisions_agree)

R8  The non-comparable branch returns before comparison work: malformed graph
    input that would fail projection does not mask a valid ContractChanged
    decision. Repeated calls are byte-deterministic and terminal-safe.
    → NEW-FIXTURE (contract_guard_precedes_comparison_loading)

R9  Latest and explicit calls leave the database byte/content digest, schema
    objects, PRAGMA user_version, and every table row/count unchanged.
    Synthetic secret/control values never appear in output or errors.
    → NEW-FIXTURE (contract_guard_is_read_only_and_secret_safe)

R10 S024–S028 suites stay green; schema stays v6; MCP descriptors and payloads
    stay byte-compatible and expose no new tool.
```

---

# 5. Design Notes

## 5.1 Frozen contract identity

```text
ComparisonContractVersions {
  comparison_contract_version: u32,
  graph_snapshot_version: u64,
  analysis_version: u32,
  finding_version: u32,
}

CURRENT_COMPARISON_CONTRACT = {
  comparison_contract_version: 1,
  graph_snapshot_version: GRAPH_SNAPSHOT_VERSION,
  analysis_version: ANALYSIS_VERSION,
  finding_version: FINDING_VERSION,
}
```

All components are positive integers. Persisted string fields are parsed as
canonical base-10 unsigned integers: digits only, no sign, whitespace,
leading zeroes, or alternate representation. Equality is structural equality
of the complete tuple; there is no ordering or compatibility inference.

The envelope version (`comparison_contract_version`) versions the tuple and
its validation semantics. A future build may introduce explicit migrations or
compatibility rules, but Sprint 029 supports only exact equality with the
current tuple.

`pico_version` is separate, bounded internal provenance. Accept the existing
package-version grammar only (1–64 printable ASCII characters from
`[0-9A-Za-z.+-]`, no whitespace/control bytes). Invalid persisted values fail
closed rather than being rendered. Validation errors identify the scan and
field but never echo the rejected raw value. All rendered values still pass
through `terminal_safe`.

## 5.2 Declaration, legacy derivation, and integrity (frozen)

New Scan metadata:

```json
{
  "comparison_contract_version": 1,
  "graph_snapshot_version": 1,
  "finding_version": 1
}
```

Do not place `analysis_version` in Scan metadata: `scan_analyses` is already
the authoritative per-scan summary, including for zero-path scans.

For each side, derive and validate in this order:

1. Validate the Scan `pico_version` grammar.
2. Load `scan_analyses`.
   - Missing row: legacy `ProvenanceUnavailable(analysis_version)`.
   - Present row: version must be canonical and status must be `COMPLETE`.
3. Read `comparison_contract_version`, `graph_snapshot_version`, and
   `finding_version` from Scan metadata.
   - `comparison_contract_version` present means all declared fields are
     required; missing/malformed is integrity failure.
   - Legacy metadata without `comparison_contract_version` may use its
     existing graph declaration and the derivation below. If every semantic
     component is derivable and consistent, the reader synthesizes envelope
     version 1; the envelope identifies these validation rules, not the old
     producer binary. If any component is missing, provenance is unavailable.
4. Validate every scan-scoped observation snapshot version against the graph
   declaration. Contradiction is an integrity failure.
5. Validate every AttackPath `analysis_version` against the summary.
   Contradiction is an integrity failure.
6. Validate the distinct Finding versions.
   - More than one, malformed, or disagreement with a declaration is an
     integrity failure.
   - A legacy scan with exactly one distinct version derives that version.
   - A legacy zero-Finding scan without a declaration is
     `ProvenanceUnavailable(finding_version)`; the current binary must not
     guess which historical Finding contract produced zero rows.
7. A legacy side without a derivable graph version is
   `ProvenanceUnavailable(graph_snapshot_version)`.

Absence is a supported historical state; contradiction is corruption. Missing
fields are reported by side and component in deterministic tuple-field order.

`ScanAnalysisRepo::upsert` remains usable while the parent Scan is RUNNING,
PARTIAL, or FAILED. It rejects replacement once the parent is COMPLETE. This
closes the existing mutable-summary hole without creating a new public API or
schema migration.

## 5.3 Frozen application DTOs

```text
DiffSide { From, To }

ComparisonContractField {
  ComparisonContractVersion,
  GraphSnapshotVersion,
  AnalysisVersion,
  FindingVersion,
}

ComparisonProvenanceGap {
  side: DiffSide,
  field: ComparisonContractField,
}

DiffSideProvenance {
  pico_version: String,
  contract: Option<ComparisonContractVersions>,
}

DiffProvenance {
  from: DiffSideProvenance,
  to: DiffSideProvenance,
}

DiffNotComparableReason {
  ProvenanceUnavailable,
  ContractChanged,
  ContractUnsupported,
}

DiffNotComparable {
  from: ScanBrief,
  to: ScanBrief,
  newest_attempt: Option<ScanBrief>,
  freshness: Freshness,
  freshness_warning: Option<String>,
  compared_via: ComparedVia,
  provenance: DiffProvenance,
  reason: DiffNotComparableReason,
  gaps: Vec<ComparisonProvenanceGap>,
}

FindingDiff {
  ...
  provenance: DiffProvenance,
}

FindingDiffResult {
  NoCompleteScan,
  NeedPrevious { ... },
  NotComparable(DiffNotComparable),
  Ready(FindingDiff),
}
```

`gaps` is non-empty only for `ProvenanceUnavailable`; it is empty for changed
or unsupported complete tuples. `Ready` guarantees both provenance contracts
are `Some`, equal, and equal to `CURRENT_COMPARISON_CONTRACT`.

`NotComparable` is a successful read result. The CLI exits successfully after
explaining why comparison was skipped. Integrity failures remain errors.

## 5.4 Pair-selection and guard ordering (frozen)

```text
select pair
→ require both Scan rows COMPLETE
→ validate from is at-or-before to in COMPLETE history
→ load/validate both contract provenances
→ unavailable: NotComparable(ProvenanceUnavailable)
→ tuples differ: NotComparable(ContractChanged)
→ equal but not current: NotComparable(ContractUnsupported)
→ current tuple: existing Findings + graph + Cause comparison
```

Today the temporal check is reached through `compare_graph`. Sprint 029 must
extract one shared chronology validator and call it before the guard, while
`compare_graph` retains or delegates to the same invariant. A reversed
cross-contract pair must not become a successful NotComparable result.

The guard runs before `findings_by_fingerprint`, graph-set projection, and
`attach_causes`. This is a structural no-fabrication guarantee, not renderer
suppression. Provenance validation may inspect version columns/metadata, but
must not materialize the actual diff inputs.

`NoCompleteScan` and `NeedPrevious` remain unchanged because no pair exists.
Missing IDs, same ID, temporal ordering, and COMPLETE-only validation preserve
their existing precedence and error behavior.

The application owns this logic through persistence repositories/private
queries; the CLI never queries SQLite.

## 5.5 CLI render contract (frozen)

For a comparable `Ready` result, add these lines after the existing
`Compared`/`Freshness` block and before `Findings`:

```text
Comparison contracts: c1-g1-a1-f1 → c1-g1-a1-f1 (SUPPORTED MATCH)
Pico versions: {from.pico_version} → {to.pico_version}
```

`c/g/a/f` mean comparison-envelope, graph, analysis, and Finding versions.
All existing Finding and graph sections then render unchanged.

For `NotComparable(ContractChanged)`:

```text
Comparison contracts: {from tuple} → {to tuple} (MISMATCH)
Pico versions: {from.pico_version} → {to.pico_version}

Security change comparison was skipped because the persisted comparison contracts differ.
No Finding, graph, lifecycle, or Cause claim was computed for this pair.
This is not an all-clear.
```

For `NotComparable(ContractUnsupported)`, use `(UNSUPPORTED)` and:

```text
Security change comparison was skipped because this Pico build does not support the persisted comparison contract.
```

For `NotComparable(ProvenanceUnavailable)`, use `(PROVENANCE UNAVAILABLE)`,
render deterministic gap lines such as `Missing: FROM finding_version`, then:

```text
Security change comparison was skipped because required historical provenance is unavailable.
```

All three non-comparable states include the same no-claim and not-all-clear
sentences. They do not render `Findings`, `Resources`, `Relationships`, their
counts, the S024 no-change sentence, or a `Cause:` line.

## 5.6 Test and evidence shape

- Primary integration file:
  `tests/integration/sprint029_cli_test.rs`, registered in
  `tests/integration.rs`.
- Unit coverage proves canonical parsing, tuple validation, gap ordering, and
  current-version construction.
- R1–R9 use persisted integration fixtures through `DiffService` and the real
  renderer. Existing manually seeded S028 COMPLETE-scan helpers must add valid
  comparison declarations/summaries; this is fixture maintenance, not a
  compatibility fallback in production code. Synthetic `finding_version =
  "v1"` rows are normalized to the production-canonical `"1"` in those
  fixtures.
- Contract-change fixtures create internally consistent sides: update the
  summary and every AttackPath together for analysis version; Scan declaration
  and every Finding together for Finding version; Scan declaration and every
  observation snapshot together for graph version.
- R5 includes a genuine schema upgrade path containing a pre-S008 COMPLETE
  scan, proving missing provenance is supported legacy state.
- R6 separately proves summary/path and declaration/row disagreements fail.
- R8 seeds malformed comparison data that would fail if loaded, proving the
  early guard structurally.
- R9 compares deterministic schema-and-table content digests, not row counts
  alone, before and after both latest and explicit service/render calls.

## 5.7 Review checkpoints (frozen)

1. Review after scan declaration/persistence validation: canonical parsing,
   legacy derivation, cross-row consistency, and COMPLETE-summary immutability
   are green before changing `DiffService`.
2. Review after application guard: R1–R8 green before changing the renderer.
3. Review after renderer/evidence: R1–R10 green, including exact copy and all
   S024–S028 regressions.
4. Confirm schema remains v6 and `src/mcp/tools.rs` plus MCP golden fixtures
   are byte-unchanged.
5. Confirm non-comparable branches occur before actual Finding/graph/Cause
   comparison loading.
6. Confirm docs say "comparison skipped," never "caused by Pico," "no
   changes," or "environment unchanged."

---

# 6. Task Breakdown

1. **Spec freeze** — approve this document, especially the composite tuple,
   legacy-unavailable behavior, current-only compatibility rule, conservative
   graph suppression, and exact CLI copy. No implementation before approval.
2. **Declarations and integrity** — add comparison/finding declarations to new
   Scan metadata; implement canonical parsing, legacy derivation, cross-row
   checks, and COMPLETE-summary immutability. No migration.
3. **Application guard** — add frozen DTOs, extract/share chronology
   validation, and use one guard path for latest/explicit comparison. Preserve
   S024–S028 behavior on the supported-match branch.
4. **CLI render** — render supported provenance and all three non-comparable
   states with exact fail-closed copy and terminal sanitization.
5. **Evidence** — add R1–R9 persisted fixtures, genuine legacy upgrade,
   early-return proof, content-digest read-only proof, and secret/control
   sweep; update older test fixtures to declare valid contracts.
6. **Documentation and gates** — update architecture only after behavior
   lands; fill §8 evidence; run fmt, clippy, all targets, and diff check.

---

# 7. Commit Policy

```text
docs(sprints): define Sprint 029 comparison contract guard
```

Implementation conventional. Do not amend. Do not claim v0.4 complete.

---

# 8. Completion Evidence (filled at execution)

```text
Date: 2026-09-04
Baseline: 5a1e9e4 (post-Sprint-028 implementation); spec: 8329ec8
Verified by: three staged review checkpoints (persistence → guard → render),
full cargo test --all-targets after each stage

fixtures (R1–R9) — tests/integration/sprint029_cli_test.rs
  R1  current_contract_pair_is_comparable
  R2  pico_version_change_alone_does_not_block
  R3  changed_contract_component_blocks_comparison
  R4  equal_unsupported_contract_is_not_comparable
  R5  legacy_missing_provenance_is_explicit
  R6  contradictory_provenance_fails_closed
  R7  latest_and_explicit_guard_decisions_agree
  R8  contract_guard_precedes_comparison_loading
  R9  contract_guard_is_read_only_and_secret_safe
  (plus in-module unit coverage: canonical parsing, pico_version grammar,
   tuple equality, gap ordering, current-version construction, guard
   decisions, chronology extraction; persistence-level COMPLETE-summary
   immutability in tests/persistence/sprint029_analysis_test.rs)

schema evidence:
  SUPPORTED_SCHEMA_VERSION = 6
  migration: none

MCP evidence:
  descriptors: list_findings, get_finding (unchanged)
  golden payloads: unchanged (git diff --stat -- src/mcp/ empty)

security/read-only evidence:
  schema-and-table content digest before/after: unchanged across latest()
  and compare() on Ready, ContractChanged, and ProvenanceUnavailable pairs
  (R9; sha256 over sqlite_master rows, user_version, and full table row
  content)
  secret/control sweep: SECRET_SENTINEL + "synthetic-token" + "ghp_" absent
  from all renders and error strings (R8/R9)

gates:
  cargo fmt --all -- --check            PASS
  cargo clippy --all-targets -- -D warnings PASS
  cargo test --all-targets              PASS (482: 202 lib, 30 domain,
                                        208 integration, 42 persistence)
  git diff --check                      PASS
```

---

# 9. Final Report Contract

When Sprint 029 is implemented, report:

- files changed and why;
- exact tuple, DTO/result, legacy, and CLI contracts delivered;
- R1–R10 results plus total test counts;
- schema and MCP non-change evidence;
- read-only, determinism, and secret-sweep evidence;
- remaining environment-versus-evidence attribution caveat;
- `Sprint 029: DONE` only if every checkpoint passes;
- `v0.4: not complete` and the remaining blockers.
