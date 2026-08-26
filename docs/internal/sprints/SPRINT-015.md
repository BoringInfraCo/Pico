# Pico — Sprint 015: Deterministic Finding Stability, Path Deduplication, and Remediation Cut Points

**Status:** READY

**Sprint:** 015
**Phase:** v0.2 — Evidence and Authority Depth
**Type:** Implementation
**Baseline:** `2d86447` (post-Sprint-014 main HEAD)
**Depends on:** Sprint 012 (live dogfood), Sprint 013 (authority tiers), Sprint 014 (provenance + freshness)

---

# 1. Purpose

Sprint 013 made authority-resolution tiers explicit and persisted. Sprint 014 made every security-critical edge carry provenance and a classified freshness that constrains confidence. The next v0.2 depth gap is **finding stability and grouping honesty**:

> Within Pico's supported OpenCode, GitHub MCP, Bash, and Cloudflare boundary, repeated scans of an unchanged environment must produce identical finding identities, and multiple paths that reach the same sink must be grouped without hiding materially different boundaries or bypasses.

This sprint closes two ROADMAP §6 v0.2 commitments Sprint 013/014 did not touch:

- "Validate path deduplication and finding stability."
- "Refine deterministic severity, confidence, and remediation cut points using dogfood evidence."

It does **not** add history/diff UX (v0.4), runtime observation (v0.5), new agents/providers (v0.3), production classification of `sink_impact` (still `UNKNOWN` by design, SPRINT-013 §8), or enforcement (v0.7).

---

# 2. Scope

- **Finding identity stability**: a finding's deterministic fingerprint must be a pure function of its security-significant content (source, edges, sink, severity basis, confidence basis, evidence refs) and the analysis version — not of scan id, timestamps, or insertion order. Repeated scans of an identical normalized graph with the same analysis version produce identical fingerprints. A security-significant change flips the fingerprint predictably.
- **Path deduplication**: when multiple candidate paths reach the same sink through the same critical edges, they are grouped into one finding; deduplication must NOT collapse paths that differ in a material boundary (hard deny vs none, sandbox vs none, approval vs none) or a distinct bypass. Materially distinct boundaries remain visible as distinct paths/findings.
- **Severity/confidence independence**: severity and confidence remain separate axes; both are deterministic and stable across unchanged scans. Refine the cut-point thresholds using the Sprint 012 dogfood evidence so they are explicit, documented, and tested.
- **Remediation cut points**: the existing remediation rule(s) (e.g., `ENFORCE_BASH_APPROVAL_OR_DENY`) must target the correct relationship deterministically and remain stable; the remediation explanation must name the precise cut point.
- **Explanation**: the explained finding must make deduplication and the chosen cut point understandable (which paths were grouped, why, and where to break it).
- **Fixtures** for: stable fingerprint across identical scans, predictable fingerprint change on security-significant change, same-sink deduplication without boundary hiding, severity/confidence separation + cut-point thresholds, remediation targets correct relationship.
- Inherits the Sprint 012 live evidence; **no new live dogfood required** (fixture/output-driven per SPRINT-013 §5 / SPRINT-014 §5).

---

# 3. Non-goals

- History/diff commands or a change-detection product (v0.4).
- Runtime/continuous observation (v0.5).
- A second agent or cloud provider (v0.3).
- Production classification of `sink_impact` / Worker authority — remains `UNKNOWN` by design.
- Enforcement, remediation execution, credential revocation (v0.7).
- LLM-decided edges, paths, severity, or confidence.
- A generic finding-deduplication query language.

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  Finding fingerprint stable across identical scans (same graph + analysis version)
    → NEW-FIXTURE (finding_fingerprint_stable_across_identical_scans)

R2  Fingerprint changes predictably on security-significant state change
    → NEW-FIXTURE (finding_fingerprint_flips_on_security_significant_change)
       extends the existing differing-id assertion with a precise expected flip

R3  Same-sink paths with identical critical edges are deduplicated into one finding
    → NEW-FIXTURE (same_sink_paths_with_identical_edges_deduplicate)

R4  Deduplication does NOT hide materially different boundaries/bypasses
    → NEW-FIXTURE (distinct_boundaries_remain_distinct_after_deduplication)

R5  Severity and confidence remain independent and stable across unchanged scans
    → NEW-FIXTURE (severity_confidence_independence_stable)

R6  Deterministic severity/confidence cut-point thresholds documented + tested
    → NEW-FIXTURE (cut_point_thresholds_are_deterministic) + DOC note

R7  Remediation rule targets the correct relationship (cut point) deterministically
    → NEW-FIXTURE (remediation_targets_correct_relationship)
       extends the existing ENFORCE_BASH_APPROVAL_OR_DENY integrity test

R8  CLI lists deduplicated findings without hiding distinct boundaries
    → FIXTURE-VERIFIED by sprint010_cli_test.rs (extends list/summary) + NEW assertion

R9  MCP list/get reflects deduplication + stable ids
    → FIXTURE-VERIFIED by sprint011_mcp_golden_test.rs (extends) + NEW assertion

R10 No secret leakage in fingerprints/remediation (no secret value embedded)
    → FIXTURE-VERIFIED by existing secret-sweep + NEW check on fingerprint content
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required by this sprint; the work is fixture- and output-driven and inherits the Sprint 012 live evidence (account `3e2742bacdabcada586f921ad89bac77`). If a live re-run is performed to confirm stability, it reuses the Sprint 012 contract verbatim.

---

# 6. Design Notes

## 6.1 Finding identity (R1–R2)
Locate the finding fingerprint/identity computation (candidate grouping key and persisted finding id). Ensure it is derived from security-significant content + `PICO_VERSION`/analysis version, NOT from `scan_id`, timestamps, or insertion order. If the current id is random/uuid-based, introduce a deterministic `fingerprint` field computed via a stable hash (e.g., SHA-256 over a canonical JSON of the security-significant fields) while keeping the random DB id only as an internal row key. Repeated identical scans => identical fingerprint; a security-significant change => different fingerprint.

## 6.2 Deduplication (R3–R4)
Deduplication is already performed by the engine's `grouping_key` (source/edges/sink/severity/confidence). Validate and harden it:
- R3: multiple candidate paths with the same critical-edge set + same sink group into one finding (already likely true; add an explicit fixture).
- R4: paths that differ in a material boundary (one has a HardDeny/MandatoryApproval/Sandbox interrupting, another does not) must NOT be collapsed. This likely means the boundary set is part of the grouping key; assert distinct boundaries => distinct grouping (distinct paths retained).

## 6.3 Severity/confidence cut points (R5–R6)
Document the severity/confidence thresholds (e.g., what makes a path CRITICAL, what confidence band applies) in a short support note. Add a fixture asserting the same inputs yield the same severity/confidence and that the thresholds are deterministic. Refine only if the Sprint 012 dogfood evidence showed a concrete instability; otherwise keep existing logic and lock it with a test.

## 6.4 Remediation cut point (R7)
The remediation rule `ENFORCE_BASH_APPROVAL_OR_DENY` (seen in integrity tests) must target the exact `target_relationship_ids` deterministically. Add a fixture asserting the rule's target relationship matches the Bash→credential (or intended) edge and is stable across identical scans.

## 6.5 Explanation (R8–R9)
Extend CLI summary/list and MCP `list_findings`/`get_finding` to surface: the finding fingerprint, the number of grouped paths (if >1), and the named remediation cut point. Add fixtures asserting these fields appear and that distinct boundaries are not silently merged in the listed output.

---

# 7. Fixtures (NEW-FIXTURE)

- `finding_fingerprint_stable_across_identical_scans` — two scans of identical graph; assert equal fingerprints.
- `finding_fingerprint_flips_on_security_significant_change` — change one security-significant edge (e.g., add a HardDeny boundary, or flip credential scope); assert fingerprint differs in the expected way.
- `same_sink_paths_with_identical_edges_deduplicate` — build N candidate paths to same sink with identical critical edges; assert one finding.
- `distinct_boundaries_remain_distinct_after_deduplication` — two paths to same sink, one with an interrupting boundary; assert both remain visible (distinct paths/findings).
- `severity_confidence_independence_stable` — identical inputs; assert severity and confidence are independent and stable.
- `cut_point_thresholds_are_deterministic` — assert severity/confidence thresholds produce identical results across runs.
- `remediation_targets_correct_relationship` — assert `ENFORCE_BASH_APPROVAL_OR_DENY` targets the intended relationship and is stable.

---

# 8. Architecture Pressure-Test

- Finding identity is a deterministic function over the existing analyzed domain (Boundary/AttackPath/Finding, ARCHITECTURE §7/§9); no new domain object required.
- Deduplication operates on the existing `grouping_key`; it only refuses to hide materially different boundaries.
- Severity/confidence remain separate axes (ARCHITECTURE §2.4); this sprint locks their cut points, it does not merge them.
- Secret-safety preserved: fingerprints hash security-significant *relationships/evidence refs*, never raw secret values (ARCHITECTURE §7.7, ROADMAP §13.2).

---

# 9. Risks and Mitigations

- **Risk:** introducing a deterministic fingerprint could change existing finding ids and break persisted references. *Mitigation:* keep the random DB row id for internal references; add `fingerprint` as a new deterministic field; existing id-based integrity tests remain valid. Migrations/version bumps handled by the existing schema-version gate.
- **Risk:** deduplication threshold too aggressive hides real variants. *Mitigation:* R4 fixture explicitly asserts materially distinct boundaries stay distinct; boundary set is part of the grouping key.
- **Risk:** "security-significant change" is underspecified. *Mitigation:* define it concretely as any change to source trust, critical-edge state, sink impact, or boundary set; the R2 fixture uses one such change.

---

# 10. Required Evidence Artifacts

- A1  Fingerprint stability fixture (R1).
- A2  Fingerprint-change fixture (R2).
- A3  Deduplication fixture (R3).
- A4  Distinct-boundary retention fixture (R4).
- A5  Severity/confidence stability + cut-point fixtures (R5–R6).
- A6  Remediation cut-point fixture (R7).
- A7  CLI/MCP deduplication + stable-id surfacing tests (R8–R9).
- A8  Secret-sweep extension for fingerprint content (R10).
- A9  Short support note: severity/confidence cut-point thresholds (§27, DOC-VERIFIED).
- A10 Completed validation matrix (§4 / §27).

Evidence artifacts quote at most credential FINGERPRINT and token id; never raw secret values.

---

# 11. Commit Policy

Authoring-only document commits as:

```text
docs(sprints): define Sprint 015 finding stability and deduplication
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
feat(findings): deterministic finding fingerprint over security-significant content
test(findings): finding fingerprint stable and flips on significant change
feat(findings): keep distinct boundaries distinct during deduplication
test(findings): remediation targets correct relationship deterministically
feat(cli): surface fingerprint, grouped-path count, and remediation cut point
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin Sprint 016.

---

# 12. Completion Evidence (filled at execution)

When validation concludes, set `Status: DONE` (or `BLOCKED`) and record:

```text
completion date and verified baseline
commits (authoring; any defect fixes; evidence record)
repository state
new fixtures (R1–R10) and their assertions
CLI/MCP deduplication + stable-id surfacing test additions
fingerprint/stability result
secret-sweep result
optional live re-run outcome (or GAP-RECORDED with reason)
comprehension result (PASS/FAIL/NOT RUN + confusion points)
usefulness judgments
defect list and dispositions (expected empty)
architecture pressure-test answers
advancement decision record
follow-ups (named, owned, unambiguous)
```

Do not claim v0.2 depth is "closed" merely because findings are stable. Claim exactly what the matrix shows: fingerprints are deterministic and stable, deduplication groups same-sink paths without hiding distinct boundaries, and remediation cut points are deterministic.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-015 — Deterministic Finding Stability, Path Deduplication, and Remediation Cut Points
Status: DONE | BLOCKED
Baseline: <verified SHA>

Stability:
  fingerprint identical-scan: PASS | FAIL
  fingerprint significant-change: PASS | FAIL

Deduplication:
  same-sink identical edges: PASS | FAIL
  distinct boundaries retained: PASS | FAIL

Cut points:
  severity/confidence independent + stable: PASS | FAIL
  remediation targets correct relationship: PASS | FAIL

Surfacing:
  CLI dedupe + stable id: PASS | FAIL
  MCP dedupe + stable id: PASS | FAIL

Validation matrix:
  R1-R10: <statuses>

Secret sweep: ZERO | INCIDENT
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17. Records whether v0.2 depth is advanced, extended, refined, or stopped, and why the next v0.2 sprint (016) is justified.
