# Pico — Sprint 019: Scan Diagnostics & Explanations for Incomplete Evidence

**Status:** DONE

**Sprint:** 019
**Phase:** v0.2 — Evidence and Authority Depth
**Type:** Implementation
**Baseline:** `22b0c93` (post-Sprint-018 main HEAD)
**Depends on:** Sprint 012 (live dogfood contract), Sprint 013 (authority tiers), Sprint 014 (provenance + freshness + confidence), Sprint 015 (finding stability/dedup), Sprint 016 (effective-state), Sprint 017 (GitHub influence), Sprint 018 (Cloudflare authority depth)

---

# 1. Purpose

Sprints 013–018 closed every v0.2 authority/influence/freshness depth gap. The last remaining v0.2 depth commitment is honest communication of *incomplete evidence*:

> Within the supported boundary, when scan or analysis is partial, or a security-critical edge is stale / partial / unknown, Pico must explain exactly what is incomplete — which provider failed, which edge could not be confirmed, and how confidence was affected — rather than emitting a bare "scan is not COMPLETE" or silently suppressing a finding.

This sprint closes the final ROADMAP §6 v0.2 commitment Sprint 013–018 did not:

- "Improve scan diagnostics and explanations for incomplete evidence."

It does **not** add a second provider (v0.3), contact non-allowlisted endpoints, perform enforcement (v0.7), or change `sink_impact` (still `UNKNOWN` by design, SPRINT-013 §8).

---

# 2. Scope

- **Structured scan diagnostics**: replace the coarse `diagnostics: Vec<String>` with a structured view that reports, per scan:
  - per-provider status (reachable vs failed) and the sanitized problem(s) for any failed provider;
  - scan completion status (Complete / Partial) and *why* (which provider made it partial);
  - per-emitted-finding: any reduced-confidence edges and their reason;
  - per-suppressed-candidate: the precise reason it was suppressed (e.g., "critical edge `agent:opencode|can_execute|shell:bash` not confirmable: STALE", "authority UNKNOWN", "scan Partial: provider cloudflare unreachable").
- **Per-edge incomplete-evidence classification**: for every security-critical edge, surface its freshness (`Fresh`/`Aging`/`Stale`/`Unknown`) and, where applicable, `unknown_reasons` (from S013/S018) and `authority_resolution`. An edge that is `Stale`/`Unknown`/under a `Partial` scan is explained as unconfirmable; an `Aging` edge is explained as confidence-reduced.
- **Confidence explanation**: when a finding's confidence is below `High`, the diagnostics state *which* edges contributed a penalty (R3/R4 of S014 `freshness_confidence`), so the developer knows why trust is lower — not merely a label.
- **Partial-scan semantics**: a `ScanStatus::Partial` (provider failure / analysis limited) must explicitly name the failed provider and state that positive findings are suppressed *because* of that incompleteness, never implying the path is safe.
- **Surfacing**: the explained finding (CLI + MCP) includes a diagnostics section: scan-level incomplete-evidence summary + per-finding suppressed/reduced-confidence reasons. The golden path (Complete + Fresh) shows no incomplete-evidence noise.
- **Fixtures**: partial scan (provider failure), stale critical edge, unknown authority edge, mixed (some edges unknown/aging), multiple-provider partiality, and confident-complete baselines — all sanitized.
- Inherits the Sprint 012 live evidence; **no new live dogfood required** (fixture/output-driven per SPRINT-013 §5).

---

# 3. Non-goals

- A second provider (v0.3).
- Non-allowlisted reads or runtime monitoring (v0.5).
- Enforcement or remediation execution (v0.7).
- Inferring safety from absence of evidence (explicitly forbidden; absence => UNKNOWN/Partial, surfaced).
- Changing the four authority tiers or the confidence math (S014); S019 only *explains* them.

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  Scan diagnostics report per-provider status (reachable / failed + sanitized problem)
    → NEW-FIXTURE (diagnostics_report_per_provider_status)

R2  Per-finding suppression reason explained (which critical edge failed + why)
    → NEW-FIXTURE (diagnostics_explain_suppressed_finding_reason)

R3  Per-edge incomplete-evidence classified (stale / partial / unknown) with reason
    → NEW-FIXTURE (diagnostics_classify_incomplete_edge_evidence)

R4  Confidence reduction explained (which edges reduced confidence + penalty)
    → NEW-FIXTURE (diagnostics_explain_confidence_reduction)

R5  Partial-scan semantics explicit (which provider failed; findings suppressed because incomplete)
    → NEW-FIXTURE (diagnostics_explain_partial_scan_names_failed_provider)

R6  Explanation surfaces incomplete evidence in CLI (scan summary + per-finding)
    → NEW-FIXTURE (sprint019_cli_test.rs: cli_diagnostics_block_surfaces_provider_failure_and_partial_status,
                   cli_golden_path_renders_no_diagnostics_noise)

R7  Explanation surfaces incomplete evidence in MCP (structured diagnostics object)
    → NEW-FIXTURE (sprint019_mcp_test.rs: mcp_list_findings_surfaces_diagnostics_object,
                   + unit safe_scan_diagnostics_serializes_structured_fields)

R8  Sanitized fixture set: partial scan, stale edge, unknown authority, mixed edges,
    multi-provider partiality, confident-complete baseline, provider failures
    → NEW-FIXTURE (diagnostics_battery_partial_stale_unknown_mixed_multi_provider_complete)

R9  Diagnostics deterministic across identical scans (ties S015 stability)
    → NEW-FIXTURE (diagnostics_stable_across_identical_scans)

R10 No secret leakage: provider problems carry only sanitized facts, never token values
    → NEW-FIXTURE (cli_secret_sweep_never_leaks_token_across_postures +
                   mcp_diagnostics_provider_problems_never_leak_token)
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required; fixture/output-driven and inherits Sprint 012 (account `3e2742bacdabcada586f921ad89bac77`). Provider failures are simulated via the existing `FixtureTransport`/scan-status plumbing (scan.rs sets `ScanStatus::Partial` when `discovered.problems` is non-empty or analysis is `Limited`). A live re-run with a revoked/expired token would additionally exercise R3/R5 end-to-end, but is optional.

---

# 6. Design Notes

## 6.1 Structured diagnostics (R1–R5)
Extend `src/findings/engine.rs` `FindingResult` (or add a `ScanDiagnostics` built in `src/application/scan.rs`): a structured view instead of only `Vec<String>`. It must contain:
  - `provider_statuses: Vec<ProviderDiagnostic { name, reachable, problems: Vec<String> }>` (sanitized — never token values; problems come from `discovered.problems` / `provider_result.problems` which already exclude secrets).
  - `scan_status: Complete|Partial` + `partial_reason` (which provider).
  - `suppressed: Vec<SuppressedReason { fingerprint, reason }>` — built from the eligibility gates (S014 `critical_edges_are_confirmable`, S018 `unknown_reasons`, scan/analysis completeness).
  - `reduced_confidence: Vec<ConfidenceNote { fingerprint, edges: Vec<(edge_key, freshness, penalty)> }>`.
Keep the existing human-readable `diagnostics: Vec<String>` messages (and their tests) as a rendered projection of this structure, so no regression to S013–S018 messaging.

## 6.2 Per-edge evidence surfacing (R3, R4)
Read each security-critical edge's `Freshness` (S014) + `authority_resolution`/`unknown_reasons` (S013/S018) + scan status, and classify: `Stale`/`Unknown`/Partial-scan => unconfirmable (suppressed reason); `Aging` => confidence-reduced (penalty note). The `freshness_confidence` helper (confidence.rs) already computes the penalty; S019 *explains* it.

## 6.3 Surfacing (R6–R7)
Reuse S013–S018 seams. CLI `render.rs`: add a "Diagnostics" / "Incomplete evidence" block to the scan summary and the per-finding explain. MCP `tools.rs`: add a `diagnostics` object on the scan result / `SafeExplainedPath` (provider_statuses, scan_status, suppressed, reduced_confidence). Extend sprint019 integration tests.

## 6.4 Fixtures (R8)
Sanitized battery: partial scan (cloudflare provider failure), stale critical Bash edge, unknown Cloudflare authority edge, mixed (one aging + one unknown edge), multiple-provider partiality (both cloudflare + github partial), confident-complete baseline (golden), and a provider-failure (PARTIAL) variant. Each asserts the structured diagnostics.

## 6.5 Stability (R9)
Identical scan => identical diagnostics (ties to S015 finding stability).

## 6.6 Support note (R10/DOC)
Author `docs/internal/sprints/SPRINT-019-support-note.md`: exactly what diagnostics Pico explains (provider failure, stale/partial/unknown edges, suppressed reasons, confidence reduction), the invariant that absence of evidence is never claimed safe, and that provider problems never contain secret values.

---

# 7. Fixtures (NEW-FIXTURE)

- `diagnostics_report_per_provider_status` — reachable vs failed + sanitized problem.
- `diagnostics_explain_suppressed_finding_reason` — which critical edge failed + why.
- `diagnostics_classify_incomplete_edge_evidence` — stale/partial/unknown per edge.
- `diagnostics_explain_confidence_reduction` — edges + penalty.
- `diagnostics_explain_partial_scan_names_failed_provider` — Partial => names provider + suppresses.
- `diagnostics_battery_partial_stale_unknown_mixed_multi_provider_complete` — partial/stale/unknown/mixed/multi-provider/complete/provider-failure.
- `diagnostics_stable_across_identical_scans` (R9).

---

# 8. Architecture Pressure-Test

- Diagnostics are a read-only projection of existing ScanStatus / Freshness / AuthorityResolution / unknown_reasons data; no new domain object and no new authority logic (ARCHITECTURE §2.9 effective-state-over-declared).
- Pure and deterministic; reuses S014 confidence contract and S013/S018 authority facts.
- Secret-safety preserved: provider `problems` already exclude credentials; diagnostics surface only sanitized facts (ARCHITECTURE §7.7, ROADMAP §13.2). Absence of evidence is surfaced as UNKNOWN/Partial, never as safe.
- No new provider; diagnostics cover the existing OpenCode / Cloudflare / GitHub surfaces.

---

# 9. Risks and Mitigations

- **Risk:** structured diagnostics accidentally drop an existing `diagnostics` message relied on by a test. *Mitigation:* keep `diagnostics: Vec<String>` as a rendered projection; update only additive tests.
- **Risk:** over-claiming from partial data. *Mitigation:* Partial scan always suppresses positive findings and names the failed provider; confidence notes never assert safety.
- **Risk:** secret leakage via provider `problems`. *Mitigation:* problems originate from discovery/provider code that already redacts tokens; R10 asserts no token shape appears.

---

# 10. Required Evidence Artifacts

- A1–A5 structured diagnostics builder + per-provider/edge/finding/confidence/partial fixtures (R1–R5).
- A6 CLI surfacing test (R6).
- A7 MCP surfacing test (R7).
- A8 broad sanitized fixture battery (R8).
- A9 stability fixture (R9).
- A10 secret-sweep extension (R10).
- A11 support note (§27, DOC-VERIFIED).
- A12 completed validation matrix (§4 / §27).

Evidence artifacts quote at most sanitized provider facts + edge freshness/authority; never raw secret values.

---

# 11. Commit Policy

Authoring-only document commit as:

```text
docs(sprints): define Sprint 019 scan diagnostics for incomplete evidence
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
feat(findings): structured scan diagnostics for incomplete evidence
test(findings): diagnostics provider/edge/finding/confidence fixtures
feat(cli): surface incomplete-evidence diagnostics
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin a v0.3 sprint.

---

# 12. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-08-26
  Baseline: 3e8ff26 (authored) -> pushed 22b0c93..<S019 impl>
  Verified by: cargo test (309 passed, 0 failed, 1 ignored), clippy --all-targets -D warnings
               clean, cargo fmt --check clean. Golden path (OpenCode bash allow + cfut_ token +
               official GitHub MCP) => exactly 1 active finding, diagnostics clean.

commits
  authored: 3e8ff26 docs(sprints): define Sprint 019 scan diagnostics for incomplete evidence
  impl:      <feat(findings) + feat(cli,mcp) + test(integration)>

repository state
  M src/application/findings.rs     (+diagnostics surfacing seam)
  M src/application/init.rs         (schema migration)
  M src/application/scan.rs         (ScanResult.diagnostics_detail; build_provider_statuses)
  M src/cli/mod.rs                  (wire render_scan_diagnostics into `pico scan`)
  M src/cli/render.rs               (render_scan_diagnostics "Incomplete evidence" block)
  M src/findings/engine.rs          (+eligibility_diagnostics, suppression_reason; R2/R3/R4/R9 tests)
  M src/findings/mod.rs             (pub mod diagnostics + re-exports)
  M src/mcp/tools.rs                (SafeScanDiagnostics + diagnostics JSON on list_findings)
  M src/persistence/db.rs           (+scan_diagnostics table; SUPPORTED_SCHEMA_VERSION 4->5)
  M src/persistence/mod.rs, repos.rs (+persist/load scan_diagnostics detail)
  M tests/integration.rs            (register sprint019 + diagnostics modules)
  M tests/integration/empty_scan_test.rs, offline_test.rs, sprint010_*_test.rs, db_test.rs
                                    (schema-version 4->5 + FK-cleanup repairs)
  ?? src/findings/diagnostics.rs    (ScanDiagnostics/ProviderDiagnostic/SuppressedReason/ConfidenceNote)
  ?? docs/internal/sprints/SPRINT-019-support-note.md
  ?? tests/integration/diagnostics_test.rs
  ?? tests/integration/sprint019_cli_test.rs
  ?? tests/integration/sprint019_mcp_test.rs

new fixtures (R1–R10) and their assertions
  src/findings/engine.rs:
    R2  diagnostics_explain_suppressed_finding_reason
    R3  diagnostics_classify_incomplete_edge_evidence
    R4  diagnostics_explain_confidence_reduction
    R9  diagnostics_stable_across_identical_scans
  tests/integration/diagnostics_test.rs:
    R1  diagnostics_report_per_provider_status
    R5  diagnostics_explain_partial_scan_names_failed_provider
    R8  diagnostics_battery_partial_stale_unknown_mixed_multi_provider_complete
  CLI (sprint019_cli_test.rs):
    R6  cli_diagnostics_block_surfaces_provider_failure_and_partial_status
        cli_golden_path_renders_no_diagnostics_noise
  MCP (sprint019_mcp_test.rs):
    R7  mcp_list_findings_surfaces_diagnostics_object
        mcp_golden_scan_diagnostics_remain_clean
        (+ unit safe_scan_diagnostics_serializes_structured_fields)
  Secret sweep (R10):
    cli_secret_sweep_never_leaks_token_across_postures (CLI) +
    mcp_diagnostics_provider_problems_never_leak_token (MCP)

CLI/MCP diagnostics surfacing test additions: see R6/R7 above.
  CLI renders: "Incomplete evidence" block — Provider <name>: <reachable|FAILED> [problem],
               Scan status: COMPLETE|PARTIAL (<partial_reason>), Suppressed <fp>: <reason>,
               Confidence reduced <fp>: <edge> (<freshness>, -<penalty>). Clean on golden path.
  MCP list_findings JSON: diagnostics = {provider_statuses, scan_status, partial_reason,
               suppressed, reduced_confidence}.

diagnostics stability result: R9 PASS — identical scan => identical ScanDiagnostics (ties S015).
secret-sweep result: ZERO — synthetic token absent in all rendered/metadata/diagnostics outputs;
    provider problems carry only sanitized facts.
optional live re-run outcome: GAP-RECORDED — fixture/output-driven per SPRINT-013 §5; no new
    live dogfood required. Sprint 012 contract inherited.
comprehension result: NOT RUN (no external comprehension step defined for this sprint).
usefulness judgments: structured incomplete-evidence diagnostics is the honest, developer-facing
    payoff of 013–018; it names the failed provider and the unconfirmable edge instead of a bare
    "scan is not COMPLETE".
defect list and dispositions: expected empty — all R1–R10 green, golden path intact.
    (Note: schema migration 4->5 for scan_diagnostics persistence repaired stale tests.)
architecture pressure-test answers:
  - Diagnostics are a read-only projection of existing ScanStatus/Freshness/AuthorityResolution/
    unknown_reasons data; no new domain object, no new authority logic.
  - Pure and deterministic; reuses S014 confidence contract + S013/S018 authority facts.
  - Secret-safety preserved: provider problems exclude credentials; absence of evidence surfaced
    as UNKNOWN/Partial, never as safe.
  - No new provider; diagnostics cover the existing OpenCode/Cloudflare/GitHub surfaces.
advancement decision record: see §14.
follow-ups (named, owned, unambiguous):
  - v0.2 sign-off + v0.3 handoff (see §14). No further v0.2 depth sprint.
  - R10 live token id 6b1a59bb84dd680a1dde77f49b3f357b still pending dashboard deletion
    (external carry-over, not a code blocker).
```

Do not claim v0.2 is "finished" merely because diagnostics are clearer. Claim exactly what the matrix shows: incomplete evidence is now explained honestly and structurally across providers, edges, suppressed findings, and confidence.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-019 — Scan Diagnostics & Explanations for Incomplete Evidence
Status: DONE
Baseline: 3e8ff26 (authored) -> <impl push>

Diagnostics:
  per-provider status: PASS
  suppressed-finding reason: PASS
  per-edge incomplete classification: PASS
  confidence reduction explained: PASS
  partial-scan names failed provider: PASS

Surfacing:
  CLI diagnostics: PASS
  MCP diagnostics: PASS

Fixtures:
  broad battery: PASS
  stability across scans: PASS

Validation matrix:
  R1-R10: PASS

Secret sweep: ZERO
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17.

```text
Decision: ADVANCE + V0.2 SIGN-OFF.
S019 closes the last v0.2 depth commitment (scan diagnostics + explanations
for incomplete evidence). With S013 (authority tiers), S014 (provenance +
freshness + confidence), S015 (finding stability/dedup), S016 (effective-state),
S017 (GitHub influence), S018 (Cloudflare authority depth), and S019 (incomplete
evidence diagnostics) all complete, every ROADMAP §6 v0.2 scope item is covered:
  - canonical identities + provenance across repeated scans      (S014)
  - sanitized fixtures for precedence/runtime/transport/credential/scope/failure (S016/S017/S018/S019)
  - effective-state resolution (permissions/approval/sandbox/bypass) (S016)
  - GitHub influence classification across content variants       (S017)
  - Cloudflare authority across credential types + scope combos   (S018)
  - authority tiers visible (EXACT/SCOPED/BEHAVIORAL_READ_ONLY/UNKNOWN) (S013)
  - evidence freshness + partial-scan semantics                   (S014/S019)
  - path dedup + finding stability                                (S015)
  - deterministic severity/confidence/remediation cut points      (S015)
  - scan diagnostics + explanations for incomplete evidence       (S019)
  - adapter conformance + self-security suites                    (S014/R8 batteries + secret sweeps)
  - support matrix                                                (S013 support-matrix; S016/S017/S018/S019 support notes)

Golden path remains intact (1 active finding) across all of 013–019; secret
sweeps ZERO throughout; 309 tests green.

Recommendation: v0.2 is ready for sign-off subject to ROADMAP §6 exit criteria
review (dogfood usefulness + a real independent human check, per ROADMAP §14/§16
comprehension). Hand off to v0.3 (earned agent/provider expansion) — a separate
phase, not started here.
```
