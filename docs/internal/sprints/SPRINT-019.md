# Pico — Sprint 019: Scan Diagnostics & Explanations for Incomplete Evidence

**Status:** READY

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
    → NEW-FIXTURE (diagnostics_partial_scan_names_failed_provider)

R6  Explanation surfaces incomplete evidence in CLI (scan summary + per-finding)
    → NEW-FIXTURE (sprint019_cli_test.rs)

R7  Explanation surfaces incomplete evidence in MCP (structured diagnostics object)
    → NEW-FIXTURE (sprint019_mcp_test.rs)

R8  Sanitized fixture set: partial scan, stale edge, unknown authority, mixed edges,
    multi-provider partiality, confident-complete baseline, provider failures
    → NEW-FIXTURE (broad fixture battery; see §7)

R9  Diagnostics deterministic across identical scans (ties S015 stability)
    → NEW-FIXTURE (diagnostics_stable_across_identical_scans)

R10 No secret leakage: provider problems carry only sanitized facts, never token values
    → NEW-FIXTURE (secret_sweep_never_leaks_in_diagnostics)
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
- `diagnostics_partial_scan_names_failed_provider` — Partial => names provider + suppresses.
- broad battery (R8): partial/stale/unknown/mixed/multi-provider/complete/provider-failure.
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

When validation concludes, set `Status: DONE` (or `BLOCKED`) and record:

```text
completion date and verified baseline
commits (authoring; any defect fixes; evidence record)
repository state
new fixtures (R1–R10) and their assertions
CLI/MCP diagnostics surfacing test additions
diagnostics stability result
secret-sweep result
optional live re-run outcome (or GAP-RECORDED with reason)
comprehension result (PASS/FAIL/NOT RUN + confusion points)
usefulness judgments
defect list and dispositions (expected empty)
architecture pressure-test answers
advancement decision record
follow-ups (named, owned, unambiguous)
```

Do not claim v0.2 is "finished" merely because diagnostics are clearer. Claim exactly what the matrix shows: incomplete evidence is now explained honestly and structurally across providers, edges, suppressed findings, and confidence.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-019 — Scan Diagnostics & Explanations for Incomplete Evidence
Status: DONE | BLOCKED
Baseline: <verified SHA>

Diagnostics:
  per-provider status: PASS | FAIL
  suppressed-finding reason: PASS | FAIL
  per-edge incomplete classification: PASS | FAIL
  confidence reduction explained: PASS | FAIL
  partial-scan names failed provider: PASS | FAIL

Surfacing:
  CLI diagnostics: PASS | FAIL
  MCP diagnostics: PASS | FAIL

Fixtures:
  broad battery: PASS | FAIL
  stability across scans: PASS | FAIL

Validation matrix:
  R1-R10: <statuses>

Secret sweep: ZERO | INCIDENT
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17. Records whether v0.2 depth is advanced, extended, refined, or stopped, and why v0.2 may be signed off (or what remains). With S019 done, all v0.2 ROADMAP §6 scope items are covered; this record should state the v0.2 sign-off decision and hand off to v0.3.
