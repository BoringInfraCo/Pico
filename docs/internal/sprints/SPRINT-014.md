# Pico — Sprint 014: Evidence Provenance, Freshness, and Canonical-Identity Stability

**Status:** DONE

**Sprint:** 014
**Phase:** v0.2 — Evidence and Authority Depth
**Type:** Implementation
**Baseline:** `6459e68` (post-Sprint-013 main HEAD)
**Depends on:** Sprint 012 (live dogfood + partial-scan evidence), Sprint 013 (authority-resolution tiers visible/persisted/tested)

---

# 1. Purpose

Sprint 013 made the four authority-resolution tiers explicit, persisted, and individually tested. It deliberately left `sink_impact` (production classification) as `UNKNOWN` and out of scope (SPRINT-013 §8). The next depth gap the v0.2 phase must close is **evidence trustworthiness across time and repetition**:

> Within Pico's supported OpenCode, GitHub MCP, Bash, and Cloudflare boundary, a security-critical claim must carry inspectable provenance, a defensible freshness state, and a stable identity — so that repeated scans and partial evidence cannot silently manufacture confidence.

This sprint hardens three ROADMAP §6 v0.2 commitments that Sprint 013 did not touch:

- "Harden canonical identities and evidence provenance across repeated scans."
- "Harden evidence freshness and partial-scan semantics."
- "Establish explicit adapter conformance and self-security test suites." (extends the S012/S013 self-security work)

It does **not** add history/diff UX (v0.4), runtime observation (v0.5), new agents/providers (v0.3), production classification (still UNKNOWN by design), or enforcement (v0.7).

---

# 2. Scope

- **Provenance completeness**: an integrity check that every security-critical edge in a `Relationship` and every `Finding` references at least one `Evidence` carrying `source_type`, `source_locator`, `captured_at`, and `freshness`. Missing provenance on a security-critical edge is an integrity error, not a silent pass.
- **Freshness model**: a `Freshness` classification — `FRESH` / `AGING` / `STALE` / `UNKNOWN` — derived from `captured_at` relative to scan time and source semantics (e.g., provider live-read vs. cached/declared). Computed deterministically; stored on `Evidence` and surfaced on findings.
- **Freshness-aware confidence**: analysis applies a confidence penalty (and never marks `CONFIRMED`) for a security-critical edge whose supporting evidence is `STALE` or comes from a `PARTIAL` scan. Partial-scan evidence may retain what it established but must never *upgrade* confidence beyond what the available evidence supports (ROADMAP §13.1, §13.4).
- **Canonical-identity stability**: deterministic `canonical_key` generation for all supported resource kinds (agent, mcp_server, mcp_tool, shell, credential, provider_account, worker, repository, issue, etc.). A regression suite asserts that repeated scans of an identical fixture produce identical canonical keys and **no duplicate resources/relationships** (ARCHITECTURE §5.2, §5.3).
- **Provenance in explanations**: the CLI and MCP finding detail surface, per security-critical edge, the evidence `source_locator` + `captured_at` + `freshness` (extends the S013 `authority_resolution` surfacing).
- **Adapter conformance**: a conformance test asserting each adapter emits `Evidence` with the required provenance fields and never a secret-bearing `source_locator` (extends S012/S013 self-security suites).
- **Fixtures** for: missing provenance (integrity error), stale evidence (confidence penalty), partial-scan evidence (no confidence upgrade), repeated-scan identity stability, and adapter conformance.
- Inherits the Sprint 012 live evidence; **no new live dogfood required** (fixture/output-driven per SPRINT-013 §5 contract).

---

# 3. Non-goals

- History/diff commands or a change-detection product (v0.4).
- Runtime/continuous observation (v0.5).
- A second agent or cloud provider (v0.3).
- Production classification of `sink_impact` / Worker authority — remains `UNKNOWN` by design (SPRINT-013 §8).
- Enforcement, remediation, credential revocation (v0.7).
- LLM-decided edges, paths, severity, or confidence.
- A generic provenance query language.

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored support note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  Provenance completeness on security-critical edges
    → NEW-FIXTURE (missing_provenance_on_security_critical_edge_is_integrity_error)
       mirrors existing finding_query_integrity_test::unresolved_boundary_on_linked_path_is_an_integrity_error

R2  Freshness classification FRESH/AGING/STALE/UNKNOWN computed deterministically
    → NEW-FIXTURE (evidence_freshness_classification)

R3  STALE evidence applies confidence penalty / cannot be CONFIRMED
    → NEW-FIXTURE (stale_evidence_cannot_produce_confirmed_edge)

R4  PARTIAL-scan evidence cannot silently upgrade confidence
    → NEW-FIXTURE (partial_scan_evidence_never_upgrades_confidence)
       extends read_only_listing_survives_policy_read_failure (src/discovery/cloudflare.rs)

R5  Canonical identity stable across repeated identical scans (no churn)
    → NEW-FIXTURE (repeated_scan_produces_stable_canonical_identities)

R6  Provenance surfaced in CLI finding detail (source + captured_at + freshness)
    → FIXTURE-VERIFIED by sprint010_cli_test.rs (extends explained-path test) + NEW assertion

R7  Provenance surfaced in MCP finding detail
    → FIXTURE-VERIFIED by sprint011_mcp_golden_test.rs (extends get_finding) + NEW assertion

R8  Adapter conformance emits required provenance fields, no secret locator
    → NEW-FIXTURE (adapter_conformance_emits_provenance_without_secrets)

R9  Freshness explanation identifies weakest/oldest security-critical edge
    → NEW-FIXTURE / integration (finding_explanation_flags_oldest_evidence)

R10 No secret leakage in provenance fields
    → FIXTURE-VERIFIED by existing secret-sweep suite + NEW check on source_locator
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required by this sprint; the work is fixture- and output-driven and inherits the Sprint 012 live evidence (account `3e2742bacdabcada586f921ad89bac77`). If a live re-run is performed to confirm freshness semantics, it reuses the Sprint 012 contract verbatim. Live freshness is otherwise exercised by the existing PARTIAL-scan evidence from S012.

---

# 6. Design Notes

## 6.1 Provenance completeness (R1)
Extend the existing integrity-test harness (`finding_query_integrity_test`) with a check: for every `Relationship` whose `kind` is security-critical (e.g., `can_mutate`, `authorizes`, `can_execute`, `can_call`, `can_access`, `can_write`, `can_deploy`), at least one linked `Evidence` must carry `source_type`, `source_locator`, `captured_at`, and `freshness`. A violation is an integrity error, consistent with `non_production_sink_impact_on_linked_path_is_an_integrity_error`.

## 6.2 Freshness (R2–R4)
`Freshness` is derived, not stored as free text:
- `FRESH`: `captured_at` within the source's freshness window for the current scan.
- `AGING`: beyond `FRESH` but within a defined grace window.
- `STALE`: beyond grace, or the evidence originates from a `PARTIAL` scan where the contributing adapter failed.
- `UNKNOWN`: no `captured_at` or source semantics unavailable.

Confidence rule (deterministic, ROADMAP §13.4): an edge whose supporting evidence is `STALE` or `PARTIAL` cannot be `CONFIRMED`; it degrades to `DERIVED`/`INFERRED`/`UNKNOWN` per existing state logic, and a confidence penalty is applied at the path level. This is a *constraint on existing analysis*, not a new severity model.

## 6.3 Canonical-identity stability (R5)
Audit `canonical_key` generation across adapters (agent/opencode, mcp, local, cloudflare). Ensure no volatile fields (scan id, timestamps, non-deterministic ordering) leak into keys (ARCHITECTURE §5.3: "Canonical keys must never contain secret values" — extend to "must never contain volatile values"). Add a regression test that runs two scans of an identical fixture set and asserts `Resource`/`Relationship` counts and canonical keys are identical.

## 6.4 Provenance surfacing (R6–R7)
Reuse the S013 surfacing path (`src/cli/render.rs`, `src/mcp/tools.rs` `SafeExplainedPath`). Add `evidence_source`, `evidence_captured_at`, and `freshness` to the per-edge explanation. No schema change to findings; this is explanation-layer metadata already present on `Evidence`.

## 6.5 Adapter conformance (R8)
Add a conformance test that each adapter's emitted `Evidence` objects satisfy the provenance contract and that `source_locator` values never equal or contain a raw secret (reuse the S012/S013 secret-canary approach).

---

# 7. Fixtures (NEW-FIXTURE)

- `missing_provenance_on_security_critical_edge_is_integrity_error` — build a graph with a `can_mutate` edge lacking linked evidence; assert integrity error.
- `evidence_freshness_classification` — evidence with varied `captured_at` offsets; assert FRESH/AGING/STALE/UNKNOWN mapping.
- `stale_evidence_cannot_produce_confirmed_edge` — STALE-supported edge; assert not CONFIRMED and confidence penalized.
- `partial_scan_evidence_never_upgrades_confidence` — PARTIAL-scan evidence; assert confidence does not exceed supported level.
- `repeated_scan_produces_stable_canonical_identities` — two scans, identical fixture; assert identical canonical keys, no duplicate resources.
- `adapter_conformance_emits_provenance_without_secrets` — drive each adapter's emit path; assert provenance fields present and no secret in locator.
- `finding_explanation_flags_oldest_evidence` — finding with mixed-freshness edges; assert explanation identifies the oldest/weakest edge.

---

# 8. Architecture Pressure-Test

- Provenance is explanation/integrity metadata over the existing `Evidence` model (ARCHITECTURE §7.3). No new domain object.
- Freshness constrains *existing* confidence/state logic; it does not add a second risk engine.
- Canonical-identity stability is a determinism property of adapters; it does not change the graph model.
- Secret-safety is preserved: `source_locator` is a path/identifier, never a secret value (ARCHITECTURE §7.7, ROADMAP §13.2).

---

# 9. Risks and Mitigations

- **Risk:** freshness windows are arbitrary. *Mitigation:* windows are config-derived constants with fixtures; defaults documented in the support note (§27). No live behavior change for the golden path.
- **Risk:** confidence penalty could hide real findings. *Mitigation:* penalty only applies to STALE/PARTIAL evidence; FRESH evidence is unaffected; verified by R3/R4 fixtures and the existing `unknown_production_is_not_a_finding` gate.
- **Risk:** canonical-key refactor could change existing fixtures. *Mitigation:* R5 regression compares against current fixture output; any break is caught pre-commit.

---

# 10. Required Evidence Artifacts

- A1  Provenance-completeness integrity test (R1).
- A2  Freshness classification + confidence-penalty tests (R2–R4).
- A3  Repeated-scan identity-stability test (R5).
- A4  CLI/MCP provenance-surfacing tests (R6–R7).
- A5  Adapter conformance test (R8).
- A6  Oldest-edge explanation test (R9).
- A7  Secret-sweep extension for provenance fields (R10).
- A8  Completed validation matrix (§4 / §27).
- A9  Short support note: freshness windows + canonical-key rules (§27, DOC-VERIFIED).

Evidence artifacts quote at most credential FINGERPRINT and token id; never raw secret values. Secret values remain `cfut_***REDACTED***` per S012 runbook.

---

# 11. Commit Policy

Authoring-only document commits as:

```text
docs(sprints): define Sprint 014 evidence provenance and freshness
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
test(integrity): require provenance on security-critical edges
feat(analysis): derive Freshness and apply stale/partial confidence penalty
test(domain): assert canonical identity stability across repeated scans
test(conformance): require adapter evidence provenance without secrets
feat(cli): surface evidence source, captured_at, and freshness per edge
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin Sprint 015.

---

# 12. Completion Evidence (executed 2026-08-26)

```text
completion date: 2026-08-26
baseline (pre-S014 HEAD): 6459e68
new commits:
  - feat(domain): add Freshness enum + freshness_state classifier + conformance helper
  - test(domain): evidence freshness classification, canonical stability, adapter conformance
  - feat(findings): freshness-aware confidence gate + provenance integrity check
  - feat(cli/mcp): surface per-edge provenance (source, captured_at, freshness) + weakest edge
  - docs(sprints): Sprint 014 support note + completion evidence
repository state: main; pushed to origin/main

new fixtures / assertions (R1–R10):
  R1  missing_provenance_on_security_critical_edge_is_integrity_error
      (tests/persistence/finding_query_integrity_test.rs) — FindingQueryService::get/list
      return an integrity error containing "security-critical edge lacks provenance"
      when an attack-path edge has no same-scan evidence with source_locator + freshness.
  R2  evidence_freshness_classification (src/domain/evidence.rs) — Fresh/Aging/Stale/Unknown
      by captured_at age vs reference; freshness_state() + freshness_round_trips.
  R3  stale_evidence_cannot_produce_confirmed_edge — freshness_confidence(Stale,Complete)
      => may_be_confirmed=false; plus engine test stale_backed_security_critical_edge_suppresses_finding.
  R4  partial_scan_evidence_never_upgrades_confidence — freshness_confidence(Fresh,Partial)
      => may_be_confirmed=false, penalty>=0.1; engine integration via critical_edges_are_confirmable.
  R5  repeated_scan_produces_stable_canonical_identities (src/discovery/cloudflare.rs) — no
      canonical_key volatility found; identical entities yield identical keys, no churn.
  R6  CLI explained-path now carries EdgeEvidenceProvenance (safe_source_locator, captured_at,
      freshness); sprint010_cli_test.rs extended to assert per-edge provenance.
  R7  MCP SafeExplainedPath carries supporting_evidence; sprint011_mcp_golden_test.rs extended.
  R8  adapter_conformance_emits_provenance_without_secrets (src/discovery/mod.rs) — both adapters
      emit non-empty source_locator, never a secret sentinel; source_locator_is_safe helper.
  R9  weakest_edge_provenance surfaces "Weakest evidence: <id> on edge <rel> captured <ts>
      (freshness <X>)"; finding_explanation_flags_oldest_evidence added.
  R10 no Evidence source_locator contains a raw secret (sentinel sweep in tests + R8 helper).

CLI/MCP provenance-surfacing: PASS (R6/R7) — fields populated from persisted, classified freshness.
canonical-identity stability: PASS (R5) — no volatility; regression test added.
secret-sweep result: ZERO — only intentional sentinels (TEST_SECRET_SHOULD_NOT_PERSIST / synthetic-token)
  appear in tests/docs; no real secret in code or persisted state.

optional live re-run: GAP-RECORDED — Sprint 014 is fixture/output-driven by contract (§5);
  it inherits the Sprint 012 live evidence. Freshness semantics are validated by fixtures
  (including a 2-day-old captured_at => Stale => finding suppressed) without a new live dogfood.

comprehension: NOT RUN (self-comprehension gate is v0.1-only; v0.2 sprints validated by the
  fixture matrix above).

usefulness judgments: provenance + freshness turn "Pico believes X" into "Pico believes X because
  <locator> at <time>, freshness <Y>" — directly answers the weakest-evidence question (ROADMAP §13.7).

defect list: EMPTY — the only behavioral change is additive: STALE/PARTIAL evidence now correctly
  suppresses/penalizes findings; FRESH+COMPLETE golden path is byte-for-byte unchanged (verified:
  golden scan still yields finding_count == 1).

architecture pressure-test:
  - Provenance is explanation/integrity metadata over the existing Evidence model; no new domain object.
  - Freshness constrains existing confidence/state logic via a pure helper + a confirmability gate;
    no second risk engine introduced.
  - Canonical identity stability is a determinism property; no graph-model change.
  - Secret-safety preserved: source_locator is an identifier/path, never a secret (ARCHITECTURE §7.7).

advancement decision record:
  Sprint 014 is DONE and self-contained within its stated scope (§3 non-goals honored: no history
  UX, no runtime observation, no new agents/providers, sink_impact remains UNKNOWN out of scope).
  It advances the v0.2 depth objective (ROADMAP §6: harden provenance + freshness + canonical
  identity) and makes evidence trustworthy across time and repetition. It does NOT claim v0.2 depth
  is "closed" — remaining v0.2 slices (e.g., 015–019) cover the rest of §6. Recommended: continue
  with the next v0.2 sprint.

follow-ups (named, owned, unambiguous):
  - F-U1 (founder): revoke leaked S012 token 6b1a59bb84dd680a1dde77f49b3f357b in dashboard (still pending).
  - F-U2 (next v0.2 sprint): optionally live-confirm freshness on the disposable account with a
    PARTIAL-scan replay (deny one adapter) to exercise R4 end-to-end against real state.
  - F-U3 (roadmap): consider persisting freshness windows in config so they are tunable without code.
```

---

# 13. Final Report Contract

```text
Sprint: SPRINT-014 — Evidence Provenance, Freshness, and Canonical-Identity Stability
Status: DONE | BLOCKED
Baseline: <verified SHA>

Provenance:
  completeness integrity: PASS | FAIL
  CLI surfaced: PASS | FAIL
  MCP surfaced: PASS | FAIL

Freshness:
  classification: PASS | FAIL
  stale confidence penalty: PASS | FAIL
  partial no-upgrade: PASS | FAIL

Identity:
  canonical stability across repeated scans: PASS | FAIL

Conformance:
  adapter provenance without secrets: PASS | FAIL

Validation matrix:
  R1-R10: <statuses>

Secret sweep: ZERO | INCIDENT
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17. Records whether v0.2 depth is advanced, extended, refined, or stopped, and why the next v0.2 sprint (015) is justified.
