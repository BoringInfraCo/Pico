# Sprint 012 Validation Matrix (Artifact A7 — skeleton, pre-run)

**Status:** SKELETON authored at planning time from code/test inspection only.
No live run has happened yet; every LIVE cell is PENDING-RUN until an actual
execution fills it (SPRINT-012.md §4).

## Status vocabulary

```text
FIXTURE-VERIFIED   proven by the existing automated suite — the "Evidence
                   artifact" column cites the real test file(s) and test
                   function name(s), located by inspection at baseline 4993bf2
LIVE-VERIFIED      proven by Sprint 012 against the real environment — cite
                   the artifact; cells start as PENDING-RUN and are filled
                   ONLY from actual runs
GAP-RECORDED       reality does not yet support this criterion; cite the gap
                   with file-level references
NOT-APPLICABLE     criterion does not bind this configuration (justify)
PENDING            row not yet resolvable before the run
```

A criterion may be FIXTURE-VERIFIED and still require live re-demonstration;
in that case Status stays FIXTURE-VERIFIED and the live duty is named in
Notes as PENDING-RUN. Do not upgrade any cell from a run that did not happen.

## Matrix — ROADMAP §5 exit criteria (sixteen)

| # | Criterion (abbreviated from SPRINT-012.md §2 quote of ROADMAP §5) | Status | Evidence artifact | Notes |
|---|------------------------------------------------------------------|--------|-------------------|-------|
| 1 | `pico init` idempotent, safe local state | FIXTURE-VERIFIED | tests/integration/empty_scan_test.rs::`init_is_idempotent_and_does_not_reset`; src/application/init.rs::`init_is_idempotent`; persistence/db_test.rs::`migration_is_idempotent` | Live repeat PENDING-RUN (runbook E1 double-init) |
| 2 | `pico scan` completes same bounded pipeline on fixtures AND controlled real environment | FIXTURE-VERIFIED (fixture half) | tests/integration/sprint007_graph_test.rs::`complete_golden_path_projects_exact_graph_manifest`; offline_test.rs::`init_and_scan_work_offline_in_temp_workspace`; opencode_scan_test.rs::`supported_opencode_is_observed_safely_and_stably_across_scans` | LIVE half PENDING-RUN (E2/E7). Caveat: A9 §3 — provider introspection may be unreachable from shipped CLI pending P3 disposition |
| 3 | Detects supported OpenCode instance; resolves effective Bash + relevant MCP permissions | FIXTURE-VERIFIED | opencode_scan_test.rs::`supported_opencode_is_observed_safely_and_stably_across_scans`, ::`bash_policy_states_remain_distinct`, ::`permission_change_preserves_identity_and_scan_history`; unit: src/discovery/agents/opencode.rs::`resolves_allow_ask_and_deny_shorthand`, ::`project_permission_overrides_global_permission`, ::`mixed_patterns_are_bounded_unknown`, ::`default_agent_override_wins`; MCP permission side: github_mcp_scan_test.rs::`remote_official_server_preserves_deny_and_spoof_is_ignored` | Live detection PENDING-RUN (E2/E3) |
| 4 | Distinguishes GitHub external influence from mere GitHub product presence | FIXTURE-VERIFIED | github_mcp_scan_test.rs::`disabled_official_server_is_observed_but_has_no_influence_edges`; ::`remote_official_server_preserves_deny_and_spoof_is_ignored` | Reality note: no sprint-numbered 002–005 files exist; these behaviors live in generically named suites. Live check PENDING-RUN (E3) |
| 5 | Establishes Bash→Cloudflare credential reachability without persisting its value | FIXTURE-VERIFIED | cloudflare_credential_scan_test.rs::`allow_reachability_is_stable_and_secret_safe_across_scans`, ::`unknown_environment_does_not_create_positive_reachability`, ::`ask_and_deny_preserve_distinct_reachability_states`, ::`credential_rotation_preserves_distinct_safe_identity_history` | Secret non-persistence re-proven live only by E8 sweep |
| 6 | Worker write authority from read-only evidence, or honest UNKNOWN without claiming a path | FIXTURE-VERIFIED | sprint006_safety_test.rs::`injected_provider_result_persists_exact_worker_authority`, ::`local_unknown_reachability_does_not_create_positive_access_state`, ::`authority_resolution_and_scope_vocabulary_remain_explicit`, ::`worker_identity_is_account_scoped_and_prefers_immutable_tag`; blocked/unresolved: sprint008_analysis_test.rs::`blocked_authority_is_reported_without_active_path`; sprint009_finding_test.rs::`blocked_and_unresolved_authority_never_emit_a_finding`; src/findings/engine.rs::`unknown_production_is_not_a_finding` | LIVE depends on P3 gate disposition (A9 §3); otherwise GAP-RECORDED for the introspection half |
| 7 | Hard deny/approval/sandbox/scope boundary blocks only the path it actually interrupts | FIXTURE-VERIFIED | sprint008_analysis_test.rs::`alternate_route_keeps_open_route_reachable_when_other_route_is_blocked`, ::`direction_and_usability_do_not_allow_reverse_or_unknown_edges`, ::`cycle_and_depth_limits_are_explicit_and_deterministic`; integrity: finding_query_integrity_test.rs::`interrupting_boundary_on_linked_path_is_an_integrity_error`, ::`unresolved_boundary_on_linked_path_is_an_integrity_error`; src/analysis/mod.rs::`blocked_authority_is_retained_as_blocked_candidate` | Live boundary absence recorded in E2/S1 |
| 8 | Unblocked fixture produces expected UNTRUSTED_TO_PRODUCTION Finding | FIXTURE-VERIFIED | sprint009_finding_test.rs::`explicit_production_classification_is_persisted_as_safe_metadata`; src/findings/engine.rs::`emits_critical_high_golden_finding` | LIVE status pre-registered: GAP-RECORDED unless §8.1 finds otherwise → it did not (see classification-gap.md); a live Finding is NOT possible today (engine.rs:149 + cloudflare.rs:456). Final cell filled after run |
| 9 | Blocked and scoped fixtures do NOT produce the active attack path | FIXTURE-VERIFIED | sprint009_finding_test.rs::`staging_and_local_dev_are_not_production_and_secret_sentinel_is_absent`, ::`absent_or_unsupported_classification_stays_unknown_even_for_production_named_worker`, ::`partial_provider_scan_never_emits_a_positive_finding` | Live analogue is S1 |
| 10 | Every security-critical edge has inspectable provenance, freshness, confidence | FIXTURE-VERIFIED | sprint010_cli_test.rs::`detail_rendering_presents_sections_in_deterministic_order`, ::`newer_incomplete_attempts_render_exact_freshness_warnings`; sprint010_finding_query_test.rs::`reason_codes_map_to_fixed_provider_neutral_text`, ::`golden_detail_renders_traversal_aware_connected_path`, ::`historical_finding_uses_originating_scan_snapshot_names` | On live data: inspect via E4/E6 once run |
| 11 | Repeat analysis over same graph ⇒ same paths/severity/confidence/identity | FIXTURE-VERIFIED | sprint009_finding_test.rs::`equivalent_production_scans_keep_finding_fingerprint_and_scope_ids`; src/findings/engine.rs::`equivalent_graphs_have_stable_finding_fingerprint`; src/analysis/mod.rs::`projects_active_golden_path_with_stable_canonical_fingerprint`; sprint010_finding_query_test.rs::`queries_are_deterministic_and_perform_zero_writes` | Real-data determinism PENDING-RUN (E7) |
| 12 | Secret canaries zero occurrences in DB, logs, diagnostics, exports | FIXTURE-VERIFIED | sprint006_safety_test.rs::`credential_and_authorization_sentinels_never_enter_persisted_state`; sprint008_analysis_test.rs::`secret_sentinel_is_not_present_in_normalized_graph_fixture`; sprint009_finding_test.rs (sentinel asserts inside `staging_and_local_dev_…`); sprint011_mcp_golden_test.rs::`secret_sentinels_never_appear_across_the_golden_session` | LIVE token+prefix+canary sweep PENDING-RUN (E8); required count ZERO |
| 13 | Provider clients cannot invoke operations outside read/introspection allowlists | FIXTURE-VERIFIED | src/discovery/cloudflare.rs tests::`client_rejects_unallowlisted_paths`, ::`read_only_listing_never_becomes_write_authority`, ::`exact_write_authority_is_derived_from_policy_scope_and_worker`; offline_test.rs::`init_and_scan_work_offline_in_temp_workspace` | LIVE allowlist conformance proof (captured request log, §7 / A4) PENDING-RUN |
| 14 | Partial adapter failure ⇒ PARTIAL scan, retained useful evidence, no false certainty | FIXTURE-VERIFIED | sprint009_finding_test.rs::`partial_provider_scan_never_emits_a_positive_finding`; opencode_scan_test.rs::`malformed_supported_opencode_config_completes_partial_without_persistence`; src/analysis/mod.rs::`partial_scan_downgrades_positive_candidate_to_unresolved`; src/findings/engine.rs::`partial_and_limited_are_fail_closed` | LIVE injections F1/F2 PENDING-RUN |
| 15 | Unfamiliar developer can explain path, why it matters, how known, uncertainty, ≥1 cut point | NOT RUN — OPEN | none | No automated suite can prove this; satisfied only by §11 comprehension check (C1/C2). NOT RUN is acceptable only if no independent developer; gate then blocks ADVANCE |
| 16 | MCP interface returns same underlying Finding as CLI; no second scanner | FIXTURE-VERIFIED | sprint011_mcp_golden_test.rs::`golden_session_serves_list_and_detail_matching_the_query_service`, ::`sessions_are_byte_deterministic_and_write_nothing`, ::`two_paths_reaching_one_sink_surface_through_both_tools`; sprint011_mcp_test.rs::`golden_stdio_session_completes_initialize_tools_list_and_list_findings`, ::`mcp_sources_are_structurally_free_of_scan_and_provider_machinery` | Real-data parity PENDING-RUN (E6) |

## Live Dogfood Results (run `scan_18cf730d87996f48_0`, baseline `72ac784`)

The live run (see `docs/internal/dogfood/evidence.md`) upgrades several rows
from PENDING-RUN. Status vocabulary is unchanged; a Fixture cell may now carry a
matching LIVE-VERIFIED note. The comprehension criterion (row 15) remains the
only OPEN item.

| # | Criterion | Fixture status | Live status | Notes |
|---|-----------|----------------|-------------|-------|
| 1 | `pico init` idempotent, safe local state | FIXTURE-VERIFIED | LIVE-VERIFIED (E1) | two live `init` runs → `.pico/pico.db` only, schema v4 |
| 2 | `pico scan` completes same bounded pipeline on fixtures AND controlled real environment | FIXTURE-VERIFIED | LIVE-VERIFIED (E2/E7) | live `scan` completed PARTIAL (Analysis COMPLETE); two runs deterministic |
| 3 | Detects supported OpenCode instance; resolves effective Bash + relevant MCP permissions | FIXTURE-VERIFIED | LIVE-VERIFIED (E2/E3) | real opencode instance + bash/credential edges present |
| 4 | Distinguishes GitHub external influence from mere GitHub product presence | FIXTURE-VERIFIED | LIVE-VERIFIED (E3) | canary github token present as product presence only, no influence fabrications |
| 5 | Establishes Bash→Cloudflare credential reachability without persisting its value | FIXTURE-VERIFIED | LIVE-VERIFIED (E8) | credential OBSERVED/REACHABLE/ACTIVE; Credential Value Stored: NO; 0 token matches in DB |
| 6 | Worker write authority from read-only evidence, or honest UNKNOWN without claiming a path | FIXTURE-VERIFIED | LIVE-VERIFIED (E2/E3) | real `can_mutate` edge, authority UNKNOWN, 2 unresolved candidates, 0 active paths |
| 7 | Hard deny/approval/sandbox/scope boundary blocks only the path it actually interrupts | FIXTURE-VERIFIED | GAP-RECORDED (live) | no live boundary exercised; honest UNRESOLVED path retained, 0 Blocked |
| 8 | Unblocked fixture produces expected UNTRUSTED_TO_PRODUCTION Finding | FIXTURE-VERIFIED | GAP-RECORDED (live) | confirmed: live can never emit — sink_impact UNKNOWN; 0 Findings is correct |
| 9 | Blocked and scoped fixtures do NOT produce the active attack path | FIXTURE-VERIFIED | GAP-RECORDED (live) | no live blocked/scoped variant; F2 confirms no fabrication on revoked token |
| 10 | Every security-critical edge has inspectable provenance, freshness, confidence | FIXTURE-VERIFIED | LIVE-VERIFIED (E4/E6) | edges carry Evidence links; CLI + MCP render same real state |
| 11 | Repeat analysis over same graph ⇒ same paths/severity/confidence/identity | FIXTURE-VERIFIED | LIVE-VERIFIED (E7) | cloudflare subgraph hash `4a25bd6136a605cf` identical across two runs |
| 12 | Secret canaries zero occurrences in DB, logs, diagnostics, exports | FIXTURE-VERIFIED | LIVE-VERIFIED (E8) | token value / first-8 / canary: 0 matches in `.pico` DB; canary github token only in opencode.json placeholder |
| 13 | Provider clients cannot invoke operations outside read/introspection allowlists | FIXTURE-VERIFIED | LIVE-VERIFIED (§7/A4) | every live call within §22.7 ALLOW; no write scope on token |
| 14 | Partial adapter failure ⇒ PARTIAL scan, retained useful evidence, no false certainty | FIXTURE-VERIFIED | LIVE-VERIFIED (F1/F2) | invalid token PASSES honest PARTIAL; revoked token PARTIAL, 0 findings, no fabrication |
| 15 | Unfamiliar developer can explain path, why it matters, how known, uncertainty, ≥1 cut point | NOT RUN — OPEN | **NOT RUN** | no independent developer named by founder; gate remains open (see evidence.md §5/§6) |
| 16 | MCP interface returns same underlying Finding as CLI; no second scanner | FIXTURE-VERIFIED | LIVE-VERIFIED (E6/MCP) | `list_findings` + `get_finding` across CLI and `pico mcp` surface identical real 0-findings state |

### Additional rows (post-run)

| # | Extra criterion | Status | Notes |
|---|-----------------|--------|-------|
| X1 | MCP parity holds on real data | LIVE-VERIFIED (E6) | two tools, semantics match CLI, no second scanner |
| X2 | Live classification gap precisely characterized (§8/§8.1) | CONFIRMED | live behavior matches classification-gap.md (sink_impact UNKNOWN); plus Defect 2 added to that doc §3.1 |
| X3 | Safe variant demonstrates absence-of-path honestly | NOT PREPARED | safe variant not prepared; F2 (revoked token) stands in as honest-degradation analogue |
| X4 | Both failure injections behave honestly (F1/F2) | LIVE-VERIFIED | F1 PASSES, F2 PARTIAL/no fabrication |
| X5 | Comprehension check administered per rules | **NOT RUN** | no independent developer available; founder to complete or accept caveat |
| X6 | Usefulness judgment captured (§12) | NOT CAPTURED | blocked by NOT RUN comprehension check |

**Live-validation ship-condition for the pipeline: MET.** The comprehension
gate (row 15 / X5) is the only OPEN item and is explicitly recorded as NOT RUN,
not faked.

## Additional rows (SPRINT-012.md §21)

These rows (X1–X6) are now resolved by the live run and recorded in the
**Live Dogfood Results** section above. Summary:

- X1 MCP parity: LIVE-VERIFIED (E6)
- X2 classification gap: CONFIRMED (matches classification-gap.md; Defect 2
  added to that doc §3.1)
- X3 safe variant: NOT PREPARED (F2 stands in as honest-degradation analogue)
- X4 F1/F2 honest: LIVE-VERIFIED
- X5 comprehension: **NOT RUN**
- X6 usefulness: NOT CAPTURED (blocked by NOT RUN comprehension check)

## Fill-in rules

```text
1. LIVE-VERIFIED may only be entered citing an artifact that exists because
   a run produced it (transcript, hash file, sweep output).
2. Row 8's final live cell is pre-committed to GAP-RECORDED unless the run
   contradicts classification-gap.md — in which case STOP (§26) before
   editing anything.
3. Any FIXTURE-VERIFIED citation above whose test name differs on re-check
   must be corrected here, never silently.
```
