# Pico — Sprint 021: GitHub Repository Mutation Authority

**Status:** DONE

**Sprint:** 021
**Phase:** v0.3 — Earned Agent and Provider Expansion
**Type:** Implementation
**Baseline:** `39a725a` (post-Sprint-020 main HEAD)
**Depends on:** Sprint 020 (Claude Code — second agent surface), Sprint 018 (Cloudflare authority depth — the authority-resolution template), Sprint 017 (GitHub MCP influence), ROADMAP §7 v0.3

---

# 1. Purpose

Sprint 020 proved the agent side of v0.3 generalizes (Claude Code). The remaining ROADMAP §7 v0.3 expansion is **one materially distinct GitHub authority path** — GitHub *repository mutation authority*:

> Within the supported GitHub boundary, Pico must resolve a GitHub credential's authority to mutate repositories — distinguishing classic PAT, fine-grained PAT, and OAuth token formats; distinguishing write (`repo`/`public_repo`) from read-only scopes where observable — and surface that honestly, without contacting non-allowlisted endpoints and without fabricating write authority from an unobservable scope.

This is the authority-side analog of Sprint 018 (which deepened Cloudflare credential/scope authority). It reuses the same domain model, graph projection, analysis engine, finding rules, and application services.

It does **not** add a second cloud provider, does **not** contact GitHub at runtime by default, and does **not** weaken the v0.2/v0.3 evidence bar.

---

# 2. Scope

- **GitHub credential discovery**: observe `GITHUB_TOKEN`, `GH_TOKEN`, and `GITHUB_PERSONAL_ACCESS_TOKEN` from environment and project `.env` (same readers as the Cloudflare credential, S012/S020), emitted as `ObservedCredential { provider: "github", credential_type, fingerprint, environment }`. Fingerprint in a GitHub namespace; the raw value is never stored.
- **Credential-type classification** (format-based, deterministic):
  - `ghp_…` => classic PAT (`classic_pat`),
  - `github_pat_…` => fine-grained PAT (`fine_grained_pat`),
  - `gho_…` => OAuth user token (`oauth`),
  - `ghs_…`/`ghr_…` => user-to-server / refresh token (`other`),
  - unrecognized => `unknown` (safe default; never invented).
- **Authority-tier resolution** (mirror S018 tiers EXACT / SCOPED / BEHAVIORAL_READ_ONLY / UNKNOWN):
  - **Offline (static, default)**: a GitHub credential's repository write scope is NOT observable from its value alone => resolution `UNKNOWN` with `unknown_reasons = ["GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE"]`. Never claim write from a `repo`-shaped token without evidence.
  - **Optional bounded live scope probe** (transport seam, offline-safe default): for a classic PAT only, a single allowlisted read `GET /user` returns the `X-OAuth-Scopes` response header; `repo`/`public_repo` present => write authority `EXACT`/`SCOPED`; only read scopes => `BEHAVIORAL_READ_ONLY`; empty => `BEHAVIORAL_READ_ONLY`. Fine-grained PATs expose per-repo permissions that the header does not reveal => remain `UNKNOWN` + `GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE`. Offline (no transport) never probes.
- **Graph projection**: a GitHub credential resource (`github:credential:<fingerprint>`), a provider-scoped repository resource (`github:repository`), and:
  - `can_mutate` edge credential → repository ONLY when write authority is evidenced (EXACT/SCOPED);
  - `can_access` (read) edge otherwise.
  Bash `can_access` the credential as today (provider-aware, S020). No cross-provider leakage and no duplicate edges with Cloudflare.
- **Surfacing**: the explained finding / scan output (CLI + MCP) states, per GitHub credential: credential type, resolved authority tier, and unknown_reasons.
- **Fixtures**: credential types, offline-vs-live resolution, classic repo/read-only/no-scope, fine-grained, mixed (Cloudflare + GitHub credentials), provider-failure (PARTIAL) — all sanitized.
- Inherits the Sprint 012 live evidence; **no new live dogfood required** (fixture/output-driven per SPRINT-013 §5; live probe exercised via `FixtureTransport`, never network in tests).

---

# 3. Non-goals

- A second cloud provider (ROADMAP §7: at most one additional authority surface OR one GitHub authority path — this sprint picks the GitHub path; a cloud provider is not added).
- Supporting every GitHub credential type or repository-mutation flavor.
- Contacting GitHub at runtime by default (offline core preserved; probe is optional + allowlisted + fixture-only in tests).
- Enforcement, automatic remediation, or write probes.
- Global MCP-server classification (tools are classified individually, S017).

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  GitHub credential discovered from env + .env (GITHUB_TOKEN / GH_TOKEN /
    GITHUB_PERSONAL_ACCESS_TOKEN) with format classification
    → NEW-FIXTURE (r1_github_credential_discovery_and_type_classification)

R2  Offline authority = UNKNOWN + GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE (never fabricated)
    → NEW-FIXTURE (r2_offline_authority_is_unknown_not_fabricated)

R3  Optional live scope probe: classic PAT repo scope => EXACT; read-only => BEHAVIORAL_READ_ONLY;
    fine-grained / offline => UNKNOWN
    → NEW-FIXTURE (r3_live_scope_probe_resolution)

R4  can_mutate emitted ONLY on evidenced write (EXACT/SCOPED); else can_access; no duplicate
    → NEW-FIXTURE (r4_github_mutation_edge_only_on_write_evidence)

R5  Golden path + mixed (Cloudflare + GitHub credentials) coexist without regression/duplicates
    → NEW-FIXTURE (r5_mixed_cloudflare_plus_github_credentials)

R6  Explanation surfaces GitHub credential type + tier + unknown_reasons (CLI)
    → NEW-FIXTURE (sprint021_cli_test.rs: cli_scan_summary_surfaces_github_credential_authority_live_exact,
                   cli_scan_summary_surfaces_github_credential_authority_offline_unknown)

R7  Explanation surfaces GitHub credential authority (MCP)
    → NEW-FIXTURE (sprint021_mcp_test.rs: github_credentials_surface_in_mcp_list_and_detail_live_exact,
                   github_credentials_surface_in_mcp_list_offline_unknown)

R8  Sanitized fixture set: credential types, offline/live, repo/read-only/no-scope,
    fine-grained, mixed, provider failures
    → NEW-FIXTURE (r8_battery_github_types_live_offline_finegrained_mixed_failure)

R9  GitHub authority resolution deterministic across identical environments (ties S015 stability)
    → NEW-FIXTURE (r9_authority_stable_across_identical_env)

R10 No secret leakage: only sanitized credential type/fingerprint/scope facts appear;
    never token values
    → NEW-FIXTURE (r10_secret_sweep_never_leaks_github_token +
                   r10_cli_surfacing_never_leaks_github_token_across_postures +
                   r10_mcp_json_never_leaks_github_token_across_postures)
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required; fixture/output-driven and inherits Sprint 012 (account `3e2742bacdabcada586f921ad89bac77`). The optional live scope probe is exercised via a `FixtureTransport` returning a synthetic `X-OAuth-Scopes` header (never network in tests; default transport is offline). A live re-run in a real repo would additionally exercise R1/R3 end-to-end, but is optional.

---

# 6. Design Notes

## 6.1 Credential discovery + classification (R1)
Extend the env + `.env` credential readers (src/discovery/agents/opencode.rs, which is the environment-level reader shared by all agents since S020) to also recognize `GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_PERSONAL_ACCESS_TOKEN`, classified by prefix via a new `classify_github_credential_type(value) -> &'static str` (`ghp_`/`github_pat_`/`gho_`/`ghs_`/`ghr_`/unknown). Emit `ObservedCredential { provider: "github", … }` with a GitHub-namespaced fingerprint (e.g. `pico:credential:github:token:v1:`). Keep the existing Cloudflare fingerprint/namespace untouched.

## 6.2 Authority resolution (R2, R3)
Add `src/discovery/github.rs` (mirror `cloudflare.rs`): a bounded provider module with a `GetTransport` seam (allowlisted path `/user` only; default offline `UnavailableTransport`). `resolve_authority(type, scopes) -> (RelationshipState, AuthorityResolution, permission_state, unknown_reasons)`:
  - offline (no probe) => `UNKNOWN` + `GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE`.
  - classic PAT live: `repo`/`public_repo` in scopes => `Derived`/`EXACT` (`permission_state="REPO_WRITE"`); read-only scopes => `Unknown`/`BEHAVIORAL_READ_ONLY`; empty => `Unknown`/`BEHAVIORAL_READ_ONLY`.
  - fine-grained PAT live => `UNKNOWN` + `GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE`.
  Expose the result on `DiscoveryResult` (e.g. `github: Option<GitHubAuthorityResult>`).

## 6.3 Graph projection (R4)
In src/application/scan.rs, after the credential resource block (which is already provider-aware, `{provider}:credential:{fingerprint}`), add a GitHub branch: build `github:repository` resource; emit `can_mutate` only when authority is EXACT/SCOPED (evidenced write), else `can_access` (read). Bash `can_access` the credential as today. No duplicate edges with the Cloudflare branch; no cross-provider leakage. `agent_count`/`provider_statuses` (S019) stay accurate.

## 6.4 Surfacing (R6–R7)
Reuse S016/S018/S020 seams: per GitHub credential, show credential type + authority tier + unknown_reasons in CLI (`render.rs`) and MCP (`tools.rs`, e.g. `github_credentials` array on the scan result / explained path). Extend sprint021 integration tests.

## 6.5 Fixtures (R8)
Sanitized battery: classic/fine-grained/oauth/unknown types; offline vs live (repo / read-only / no-scope / fine-grained); mixed Cloudflare+GitHub; provider-failure (PARTIAL — probe unavailable). Each asserts type + tier + edges.

## 6.6 Stability (R9)
Identical environment => identical GitHub authority resolution (ties S015/S020 stability).

## 6.7 Support note (R10/DOC)
Author `docs/internal/sprints/SPRINT-021-support-note.md`: exactly what GitHub mutation authority Pico can/cannot establish (type-aware; scope observable only via optional classic-PAT probe; fine-grained per-repo permissions unobservable; offline => UNKNOWN; no write fabrication; no non-allowlisted calls).

---

# 7. Fixtures (NEW-FIXTURE)

- `r1_github_credential_discovery_and_type_classification` — env/.env keys + prefix => type.
- `r2_offline_authority_is_unknown_not_fabricated` — offline => UNKNOWN + reason.
- `r3_live_scope_probe_resolution` — classic repo => EXACT; read-only => BEHAVIORAL_READ_ONLY; fine-grained => UNKNOWN.
- `r4_github_mutation_edge_only_on_write_evidence` — can_mutate only on EXACT/SCOPED; else can_access.
- `r5_mixed_cloudflare_plus_github_credentials` — both coexist, no duplicates.
- `r8_battery_github_types_live_offline_finegrained_mixed_failure` — types/offline/live/repo/read-only/no-scope/fine-grained/mixed/failure.
- `r9_authority_stable_across_identical_env` (R9).

---

# 8. Architecture Pressure-Test

- GitHub authority is an analyzed interpretation of credential format + (optionally) bounded scope evidence (ARCHITECTURE §2.9 effective-state-over-declared); it feeds the existing Credential/Relationship/Boundary model; no new domain object.
- Pure and deterministic; reuses the S018 authority-tier contract and the S020 provider-aware key scheme.
- Secret-safety preserved (ARCHITECTURE §7.7, ROADMAP §13.2): only credential type + fingerprint + scope facts; token VALUE never appears. Offline core preserved (probe optional, allowlisted, offline-safe).
- No second cloud provider; GitHub mutation authority is the selected v0.3 GitHub authority path.

---

# 9. Risks and Mitigations

- **Risk:** over-claiming write authority from a `repo`-shaped token. *Mitigation:* static => UNKNOWN; write only on evidenced scope (live classic-PAT probe); fixture R2/R3 pin it.
- **Risk:** adding a live probe is mistaken for runtime monitoring. *Mitigation:* probe is a single allowlisted read, offline by default, fixture-only in tests; documented in the support note.
- **Risk:** duplicate/colliding edges with Cloudflare credentials. *Mitigation:* provider-namespaced keys (`github:credential:`); R5 asserts no duplicates.

---

# 10. Required Evidence Artifacts

- A1–A5 GitHub credential/authority resolver + probe + graph fixtures (R1–R5).
- A6 CLI surfacing test (R6).
- A7 MCP surfacing test (R7).
- A8 broad sanitized fixture battery (R8).
- A9 stability fixture (R9).
- A10 secret-sweep extension (R10).
- A11 support note (§27, DOC-VERIFIED).
- A12 completed validation matrix (§4 / §27).

Evidence artifacts quote at most sanitized credential type/fingerprint/scope facts; never raw token values.

---

# 11. Commit Policy

Authoring-only document commit as:

```text
docs(sprints): define Sprint 021 GitHub repository mutation authority
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
feat(discovery): resolve GitHub credential type and mutation authority
feat(scan): project GitHub repository mutation authority to the graph
feat(cli): surface GitHub credential authority
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin a new v0.3 sprint.

---

# 12. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-08-26
  Baseline: 2c4c463 (authored) -> pushed 39a725a..<S021 impl>
  Verified by: cargo test (349 passed, 0 failed, 1 ignored), clippy --all-targets -D warnings
               clean, cargo fmt --check clean. Golden path (opencode-only) => exactly 1 finding
               with agent:opencode keys intact; CLI/MCP output unchanged (no GitHub block).

commits
  authored: 2c4c463 docs(sprints): define Sprint 021 GitHub repository mutation authority
  impl:      <feat(discovery) + feat(scan) + feat(cli,mcp) + test(integration)>

repository state
  ?? src/discovery/github.rs               (new GitHub provider module: transport + scope probe + authority)
  M  src/discovery/agents/opencode.rs      (GITHUB_TOKEN/GH_TOKEN/GITHUB_PERSONAL_ACCESS_TOKEN discovery + classify)
  M  src/discovery/mod.rs                  (pub mod github; DiscoveryResult.github; secret-sweep check)
  M  src/application/scan.rs               (GitHub graph branch: can_mutate only on write evidence; provider_statuses)
  M  src/application/findings.rs           (+GitHubCredentialView; github_credentials on FindingList/Detail)
  M  src/application/mod.rs                (re-export)
  M  src/cli/mod.rs + src/cli/render.rs    (GitHub credential authority block in `pico scan`)
  M  src/mcp/tools.rs                      (SafeGitHubCredentialView + github_credentials JSON)
  M  tests/integration.rs + sprint016/017/018_cli_test.rs (github_credentials: vec![])
  ?? docs/internal/sprints/SPRINT-021-support-note.md
  ?? tests/integration/sprint021_authority_test.rs / sprint021_cli_test.rs / sprint021_mcp_test.rs

new fixtures (R1–R10) and their assertions
  opencode.rs:
    R1  r1_github_credential_discovery_and_type_classification (env/.env keys + prefixes; no cloudflare interaction)
  github.rs (unit):
    R2  r2_offline_authority_is_unknown_not_fabricated
    R3  r3_live_scope_probe_resolution (classic repo => EXACT; read-only => BEHAVIORAL_READ_ONLY; fine-grained => UNKNOWN)
    R9  r9_authority_stable_across_identical_env
    (+ classifies_github_credential_types_by_prefix, github_fingerprint_is_namespaced_and_stable, resolve_authority_table)
  sprint021_authority_test.rs:
    R4  r4_github_mutation_edge_only_on_write_evidence (can_mutate on EXACT/SCOPED; else can_access)
    R5  r5_mixed_cloudflare_plus_github_credentials (coexist; golden count unchanged; no duplicates)
    R8  r8_battery_github_types_live_offline_finegrained_mixed_failure
    R10 r10_secret_sweep_never_leaks_github_token
  sprint021_cli_test.rs:
    R6  cli_scan_summary_surfaces_github_credential_authority_live_exact
        cli_scan_summary_surfaces_github_credential_authority_offline_unknown
        cli_scan_summary_golden_path_has_no_github_block
  sprint021_mcp_test.rs:
    R7  github_credentials_surface_in_mcp_list_and_detail_live_exact
        github_credentials_surface_in_mcp_list_offline_unknown
        github_credentials_empty_in_mcp_golden_path
        (+ unit safe_github_credential_view_serializes_authority_facts)
  Secret sweep (R10, surfacing level):
    r10_cli_surfacing_never_leaks_github_token_across_postures (CLI) +
    r10_mcp_json_never_leaks_github_token_across_postures (MCP)

CLI/MCP GitHub-authority surfacing test additions: see R6/R7 above.
  CLI renders: "GitHub <credential_type> authority: resolution=<tier> permission=<state> reasons=[...]"
               (in `pico scan` summary; absent on golden path).
  MCP JSON: top-level github_credentials[] = {credential_type, authority_resolution, permission_state,
               unknown_reasons} in list_findings + get_finding.

mixed-environment result: R5 PASS — Cloudflare + GitHub credentials coexist; no duplicate edges;
    golden finding count unchanged.
authority stability result: R9 PASS — identical env => identical authority (ties S015/S020 stability).
secret-sweep result: ZERO — synthetic ghp_ token absent in all rendered/metadata outputs;
    provider facts only (type/fingerprint/scope).
optional live re-run outcome: GAP-RECORDED — fixture/output-driven per SPRINT-013 §5; live probe
    exercised via FixtureTransport seams (offline default); a real repo re-run optional.
comprehension result: NOT RUN (no external comprehension step defined for this sprint).
usefulness judgments: GitHub credential mutation authority is the first v0.3 authority-side
    expansion; honest UNKNOWN-when-unobservable + scope-where-evidenced mirrors S018.
defect list and dispositions: expected empty — all R1–R10 green, golden paths intact.
architecture pressure-test answers:
  - GitHub authority feeds existing Credential/Relationship/Boundary model; no new domain object.
  - Pure and deterministic; reuses S018 tier contract + S020 provider-aware keys.
  - Secret-safety preserved; offline core preserved (probe optional, allowlisted, offline-safe).
  - No second cloud provider; GitHub mutation authority is the selected v0.3 GitHub authority path.
advancement decision record: see §14.
follow-ups (named, owned, unambiguous):
  - v0.3 exit-criteria review + handoff decision (see §14).
  - R10 live token id 6b1a59bb84dd680a1dde77f49b3f357b still pending dashboard deletion
    (external carry-over, not a code blocker).
```

Do not claim v0.3 is "won" merely because GitHub mutation authority is added. Claim exactly what the matrix shows: a GitHub credential's repository mutation authority is resolved honestly (type-aware, scope-where-observable, UNKNOWN otherwise), projected to the graph, and surfaced — with the OpenCode/Claude golden paths intact.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-021 — GitHub Repository Mutation Authority
Status: DONE
Baseline: 2c4c463 (authored) -> <impl push>

GitHub authority:
  credential discovery + type: PASS
  offline authority (UNKNOWN): PASS
  live scope probe: PASS
  can_mutate on write evidence: PASS
  mixed with Cloudflare: PASS

Surfacing:
  CLI GitHub credential authority: PASS
  MCP GitHub credential authority: PASS

Fixtures:
  broad battery: PASS
  stability across envs: PASS

Validation matrix:
  R1-R10: PASS

Golden path: 1 finding intact
Secret sweep: ZERO
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17.

```text
Decision: ADVANCE v0.3 — v0.3 scope complete.
S020 added the earned second agent surface (Claude Code); S021 added the
materially distinct GitHub authority path (repository mutation authority,
type-aware + scope-where-observable + UNKNOWN otherwise). Both reuse the same
domain model, graph projection, analysis engine, finding rules, and application
services; the OpenCode golden path is byte-identical throughout.

ROADMAP §7 v0.3 exit criteria status:
  - One new end-to-end path through the existing core engine: PASS (Claude Code
    actor + Bash + MCP; GitHub credential authority).
  - Each new adapter declares supported operations/evidence precision/failure/
    unresolved states: PASS (S020/S021 support notes + S013 matrix appendix).
  - Fixture/integration/determinism/secret-safety/controlled-dogfood coverage
    equivalent to the golden path: PASS (R1–R10 both sprints; secret sweeps ZERO).
  - Mixed supported environments: PASS (R5 mixed env S020; R5 mixed credentials S021).
  - Unsupported configs degrade to explicit partial/unknown: PASS.
  - Integration intelligence never substitutes for environment evidence: PASS
    (offline core preserved; probes optional/allowlisted/fixture-only).
  - No regression to scan clarity/local performance/quality bar: PASS (349 tests).

Recommendation: v0.3 earned expansion is complete for the selected surfaces.
Further v0.3 work (e.g., a second coding agent like Codex, or a cloud provider)
is a new phase decision, not started here. Recommended next: dogfood review of
the two new surfaces + v0.3 sign-off, per ROADMAP §17.
```