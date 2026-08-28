# Pico — Sprint 021: GitHub Repository Mutation Authority

**Status:** READY

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
    → NEW-FIXTURE (github_credential_discovery_and_type_classification)

R2  Offline authority = UNKNOWN + GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE (never fabricated)
    → NEW-FIXTURE (github_offline_authority_is_unknown_not_fabricated)

R3  Optional live scope probe: classic PAT repo scope => EXACT; read-only => BEHAVIORAL_READ_ONLY;
    fine-grained / offline => UNKNOWN
    → NEW-FIXTURE (github_live_scope_probe_resolution)

R4  can_mutate emitted ONLY on evidenced write (EXACT/SCOPED); else can_access; no duplicate
    → NEW-FIXTURE (github_mutation_edge_only_on_write_evidence)

R5  Golden path + mixed (Cloudflare + GitHub credentials) coexist without regression/duplicates
    → NEW-FIXTURE (mixed_cloudflare_plus_github_credentials)

R6  Explanation surfaces GitHub credential type + tier + unknown_reasons (CLI)
    → NEW-FIXTURE (sprint021_cli_test.rs)

R7  Explanation surfaces GitHub credential authority (MCP)
    → NEW-FIXTURE (sprint021_mcp_test.rs)

R8  Sanitized fixture set: credential types, offline/live, repo/read-only/no-scope,
    fine-grained, mixed, provider failures
    → NEW-FIXTURE (broad fixture battery; see §7)

R9  GitHub authority resolution deterministic across identical environments (ties S015 stability)
    → NEW-FIXTURE (github_authority_stable_across_identical_env)

R10 No secret leakage: only sanitized credential type/fingerprint/scope facts appear;
    never token values
    → NEW-FIXTURE (secret_sweep_never_leaks_github_token)
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

- `github_credential_discovery_and_type_classification` — env/.env keys + prefix => type.
- `github_offline_authority_is_unknown_not_fabricated` — offline => UNKNOWN + reason.
- `github_live_scope_probe_resolution` — classic repo => EXACT; read-only => BEHAVIORAL_READ_ONLY; fine-grained => UNKNOWN.
- `github_mutation_edge_only_on_write_evidence` — can_mutate only on EXACT/SCOPED; else can_access.
- `mixed_cloudflare_plus_github_credentials` — both coexist, no duplicates.
- broad battery (R8): types/offline/live/repo/read-only/no-scope/fine-grained/mixed/failure.
- `github_authority_stable_across_identical_env` (R9).

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

When validation concludes, set `Status: DONE` (or `BLOCKED`) and record:

```text
completion date and verified baseline
commits (authoring; any defect fixes; evidence record)
repository state
new fixtures (R1–R10) and their assertions
CLI/MCP GitHub-authority surfacing test additions
mixed-environment result
authority stability result
secret-sweep result
optional live re-run outcome (or GAP-RECORDED with reason)
comprehension result (PASS/FAIL/NOT RUN + confusion points)
usefulness judgments
defect list and dispositions (expected empty)
architecture pressure-test answers
advancement decision record
follow-ups (named, owned, unambiguous)
```

Do not claim v0.3 is "won" merely because GitHub mutation authority is added. Claim exactly what the matrix shows: a GitHub credential's repository mutation authority is resolved honestly (type-aware, scope-where-observable, UNKNOWN otherwise), projected to the graph, and surfaced — with the OpenCode/Claude golden paths intact.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-021 — GitHub Repository Mutation Authority
Status: DONE | BLOCKED
Baseline: <verified SHA>

GitHub authority:
  credential discovery + type: PASS | FAIL
  offline authority (UNKNOWN): PASS | FAIL
  live scope probe: PASS | FAIL
  can_mutate on write evidence: PASS | FAIL
  mixed with Cloudflare: PASS | FAIL

Surfacing:
  CLI GitHub credential authority: PASS | FAIL
  MCP GitHub credential authority: PASS | FAIL

Fixtures:
  broad battery: PASS | FAIL
  stability across envs: PASS | FAIL

Validation matrix:
  R1-R10: <statuses>

Golden path: <1 finding intact | REGRESSED>
Secret sweep: ZERO | INCIDENT
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17. Records whether v0.3 is advanced, extended, refined, or stopped, and whether the ROADMAP §7 v0.3 exit criteria are met (one agent surface + one authority path through the same engine, mixed-environment validated, matrices extended) or whether a further v0.3 sprint is justified.