# Pico — Sprint 018: Cloudflare Authority Resolution Depth (Credential Types & Scope Combinations)

**Status:** READY

**Sprint:** 018
**Phase:** v0.2 — Evidence and Authority Depth
**Type:** Implementation
**Baseline:** `6307b85` (post-Sprint-017 main HEAD)
**Depends on:** Sprint 012 (live dogfood contract), Sprint 013 (authority tiers), Sprint 014 (provenance + freshness), Sprint 015 (finding stability/dedup), Sprint 016 (effective-state), Sprint 017 (GitHub influence)

---

# 1. Purpose

Sprints 013–017 made authority tiers visible (EXACT/SCOPED/BEHAVIORAL_READ_ONLY/UNKNOWN), evidence trustworthy, findings stable, OpenCode effective-state honest, and GitHub influence classified. The remaining v0.2 depth gap on the **Cloudflare authority leg** of the golden path is resolving authority across the *supported credential types and scope combinations*:

> Within the supported Cloudflare boundary, Pico must resolve a credential's authority across its type (API token vs global API key vs OAuth) and its scope combinations (account-scoped vs zone-scoped vs all-accounts; read-only vs write permission groups), and reflect that honestly as a deterministic tier and surfaced fact.

This sprint closes ROADMAP §6 v0.2 commitment Sprint 013–017 did not:

- "Deepen Cloudflare authority resolution across supported credential types and scope combinations."

It does **not** add a second provider (v0.3), contact non-allowlisted Cloudflare endpoints, perform enforcement (v0.7), or change `sink_impact` (still `UNKNOWN` by design, SPRINT-013 §8).

---

# 2. Scope

- **Credential-type classification**: distinguish `api_token` (`cfut_…`, scoped, policy-driven), `api_key` (global key, account-wide authority), and `oauth` (user token) from the discovered credential's format/fingerprint. The discovery layer already computes a `credential_type`; S018 makes it precise and propagates it into authority resolution. A global API key cannot be inspected via the token endpoints, so its authority is resolved from type alone as `EXACT` with an explicit `GLOBAL_KEY_UNVERIFIED` caveat (no fabricated live facts).
- **Scope combinations**: resolve authority at the granularity the token actually grants:
  - account-scoped Workers write (`com.cloudflare.api.account.<id>` or `*`),
  - zone-scoped Workers write (`com.cloudflare.api.account.zone.<id>`),
  - all-accounts (`*`),
  - unresolved scope (write group present, no account/zone resource) => `SCOPED`.
  The current `policy_facts` collects only account ids; S018 adds zone-id collection and zone-aware `scope_for`.
- **Permission-group distinction**: `Workers Scripts Write` / `Workers Scripts Edit` => write authority; `Workers Scripts Read` (and other read groups) => read-only. Surface the *granted* permission group names (e.g., "Workers Scripts Write") so the developer sees exactly what was granted, not just a tier label.
- **Tier mapping**: keep the four tiers (EXACT / SCOPED / BEHAVIORAL_READ_ONLY / UNKNOWN) fed by the deepened `policy_facts`/`authority_for`; a `can_mutate` Worker edge remains the boundary seam. No new domain object.
- **Surfacing**: the explained finding (CLI + MCP) states the credential type, granted permission groups, and resolved tier per Cloudflare Worker edge.
- **Fixtures**: credential types, scope combinations, read/write permission groups, deny, expired/inactive token, multiple accounts/zones, and provider-failure (PARTIAL) variants — all sanitized (synthetic token-info JSON; never real token values).
- Inherits the Sprint 012 live evidence; **no new live dogfood required** (fixture/output-driven per SPRINT-013 §5). Live inspection uses only allowlisted read endpoints (cloudflare.rs `is_allowlisted_path`).

---

# 3. Non-goals

- A second cloud provider (v0.3).
- Non-allowlisted Cloudflare reads or any write/mutate call.
- Runtime/continuous monitoring (v0.5).
- Enforcement or automatic remediation (v0.7).
- LLM-decided authority.
- Resolving repository/zone visibility by contacting GitHub (out of scope; see S017).

---

# 4. Validation Matrix

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE        proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED       proven by an authored note (cite §27 artifact)
NOT-APPLICABLE     does not bind this configuration (justify)
```

```text
R1  Credential type classified honestly (api_token / api_key / oauth)
    → NEW-FIXTURE (cloudflare_credential_type_classification)

R2  Scope combinations resolved (account-scoped / zone-scoped / all-accounts / unresolved)
    → NEW-FIXTURE (cloudflare_scope_combinations)

R3  Read-only vs write permission groups distinguished
    (Workers Scripts Read => BEHAVIORAL_READ_ONLY; Write/Edit => write authority)
    → NEW-FIXTURE (cloudflare_read_vs_write_permission_groups)

R4  Global API key mapped to EXACT with explicit unverified caveat
    → NEW-FIXTURE (cloudflare_global_api_key_resolution)

R5  Authority maps to the correct tier/boundary
    (Exact/Scoped/BehavioralReadOnly/Unknown + can_mutate boundary)
    → NEW-FIXTURE (cloudflare_authority_to_tier_table)

R6  Explanation surfaces credential type + granted scopes + tier (CLI)
    → NEW-FIXTURE (sprint018_cli_test.rs)

R7  Explanation surfaces credential type + granted scopes + tier (MCP)
    → NEW-FIXTURE (sprint018_mcp_test.rs)

R8  Sanitized fixture set: credential types, scope combos, permission groups,
    deny, expired/inactive token, multiple accounts/zones, provider failures
    → NEW-FIXTURE (broad fixture battery; see §7)

R9  Cloudflare authority resolution is deterministic across repeated identical token-info
    → NEW-FIXTURE (cloudflare_authority_stable_across_identical) — ties to S015 stability

R10 No secret leakage: only fingerprint + sanitized policy facts appear; never token values
    → NEW-FIXTURE (secret_sweep_never_leaks_cloudflare_token)
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required; fixture/output-driven and inherits Sprint 012 (account `3e2742bacdabcada586f921ad89bac77`). The Cloudflare adapter's `Client` accepts a `FixtureTransport` in tests (cloudflare.rs), so credential-type/scope/permission variants are exercised without network or real tokens. A live re-run with a real `cfut_` token would additionally exercise R1/R2/R5 end-to-end, but is optional.

---

# 6. Design Notes

## 6.1 Credential-type classification (R1, R4)
In discovery (src/discovery/agents/opencode.rs token readers + src/discovery/cloudflare.rs), classify `credential_type` by format: `cfut_` prefix => `api_token`; a 32+ hex/alnum global key shape => `api_key`; a `cwo_…`/`fou_…`/oauth shape => `oauth`. For `api_key`, the live `inspect` cannot use token endpoints, so `authority_for` returns `Exact` with `permission_state="GLOBAL_API_KEY"` and `unknown_reasons` including `GLOBAL_KEY_UNVERIFIED`. Keep BEHAVIORAL_READ_ONLY / no fabrication.

## 6.2 Scope combinations (R2, R3)
Extend `policy_facts` (src/discovery/cloudflare.rs) to collect **zone** ids (from `com.cloudflare.api.account.zone.<id>` resources) in addition to account ids; add `all_zones` and `explicit_zones`. `scope_for` resolves InScope for a matching account or zone. Recognize read permission groups (`Workers Scripts Read`) as read-only; write groups as before. Surface the granted write group **names** (e.g., "Workers Scripts Write") in `PolicyFacts`/`AuthorityObservation` so surfacing can list them.

## 6.3 Tier mapping (R5)
Keep `authority_for` four-tier logic; ensure zone-scoped write => `Exact` when the Worker's account/zone matches; unresolved scope => `Scoped`; read-only => `BehavioralReadOnly`; no write group + unverifiable => `Unknown`. The `can_mutate` Worker edge (scan.rs) stays the boundary seam (no regression to 013–017).

## 6.4 Surfacing (R6–R7)
Reuse S013–S017 seams. The explained finding (CLI `render.rs`, MCP `tools.rs`) states, per Cloudflare `can_mutate` edge: `credential_type`, `granted_permissions` (write group names), and `authority_resolution`. Extend sprint018 integration tests.

## 6.5 Fixtures (R8)
Sanitized battery: credential types (token/key/oauth), scope combos (account/zone/all/unresolved), read vs write groups, deny policy, expired/inactive token (status != active), multiple accounts/zones, and a provider-failure (PARTIAL — token-details 403, authorities Unknown but accounts/workers survive). Each asserts resolution + surfaced facts.

## 6.6 Stability (R9)
Identical token-info => identical classification (ties to S015 finding stability).

## 6.7 Support note (R10/DOC)
Author `docs/internal/sprints/SPRINT-018-support-note.md`: exactly what Cloudflare authority Pico can/cannot establish (credential-type aware; scope at account/zone granularity; global key unverified; read-only vs write; no non-allowlisted calls).

---

# 7. Fixtures (NEW-FIXTURE)

- `cloudflare_credential_type_classification` — api_token / api_key / oauth => expected type.
- `cloudflare_scope_combinations` — account / zone / all / unresolved => expected tier + scope.
- `cloudflare_read_vs_write_permission_groups` — Read => BEHAVIORAL_READ_ONLY; Write/Edit => write.
- `cloudflare_global_api_key_resolution` — api_key => EXACT + GLOBAL_KEY_UNVERIFIED.
- `cloudflare_authority_to_tier_table` — each combo => expected tier + boundary.
- broad battery (R8): types/scope/perm/deny/expired/multi-account-zone/provider-failure.
- `cloudflare_authority_stable_across_identical` (R9).

---

# 8. Architecture Pressure-Test

- Authority resolution is an analyzed interpretation of Cloudflare token policy / credential type (ARCHITECTURE §2.9 effective-state-over-declared); it feeds the existing Authority/Relationship/Boundary model; no new domain object.
- The resolver is pure and deterministic; reuses the boundary-evaluation contract (ARCHITECTURE §AD005). Zone scope reuses `valid_id`/resource collection.
- Secret-safety preserved: only credential fingerprint + sanitized permission-group names/account-zone ids; token VALUE never appears (ARCHITECTURE §7.7, ROADMAP §13.2). Global key authority is labeled unverified, never fabricated.
- No new provider; Cloudflare remains the only supported cloud authority surface.

---

# 9. Risks and Mitigations

- **Risk:** zone-scoped resources are easy to misclassify as account-scoped. *Mitigation:* collect zone ids distinctly; `scope_for` matches zone prefix; fixture R2 pins it.
- **Risk:** global API key authority is tempting to over-claim. *Mitigation:* label `GLOBAL_KEY_UNVERIFIED`; never assert specific Worker write without evidence.
- **Risk:** credential-type detection from format is heuristic. *Mitigation:* only three documented shapes; unrecognized => keep current `api_token` default + `unknown_reasons`.

---

# 10. Required Evidence Artifacts

- A1–A5 authority resolver + credential-type/scope/permission/tier fixtures (R1–R5).
- A6 CLI surfacing test (R6).
- A7 MCP surfacing test (R7).
- A8 broad sanitized fixture battery (R8).
- A9 stability fixture (R9).
- A10 secret-sweep extension (R10).
- A11 support note (§27, DOC-VERIFIED).
- A12 completed validation matrix (§4 / §27).

Evidence artifacts quote at most credential fingerprint + sanitized permission-group names/account-zone ids; never raw token values.

---

# 11. Commit Policy

Authoring-only document commit as:

```text
docs(sprints): define Sprint 018 Cloudflare authority resolution depth
```

Defect-fix or visibility commits use conventional messages naming the change, each containing its regression test, e.g.:

```text
feat(discovery): deepen Cloudflare authority across credential types and scope combos
test(discovery): Cloudflare credential-type, scope, permission fixtures
feat(cli): surface Cloudflare credential type and granted scopes
```

Do not amend previous commits. Do not push unless explicitly instructed. Do not begin Sprint 019.

---

# 12. Completion Evidence (filled at execution)

When validation concludes, set `Status: DONE` (or `BLOCKED`) and record:

```text
completion date and verified baseline
commits (authoring; any defect fixes; evidence record)
repository state
new fixtures (R1–R10) and their assertions
CLI/MCP Cloudflare-authority surfacing test additions
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

Do not claim v0.2 depth is "closed" merely because authority is deeper. Claim exactly what the matrix shows: Cloudflare authority is resolved across supported credential types and scope combinations, surfaced honestly, and mapped to the correct tier.

---

# 13. Final Report Contract

```text
Sprint: SPRINT-018 — Cloudflare Authority Resolution Depth
Status: DONE | BLOCKED
Baseline: <verified SHA>

Authority resolution:
  credential-type classification: PASS | FAIL
  scope combinations: PASS | FAIL
  read vs write permission groups: PASS | FAIL
  global API key: PASS | FAIL
  maps to correct tier/boundary: PASS | FAIL

Surfacing:
  CLI credential type + scopes: PASS | FAIL
  MCP credential type + scopes: PASS | FAIL

Fixtures:
  broad battery: PASS | FAIL
  stability across scans: PASS | FAIL

Validation matrix:
  R1-R10: <statuses>

Secret sweep: ZERO | INCIDENT
```

---

# 14. Advancement Decision Record (filled at execution)

Per ROADMAP §17. Records whether v0.2 depth is advanced, extended, refined, or stopped, and why the next v0.2 sprint (019) is justified.
