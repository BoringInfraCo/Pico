# Pico — Sprint 013 Cloudflare Authority-Resolution Support Matrix

**Status:** README-style reference, not a sprint doc.
**Sprint:** 013 (R9 / D1, cited in `docs/internal/sprints/SPRINT-013.md` §27).
**Provider:** Cloudflare only. This matrix does **not** generalize to OpenCode, GitHub, or Bash.
**Source of truth:** `src/discovery/cloudflare.rs` — `AuthorityResolution` (lines 35–52), `policy_facts` (lines 558–606), `authority_for` (lines 626–672). The tier is a pure function of `PolicyFacts` + `ScopeState` + `write_group_ids`; no other module derives it.

> **Appendix (Sprint 020):** Claude Code is now a **supported agent** for the
> same authority tiers. Sprint 020 added the Claude Code adapter
> (`src/discovery/agents/claude.rs`) as a second agent surface on the *same*
> normalized Bash-`can_execute` model and the *same* authority-resolution tiers
> documented below. Claude Code is **config-only**: it contributes an actor, a
> Bash effective state, and MCP-server facts, but no credential facts — the
> Cloudflare token/authority projection stays exclusively OpenCode-sourced.
> See `docs/internal/sprints/SPRINT-020-support-note.md` for the full Claude
> conformance statement. The tiers below therefore apply unchanged to whichever
> agent surfaces a path; per-agent Bash posture is additionally surfaced per the
> Sprint 020 R6/R7 contract.

**Live anchor:** the real `UNKNOWN` tier from the Sprint 012 dogfood — scan `scan_18cf730d87996f48_0`, account `3e2742bacdabcada586f921ad89bac77`, where the token lacked `User Details: Read` and every authority edge collapsed to `UNKNOWN` with `unknown_reasons [ACCOUNT_SCOPE_UNRESOLVED, WORKERS_SCRIPTS_WRITE_UNRESOLVED]` (`docs/internal/dogfood/evidence.md` §3).

---

## 1. The two axes (do not conflate)

**Statement 1 — different axes.**

The authority-resolution tier describes **AUTHORITY-RESOLUTION PRECISION**: how confidently Pico established that a Cloudflare token can mutate (write to) a Worker. It is a **different axis** from **PRODUCTION CLASSIFICATION** (`sink_impact`), which answers *what the Worker affects in production* (e.g. production vs. staging vs. local dev).

- `sink_impact` stays normalized to `UNKNOWN` from live data and is **out of Sprint 013 scope** (cite `SPRINT-013` §8).
- The two must never be merged in output or docs. A `BEHAVIORAL_READ_ONLY` token is not "safer" or "more production" than an `UNKNOWN` token — it is merely *more resolved on the authority axis*.

---

## 2. Support matrix — one row per tier

Columns: **Tier** · **Meaning** · **Token scope required** · **What Pico CAN establish** · **What Pico CANNOT establish** · **Honest UNKNOWN note**.

| Tier | Meaning | Token scope required | What Pico CAN establish | What Pico CANNOT establish | Honest UNKNOWN note |
|------|---------|----------------------|--------------------------|----------------------------|---------------------|
| **EXACT** (derived write) | Token policy **allows** Workers Scripts Write against an **in-scope** account, and the catalog carries the write group id. Resolution `EXACT`, state `Derived`. (`authority_for` lines 645–651.) | `User Details: Read` (Account: Account Settings: Read) so `/user/tokens/{id}` succeeds **+** a policy with `effect: allow` on `Workers Scripts Write`/`Edit` **+** an in-scope account resource (explicit account id or `*` all-accounts) **+** `Workers Scripts: Read` to list. Without `User Details: Read` the tier collapses to `UNKNOWN`. | The token is *derived* to be able to mutate the Worker: write permission is present, scoped, and confirmed. | What the Worker does in production (`sink_impact`); any finer-grained effect beyond "has write authority"; cross-account reach the policy named. | This is the highest-confidence authority state. It is still **not** a production classification — `sink_impact` remains `UNKNOWN`. |
| **EXACT** (blocked) | Token policy **denies** Workers Scripts Write, or scopes the write to an **out-of-scope** account. Resolution `EXACT`, state `Blocked`. (`authority_for` lines 637–643.) | `User Details: Read` (so the policy is readable) **+** a policy with `effect: deny` on Workers Scripts Write **OR** a write permission whose account resource resolves `OutOfScope`. | The token is *derived* to be **unable** to mutate the Worker: write is denied or confined to accounts Pico observed as out-of-scope. State is `Blocked`, not `Unknown`. | Whether the block is intentional vs. misconfigured; `sink_impact`; whether other tokens could still mutate. | "Exact" here means *precisely blocked*, not *precisely authoritative*. No write authority is claimed. |
| **SCOPED** | Token policy **allows** Workers Scripts Write, but the account **scope is unresolved** (`scope_known == false`). Resolution `Scoped`, state `Unknown`. (`authority_for` lines 653–661, branch `write_allowed && scope == InScope` *not* taken because scope is `Unknown`.) | `User Details: Read` **+** `effect: allow` on Workers Scripts Write **+** a policy that does **not** resolve an in-scope or out-of-scope account resource (no explicit account id and no `*` in `resources`). | Write authority is *likely* present but bounded by an **unresolved account scope**: Pico knows the permission, not the exact account boundary the write applies to. | Which specific accounts the write reaches; whether the write is truly in-scope. Account scope is reported `UNKNOWN`. | `SCOPED` is an honest *partial* resolution: write is confirmed, account boundary is not. Not the same as `UNKNOWN` — write authority is established. |
| **BEHAVIORAL_READ_ONLY** | Token **read its own policy successfully** (User Details: Read succeeded), the policy contains **no write effect**, yet the permission-group **catalog contains a Workers Scripts Write group id**. Resolution `BehavioralReadOnly`, state `Unknown`. (`authority_for` lines 661–664; this is the Sprint 012 gap tier, `SPRINT-013` §3 R4.) | `User Details: Read` (policy readable) **+** a readable policy with **no** Workers Scripts Write effect **+** `/user/tokens/permission_groups` returning a `Workers Scripts Write`/`Edit` group id. | The token can read its own policy, has **no write authority** over Workers, but Pico observed that the catalog *could* grant write — so the read-only state is established by evidence, not assumed. | Any write authority; `sink_impact`. The absence of write in the policy is confirmed, not inferred from the catalog alone. | This is the **positive counterpart** to the denied-policy `UNKNOWN` case: policy read *succeeded*, so the read-only conclusion is evidence-backed. Without `User Details: Read` it would instead be `UNKNOWN`. |
| **UNKNOWN** | Token **could NOT read its own policy** (policy-read denied or empty `write_group_ids`), so no tier beyond "unknown" can be derived. Resolution `Unknown`, state `Unknown`. (`authority_for` lines 663–664; `SPRINT-013` §3 R2, `evidence.md` §3.) | None of the resolving scopes present — typically **missing `User Details: Read`** (so `/user/tokens/{id}` is denied and `write_group_ids` stays empty) **or** the catalog returns no Workers Scripts Write group id. | That the token is active and can list accounts/Workers (read-only facts survive, per `evidence.md` Defect 2 fix); that authority resolution is **honestly `UNKNOWN`**. | Whether the token can write; whether its account scope is in/out; `sink_impact`. Every write-relevant fact is unresolved. | `UNKNOWN` is an **explained state**, not a defect. In the Sprint 012 dogfood the token lacked `User Details: Read`, so all edges were `UNKNOWN` with `[ACCOUNT_SCOPE_UNRESOLVED, WORKERS_SCRIPTS_WRITE_UNRESOLVED]`. This is the documented support limit. |

---

## 3. The `User Details: Read` support limit (documented, not a defect)

**Statement 2 — collapse to UNKNOWN is a documented support limit.**

Without `User Details: Read` (Cloudflare permission: `Account: Account Settings: Read`), Pico cannot call `/user/tokens/{id}` to read the token's own policy. `policy_facts` then receives no policy (`cloudflare.rs` line 558–565 default) and `write_group_ids` is empty, so **every** authority edge collapses to `UNKNOWN` (`authority_for` line 663–664).

> **This is a documented support limit, NOT a defect.** The read-only account/Worker facts are still projected and the `UNKNOWN` is reported with explicit `unknown_reasons`. The Sprint 012 dogfood (account `3e2742bacdabcada586f921ad89bac77`) exercised exactly this limit and the pipeline behaved correctly.

The token scope that moves an `UNKNOWN` toward a more-resolved tier:

| Adding this token scope | Moves an `UNKNOWN` toward |
|--------------------------|---------------------------|
| **`User Details: Read`** (so `/user/tokens/{id}` succeeds) | `BEHAVIORAL_READ_ONLY` (no write effect in policy but catalog has write group id) **or** `EXACT` (if the now-readable policy grants/denies write) |
| **Workers Scripts Write present in the readable policy** | `SCOPED` (allow + unresolved scope) **or** `EXACT` derived (allow + in-scope account) |
| **An in-scope account resource in the readable policy** (explicit id or `*`) | `EXACT` derived (allow + write + in-scope) |

In short: `User Details: Read` is the prerequisite that unlocks any non-`UNKNOWN` tier; the write group id and account scope then determine which of `EXACT` / `SCOPED` / `BEHAVIORAL_READ_ONLY` applies.

---

## 4. What Pico can / cannot establish — tier summary

- **At `EXACT` (derived or blocked):** Pico *can* establish the definitive mutation authority (granted or denied) with confidence. Pico *cannot* establish `sink_impact` (production classification stays `UNKNOWN`).
- **At `SCOPED`:** Pico *can* establish that write authority exists but the account boundary is unresolved. Pico *cannot* name the exact accounts in scope.
- **At `BEHAVIORAL_READ_ONLY`:** Pico *can* establish, from a successfully read policy, that the token has no write authority while the catalog could grant it. Pico *cannot* establish any write authority or `sink_impact`.
- **At `UNKNOWN`:** Pico *can* establish only that the token is active and lists read-only facts; it *cannot* establish any write authority, scope, or production classification — and says so explicitly.

**Statement 3 — no live Finding is emitted, and that is correct.**

Because `sink_impact` stays `UNKNOWN`, the engine eligibility gate (`src/findings/engine.rs:149`, normalization at `src/application/scan.rs:1089–1113`) remains closed. **No `Finding` is emitted live** at any authority tier — this is unchanged and correct. Sprint 013 changes **only** tier *visibility* and *persistence*, never Finding semantics, severity, or eligibility. An `UNKNOWN` authority edge is an explained state, not a Finding trigger.

---

## 5. Scope boundary

This matrix covers **Cloudflare authority-resolution tiers only**. It does not assert production classification, does not cover other providers, and does not authorize any credential change or write probe. All four tiers and their token-scope requirements above are the complete, supported set (`SPRINT-013` §3; `ROADMAP.md` §6 v0.2 authority-depth scope).
