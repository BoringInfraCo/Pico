# Pico — Sprint 014 Support Note: Freshness, Provenance & Canonical-Identity Rules

**Status:** reference note, not a sprint doc.
**Sprint:** 014 (cited in `docs/internal/sprints/SPRINT-014.md` §4 validation matrix R-DOC and §10 artifact A9).
**Audience:** operator / reviewer. Defines the supported, documented behavior for evidence freshness, provenance completeness, and canonical-key stability introduced by Sprint 014. This note is DOC-VERIFIED; the assertions it makes are backed by the fixtures cited in `SPRINT-014.md` §7.

---

## 1. Freshness windows (config constants, golden-path preserving)

Freshness is derived, never stored as free text (see `SPRINT-014.md` §6.2). Classification compares the `Evidence.captured_at` timestamp against the **scan reference time** (the current scan's coherent snapshot time, per `ARCHITECTURE.md` §8.6) using two documented config constants:

- `FRESH_WINDOW_SECS = 3600` — one hour.
- `AGING_WINDOW_SECS = 86400` — one day.

`freshness_state` classification by age `= scan_reference_time − captured_at`:

| State | Condition |
|-------|-----------|
| **FRESH** | `age ≤ FRESH_WINDOW_SECS` (≤ 1h). |
| **AGING** | `FRESH_WINDOW_SECS < age ≤ AGING_WINDOW_SECS` (>1h, ≤1d). |
| **STALE** | `age > AGING_WINDOW_SECS` (>1d), **or** the evidence originates from a `PARTIAL` scan where the contributing adapter failed. |
| **UNKNOWN** | `captured_at` absent, or source semantics unavailable. |

These are **config constants, documented here** (`SPRINT-014.md` §9 risk: "windows are config-derived constants with fixtures; defaults documented in the support note"). The defaults are **default-preserving for the golden path**: an evidence set that is `FRESH` and `COMPLETE` yields **no behavior change** — no confidence penalty, no integrity error, no new finding semantics. The penalty path (R3/R4) only engages on `STALE`/`PARTIAL` evidence.

---

## 2. Canonical-key rules

A `canonical_key` (`ARCHITECTURE.md` §5.3) must contain **only stable identifiers**: provider, account id, worker name, resource kind. It must **NEVER** contain `scan_id`, timestamps, random ids, or secret values (§5.3: "Canonical keys must never contain secret values" — extended in `SPRINT-014.md` §6.3 to "never contain volatile values"). This is what makes identity stable across repeated scans (R5).

Supported resource kinds and their canonical_key shapes:

| Kind | canonical_key shape |
|------|---------------------|
| agent | `agent:opencode:default` |
| mcp_server | `mcp:github:server` |
| mcp_tool | `mcp:github:tool:<name>` |
| shell | `shell:bash` |
| credential | `credential:cloudflare:<fingerprint>` |
| provider_account | `cloudflare:account:<id>` |
| worker | `cloudflare:worker:<account>:<name>` |
| repository | `github:repo:<owner>/<repo>` |
| issue | `github:issue:<owner>/<repo>#<n>` |

`<fingerprint>` and `<id>` are non-secret, stable identifiers (the credential fingerprint is a hash reference; never the raw token value). No `scan_id`, no `captured_at`, no random `ev_*` id appears in any key.

---

## 3. Provenance contract (integrity error when missing)

Every **security-critical edge** (`Relationship.kind` ∈ `can_mutate`, `authorizes`, `can_execute`, `can_call`, `can_access`, `can_write`, `can_deploy`) — and every `Finding` — must carry at least one `Evidence` with **all four** provenance fields (`SPRINT-014.md` §2, §6.1, R1):

- `source_type`
- `source_locator`
- `captured_at`
- a non-empty freshness classification (`freshness_state`)

Missing provenance on a security-critical edge is an **integrity error**, not a silent pass (mirrors the S013 `non_production_sink_impact_on_linked_path_is_an_integrity_error` gate). `source_locator` is a path/identifier (e.g. `~/.config/opencode/opencode.json`), never a secret value (`ARCHITECTURE.md` §7.7, `SPRINT-014.md` §8).

---

## 4. Freshness/provenance ≠ production classification (do not conflate)

Freshness and provenance address **EVIDENCE TRUST** — is the supporting evidence recent, complete, and attributable? This is a **different axis** from **production classification** (`sink_impact`), which answers *what a resource affects in production* (production vs. staging vs. dev).

- `sink_impact` remains normalized to **`UNKNOWN`** and is **out of Sprint 014 scope** (cite `SPRINT-013.md` §8 and `SPRINT-013-support-matrix.md` §1).
- The two axes must never be merged in output or docs. A `STALE` evidence set is not "more production" than a `FRESH` one — it is merely *less trusted on the evidence axis*.
- Sprint 014 changes only evidence trustworthiness and identity stability; it does not emit new Findings on the production-classification axis (engine eligibility gate unchanged, `SPRINT-013-support-matrix.md` §4).

---

**Scope boundary:** This note covers evidence freshness, the provenance contract, and canonical-key stability for Sprint 014 only. It does not assert production classification, does not authorize any credential change or write probe, and contains no secrets or real token values.
