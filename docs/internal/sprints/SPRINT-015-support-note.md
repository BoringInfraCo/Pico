# Pico — Sprint 015 Support Note: Finding Fingerprint, Deduplication & Remediation Cut Points

**Status:** reference note, not a sprint doc.
**Sprint:** 015 (cited in `docs/internal/sprints/SPRINT-015.md` §2 identity-stability and §5 remediation-cut-point sections).
**Audience:** operator / reviewer. Defines the supported, documented behavior for finding fingerprint stability, same-sink path deduplication, and deterministic severity/confidence/remediation axes introduced by Sprint 015. This note is DOC-VERIFIED; the assertions it makes are backed by the engine tests cited in `SPRINT-015.md` §7.

---

## 1. Finding fingerprint is a pure hash of security-significant content

A `Finding.fingerprint` is `sha256:` over a deterministic, length-prefixed record containing:

- the **finding/analysis version** (`FINDING_VERSION`),
- the finding **class** (`UNTRUSTED_TO_PRODUCTION`),
- the **source / actor / sink** canonical identities,
- every **path fingerprint** (`attack_path_fingerprints`),
- the **severity** and **confidence** tier strings, and
- every **remediation rule id**.

Each `attack_path_fingerprint` itself already incorporates the **boundary evaluations** along the path (`engine.rs` folds boundary decisions into the path fingerprint), so a boundary change is a security-significant change at the path level and therefore at the finding level.

Consequences, both exercised by the engine tests:

- **Identical environments yield identical fingerprints.** Re-running analysis over the same normalized graph and the same analysis version produces the same `sha256:` string; the fingerprint is not a function of `scan_id`, timestamps, or insertion order.
- **Security-significant changes flip the fingerprint predictably.** Changing a path's boundary evaluation, a severity/confidence tier, a source/actor/sink identity, or adding/removing a remediation rule changes the hashed input and therefore the fingerprint. This is what makes a finding *stable yet honest*: stable across redundant scans, distinct the moment something security-relevant moves.

---

## 2. Deduplication groups same-sink paths without hiding distinct boundaries

Multiple attack paths that reach the same production sink are grouped into **one** Finding when they share the same deterministic `grouping_key` (`source;actor;authority;severity;confidence`) **and** identical path fingerprints (`candidates.dedup_by(path.fingerprint)`). The authority set in the grouping key is derived from the critical `AUTHORITY`-role edges of each path.

Because the path fingerprint **includes boundary evaluations**, two paths that would otherwise look identical by endpoints still remain **distinct** when their boundaries differ materially:

- Same critical edges + same boundary decisions → deduplicated into one grouped path; the grouped-path count (`attack_path_fingerprints.len()`) reflects the surviving paths.
- Distinct boundary decisions (e.g. one path carries a `DoesNotInterrupt` evaluation, another does not) → different path fingerprints → the paths are not collapsed, so a materially weaker boundary is never hidden behind a stronger one.

The grouped-path count exposed on the surface (`FindingDetail.attack_path_fingerprints.len()`, rendered as `Grouped paths: N`) is exactly this deduplicated set — it is the faithful count of security-distinct paths, not a raw edge tally.

---

## 3. Severity and confidence are independent, deterministic axes

Severity and confidence are computed separately and never inferred from one another. Both are fail-closed: when their preconditions are not fully met, the candidate is dropped (no Finding), rather than downgraded.

**Severity** is a function of `source_trust` only:

- `SourceTrust::PublicExternal` or `SourceTrust::OpenWorld` → **CRITICAL**.
- `SourceTrust::AuthenticatedExternal` → **HIGH**.
- Anything else (or an ineligible candidate) → **no Finding**.

**Confidence** is **HIGH** if and only if *every* path and *every* production Evidence is **non-Inferred** and of class **Direct | Declared | Derived** (`evidence_quality` gate). If any critical edge's supporting or production Evidence is `Inferred`, or the production class is not in `{Direct, Declared, Derived}`, the candidate fails closed → **no Finding**.

**Boundaries fail closed.** Any boundary evaluation whose `decision != DoesNotInterrupt` disqualifies the candidate entirely (it is not folded into a weaker Finding). The active-Finding eligibility gate therefore only admits paths whose recorded boundaries `DoesNotInterrupt`.

These two axes are surfaced independently on every view (`Severity:` / `Confidence:`) and never conflated.

---

## 4. Remediation cut points are deterministic

Remediations are derived purely from the critical edges of the grouped paths: each edge `kind` maps to exactly one rule (e.g. `can_execute` → `ENFORCE_BASH_APPROVAL_OR_DENY`, `can_access`/`uses_credential`/`authenticates_to` → `REMOVE_AGENT_CREDENTIAL_REACHABILITY`, retrieval edges → `RESTRICT_EXTERNAL_RETRIEVAL`, `can_mutate`/`can_deploy` → `SCOPE_PRODUCTION_MUTATION_AUTHORITY`). The rule set and their `cut_phase` (`INFLUENCE`/`AUTHORITY`) are fixed and ordered, so the same graph always yields the same cut points.

`ENFORCE_BASH_APPROVAL_OR_DENY` deterministically targets the **Bash → credential authority edge** — the `can_execute` relationship through which the autonomous Actor reaches the authority-bearing credential. Its `target_relationship_ids` and the human-readable `target_relationship_descriptions` (e.g. `Agent -> Bash (can_execute)`) are computed from the same edge, so the cut point is reproducible across scans and surfaces identically through the CLI and MCP views.

---

**Scope boundary:** This note covers finding fingerprint stability, same-sink path deduplication, and the deterministic severity/confidence/remediation axes for Sprint 015 only. It does not authorize any credential change or write probe and contains **no secrets or real token values** — credential identities are referenced only by their non-secret fingerprint-bearing canonical key (`credential:cloudflare:<fingerprint>`).
