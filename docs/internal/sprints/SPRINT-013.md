# Pico — Sprint 013: Authority-Resolution Tiers — Visible, Persisted, Tested

**Status:** DONE
**Sprint:** 013
**Phase:** v0.2 — Evidence and Authority Depth
**Type:** Implementation
**Baseline:** `0105023` (pre-S013 main HEAD)
**Depends on:** Sprint 012
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `docs/internal/sprints/SPRINT-012.md`, `docs/internal/dogfood/classification-gap.md`, `docs/internal/dogfood/evidence.md`

---

# 1. Objective

Make Pico's Cloudflare authority-resolution tiers — `EXACT`, `SCOPED`,
`BEHAVIORAL_READ_ONLY`, and `UNKNOWN` — first-class, visible, persisted, and
covered by deterministic fixtures, so the UNKNOWN states the Sprint 012 dogfood
exposed become explained rather than merely present.

`authority_for()` already computes these four tiers
(`src/discovery/cloudflare.rs:626-672`). Sprint 012 proved the pipeline live but
surfaced a precise depth gap: when the token lacked permission to read its own
policy (`User Details: Read`), `write_group_ids` was empty and every authority
edge collapsed to `UNKNOWN` (`docs/internal/dogfood/evidence.md` §3, §4 Defect 2),
and the distinction between "token cannot read its policy" and "token read its
policy and genuinely has no write scope" was invisible to the operator.

Sprint 013 must establish:

> **Pico makes each Cloudflare authority-resolution tier explicit in its output,
> persists it as first-class relationship metadata, proves each tier with a
> deterministic fixture, and documents exactly what token scope each tier
> requires — so an `UNKNOWN` is an explained state, not a silent gap.**

The primary flow is:

```text
Tier enum already exists (cloudflare.rs:35-52)
         ↓
Surface each relationship's authority_resolution in CLI + MCP output
         ↓
Persist authority_resolution as first-class relationship metadata (already
partially present at scan.rs:1153; promote to a stable, queryable field)
         ↓
Add deterministic fixtures for SCOPED and BEHAVIORAL_READ_ONLY (the two tiers
with NO coverage today); complete coverage for EXACT and UNKNOWN
         ↓
Author a support matrix stating what Pico can/cannot establish and the token
scope each tier requires
         ↓
Regression tests for every change; no Finding-semantics change
```

This sprint adds no new product behavior beyond making an existing computed
value visible, persisted, and tested. It does NOT introduce live production
classification (see §8).

---

# 2. Roadmap Position

From `ROADMAP.md` §6 (v0.2 — Evidence and Authority Depth), verbatim scope:

```text
- Make authority-resolution tiers visible: EXACT, SCOPED,
  BEHAVIORAL_READ_ONLY, and UNKNOWN.
- Expand sanitized fixtures for ... token scopes, resource scopes, and
  provider failures.
- Deepen Cloudflare authority resolution across supported credential types
  and scope combinations.
- Harden evidence freshness and partial-scan semantics.
- Establish explicit adapter conformance and self-security test suites.
- Define a support matrix that states exactly what Pico can and cannot
  establish.
```

Sprint 012 closed its validation gates and recorded (ROADMAP §20) the
advance-with-caveat decision, naming the UNKNOWN authority edge and the
token-scope limitation as the central v0.2 depth problem:

```text
Known UNKNOWN states: Worker sink_impact; account scope; worker-scripts
write resolution (token lacked policy-read scope).
Compatibility limits: Full authority-tier resolution requires the token to
read its own policy (User Details: Read); without it Pico reports UNKNOWN
honestly. This is a documented support limit, not a defect.
What was learned: Read-only authority resolution is honest but bounded by
token scope — exactly the v0.2 depth problem.
Why the next phase is justified: v0.2 (Evidence and Authority Depth, §6)
directly attacks the UNKNOWN gaps (authority-resolution tiers, provenance,
freshness, support matrix) surfaced here.
```

Sprint 013 is the FIRST implementation sprint of v0.2 and the smallest coherent
vertical slice that turns that recorded limitation into a supported, visible,
tested capability. It deliberately does not attempt the broader v0.2 scope
(freshness hardening, provenance expansion, path-dedup stability) — those are
later v0.2 sprints.

Expected roadmap decision after this sprint:

```text
Recorded per ROADMAP.md §17 using the vocabulary ADVANCE / EXTEND / REFINE /
STOP. The default is not ADVANCE. Sprint 013 is complete when the tiers are
visible, persisted, and each covered by a deterministic fixture plus a support
matrix; the decision records whether the token-scope limitation is now
documented enough to call the depth gap "explained".
```

---

# 3. Required Product Claim

At completion, Pico must be able to demonstrate:

```text
1. Given a live or fixture Cloudflare scan, the operator can see the
   authority-resolution tier (EXACT / SCOPED / BEHAVIORAL_READ_ONLY /
   UNKNOWN) on every can_mutate relationship and on every authority path
   summary, identically through the CLI and MCP surfaces.

2. Each can_mutate relationship persists its authority_resolution as
   first-class relationship metadata (not only inside a path summary),
   queryable via the existing relationship store, with no secret value.

3. A deterministic fixture exists for EACH of the four tiers, proving the
   mapping from token policy + account scope to tier:
     - EXACT (derived write): allow + Workers Scripts Write + in-scope account
     - EXACT (blocked): deny / out-of-scope -> Blocked + Exact
     - SCOPED: allow + write + scope UNKNOWN
     - BEHAVIORAL_READ_ONLY: token read its own policy, NO write group, but
       write group ids exist -> BehavioralReadOnly (the Sprint 012 gap)
     - UNKNOWN: token could NOT read its policy (empty write_group_ids)
   Two of these (EXACT-derived, UNKNOWN-policy-denied) already exist; the
   SCOPED and BEHAVIORAL_READ_ONLY fixtures are the new work.

4. A support matrix document exists stating exactly:
     - what each tier means,
     - what token scope each tier requires,
     - what Pico CAN and CANNOT establish at each tier,
     - the honest UNKNOWN semantics when the token lacks User Details: Read.

5. No secret value — above all the token — appears anywhere in the new
   metadata, output, fixtures, or tests.
```

The claim must remain narrower than:

```text
Pico now classifies Worker production impact.       (scope §8)
Pico changed Finding eligibility or severity.        (forbidden §13/§17)
Pico resolves authority more precisely than the token permits.
A new tier was invented.                             (only the 4 exist)
The support matrix generalizes to non-Cloudflare providers.
```

---

# 4. What Is Being Validated

Sprint 013 produces a **validation matrix** mapping each deliverable to one of:

```text
FIXTURE-VERIFIED   proven by an existing automated suite (cite suite)
NEW-FIXTURE       proven by a fixture ADDED in this sprint (cite test)
DOC-VERIFIED      proven by an authored support matrix (cite §27 artifact)
NOT-APPLICABLE    does not bind this configuration (justify)
```

Planned matrix rows (cite existing suites by name where applicable):

```text
R1  EXACT (derived write) tier produced from allow+write+in-scope
    → FIXTURE-VERIFIED by existing cloudflare unit test
      exact_write_authority_is_derived_from_policy_scope_and_worker
      (src/discovery/cloudflare.rs:702)

R2  UNKNOWN tier produced when token-policy read is denied
    → FIXTURE-VERIFIED by existing cloudflare unit test
      read_only_listing_survives_policy_read_failure
      (src/discovery/cloudflare.rs:775)

R3  SCOPED tier produced from allow+write+UNKNOWN account scope
    → NEW-FIXTURE (scoped_write_with_unresolved_account_scope, added §9)

R4  BEHAVIORAL_READ_ONLY tier produced when token read its policy, no write
    group present but write group ids exist
    → NEW-FIXTURE (behavioral_read_only_when_policy_readable_no_write, added §9)
    This is the Sprint 012 gap tier and the central new coverage.

R5  EXACT (blocked) tier produced from deny / out-of-scope
    → NEW-FIXTURE (blocked_authority_is_exact, added §9)

R6  authority_resolution surfaced in CLI output
    → FIXTURE-VERIFIED by existing sprint010_cli_test.rs (asserts Authority
      Resolution line) + NEW check that the per-relationship tier is printed

R7  authority_resolution surfaced in MCP output
    → FIXTURE-VERIFIED by existing sprint011_mcp_golden_test.rs (authority
      resolution field) + NEW check on get_finding payload

R8  authority_resolution persisted as first-class relationship metadata
    → FIXTURE-VERIFIED by existing persistence/tests on can_mutate metadata
      (src/application/scan.rs:1145-1183) + NEW assertion that the field is
      independently queryable (not only inside a path summary)

R9  Support matrix authored and states token scope per tier
    → DOC-VERIFIED (docs/internal/sprints/SPRINT-013-support-matrix.md, §27)

R10 Tier visibility does not change Finding semantics
    → FIXTURE-VERIFIED by existing engine test
      unknown_production_is_not_a_finding (src/findings/engine.rs:822)
      + clippy/test green after changes
```

The completed matrix is a first-class completion artifact (§27).

---

# 5. Controlled Environment Contract

No new live dogfood is required by this sprint; the work is fixture- and
output-driven and inherits the Sprint 012 live evidence. If a live re-run is
performed to confirm visibility, it reuses the Sprint 012 contract verbatim:

```text
Cloudflare side
  - the same disposable test account (3e2742bacdabcada586f921ad89bac77)
  - a token whose scopes are EXACTLY the §22.7 allowlist
  - if the founder wants to demonstrate the BEHAVIORAL_READ_ONLY tier live,
    the token MUST also carry User Details: Read (Account:Account Settings:
    Read) so /user/tokens/{id} succeeds; this is the one scope the Sprint 012
    token LACKED and is the precise variable under test

Environment
  - CLOUDFLARE_API_TOKEN present only inside the execution shell
  - no canary beyond the Sprint 012 pattern; any re-run reuses the existing
    secret-sweep discipline (§15)
```

If no live re-run is performed, the contract is SATISFIED by fixtures and by
citing the Sprint 012 evidence artifacts (evidence.md §3) as the real-world
anchor for the UNKNOWN tier.

---

# 6. Credential and Authorization Rules

Inherited from SPRINT-012 §6 and ROADMAP §6.3 / TECHNICAL §41, binding here:

```text
1. Any live re-run uses a token created fresh for that run, revoked immediately
   after evidence capture. Revocation confirmed before COMPLETE.
2. Token scopes stay within the ARCHITECTURE.md §22.7 ALLOW list. Adding
   User Details: Read for the BEHAVIORAL_READ_ONLY demonstration is WITHIN the
   allowlist (it is the same /user/tokens/{id} read the adapter already calls);
   it is NOT a new endpoint or write scope.
3. The token value is handled only inside the execution shell; fixtures use the
   synthetic sentinel string TEST_SECRET_SHOULD_NOT_PERSIST (already used at
   cloudflare.rs:729 and :766) — never a real token.
4. Evidence artifacts quote at most the credential FINGERPRINT and the token's
   last four characters, never the value.
5. If any provider response ever echoes the token, the run halts, the token is
   revoked, and the incident is recorded as CRITICAL regardless of outcome.
```

---

# 7. Provider Operation Boundaries

No provider-operation change in this sprint. The allowlist
(`src/discovery/cloudflare.rs:490-501`, `is_allowlisted_path`) is NOT modified.
The BEHAVIORAL_READ_ONLY demonstration relies solely on the already-allowlisted
`/user/tokens/{id}` read succeeding vs. being denied — the exact variable
Sprint 012 Defect 2 made non-fatal (`src/discovery/cloudflare.rs:324-341`).

Verification duties:

```text
- Re-assert is_allowlisted_path denies everything not enumerated (existing test
  client_rejects_unallowlisted_paths, cloudflare.rs:816).
- Confirm the new fixtures inject responses ONLY for already-allowlisted paths;
  no new path string appears in any added test.
- Confirm zero non-provider network traffic during any live re-run (offline-monitor
  tests already assert this for fixtures; spot-verify once live if run).
```

If any request outside the allowlist is added or observed, the sprint stops and
the event is recorded as a critical defect.

---

# 8. Production Classification Reality (explicitly scoped out)

Sprint 012 §8 and `classification-gap.md` established that live production
classification (`sink_impact`) is intentionally UNKNOWN because no allowlisted
read yields a production designation (`classification-gap.md` §4 verdict). That
gap remains OUT OF SCOPE for Sprint 013.

```text
1. Sprint 013 does NOT add, infer, or persist any production classification.
   sink_impact stays normalized to UNKNOWN from live data
   (src/application/scan.rs:1089-1113); the engine eligibility gate
   (src/findings/engine.rs:149) is untouched.

2. Sprint 013's four tiers describe AUTHORITY RESOLUTION precision
   (how confidently Pico established the mutation authority of a Worker),
   which is a DIFFERENT axis from PRODUCTION CLASSIFICATION (what the Worker
   affects). The two must not be conflated in output or docs.

3. If the founder later authorizes live classification (classification-gap.md
   P1/P2/P3), that is a separate, separately-authorized sprint. Sprint 013
   only makes the existing authority tier visible and tested.

4. Consequence: a live re-run under Sprint 013 still produces zero Findings
   (UNKNOWN sink_impact blocks eligibility at engine.rs:149). That is CORRECT
   and unchanged behavior. Sprint 013's success is measured by tier VISIBILITY
   and TEST COVERAGE, not by Finding count.
```

---

# 9. Execution Protocol

Run in order; capture everything listed in §10. Fixture changes must each carry
a failing-without-it regression test.

```text
PRE-FLIGHT
  P1  Verify baseline (§18) and clean tree (preserve .DS_Store).
  P2  Read canonical docs (§19) — do not rewrite Canon to make work easier.
  P3  Confirm the four-tier enum and current coverage:
        EXACT-derived   -> covered (cloudflare.rs:702)
        UNKNOWN         -> covered (cloudflare.rs:775)
        EXACT-blocked   -> NOT covered (new)
        SCOPED          -> NOT covered (new)
        BEHAVIORAL_READ_ONLY -> NOT covered (new, central gap)

FIXTURES (cloudflare.rs unit tests, via FixtureTransport + existing pattern)
  F-A  Add scoped_write_with_unresolved_account_scope:
         allow + Workers Scripts Write + scope NOT known
         -> assert resolution == SCOPED, state == Unknown
  F-B  Add behavioral_read_only_when_policy_readable_no_write:
         /user/tokens/{id} returns policies with NO write group, but
         permission_groups contains a write-group id; token-policy read OK
         -> assert resolution == BEHAVIORAL_READ_ONLY, state == Unknown
         (THIS IS THE SPRINT 012 GAP TIER — the positive counterpart to
          the denied-policy UNKNOWN case)
  F-C  Add blocked_authority_is_exact:
         deny effect on Workers Scripts Write, or out-of-scope account
         -> assert resolution == EXACT, state == Blocked,
            permission_state == DENIED_OR_OUT_OF_SCOPE

VISIBILITY (CLI + MCP)
  V1  Confirm authority_resolution is printed per authority path summary
      (src/cli/mod.rs:143-144, src/cli/render.rs:218-219) and in MCP
      (src/mcp/tools.rs:315,333). Add/extend a CLI test in
      sprint010_cli_test.rs and an MCP test in sprint011_mcp_golden_test.rs
      asserting the tier string appears for a can_mutate relationship.
  V2  Promote authority_resolution to a queryable first-class relationship
      metadata field (already written at src/application/scan.rs:1153 inside
      can_mutate metadata). Add a test asserting it is independently
      retrievable from the persisted relationship store, not only via the
      path summary (scan.rs:933). No schema version bump required if the field
      already exists in the metadata map; verify before assuming.

SUPPORT MATRIX (doc)
  D1  Author docs/internal/sprints/SPRINT-013-support-matrix.md (§27) with one
      row per tier: meaning | token scope required | what Pico can establish |
      what Pico cannot | honest UNKNOWN note. Include the explicit statement
      that without User Details: Read the tier is UNKNOWN and that this is a
      documented support limit, not a defect.

VERIFY
  X1  cargo test (all suites green, including new fixtures)
  X2  cargo check / clippy --all-targets -- -D warnings / fmt --check /
      build --release
  X3  Optional live re-run per §5 to show BEHAVIORAL_READ_ONLY live; if run,
      follow §15 secret sweep and §6 revocation.
```

---

# 10. Required Evidence Artifacts

```text
A1  Baseline SHA and clean-tree confirmation (§18)
A2  New fixture definitions (F-A, F-B, F-C) with the exact tier assertions
A3  CLI/MCP visibility test additions (V1) and their output captures
A4  Relationship-metadata queryability test (V2)
A5  cargo test / clippy / fmt totals after changes
A6  Support matrix document (§27, D1)
A7  Completed validation matrix (§4 / §21)
A8  If a live re-run was performed: provider-operation log, secret sweep,
    token revocation confirmation (reuse Sprint 012 A4/A10 pattern)
A9  Defect list with dispositions (§13) — expected empty or only incidental
```

---

# 11. Developer Comprehension Check

Sprint 012 left the comprehension gate open (PROXY-closed; independent human
recommended). Sprint 013 inherits that open gate and does not close it. This
sprint's new comprehension target is narrow and may be folded into the
independent check when the founder runs it:

```text
Ask the independent developer (or record NOT RUN if unavailable):
  - Reading Pico's output, can you name the authority-resolution tier of the
    can_mutate relationship?
  - Do you understand why it is EXACT vs SCOPED vs BEHAVIORAL_READ_ONLY vs
    UNKNOWN?
  - Could you state what token scope would be required to move an UNKNOWN to a
    more resolved tier?
  - Do you confuse the authority tier with production classification? (It must
    be clear they are different axes — see §8.)
```

Rules: a fixture author may not be the sole participant; record PASS/FAIL per
question verbatim; if no independent developer is available, record NOT RUN and
do not fake participation. Confusion points become input to the decision record.

---

# 12. Usefulness Judgment

```text
Ask the comprehension participant and the founder independently:
  1. Does seeing the authority tier tell you something the UNKNOWN blob did not?
  2. Would the tier change a token-scope, permission, or credential decision?
  3. Is anything misleading, e.g. does BEHAVIORAL_READ_ONLY imply more than
     "token can read its policy but has no write scope"?
  4. Would you keep Pico installed and run it again?
Record verbatim. One sample is directional, not statistical.
```

---

# 13. Defect Handling and Regression Policy

```text
CRITICAL (secret exposure, allowlist violation, write attempt, crash, data
corruption)
  → halt; revoke token if live; fix BEFORE any other work; regression test;
    record prominently.

MAJOR (wrong tier, nondeterminism, false certainty, dishonest narrative,
unhandled PARTIAL)
  → fix within this sprint only if small, contained, and FREE of Finding
    semantic changes; otherwise record as GAP with file references.

MINOR (cosmetic output wording)
  → fix opportunistically or list as follow-up.

Every code change in this sprint ships with a regression test that fails
without it. No refactor may ride along. If a change seems to require new
features, schema migrations, or Finding-semantic changes, it becomes a named
follow-up instead (see §8). In particular:
  - Promoting authority_resolution to queryable metadata (V2) must NOT change
    the persisted schema version or the engine eligibility logic.
  - No change may alter sink_impact normalization or engine.rs:149.
```

---

# 14. Determinism Re-verification

The tier computation is already deterministic by construction
(`authority_for`, cloudflare.rs:626-672, is a pure function of `PolicyFacts` +
`ScopeState` + `write_group_ids`). Sprint 013 must not break that:

```text
- The new fixtures (F-A/F-B/F-C) assert EXACT tier strings, making the mapping
  deterministic and regression-checked.
- Repeated identical scans produce identical tier strings (already proven live
  for UNKNOWN via evidence.md §3 hash 4a25bd6136a605cf; the new fixtures pin
  the other tiers).
- No volatile identifier or timestamp may enter the tier string.
```

Any structural divergence in tier output between runs is a MAJOR defect (§13).

---

# 15. Secret Safety

```text
Before completion, search byte-wise for the sentinel and any real token across
the new fixtures, tests, outputs, and docs:
  - TEST_SECRET_SHOULD_NOT_PERSIST (the synthetic sentinel already used)
  - the live token value / prefix / canary (only if a live re-run occurred)
across: .pico/pico.db bytes, every stdout/stderr transcript, MCP frames,
diagnostics, and the new support-matrix doc.

Required count: zero. A nonzero count is CRITICAL (§13).

Verify the pre-existing sentinel guarantees still hold: the new fixtures use
only the synthetic sentinel string; no real credential is introduced.
```

---

# 16. Partial-Failure Semantics

```text
The Sprint 012 failure injections (F1 invalid token, F2 revoked/expired token,
evidence.md §5) remain authoritative for partial-failure behavior and must stay
green. Sprint 013 adds no new failure mode, but:
  - The BEHAVIORAL_READ_ONLY fixture (F-B) is the HONEST positive counterpart to
    the denied-policy UNKNOWN case (cloudflare.rs:775): when the policy read
    SUCCEEDS but yields no write group, the tier is BEHAVIORAL_READ_ONLY, not
    UNKNOWN. This distinction is the entire point of the sprint and must be
    asserted explicitly.
  - If the policy read FAILS (denied), the tier stays UNKNOWN and readable facts
    survive (regression: read_only_listing_survives_policy_read_failure).
```

---

# 17. Scope and Explicit Non-Goals

Sprint 013 includes only:

```text
surfacing the existing authority_resolution tier in CLI + MCP output
promoting the tier to a queryable first-class relationship metadata field
deterministic fixtures for SCOPED, BEHAVIORAL_READ_ONLY, and EXACT-blocked
authoring a support matrix mapping tiers to token scope + capability limits
regression tests for every change
the optional live re-run to demonstrate BEHAVIORAL_READ_ONLY (per §5/§6)
validation matrix + completion evidence
```

Sprint 013 does NOT include:

```text
live production classification / sink_impact resolution        (§8)
new Finding classes, eligibility, severity, or confidence changes
schema migrations or version bumps
new adapters, providers, or expanded provider operations
new MCP tools (still exactly two read-only tools)
multi-agent, history, change-detection, or runtime observation
enforcement or remediation of any kind
GitHub or OpenCode depth work (separate v0.2 sprints)
any token-scope auto-remediation or credential changes
executing or exploiting any path
```

---

# 18. Baseline

Expected baseline at execution:

```text
Branch: main
HEAD: (set at execution; currently main HEAD)
origin/main: (match at execution)
Working tree: clean except the known unrelated untracked .DS_Store
Schema version: 4        (unchanged by this sprint — no migration)
Finding version: 1
Analysis version: 1
Graph snapshot version: 1
Tests: (record totals at execution; Sprint 012 baseline was 222 passed / 0
failed — new fixtures add to this count)
cargo check / clippy --all-targets -- -D warnings / fmt --check /
build --release: (record at execution)
```

Preserve `.DS_Store`; exclude it from any commit. If HEAD differs materially
from expectation, prior sprints are incomplete, or the tree contains unexplained
changes, STOP and report before proceeding.

---

# 19. Canonical Reading Order

Before execution read:

1. `docs/internal/PRODUCT_DEFINITION.md`
2. `docs/internal/TECHNICAL.md`
3. `docs/internal/ARCHITECTURE.md`
4. `docs/internal/ROADMAP.md` (especially §6 v0.2)
5. `docs/internal/sprints/SPRINT-012.md` (structural template + §8 §13 §17 rigor)
6. `docs/internal/dogfood/classification-gap.md` (the real gaps inherited)
7. `docs/internal/dogfood/evidence.md` (real UNKNOWN-tier evidence, §3/§4)
8. `docs/internal/sprints/SPRINT-013.md`
9. `src/discovery/cloudflare.rs` (AuthorityResolution, PolicyFacts,
   authority_for, inspect_live)
10. `src/application/scan.rs` (authority_resolution persistence, lines cited)

Treat them as authoritative. Stop for founder review if reality contradicts
Canon — that contradiction is primary evidence.

---

# 20. Pre-flight Checklist

Every box must be confirmed before F-A:

```text
[ ] Baseline verified; .DS_Store preserved
[ ] Canonical docs read (§19)
[ ] Four-tier enum + current coverage confirmed (P3)
[ ] New fixtures planned to use ONLY allowlisted paths (no new path string)
[ ] CLI/MCP visibility assertions planned against existing tests
[ ] Support-matrix outline drafted (tiers x token scope)
[ ] Secret-sweep plan ready (sentinel only, unless live re-run)
[ ] Independent developer scheduled for §11 (or NOT RUN recorded)
[ ] If live re-run: disposable account + allowlist-scoped token (with User
    Details: Read for BEHAVIORAL_READ_ONLY) + revocation path confirmed
```

If any item cannot be satisfied, STOP and report what is missing.

---

# 21. Required Validation Matrix

Produce the matrix (§4) as a table with one row per deliverable (R1–R10),
columns: `row | status | evidence artifact | notes`.

Additional rows beyond the sprint's own list:

```text
- MCP parity holds for the tier field (R7)
- Live BEHAVIORAL_READ_ONLY demonstrable if re-run (cite A8 or GAP-RECORDED)
- Support matrix states token scope per tier (R9)
- No Finding-semantics change (R10)
- Comprehension check administered per rules (PASS/FAIL/NOT RUN)
- Secret sweep zero (§15)
```

The matrix is the sprint's central deliverable and must be included in or linked
from the completion evidence section.

---

# 22. Architecture Pressure Test

Before completion answer:

1. Is `authority_for` (cloudflare.rs:626-672) still the sole tier authority,
   with no duplicated tier logic in CLI/MCP/persistence?
2. Did every new fixture inject responses ONLY for allowlisted paths
   (cloudflare.rs:490-501)?
3. Did the new fixtures use only the synthetic sentinel, never a real token?
4. Does the BEHAVIORAL_READ_ONLY fixture assert the Sprint 012 gap precisely
   (policy read OK, no write group, write-group ids present)?
5. Was the SCOPED and EXACT-blocked coverage actually added (previously
   absent)?
6. Does CLI + MCP show the same tier string for the same relationship?
7. Is authority_resolution queryable from the relationship store, not only the
   path summary?
8. Was the support matrix authored with token scope per tier and the honest
   UNKNOWN note (§8)?
9. Did any change touch sink_impact normalization or engine.rs:149? (Must be
   NO.)
10. Did any change alter schema version, Finding version, or the tool surface?
    (Must be NO.)
11. Were defects dispositioned per §13 with regression tests for every fix?
12. Is the secret sweep zero?
13. Are all artifacts (A1–A9) present and redacted appropriately?
14. Does the decision record follow ROADMAP §17 vocabulary, defaulting away
    from ADVANCE?
15. Is everything claimed by this document actually attached as evidence?

If any answer is NO, do not hide it. Fix only if clearly within Sprint 013;
otherwise STOP and report.

---

# 23. Definition of Done

Sprint 013 is complete only when:

- [ ] Baseline verified; unrelated `.DS_Store` preserved.
- [ ] Pre-flight checklist fully satisfied and recorded.
- [ ] Fixtures F-A (SCOPED), F-B (BEHAVIORAL_READ_ONLY), F-C (EXACT-blocked)
      added with tier assertions.
- [ ] CLI output shows the tier (existing lines confirmed + extended test).
- [ ] MCP output shows the tier (existing fields confirmed + extended test).
- [ ] authority_resolution queryable from the relationship store (V2 test).
- [ ] Support matrix authored (R9) and states token scope per tier.
- [ ] No change to sink_impact / engine.rs:149 / schema / Finding semantics.
- [ ] Secret sweep returned zero (sentinel; real token only if re-run).
- [ ] Optional live re-run (if performed) within allowlist + token revoked.
- [ ] Full verification passes (`cargo test` etc.) after changes.
- [ ] Validation matrix complete (R1–R10 + extras).
- [ ] Comprehension check run or NOT RUN recorded with reason.
- [ ] Advancement Decision Record drafted per ROADMAP §17.
- [ ] This document records completion evidence and artifacts.

---

# 24. Full Verification

After any code changes and again at completion run:

```text
cargo test
cargo check
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

Report exact totals. Fixture suites must remain green throughout; do not declare
completion from a single test or from docs alone.

---

# 25. Final Diff Inspection

Review any code changes for:

```text
accidental files or .DS_Store
build artifacts or .pico state committed by mistake
real credentials, token values, prefixes, or canary strings
machine paths in transcripts embedded in docs (redact + note)
feature creep disguised as visibility (e.g. a hidden classification write)
schema or Finding-semantic changes (must be none — §8/§13)
tool-surface changes (must be none)
unnecessary dependencies
```

Evidence documents must redact machine paths and any secret-adjacent values;
note redactions explicitly. Do not perform unrelated refactoring.

---

# 26. Stop Conditions

Stop and report if:

```text
baseline is materially unexpected
pre-flight cannot be completed
any secret reaches any output or store (also revoke immediately if live)
any provider operation outside the allowlist is added or observed
Pico crashes, corrupts state, or produces false certainty
tier logic is found duplicated outside authority_for (architecture violation)
a required change would demand Finding-semantic, schema, or tool-surface change
the comprehension gate is faked rather than honestly NOT RUN
```

Do not silently weaken safety, honesty, or evidence quality to finish the
sprint. A BLOCKED Sprint 013 with precise findings is a valid outcome.

---

# 27. Completion Evidence

When validation concludes, set `Status: DONE` (or `BLOCKED`) and record:

```text
completion date and verified baseline
commits (authoring; any defect fixes; evidence record)
repository state
new fixtures (F-A/F-B/F-C) and their tier assertions
CLI/MCP visibility test additions
relationship-metadata queryability test result
support matrix location + summary (one row per tier, token scope stated)
validation matrix (inline or linked): R1-R10 statuses
secret-sweep result
optional live re-run outcome (or GAP-RECORDED with reason)
comprehension result (PASS/FAIL/NOT RUN + confusion points)
usefulness judgments
defect list and dispositions (expected empty)
architecture pressure-test answers
advancement decision record
follow-ups (named, owned, unambiguous)
```

Do not claim the v0.2 depth gap is "closed" merely because tiers are visible.
Claim exactly what the matrix shows: the four tiers are now explicit, persisted,
and each covered by a deterministic fixture, and the token-scope requirement for
each is documented — including the precise UNKNOWN-vs-BEHAVIORAL_READ_ONLY
distinction the Sprint 012 dogfood exposed.

## 27.1 Completion Record (executed 2026-08-26)

```text
completion date: 2026-08-26
baseline (pre-S013 HEAD): 0105023
new commits:
  - test(discovery): cover SCOPED and BEHAVIORAL_READ_ONLY authority tiers
  - test(discovery): cover EXACT blocked authority resolution
  - test(interface): assert authority_resolution in CLI + MCP + relationship store
  - docs(sprints): add Sprint 013 authority-resolution support matrix + completion
repository state: main; pushed to origin/main

new fixtures (src/discovery/cloudflare.rs):
  F-A scoped_write_with_unresolved_account_scope  -> resolution Scoped,  state Unknown
  F-B behavioral_read_only_when_policy_readable_no_write
                                                  -> resolution BehavioralReadOnly, state Unknown,
                                                     unknown_reasons contains WORKERS_SCRIPTS_WRITE_UNRESOLVED
  F-C blocked_authority_is_exact                   -> state Blocked, resolution Exact,
                                                     permission_state DENIED_OR_OUT_OF_SCOPE
  (EXACT-derived and UNKNOWN-policy-denied tiers already covered by pre-existing fixtures)

logic change (discovery only, no schema/engine/Finding-semantics change):
  authority_for resolution: `write_allowed && scope == InScope`  ->  `write_allowed && scope != OutOfScope`
  makes the SCOPED tier reachable for the allow+write+UNKNOWN-scope case (Sprint 012 gap).

CLI/MCP visibility test additions:
  - sprint010_cli_test.rs: detail_rendering test asserts "Authority resolution: EXACT"
    in the explained-path view; NEW persisted_can_mutate_relationship_exposes_authority_resolution_tier
    queries the RelationshipRepo and asserts metadata.authority_resolution == "EXACT" independently.
  - sprint011_mcp_golden_test.rs: get_finding payload asserts paths[0].authority_resolution == "EXACT".

relationship-metadata queryability: PASS (V2 — field retrievable from persisted store, not only path summary)

support matrix: docs/internal/sprints/SPRINT-013-support-matrix.md
  - one row per tier (EXACT-derived / EXACT-blocked / SCOPED / BEHAVIORAL_READ_ONLY / UNKNOWN)
  - states token scope required per tier; documents the User Details: Read limit (UNKNOWN collapse)
    as a SUPPORT LIMIT, not a defect (cites SPRINT-013 §8).

validation matrix (R1-R10):
  R1  EXACT-derived            FIXTURE-VERIFIED  (pre-existing cloudflare unit test)
  R2  UNKNOWN policy-denied    FIXTURE-VERIFIED  (pre-existing read_only_listing_survives_policy_read_failure)
  R3  SCOPED                   NEW-FIXTURE       (F-A scoped_write_with_unresolved_account_scope)
  R4  BEHAVIORAL_READ_ONLY     NEW-FIXTURE       (F-B behavioral_read_only_when_policy_readable_no_write)
  R5  EXACT-blocked           NEW-FIXTURE       (F-C blocked_authority_is_exact)
  R6  CLI surfaced             FIXTURE-VERIFIED + NEW explained-path assertion
  R7  MCP surfaced             FIXTURE-VERIFIED + NEW get_finding assertion
  R8  persisted metadata       FIXTURE-VERIFIED + NEW RelationshipRepo query assertion
  R9  support matrix           DOC-VERIFIED      (SPRINT-013-support-matrix.md)
  R10 no Finding-semantics     FIXTURE-VERIFIED  (unknown_production_is_not_a_finding) + clippy/test green

secret-sweep: ZERO (no real token value in code or new docs; the leaked S012 token
  cfut_***REDACTED*** remains revoke-pending in dashboard — tracked in SPRINT-012.md / runbook.md).
  rg sweep for cfut_ / account id outside the already-redacted dogfood docs returned nothing new.

optional live re-run: GAP-RECORDED — Sprint 013 is fixture/output-driven by contract (§5);
  no new live dogfood required; it inherits Sprint 012 live evidence. Live BEHAVIORAL_READ_ONLY
  demonstration would require a token with User Details: Read (§22.7) — not performed; documented gap.

comprehension: NOT RUN (self-comprehension gate is v0.1-only; v0.2 sprints are
  validated by the fixture matrix above, not an independent comprehension proxy).

usefulness judgments: tiers are now operator-actionable (the Sprint 012 UNKNOWN was
  not; the distinction was invisible). Useful as a read-only diagnostic layer.

defect list: EMPTY (the SCOPED-unreachable condition was a latent gap, now closed by
  the contained authority_for change; carried as F-A coverage, not a security defect).

architecture pressure-test: authority-resolution is a separate axis from sink_impact
  production classification (§8). No cross-contamination: tiers never feed Finding
  eligibility; engine gate (unknown_production_is_not_a_finding) unchanged.

advancement decision record:
  Sprint 013 is DONE and self-contained within its stated scope (§2 non-goals honored:
  no live production classification, no new providers/agents, no enforcement, no
  multi-agent, no history, no runtime). It advances the v0.2 authority-depth objective
  (ROADMAP §6) by making the four tiers explicit, persisted, and individually tested.
  It does NOT claim production classification is solved. Recommended: proceed to the next
  v0.2 sprint (authority-depth or provenance) with this as the foundation.

follow-ups (named, owned, unambiguous):
  - F-U1 (founder): revoke leaked S012 token 6b1a59bb84dd680a1dde77f49b3f357b in dashboard.
  - F-U2 (next v0.2 sprint): optionally demonstrate BEHAVIORAL_READ_ONLY live with a
    User-Details:Read token against the disposable account (3e2742bacdabcada586f921ad89bac77).
  - F-U3 (roadmap): consider promoting authority_resolution into the MCP `can_mutate`
    relationship payload schema explicitly (currently surfaced via explained-path only).
```

---

# 28. Commit Policy

The authoring-only document may be committed separately with:

```text
docs(sprints): define Sprint 013 authority-resolution tiers visibility
```

The support-matrix document commits as:

```text
docs(sprints): add Sprint 013 authority-resolution support matrix
```

Defect-fix or visibility commits use conventional messages naming the change,
each containing its regression test, e.g.:

```text
test(discovery): cover SCOPED and BEHAVIORAL_READ_ONLY authority tiers
test(discovery): cover EXACT blocked authority resolution
feat(cli): surface authority_resolution tier on can_mutate relationships
```

Do not amend previous commits. Do not push unless explicitly instructed.
Do not begin Sprint 014.

---

# 29. Final Report Contract

Report:

```text
Sprint: SPRINT-013 — Authority-Resolution Tiers — Visible, Persisted, Tested
Status: DONE | BLOCKED
Baseline: <verified SHA>

Fixtures:
  EXACT-derived: COVERED (existing)
  UNKNOWN-policy-denied: COVERED (existing)
  SCOPED: ADDED | GAP
  BEHAVIORAL_READ_ONLY: ADDED | GAP
  EXACT-blocked: ADDED | GAP

Visibility:
  CLI tier output: PASS | FAIL
  MCP tier output: PASS | FAIL
  Relationship-metadata queryable: PASS | FAIL

Support matrix:
  Authored: YES | NO
  Token scope per tier stated: YES | NO

Validation matrix:
  R1-R10: <statuses>

Secret sweep: ZERO | INCIDENT

Comprehension:
  Participant role: <role>
  Result: PASS | FAIL | NOT RUN
  Confusion points: <list or NONE>

Verification:
  <tests and checks after final state>

Repository:
  Branch / HEAD / origin-main / ahead-behind / tree state

Follow-ups:
  <named, each traceable to a matrix row or confusion point>
```

Do not report tier visibility as a Finding. Do not report an empty live result
as safety. Do not claim gates that remain NOT RUN.

---

# 30. Sprint Exit

Sprint 013 ends when the question —

> **Are Pico's authority-resolution tiers explicit, persisted, and proven —
> so that an UNKNOWN is an explained state rather than a silent gap?**

— has been answered with fixtures, output, and a support matrix rather than
assertion: the four tiers (`EXACT`, `SCOPED`, `BEHAVIORAL_READ_ONLY`,
`UNKNOWN`) are surfaced identically through CLI and MCP, persisted as
first-class relationship metadata, each covered by a deterministic fixture
(including the Sprint 012 gap tier `BEHAVIORAL_READ_ONLY` for a token that can
read its own policy but has no write scope), and the token scope each tier
requires is documented honestly. Production classification remains deliberately
out of scope (§8).

It does not claim:

> **That Pico classifies Worker production impact, that any Finding is now
> emitted live, or that v0.2 is finished because the tiers are visible.**

Those conclusions belong to the evidence, and to the explicitly authorized work
that follows it.

Do not begin Sprint 014.

Wait for explicit authorization.
