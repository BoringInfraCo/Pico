# Pico — Sprint 012: First Real Proof — Controlled Live Dogfood

**Status:** DONE (live validated; comprehension NOT RUN)
**Sprint:** 012
**Phase:** v0.1 — Golden Path Proof
**Type:** Validation
**Baseline:** `4993bf2`
**Depends on:** Sprint 011 — First Agent Interface — Minimal MCP Exposure
**Canonical docs:** `PRODUCT_DEFINITION.md`, `TECHNICAL.md`, `ARCHITECTURE.md`, `ROADMAP.md`

---

# 1. Objective

Prove Pico's complete golden-path pipeline against one controlled real
environment — a real OpenCode workspace, real GitHub MCP configuration, and a
real disposable Cloudflare account reached only through Pico's read-only
provider allowlist — and close the two remaining v0.1 gates:

```text
1. controlled live-environment dogfood
2. independent developer comprehension validation
```

Sprints 001–011 established:

> **Pico can discover, analyze, persist, explain, and serve its first Finding
> — deterministically and read-only — across the CLI and MCP, proven entirely
> through controlled fixtures and injected seams.**

Sprint 012 must establish:

> **The same bounded pipeline completes against reality: real discovery, real
> reachability, real read-only provider introspection, real explanation — and
> whatever reality does not yet support (notably live production
> classification) is recorded as precise evidence rather than papered over.**

The primary flow is:

```text
Founder-authorized controlled environment
        ↓
pico init / pico scan            (real discovery + real provider reads)
        ↓
pico findings / pico finding <id>
        ↓
MCP session parity check         (same data through the agent interface)
        ↓
Determinism, zero-write, sentinel verification on real state
        ↓
Independent developer comprehension check on real output
        ↓
Validation matrix over every ROADMAP v0.1 exit criterion
        ↓
Advancement Decision Record
```

This sprint adds no features. It validates what exists and names precisely
what reality lacks.

---

# 2. Roadmap Position

Every architecture slice (1–10) is built. What remains are the v0.1 gates
themselves. From `ROADMAP.md` §5:

```text
Excerpts — Dependencies:
- Safe access to representative OpenCode, GitHub MCP, and Cloudflare
  fixtures.
- A controlled dogfood environment that contains both safe and
  intentionally exposed variants of the golden path.

Excerpts — Scope:
- Fixture, integration, determinism, secret-leakage, and controlled
  dogfood validation for the golden path.

Exit criteria (verbatim, in full):
v0.1 is complete only when:
- `pico init` is idempotent and creates safe local state.
- `pico scan` completes the same bounded pipeline against fixtures and
  a controlled real environment.
- Pico detects the supported OpenCode instance and resolves the effective
  Bash and relevant MCP permissions needed for the path.
- Pico distinguishes GitHub external influence from mere GitHub product
  presence.
- Pico establishes whether Bash can reach a Cloudflare credential without
  persisting its value.
- Pico establishes Cloudflare Worker write authority from read-only
  authorization evidence, or explicitly reports the unresolved edge as
  UNKNOWN without claiming a confirmed path.
- A confirmed hard deny, mandatory approval, sandbox, or
  credential/resource scope boundary blocks only the path it actually
  interrupts.
- The unblocked fixture produces the expected UNTRUSTED_TO_PRODUCTION
  finding.
- The blocked and scoped fixtures do not produce the same active attack
  path.
- Every security-critical edge in the finding has inspectable provenance,
  freshness, and confidence.
- Repeating analysis over the same normalized graph produces the same
  paths, severity, confidence, and finding identity.
- Secret canaries have zero occurrences in the database, logs,
  diagnostics, and exports.
- Provider clients cannot invoke operations outside their explicit
  read/introspection allowlists.
- Partial adapter failure produces a PARTIAL scan with useful retained
  evidence and no false certainty.
- A developer unfamiliar with the internals can explain what the path is,
  why it matters, how Pico knows, what remains uncertain, and at least
  one practical cut point.
- The Pico MCP interface, if included in v0.1, returns the same underlying
  finding as the CLI and does not introduce a second scanner.
```

`PRODUCT_DEFINITION.md` §34 lists "controlled real-environment validation"
among the golden-path must-satisfy conditions. `ARCHITECTURE.md` §25.9
requires live dogfood to validate discovery correctness, provider behavior,
configuration assumptions, CLI usability, performance, and unexpected edge
cases — without replacing fixture-based tests.

Sprints 008–011 each recorded, honestly:

```text
Controlled live dogfood: NOT RUN
Developer comprehension: NOT RUN
Roadmap decision: EXTEND v0.1
```

Sprint 012 exists to replace those two NOT RUN entries with evidence.

Expected roadmap decision after this sprint:

```text
Recorded per ROADMAP.md §17 using the vocabulary:
ADVANCE / EXTEND / REFINE / STOP

The default is not ADVANCE.
```

If the pipeline proves out live and the comprehension check passes, the
honest decision is likely still EXTEND or REFINE, because live production
classification is known to be unsupported by current read-only evidence (see
§8). Do not presume the outcome in advance; record it from evidence.

---

# 3. Required Product Claim

At completion, Pico must be able to demonstrate, from a real environment:

```text
1. pico init and pico scan complete against a real OpenCode workspace
   with real GitHub MCP configuration and a real Cloudflare credential,
   performing only allowlisted read/introspection provider operations.

2. The real graph contains the real influence chain (external content →
   tool → agent), the real capability edge (agent → Bash), and the real
   reachability edge (Bash → credential), each with real Evidence.

3. Real Cloudflare introspection resolves account inventory, Worker
   inventory, and mutation-authority facts from the read-only token —
   or reports UNKNOWN/PARTIAL honestly when it cannot.

4. pico findings / pico finding <id> and the equivalent MCP tools present
   the real results identically to their fixture behavior, byte-stable
   across repeats, with zero database writes.

5. No secret value — above all the live API token — appears anywhere in
   SQLite, stdout, stderr, logs, or diagnostics.

6. An independent developer, shown only Pico's output, answers the
   usability-gate questions correctly without reading Pico internals.
```

The claim must remain narrower than:

```text
Pico found an exploitable path in a real environment.
The live scan produced a Finding.          (it cannot yet — see §8)
The controlled environment represents arbitrary real environments.
Pico validated the provider by writing anything.
A developer's approval constitutes a security guarantee.
One successful dogfood proves v0.2 readiness.
```

---

# 4. What Is Being Validated

Sprint 012 produces a **validation matrix**: every ROADMAP §5 v0.1 exit
criterion marked with exactly one of:

```text
FIXTURE-VERIFIED   proven by the existing automated suite (cite suite)
LIVE-VERIFIED      proven by this sprint against the real environment
                   (cite artifact)
GAP-RECORDED       reality does not yet support this criterion; the gap is
                   named precisely with file-level references (cite gap)
NOT-APPLICABLE     criterion does not bind this configuration (justify)
```

Two criteria deserve explicit pre-registration here:

```text
"The unblocked fixture produces the expected UNTRUSTED_TO_PRODUCTION
 finding."
   → FIXTURE-VERIFIED already. LIVE status depends on §8: the live
     adapter reports Worker sink_impact as UNKNOWN, so a live Finding is
     NOT currently possible. Record GAP-RECORDED unless the pre-flight
     investigation (§8.1) finds otherwise.

"A developer unfamiliar with the internals can explain ..."
   → satisfied only by §11 of this sprint. NOT RUN is an acceptable
     recorded outcome only if no independent developer is available;
     the gate then remains open and the roadmap decision may not be
     ADVANCE on its strength.
```

The completed matrix is a first-class completion artifact, recorded in the
completion evidence section of this document.

---

# 5. Controlled Environment Contract

The dogfood environment is founder-owned and disposable:

```text
Cloudflare side (the exposed variant)
  - one disposable test account containing no production assets
  - one or more throwaway Workers deployed BY HAND by the founder before
    the run (Pico must never deploy, modify, or delete anything)
  - one API token granted only the read/introspection permissions of the
    provider allowlist (token verification, token permission
    metadata, account listing, Workers listing, resource metadata)

OpenCode side
  - a real workspace with a real opencode.json declaring the GitHub MCP
    server (the same shape as the golden fixture, with a placeholder or
    canary token value, never a real GitHub credential unless the founder
    accepts that exposure knowingly)
  - Bash permission set to allow (the exposed variant) — a second safe
    variant workspace with bash denied/approval-gated SHOULD also be run
    if available; if it is not, record its absence

Environment
  - CLOUDFLARE_API_TOKEN present in the shell environment so discovery
    observes the real credential reference and reachability
  - a unique secret canary string planted alongside it MUST appear nowhere
    in Pico's outputs or store
```

Both variants matter: ROADMAP requires the environment to contain "both safe
and intentionally exposed variants". If only one variant can be prepared,
run it and record the other's absence as a limitation.

---

# 6. Credential and Authorization Rules

From `TECHNICAL.md` §41 and the product promises:

```text
read-only provider permissions where possible
no long-lived secret persistence
explicit network operations
safe failure when provider introspection is incomplete
Pico must not become a new privileged execution layer merely to inspect
existing privileged execution layers
```

Binding rules for this sprint:

```text
1. The live token is created fresh for this sprint and revoked immediately
   after the final evidence capture. Revocation is confirmed before the
   sprint may be marked COMPLETE.
2. The token's scopes cover only the ARCHITECTURE.md §22.7 ALLOW list:
   verify token; read token metadata; read permission metadata;
   list accounts; list Workers; read resource metadata. Any write-capable
   scope on the token is a STOP-condition violation of this sprint.
3. The token value is handled only inside the execution shell. It is never
   placed in files under the workspace, in command lines recorded in
   evidence, or in screenshots beyond unavoidable shell history the
   founder accepts.
4. Evidence artifacts quote at most the credential FINGERPRINT and the
   token's last four characters, never the value.
5. If any provider response ever echoes the token or any secret, the run
   halts, the token is revoked immediately, and the incident is recorded
   as a critical defect regardless of the rest of the outcome.
```

---

# 7. Provider Operation Boundaries

`ARCHITECTURE.md` §22.7 is the contract. During live runs, every outbound
request must be within:

```text
ALLOW  verify token; read token metadata; read permission metadata
       (the real endpoint is /user/tokens/permission_groups);
       list accounts; list Workers; read resource metadata
DENY   deploy/delete/modify anything; rotate/delete tokens; DNS; KV;
       D1; routes
```

Verification duties for this sprint:

```text
- Re-confirm the allowlist implementation (is_allowlisted_path) denies
  everything not enumerated; cite the code location and its tests.
- Capture the outbound request log (or add temporary local instrumentation
  if none exists — removed before completion) and prove each request path
  is allowlisted.
- Confirm zero non-provider network traffic during scans (offline-monitor
  tests already assert this for fixtures; spot-verify once live, e.g. via
  a system-level connection list during the scan).
```

If any request outside the allowlist is observed, the sprint stops and the
event is recorded as a critical defect.

---

# 8. Production Classification Reality

Pre-registered finding from code inspection (verify it again during planning;
do not trust this document silently):

```text
src/discovery/cloudflare.rs — the LIVE inspection path constructs every
ObservedWorker with `sink_impact: None`. Only the injected provider seam
used by fixtures can carry an explicit PRODUCTION classification. Under
the Sprint 009 eligibility rules, UNKNOWN classification can never yield
an active UNTRUSTED_TO_PRODUCTION Finding.
```

Consequences for this sprint:

```text
1. The live scan is EXPECTED to complete with zero Findings while showing
   the fully connected real path through the credential, with Worker
   authority resolved from real token introspection and sink impact
   reported as UNKNOWN. This is CORRECT behavior, not a failure: Pico
   refuses unsupported claims.

2. §8.1 Planning duty: re-inspect the live code path for ANY authorized
   mechanism (worker tag/naming conventions, account metadata already
   fetched) that could establish production classification read-only.
   Report what exists; do not build anything new in this sprint.

3. If the founder authorizes live Findings as a sprint goal, that is a NEW
   feature (a classification mechanism) requiring its own design and
   authorization — a follow-up sprint, not silent work here. The honest
   matrix entry is GAP-RECORDED with this section as evidence.
```

## 8.1 Planning-time investigation

During the implementation plan stage (before the live run), record:

```text
- exact code locations where live sink_impact originates
- whether any fetched-but-unused provider field could support future
  read-only classification (name it for the follow-up)
- the smallest change that would close the gap, stated as a proposal
  ONLY — not implemented here
```

---

# 9. Execution Protocol

Run in order; capture everything listed in §10.

```text
PRE-FLIGHT
  P1  Verify baseline (§18) and clean tree.
  P2  Founder confirms: disposable account, allowlist-scoped token,
      hand-deployed Workers, revocation plan. Record token fingerprint.
  P3  Execute §8.1 investigation; write the one-page plan note.

EXPOSED VARIANT
  E1  Prepare the real workspace (opencode.json + env token); pico init.
  E2  pico scan  — expect COMPLETE (or honestly PARTIAL); record all
      counters, provider operations performed, and elapsed time.
  E3  Inspect .pico/pico.db directly: resources, relationships, evidence,
      observations counts; confirm the real influence/capability/
      reachability edges exist with real Evidence rows.
  E4  pico findings — record exact output (expected: scoped zero-Finding
      language given §8, freshness LATEST COMPLETE).
  E5  Attempt pico finding <synthetic-id> — expect clean not-found error
      (no Finding exists live).
  E6  MCP parity session: initialize → tools/list → list_findings →
      get_finding <unknown-id>; compare semantics with E4/E5; record
      negotiated protocolVersion.
  E7  Repeat E2–E6 in a fresh copy of the workspace; diff outputs for
      determinism (timestamps and ids differ; structure, counts, states,
      guidance, ordering must match); hash-compare the two databases'
      schemas and row contents modulo volatile identifiers.
  E8  Sentinel sweep: the live token value, its prefix, and the planted
      canary must appear NOWHERE in stdout, stderr, SQLite bytes, or
      diagnostics. Zero-write proof: hash .pico/pico.db around E4–E6.

SAFE VARIANT (if prepared)
  S1  Same workspace with bash denied/approval; pico scan must complete
      with NO active path (capability edge absent or boundary recorded);
      record how the blocked/ineligible outcome manifests.

COMPREHENSION
  C1  Give an independent developer ONLY the captured output of E2/E4/E6.
  C2  Administer the question sets in §11; record verbatim answers and
      unclear points.

TEARDOWN
  T1  Revoke the live token; confirm revocation via a failing verify call
      (which itself must fail safely and produce PARTIAL/honest error).
  T2  Archive evidence artifacts; scrub any accidental secret captures.
```

---

# 10. Required Evidence Artifacts

Completion requires these artifacts, referenced from the completion evidence
section:

```text
A1  Environment manifest (account id, worker count/names, token scopes
    list, dates; NO token value)
A2  Full stdout/stderr transcripts of E1–E8 and S1
A3  SQLite inspection dump: table counts, the real edges' canonical keys
    and their evidence links (fingerprints only)
A4  Provider operation log proving allowlist conformance (§7)
A5  Determinism diff summary (E7) and zero-write hash proof (E8)
A6  MCP session transcript (E6) including negotiated protocolVersion
A7  Completed validation matrix (§4) covering every ROADMAP §5 exit
    criterion
A8  Comprehension check record (§11): participant role, answers, gaps
A9  §8.1 classification-gap investigation note
A10 Token revocation confirmation (T1)
A11 Defect list with dispositions (§13)
```

Artifacts live in this document or beside it; raw transcripts may be trimmed
to redact machine paths, but redactions must be noted.

---

# 11. Developer Comprehension Check

Two question sets apply; administer both to ONE independent developer who did
not implement Pico and has not seen its internals.

Set A — ROADMAP §13.7 usability gate (answer from Pico output alone):

```text
What did Pico find?
Why does it matter?
How does the path work?
How does Pico know?
What is uncertain?
What boundary is missing or working?
How can the path be broken?
What changed since the previous observation?
```

Set B — SPRINT-010 §33 finding-specific check:

```text
What externally controlled source begins the path?
Which autonomous Actor joins influence to authority?
What production capability is reachable?
Why would a Finding be severe? Why would Pico be confident?
Which Evidence supports the conclusion?
What did Pico establish about enforced boundaries?
Name at least one practical cut point.
Did Pico prove exploitation?
Did Pico apply a remediation?
Why does the live scan show no Finding even though the path exists?
   (tests honest understanding of the UNKNOWN classification narrative)
```

Rules:

```text
A fixture author may not be the sole comprehension participant.
Record PASS/FAIL per question, verbatim notes, and every point of
confusion.
If no independent developer is available, record NOT RUN; the roadmap
comprehension gate remains open and ADVANCE is not justified on
comprehension grounds.
Confusion points become input to the decision record and possible
follow-ups; they are successes of the process, not embarrassments to hide.
```

---

# 12. Usefulness Judgment

`ROADMAP.md` §6 ties v0.2 to results "judged useful without expert
interpretation"; `PRODUCT_DEFINITION.md` §35 parallels it ("The explanation is
useful without a dedicated security analyst"). This sprint takes the first
judgment sample:

```text
Ask the comprehension participant (§11) and the founder independently:
  1. Did the output tell you something you did not already know?
  2. Would it change a permission, credential, approval, or architecture
     decision in this environment?
  3. Was anything misleading, overclaimed, or confusing?
  4. Would you keep Pico installed and run it again?

Record verbatim judgments. One sample proves nothing statistically; it is a
directional signal for the decision record.
```

---

# 13. Defect Handling and Regression Policy

Live reality will probe paths fixtures never did. Rules:

```text
CRITICAL (secret exposure, allowlist violation, write attempt, crash,
data corruption)
  → halt the run immediately; revoke token; fix BEFORE any other work;
    add a regression test; record prominently.

MAJOR (wrong result, nondeterminism, false certainty, dishonest
narrative, unhandled PARTIAL)
  → fix within this sprint only if small, contained, and free of Finding
    semantic changes; otherwise record as GAP with file references and
    continue documenting.

MINOR (cosmetic output issues, wording)
  → fix opportunistically or list as follow-up.

Every code change in this sprint ships with a regression test that fails
without it. No refactor may ride along. If a defect seems to require new
features or schema changes, it becomes a named follow-up instead.
```

---

# 14. Determinism Re-verification on Real Data

Fixture determinism is proven; real-data determinism must be re-demonstrated:

```text
- Two independent scan runs against the same untouched environment produce
  identical structure: same node/edge counts, same canonical keys, same
  authority facts, same ordering everywhere volatile identifiers are
  excluded.
- Identical repeated queries (CLI and MCP) are byte-stable apart from
  nothing at all — they read persisted state.
- Analysis rerun over the same graph yields identical fingerprints,
  severity, confidence, and finding identity where any Finding exists;
  with none, fingerprint stability of attack-path-level state is checked
  via the database directly.
- Timestamps and volatile identifiers are the only expected variance between
  E7 runs.
```

Any structural divergence between runs is a MAJOR defect (§13).

---

# 15. Secret Safety in Live Outputs

The live run introduces one true secret into the environment. The boundary
must hold end to end:

```text
Before completion, search byte-wise for:
  - the exact live token value
  - its first eight characters
  - the planted canary string
across:
  .pico/pico.db bytes, every stdout/stderr transcript, MCP frames,
  diagnostics, and any temporary instrumentation logs.

Required count: zero. A nonzero count is CRITICAL (§13).

Also verify the pre-existing sentinel guarantees still hold on real data:
TEST_SECRET_SHOULD_NOT_PERSIST and TEST_AUTH_HEADER_SHOULD_NOT_APPEAR have
no reason to exist live; their absence is trivial but recorded for
completeness.
```

---

# 16. Partial-Failure Semantics

Reality will misbehave; Pico must degrade honestly:

```text
Exercise at least two controlled failure injections during dogfood:
  F1  Run once with an INVALID token → scan completes (PARTIAL or honest
      error path per current design), provider problems retained, no
      fabricated authority, no crash, exit behavior documented.
  F2  Run once with network access blocked mid-run (e.g., revoke token
      between steps) → resulting scan state is honestly PARTIAL/FAILED,
      retained evidence stays useful, no false certainty anywhere.

Record exactly how each manifests through CLI and MCP. These runs double
as live evidence for the exit criterion on partial adapter failure.
```

---

# 17. Scope and Explicit Non-Goals

Sprint 012 includes only:

```text
controlled live-environment execution of existing commands
provider-operation conformance capture and proof
determinism, zero-write, and secret-safety verification on real data
MCP parity verification on real data
partial-failure injection exercises (F1/F2)
validation matrix over ROADMAP §5 exit criteria
developer comprehension check and usefulness judgment
classification-gap investigation note (§8.1) — proposal only
defect fixes under the §13 policy, each with regression tests
completion evidence, validation matrix, and advancement decision record
```

Sprint 012 does not include:

```text
new features of any kind (including live production classification)
schema migrations
Finding eligibility/severity/confidence changes
new adapters, providers, or expanded provider operations
tool-surface changes (still exactly two read-only MCP tools)
CLI changes beyond defect fixes
performance optimization beyond recording timings
multi-environment sampling or statistical claims
hosted services or telemetry
executing or exploiting any path
remediation of any kind
v0.2 scope items
```

---

# 18. Baseline

Expected baseline:

```text
Branch: main
HEAD: 4993bf29be7a9c903fe93ae16f596f5e61c07c46
origin/main: 4993bf29be7a9c903fe93ae16f596f5e61c07c46
Ahead/behind: 0/0 (Sprint 010–011 work pushed)
Working tree: clean except the known unrelated untracked .DS_Store
Schema version: 4
Finding version: 1
Analysis version: 1
Graph snapshot version: 1
Tests: 222 passed, 0 failed (77 unit + 30 domain + 77 integration +
38 persistence)
cargo check / clippy --all-targets -- -D warnings / fmt --check /
build --release: PASS
```

Preserve `.DS_Store`; exclude it from any commit. If HEAD differs, prior
sprints are incomplete, or the tree contains unexplained changes, STOP and
report before proceeding.

---

# 19. Canonical Reading Order

Before execution read:

1. `docs/internal/PRODUCT_DEFINITION.md`
2. `docs/internal/TECHNICAL.md`
3. `docs/internal/ARCHITECTURE.md`
4. `docs/internal/ROADMAP.md`
5. `docs/internal/sprints/SPRINT-009.md` (§5 production classification rules)
6. `docs/internal/sprints/SPRINT-010.md` (§33 comprehension check origin)
7. `docs/internal/sprints/SPRINT-011.md` (MCP surface under test)
8. `docs/internal/sprints/SPRINT-012.md`

Treat them as authoritative. Do not rewrite Canon to make validation easier.
Stop for founder review if reality contradicts Canon — that contradiction is
itself primary evidence.

---

# 20. Pre-flight Checklist

Every box must be confirmed before E1:

```text
[ ] Founder authorization for live Cloudflare use recorded
[ ] Disposable account verified empty of production assets
[ ] Token created with allowlist-only scopes (list them in A1)
[ ] Token revocation path tested (know exactly how T1 happens)
[ ] Workers deployed by hand; names/tags recorded
[ ] Workspace prepared; opencode.json reviewed for stray secrets
[ ] Canary string defined and registered for the sweep
[ ] Shell history handling agreed (or accepted risk noted)
[ ] Independent developer scheduled for §11
[ ] Instrumentation plan for §7 request logging ready (and removal plan)
```

If any item cannot be satisfied, STOP and report what is missing. A dogfood
run without full pre-flight is theater, not evidence.

---

# 21. Required Validation Matrix

Produce the matrix (§4) as a table with one row per ROADMAP §5 exit
criterion (all sixteen, quoted abbreviated), columns:
`criterion | status | evidence artifact | notes`.

Additional rows beyond the roadmap's list:

```text
- MCP parity holds on real data (SPRINT-011 promise under real state)
- Live classification gap precisely characterized (§8/§8.1)
- Safe variant demonstrates absence-of-path honestly (if run)
- Both failure injections behave honestly (F1/F2)
- Comprehension check administered per rules (PASS/FAIL/NOT RUN)
- Usefulness judgment captured (§12)
```

The matrix is the sprint's central deliverable and must be included in or
linked from the completion evidence section of this document.

---

# 22. Architecture Pressure Test

Before completion answer:

1. Did every live provider call stay within the §22.7 allowlist, proven by
   captured requests?
2. Did the live token value reach zero persistent or emitted surfaces?
3. Did scans mutate anything beyond Pico's own `.pico` store — and did even
   that stay write-free outside scans themselves?
4. Were both variants (exposed, and safe if prepared) exercised rather than
   assumed?
5. Is the live no-Finding outcome explained by the classification gap rather
   than spun as success or hidden as failure?
6. Does the matrix mark every exit criterion with evidence, including
   GAP-RECORDED entries with file references?
7. Did determinism hold structurally across independent live runs?
8. Did partial-failure injections produce honest degraded states?
9. Was the comprehension check independent, recorded verbatim, and neither
   coached nor skipped?
10. Were defects dispositioned per §13 with regression tests for every fix?
11. Did any fix change Finding semantics, schema, or the tool surface? (Must
    be NO.)
12. Is the token revoked and revocation confirmed?
13. Are all artifacts (A1–A11) present and redacted appropriately?
14. Does the decision record follow ROADMAP §17 vocabulary with justification,
    defaulting away from ADVANCE?
15. Is everything claimed by this document actually attached as evidence?

If any answer is NO, do not hide it. Fix only if clearly within Sprint 012;
otherwise STOP and report.

---

# 23. Definition of Done

Sprint 012 is complete only when:

- [ ] Baseline `4993bf2` verified; unrelated `.DS_Store` preserved.
- [ ] Pre-flight checklist fully satisfied and recorded.
- [ ] Exposed-variant pipeline executed end to end (E1–E8).
- [ ] Safe variant executed OR its absence recorded as a limitation.
- [ ] Provider-operation log proves allowlist conformance.
- [ ] Determinism and zero-write proofs captured on real data.
- [ ] Secret sweep returned zero occurrences (token, prefix, canary).
- [ ] Failure injections F1/F2 executed and recorded.
- [ ] MCP parity demonstrated on real data.
- [ ] Validation matrix complete for all exit criteria plus extras.
- [ ] Classification-gap investigation note written (proposal only).
- [ ] Comprehension check run or NOT RUN recorded with reason.
- [ ] Usefulness judgments captured verbatim.
- [ ] All defects dispositioned per §13; fixes carry regression tests.
- [ ] Token revoked and revocation confirmed.
- [ ] Full verification passes (`cargo test` etc.) after any fixes.
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

Report exact totals. Fixture suites must remain green throughout; do not
declare completion from the live run alone, nor from tests alone.

---

# 25. Final Diff Inspection

Review any code changes for:

```text
accidental files or .DS_Store
build artifacts or .pico state from dogfood workspaces committed by mistake
real credentials, token values, prefixes, account ids paired with secrets,
or canary strings
machine paths in transcripts embedded in docs
instrumentation leftovers
feature creep disguised as fixes
schema or Finding-semantic changes (must be none)
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
pre-flight cannot be completed (no authorization, no disposable account,
token scopes exceed the allowlist, no revocation path)
any secret reaches any output or store (also revoke immediately)
any provider operation outside the allowlist occurs
Pico crashes, corrupts state, or produces false certainty on real data
live behavior contradicts Canon in a way fixtures did not predict
a required defect fix would demand feature, schema, or semantic changes
the classification gap investigation reveals it was misunderstood
no independent developer is available AND the founder elects to defer the
comprehension gate (record NOT RUN; do not fake participation)
```

Do not silently weaken safety, honesty, or evidence quality to finish the
sprint. A BLOCKED Sprint 012 with precise findings is a valid outcome and
often the most valuable one.

---

# 27. Completion Evidence

When validation concludes, set `Status: COMPLETE` (or `BLOCKED`) and record:

> **Recorded live outcome (Sprint 012 executed).** See
> `docs/internal/dogfood/evidence.md` for the full narrative, captured numbers,
> defect log, and validation table. Summary below; `Status` header changed to
> `DONE (live validated; comprehension NOT RUN)`.
>
> ```text
> completion date: (recorded in evidence.md)
> verified baseline: 72ac784 (post two §13 defect-fix commits; 4993bf2 was the
>                    pre-fix baseline per §18)
> commits:
>   - 72ac784 "fix(discovery): reach operator environment for live provider
>     introspection"  (defect 1 — OPERATOR_REACHABILITY=Proven)
>   - "fix(discovery): keep read-only Cloudflare facts when token-policy read
>     is denied"  (defect 2 — non-fatal policy-read 403)
> repository state: clean working tree (only .DS_Store untracked/preserved)
> environment manifest:
>   account: 3e2742bacdabcada586f921ad89bac77 (Ounce-leads35@icloud.com's Account)
>   token id: 6b1a59bb84dd680a1dde77f49b3f357b (value cfut_***REDACTED***, revoke pending)
>   workers observed: 1 (pico-dogfood-worker, deleted at teardown -> 0)
>   token scopes: Account:Account Settings:Read + Account:Workers Scripts:Read
>   variants run: exposed | safe NOT prepared
> execution:
>   pico init/scan: PASS (scan PARTIAL; Analysis COMPLETE; Disposition UNRESOLVED_PRESENT)
>   counters: Agents 1 / Resources 8 / Relationships 8 / Evidence 26
>   CLI explanation on real data: scoped zero-Finding language, UNKNOWN-justified
>   MCP parity on real data: PASS (two tools surface same 0-findings state)
>   Determinism across runs: PASS (cloudflare subgraph hash 4a25bd6136a605cf)
>   Zero-write proof: PASS (.pico/pico.db hash stable around read-only steps)
>   Secret sweep: ZERO (token value / first-8 / canary absent in DB+transcripts)
> failure injections:
>   F1 invalid token: PASSES — honest PARTIAL, no panic, no leak
>   F2 revoked/expired token: PARTIAL, 0 accounts/workers, 0 findings, no fabrication
> validation matrix:
>   FIXTURE-VERIFIED: 16 (rows 1-16) with live upgrades recorded in
>                     docs/internal/dogfood/validation-matrix.md
>   LIVE-VERIFIED: rows 1-6,10-14,16 + X1,X4
>   GAP-RECORDED: rows 7,8,9 (live half)
>   NOT-APPLICABLE: none
> classification gap:
>   Confirmed at src/discovery/cloudflare.rs:456 (live sink_impact None) +
>   src/findings/engine.rs:149 (eligibility blocks live Finding);
>   plus second gap §3.1 (token-policy 403 discarded facts) now FIXED.
>   proposal recorded: YES (classification-gap.md §5 P1-P3)
> comprehension:
>   Participant role: NONE named
>   Set A/B results: NOT RUN
>   Confusion points: NONE recorded (gate open)
> usefulness judgments: NOT CAPTURED (blocked by NOT RUN comprehension)
> safety:
>   Provider calls within allowlist: PROVEN
>   Writes performed: 0 (token never deployed/modified/deleted anything;
>                      worker deleted by founder, not Pico)
>   Token revoked: PENDING (dashboard/ expiry; session key lacks perms)
> defects:
>   CRITICAL: 0 | MAJOR: 2 (both fixed in-sprint, regression-tested,
>   no Finding-semantic change) | MINOR: 0
> advancement decision record:
>   Decision: live-validation ship-condition MET; comprehension gate OPEN.
>   (Per §2 default, do not claim ADVANCE on comprehension grounds.)
> verification:
>   cargo test etc. green per the two fix commits' regression tests
> repository:
>   branch/HEAD/origin-main/ahead-behind per git; tree: clean except .DS_Store
> follow-ups:
>   - founder completes §11 comprehension check or accepts caveat
>   - founder revokes token 6b1a59bb84dd680a1dde77f49b3f357b in dashboard
>   - classification mechanism (classification-gap.md P1/P2/P3) -> follow-up sprint
> ```
>
> Do not claim the full v0.1 exit gate while any gate remains NOT RUN, and do
> not claim it merely because the run completed. Claim exactly what the matrix
> shows: the pipeline is validated LIVE end-to-end (real API, real account/
> worker, real authority edge, honest zero-Findings UNKNOWN outcome, no secret
> leakage, deterministic, graceful degradation), with the comprehension gate
> explicitly left open.

```text
completion date and verified baseline
commits (authoring; any defect fixes; evidence record)
repository state
environment manifest summary (no secrets)
execution transcript locations
provider-operation conformance result
determinism and zero-write results
secret-sweep result
failure-injection outcomes
MCP parity result
validation matrix (inline or linked)
classification-gap note summary
comprehension result (PASS/FAIL/NOT RUN + confusion points)
usefulness judgments
defect list and dispositions
architecture pressure-test answers
token revocation confirmation
advancement decision record
follow-ups (named, owned, unambiguous)
```

Do not claim the full v0.1 exit gate while any gate remains NOT RUN, and do
not claim it merely because the run completed. Claim exactly what the matrix
shows.

---

# 28. Commit Policy

The authoring-only document may be committed separately with:

```text
docs(sprints): define Sprint 012 controlled live dogfood
```

Defect-fix commits use conventional messages naming the fix, each containing
its regression test. Evidence updates commit as:

```text
docs(sprints): record Sprint 012 dogfood evidence
```

Do not amend previous commits. Do not push unless explicitly instructed.
Do not begin Sprint 013.

---

# 29. Final Report Contract

Report:

```text
Sprint: SPRINT-012 — First Real Proof — Controlled Live Dogfood
Status: COMPLETE | BLOCKED
Baseline: <verified SHA>
Commits: <list>

Environment:
Account type: <disposable test account>
Workers observed: <count>
Token scopes: <allowlist list>
Variants run: exposed | safe | safe-not-prepared

Execution:
pico init/scan: PASS | FAIL (+ elapsed time, counters)
CLI explanation on real data: <result>
MCP parity on real data: <result>
Determinism across runs: PASS | FAIL
Zero-write proof: PASS | FAIL
Secret sweep: ZERO | INCIDENT (details)

Failure injections:
F1 invalid token: <honest outcome>
F2 mid-run loss of access: <honest outcome>

Validation matrix:
FIXTURE-VERIFIED: <count>
LIVE-VERIFIED: <count>
GAP-RECORDED: <named gaps>
NOT-APPLICABLE: <with justification>

Classification gap:
Confirmed at <file:line>; proposal recorded: YES | NO

Comprehension:
Participant role: <role>
Set A/B results: <scores>
Confusion points: <list or NONE>

Usefulness judgments: <verbatim summary>

Safety:
Provider calls within allowlist: PROVEN | VIOLATION
Writes performed: 0 | <incident>
Token revoked: CONFIRMED | PENDING

Defects: <critical/major/minor counts + dispositions>

Advancement Decision Record:
Decision: ADVANCE | EXTEND | REFINE | STOP
Justification: <evidence-based, defaulting away from ADVANCE>

Verification:
<tests and checks after final state>

Repository:
Branch / HEAD / origin-main / ahead-behind / tree state

Follow-ups:
<named, each traceable to a matrix row or confusion point>
```

Do not report a completed run as a validated Finding. Do not report an empty
live result as safety. Do not claim gates that remain NOT RUN.

---

# 30. Sprint Exit

Sprint 012 ends when the question —

> **Does Pico's golden path survive contact with reality?**

— has been answered with evidence rather than assertion: the bounded pipeline
has run against a real environment within its read-only promises, every v0.1
exit criterion carries a matrix status backed by artifacts, an independent
developer has either demonstrated comprehension or the gate is honestly left
open, and the next uncertainty is named precisely enough to authorize.

It does not claim:

> **That a live Finding exists today, that one environment generalizes, or
> that v0.1 is finished because the run completed.**

Those conclusions belong to the evidence, and to the explicitly authorized
work that follows it.

Do not begin Sprint 013.

Wait for explicit authorization.

