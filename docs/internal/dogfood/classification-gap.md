# Classification-Gap Investigation (Sprint 012 Artifact A9)

**Status:** AUTHORED (planning-time, code inspection only — no scan was executed)
**Sprint:** 012 §8.1 duty
**Baseline inspected:** `4993bf2` (working tree at authoring time)
**Scope:** where live `sink_impact` originates, whether any fetched-but-unused
provider field could support read-only classification, and the smallest
conceivable closure — stated as PROPOSALS ONLY. Nothing here is implemented.

---

# 1. The Live Path, Traced

Follow one `pico scan` through the shipped binary:

```text
src/cli/mod.rs:72            run_scan() calls ScanService::run(workspace)
src/application/scan.rs:73   ScanService::run -> run_with_home
src/application/scan.rs:87   run_with_home hardcodes
                             EnvironmentReachability::Unknown
src/application/scan.rs:113  run_with_home_and_environment_and_provider:
                             provider_result is None in production; the seam
                             override only fires when a test injects a result
                             (scan.rs:139-141)
src/discovery/mod.rs:169-176 discover_with_environment delegates to the single
                             OpenCode adapter
src/discovery/agents/opencode.rs:152      project-root .env is read for
                                          CLOUDFLARE_API_TOKEN
src/discovery/agents/opencode.rs:171-181  provider inspection gate + call
src/discovery/cloudflare.rs:481           inspect_live(token, fingerprint)
src/discovery/cloudflare.rs:270-475       Client::inspect walks verify ->
                             token details -> permission_groups -> accounts
                             -> per-account workers/scripts
```

Inside the Worker loop (`src/discovery/cloudflare.rs:439-472`), every
`ObservedWorker` is constructed identically:

```text
src/discovery/cloudflare.rs:456        sink_impact: None,
```

The doc comment on the field (`src/discovery/cloudflare.rs:90-94`) is the
contract being honored: *absence remains UNKNOWN and must never be inferred
from names or presence*.

Persisted projection in `ScanService`:

```text
src/application/scan.rs:975-983   normalize_sink_impact(None) == "UNKNOWN"
                                  (the match arm `_ => "UNKNOWN"` also swallows
                                  any non-canonical string)
src/application/scan.rs:1105-1113 worker Resource metadata carries both
                                  "environment" and "sink_impact" keys, set to
                                  the normalized value (UNKNOWN live)
src/application/scan.rs:1125-1130 cloudflare_worker_inventory Evidence metadata
                                  records "sink_impact": UNKNOWN
src/application/scan.rs:1140-1149 can_mutate Relationship metadata records
                                  "sink_impact": UNKNOWN
```

Engine consumption — the eligibility gate that makes a live Finding
impossible today:

```text
src/findings/engine.rs:134-152  eligible_candidate requires, among other
                                conditions, at line 149:
                                    || path.sink_impact != SinkImpact::Production
                                -> return None
src/findings/engine.rs:160-163  independent second gate: the sink node's own
                                safe metadata must explicitly say PRODUCTION
src/findings/engine.rs:239-249  explicit_production_metadata accepts it from
                                exactly three metadata keys: sink_impact,
                                environment, production_classification — each
                                compared case-insensitively to "PRODUCTION"
```

Since live persistence writes only `UNKNOWN` into all of those places, no
attack path built from live data can ever satisfy engine.rs:149. The unit
test pinning this exact semantic is
`src/findings/engine.rs:822 unknown_production_is_not_a_finding`.

---

# 2. Contrast: The Fixture Seam

The injected-provider path used by controlled fixtures is the same service
entry point with one extra argument:

```text
tests/integration/sprint009_finding_test.rs:40-85   provider() builds a
                                                    ProviderResult by hand;
                                                    the classification arrives
                                                    as the sink_impact
                                                    parameter (:43) and is
                                                    written into ObservedWorker
                                                    at :59
tests/integration/sprint009_finding_test.rs:112     scan_with_classification(
                                                    Some("PRODUCTION"), ...)
tests/integration/sprint009_finding_test.rs:110-130 explicit_production_
                                                    classification_is_persisted_
                                                    as_safe_metadata asserts the
                                                    Finding is emitted
```

Identical seams exist in `sprint010_cli_test.rs:42-87`,
`sprint010_finding_query_test.rs:47+`, and
`sprint011_mcp_golden_test.rs:55+`. The ONLY producer of
`Some("PRODUCTION")` in the entire repository is these tests. Production code
has no path that yields any value except `None`.

Where the classification lands when the seam does provide it:
`resource.metadata["sink_impact"]` / `["environment"]`
(src/application/scan.rs:1105-1113), which is exactly what
`explicit_production_metadata` (engine.rs:239-249) later reads off the graph
node.

---

# 3. Upstream Inspection Finding: Live Provider Calls Have an Additional Gate

Code inspection found something §8 did not pre-register, recorded here
because §8.1 demands exact code locations and honesty about them:

1. `ScanService::run` — the ONLY entry the CLI uses — passes
   `EnvironmentReachability::Unknown` (src/application/scan.rs:87).
2. The dotenv branch gates `inspect_live` on the **parameter**, not on the
   credential's own proven status:
   `provider_reachable = environment_reachability == Proven && bash allow +
   unrestricted` (src/discovery/agents/opencode.rs:171-176). With the
   parameter pinned to Unknown upstream, this is always false.
3. Only the project `.env` source can reach the provider call at all
   (opencode.rs:152-181). A shell-environment `CLOUDFLARE_API_TOKEN`
   (opencode.rs:126-151) produces a credential reference with no provider
   inspection under any configuration.

Consequence: **as authored, the shipped binary cannot execute
`inspect_live` at all.** Sprint 012 §8's expectation ("Worker authority
resolved from real token introspection") additionally depends on resolving
this gate. This note does not resolve it; the runbook instructs recording
whichever outcome manifests, and P3/founder disposition decides between a
§13 defect fix (with regression test) and a second GAP-RECORDED entry.
Do not silently change reachability semantics during the run.

---

# 4. Fetched-but-Unused Provider Fields Inventory

What the adapter reads vs. what Cloudflare returns on allowlisted endpoints:

```text
GET /user/tokens/verify          read: result.id (:302), result.status (:307)
                                 dropped: everything else in `result`
GET /user/tokens/{id}            read: result.policies (:562, then effect /
                                 permission_groups id+name / resources)
                                 dropped: token name, issued_on, expires_on,
                                 last_used_on, condition (IP/ACL), status
GET /user/tokens/permission_groups
                                 read: id + name per group (:520-533)
                                 dropped: scopes arrays and descriptions
GET /accounts                    read: id (:387), name (:413-416),
                                 type (:417-420)
                                 dropped: every remaining account field
GET /accounts/{id}/workers/scripts
                                 read: item.id (:445), item.tag (:451-454)
                                 dropped: EVERYTHING ELSE per script item
```

The workers-list drop is the relevant one. Per Cloudflare's public API
documentation, each scripts-list item carries more than `id`/`tag` —
typically timestamps (`created_on`, `modified_on`) and environment/
deployment metadata (e.g., an `environments` array with named
sub-environments). **Honesty caveat:** the exact live response shape has not
been captured yet (no execution was performed for this note); E2/A4 should
record one real response body (redacted) to make this inventory factual.

Assessment against the question §8.1 actually asks — *could any of this
support future READ-ONLY production classification?*

```text
- No fetched field observed today carries an explicit production
  designation. Timestamps do not classify. Account name/type do not
  classify.
- An `environments` array naming a sub-environment is NOT a production
  classification; mapping its presence or naming conventions to PRODUCTION
  is inference, prohibited by the ObservedWorker contract
  (cloudflare.rs:90-94) and by TECHNICAL.md §3.1 / §41 (evidence before
  conclusions; narrow discovery).
- Therefore: NO fetched-but-unused field currently supports authorized
  read-only classification. The inventory above is named so a follow-up can
  re-check after a real response capture (A4), not as a claim that one
  exists.
```

---

# 5. Smallest Conceivable Closures — PROPOSALS ONLY

None of this may be built in Sprint 012 (SPRINT-012.md §17: "new features of
any kind (including live production classification)"). Sketches, trade-offs,
and the Canon lines constraining each:

## P1 — Operator-declared classification file in the workspace

```text
Sketch: discovery reads ONE exact documented file (e.g., pico-sinks.json in
the workspace root) mapping worker identity (tag or account-scoped name) to
a normalized classification. Persisted as DECLARED evidence
(TECHNICAL.md §10.1 DECLARED, line 442), feeding resource metadata keys the
engine already reads (engine.rs:243-249). No new provider calls.

Trade-offs:
  + smallest honest mechanism; classification becomes inspectable evidence
    with provenance ("operator declared") instead of inference
  + zero new network surface; fits narrow-discovery pattern already used
    for opencode.json / .env
  - declares rather than verifies: confidence ceiling must reflect the
    declared evidence class; TECHNICAL.md §43 (claims not allowed without
    stronger evidence) still binds wording
  - new config surface = new parser = new failure modes; PARTIAL semantics
    must cover malformed declarations

Canon constraints:
  TECHNICAL.md §41 "narrow filesystem discovery" / "no arbitrary recursive
  home-directory scanning" (heading line 1677): exact filename, exact
  location, bounded size — same discipline as CONFIG_NAMES
  (src/discovery/agents/opencode.rs:21).
  PRODUCT_DEFINITION.md §32 V0 Non-Goals (line 1531): Pico must not modify
  agent permissions or infrastructure (lines 1557-1560); a read-only
  declaration file does not cross those lines, but "broad integration
  catalog" (§32 list) cautions against generalizing it.
  PRODUCT_DEFINITION.md §31.2 (line 1518): additional finding classes /
  adapters stay out of V0 breadth — keep the file golden-path-narrow.
```

## P2 — Provider-side classification if Cloudflare exposes one via an existing allowlisted read

```text
Sketch: IF the captured live workers-list response (A4) reveals an explicit,
documented environment-classification field, extend adapter normalization to
map THAT FIELD ONLY into sink_impact. No new endpoints; allowlist unchanged.

Trade-offs:
  + strongest provenance (DIRECT provider evidence)
  - current knowledge says no such field exists on this endpoint; treating
    environments-array naming as classification would be inference and is
    rejected above (§4)
  - any mapping table is policy and needs its own design sprint

Canon constraints:
  ARCHITECTURE.md §22.7 ALLOW list (via SPRINT-012.md §7): no endpoint
  expansion without authorization.
  TECHNICAL.md §3.1 Evidence before conclusions (line 81): only an explicit
  provider statement qualifies.
  ObservedWorker doc comment (src/discovery/cloudflare.rs:90-94): absence
  stays UNKNOWN; never infer from names or presence.
```

## P3 — Close the upstream reachability gate so live introspection happens AT ALL (orthogonal to classification)

```text
Sketch: derive EnvironmentReachability::Proven in the ScanService::run chain
from the already-proven project-dotenv contract (opencode.rs:165 hardcodes
Proven on the credential itself while :171 consults the weaker parameter),
or pass the credential's own reachability into provider_reachable.

Trade-offs:
  + makes §8's expected live behavior (real accounts/workers/authority,
    UNKNOWN sink) reachable without touching Finding semantics
  - changes network-behavior gating of the shipped binary; absolutely
    requires regression tests proving no inspection without bash
    allow+unrestricted and without the dotenv contract
  - NOT a classification fix: even after P3, sink_impact remains UNKNOWN
    and engine.rs:149 still blocks live Findings

Canon constraints:
  TECHNICAL.md §41 "explicit network operations" and "safe failure when
  provider introspection is incomplete" (heading line 1677).
  SPRINT-012.md §13 defect policy: only the founder can disposition this as
  an in-sprint defect fix (small, contained, regression-tested) versus a
  GAP-RECORDED entry; it must not ride along with anything else.
```

Recommendation ordering for a follow-up sprint: P3 first (without it, no
live provider evidence exists to explain), then P1 (only honest closure of
classification itself), P2 only if A4 evidence contradicts §4's assessment.

---

# 6. Verdict

The live no-Finding outcome is **CORRECT behavior today**, and it is correct
twice over: first, because every live `ObservedWorker` carries
`sink_impact: None` (src/discovery/cloudflare.rs:456), normalized to
`UNKNOWN` (src/application/scan.rs:975-983) and persisted as such
(scan.rs:1105-1113), so eligibility fails deterministically at
src/findings/engine.rs:149 before any severity or confidence is computed;
and second, because refusing unsupported claims is the product promise —
Pico reports UNKNOWN honestly instead of inferring production from worker
names, account labels, or environment-array shapes, exactly as
cloudflare.rs:90-94 and TECHNICAL.md §3.1 require. A live UNTRUSTED_TO_
PRODUCTION Finding would be evidence of a defect, not of capability. The
honest validation-matrix entry for the unblocked-finding criterion remains
FIXTURE-VERIFIED (fixtures prove the rule) with the live half GAP-RECORDED
against this note, unless a follow-up sprint authorizes a classification
mechanism.
