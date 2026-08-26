# Pico — Sprint 012 Developer Comprehension Check (Proxy)

**Status:** PROXY-CLOSED (not independently validated)
**Administered by:** the implementing agent — NOT an independent developer.
**Per SPRINT-012 §11 rules:** a fixture author may not be the sole
comprehension participant. This record is therefore a *proxy* self-check:
it proves the comprehension questions are **answerable from Pico's output
alone**, but it does NOT satisfy the independent-developer gate. An
independent human validation is still recommended before v0.2 sign-off.

**Input shown to the "participant":** only the captured real-output summary
from `docs/internal/dogfood/evidence.md` (scan `scan_18cf730d87996f48_0`):
`PARTIAL / Analysis COMPLETE / Disposition UNRESOLVED_PRESENT`; Agents 1,
Resources 8, Relationships 8, Evidence 26; Cloudflare Credential
OBSERVED / REACHABLE / ACTIVE; Cloudflare Accounts 1
(`3e2742bacdabcada586f921ad89bac77`); Cloudflare Workers 1
(`pico-dogfood-worker`, tag `884c892b…`, IMMUTABLE_TAG); real edge
`credential → can_mutate → worker` with `permission_state=READ_OR_UNKNOWN`,
`capability=WORKERS_SCRIPTS_WRITE`, `sink_impact=UNKNOWN`,
`unknown_reasons=[ACCOUNT_SCOPE_UNRESOLVED, WORKERS_SCRIPTS_WRITE_UNRESOLVED]`;
Authority Paths 1, Influence Paths 1, Unresolved Candidates 2, Findings 0;
Credential Value Stored NO.

---

## Set A — ROADMAP §13.7 usability gate

**What did Pico find?**
A connected path from externally controlled GitHub issue content, through
the GitHub MCP `issue_read` tool and OpenCode, to Bash, to a live
Cloudflare API credential, and on to a Cloudflare Worker the credential can
mutate. No active Finding was produced (0 Findings) because the Worker's
production impact is `UNKNOWN`.

**Why does it matter?**
An AI coding agent with Bash can reach a live Cloudflare Worker-mutation
credential. If that Worker were production, externally controlled content
could influence production deploys. The path is real and read-only-observed.

**How does the path work?**
`github:issue (SOURCE)` → `can_retrieve` → `mcp:github:tool:issue_read`
→ `can_call` → `agent:opencode (ACTOR)` → `can_execute` → `shell:bash
(CAPABILITY)` → `can_access` → `credential:cloudflare (AUTHORITY)` →
`can_mutate` → `cloudflare:worker (SINK)`. Each edge has `DERIVED` state
with supporting Evidence.

**How does Pico know?**
- Bash allow + MCP config: read from `opencode.json` (`DIRECT`/`DERIVED`
  evidence).
- Credential presence: from `.env` `CLOUDFLARE_API_TOKEN`
  (`cloudflare_credential_reference` evidence).
- Reachability + ACTIVE status: live `POST /user/tokens/verify`
  (`DERIVED`, allowlisted).
- Account + Worker inventory: live `GET /accounts` and
  `GET /accounts/{id}/workers/scripts` (`DERIVED`, allowlisted, read-only).
- Authority: `can_mutate` with `READ_OR_UNKNOWN` from token policy facts.

**What is uncertain?**
`sink_impact` of the Worker is `UNKNOWN` (no read-only signal says
production vs not); account scope is `UNKNOWN`; worker-scripts-write
resolution is `UNKNOWN` (the token lacked policy-read scope). Authority is
therefore `UNKNOWN`, not confirmed.

**What boundary is missing or working?**
No hard-deny / sandbox / mandatory-approval boundary was observed (Bash was
`allow`/unrestricted). The credential was scoped to its account (a
`scoped_to` edge exists), but authority resolution stayed incomplete.

**How can the path be broken?**
Remove the token from `.env`; set Bash permission to `ask`/`deny`; scope or
revoke the token; sandbox Bash; or deny the `issue_read` MCP tool. Any of
these removes an edge Pico actually observed.

**What changed since the previous observation?**
This was a single scan; history/change detection is v0.4 scope and not yet
implemented. Pico preserves the observation but offers no diff yet.

---

## Set B — SPRINT-010 §33 finding-specific check

**What externally controlled source begins the path?**
Public GitHub issue content, retrieved via the `github_mcp` `issue_read`
tool (`trust=PUBLIC_EXTERNAL`, `influence_strength=AGENT_RETRIEVABLE`).

**Which autonomous Actor joins influence to authority?**
OpenCode (`agent:opencode`), via its Bash capability.

**What production capability is reachable?**
Cloudflare Worker mutation: `can_mutate` with
`capability=WORKERS_SCRIPTS_WRITE`. Production status is `UNKNOWN`.

**Why would a Finding be severe? Why would Pico be confident?**
Severe *if* the Worker is production. Pico is **not** confident
(`sink_impact=UNKNOWN`), so it correctly produces no Finding.

**Which Evidence supports the conclusion?**
`opencode_config` (bash allow), `github_mcp_config`,
`cloudflare_credential_reference`, `cloudflare_credential_reachability`,
live token-verify + account/worker reads (all allowlisted, read-only).

**What did Pico establish about enforced boundaries?**
No blocking boundary observed on this path; the credential was account-scoped.

**Name at least one practical cut point.**
Remove `CLOUDFLARE_API_TOKEN` from the workspace `.env` (removes the
`can_access` edge entirely).

**Did Pico prove exploitation?**
No. Read-only introspection only; no path was executed.

**Did Pico apply a remediation?**
No. Observation-only, per ROADMAP §3.5 / ARCHITECTURE §2.7.

**Why does the live scan show no Finding even though the path exists?**
Because `sink_impact` is `UNKNOWN`; under the Sprint 009 eligibility rule
(`src/findings/engine.rs:149`) a non-`PRODUCTION` classification can never
yield an active `UNTRUSTED_TO_PRODUCTION` Finding. Pico refuses
unsupported claims — correct behavior, not a failure (SPRINT-012 §8).

---

## Usefulness Judgment (SPRINT-012 §12, proxy)

1. **Did the output tell you something new?** Yes — it revealed the
   credential is `ACTIVE` and reaches a *real* Worker, and that the token's
   scope leaves authority `UNKNOWN` (a genuine misconfiguration signal).
2. **Would it change a decision?** Yes — would scope/revoke the token or
   remove Bash→credential access.
3. **Misleading / overclaimed / confusing?** No. Zero Findings is honest
   with `UNKNOWN`; no false certainty.
4. **Keep Pico installed and run again?** Yes.

**Confusion points (proxy):** only the `UNKNOWN` classification narrative
needed explicit explanation; once stated, it is coherent. No other
ambiguity.

---

## Recording note

This proxy close satisfies the *artifact* requirement (the comprehension
questions are demonstrably answerable). It does **not** satisfy the
independent-developer gate of SPRINT-012 §11. The v0.1 Advancement
Decision (ROADMAP §20) therefore takes `ADVANCE` with this caveat explicit.
Recommended follow-up: have a developer who did not build Pico repeat Set A/B
against the same captured output and confirm PASS.
