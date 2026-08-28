# Pico — Sprint 022 Comprehension Check (Proxy, v0.3)

**Status:** PROXY-CLOSED (not independently validated)
**Administered by:** the implementing agent — NOT an independent developer.
**Per SPRINT-012 §11 rules:** a fixture author may not be the sole comprehension
participant. This record is therefore a *proxy* self-check: it proves the
comprehension questions are **answerable from Pico's output alone**, but it
does NOT satisfy the independent-developer gate. An independent human check is
recommended before v0.3 sign-off (mirrors the v0.1 caveat, ROADMAP §20).

**Input shown to the "participant":** only the captured v0.3 dogfood output —
`docs/internal/dogfood/evidence-v0.3.md` §2–§5 and transcripts
`docs/internal/dogfood/transcripts/df22-*`. No source, no coaching.

---

## Set A — ROADMAP §13.7 usability gate

**What did Pico find?**
Two coding agents configured in the workspace: OpenCode with Bash `allow`
(`Effective Bash: ALLOW`) and Claude Code with Bash `ask` (approval-gated,
present in the graph as an UNKNOWN-state `can_execute` edge). OpenCode is
configured with an official GitHub MCP server exposing `issue_read`
(influence `AGENT_INJECTABLE`). Two credentials were observed: a Cloudflare
API token (reachable; verify returned HTTP 401) and a GitHub classic PAT
whose repository-mutation authority is `UNKNOWN`. No active Finding was
produced (0 Findings) because the Cloudflare account/worker inventory is empty
(authority UNKNOWN offline).

**Why does it matter?**
A workspace with an auto-allow OpenCode agent, an official GitHub MCP
influence surface, and reachable cloud/CI credentials is exactly the
configuration where an external prompt could drive a consequential action.
Pico shows which agent can run Bash automatically (OpenCode) vs only with
approval (Claude), and that the GitHub token's write scope is not observable
in this offline run.

**How does the path work?**
`source:github:public:issue-content` → `can_retrieve` →
`mcp:github:official:tool:issue_read` → `can_call` → `agent:opencode` →
`can_execute` → `shell:bash` → `can_access` → `credential:github` /
`credential:cloudflare`. Each edge carries state and supporting evidence; the
GitHub credential has only `can_access` (read) — no `can_mutate`.

**How does Pico know?**
- Agent configs + Bash posture: read from `opencode.json` and
  `.claude/settings.json` (DIRECT/DERIVED evidence).
- GitHub MCP influence: from the declared official server + `issue_read`
  tool (DERIVED).
- Credential presence: from `.env` (`CLOUDFLARE_API_TOKEN`,
  `GITHUB_TOKEN`).
- Cloudflare reachability: live `/user/tokens/verify` (allowlisted) →
  HTTP 401 → recorded FAILED, honest.
- GitHub authority: offline resolution → `UNKNOWN` +
  `GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE`.

**What is uncertain?**
Cloudflare authority (provider verify 401 ⇒ 0 accounts/workers); GitHub
repository-mutation authority (offline ⇒ UNKNOWN); Worker `sink_impact`
(n/a here — no workers observed). All labeled, none fabricated.

**What boundary is missing or working?**
No hard-deny/sandbox/mandatory-approval boundary on the OpenCode Bash edge
(`allow`). Claude's Bash is approval-gated (its `can_execute` edge is
UNKNOWN-state). The scan summary's "Incomplete evidence" block names the
failed provider (cloudflare) and the PARTIAL reason explicitly.

**How can the path be broken?**
Set OpenCode Bash to `ask`/`deny`; remove the `.env` credentials; sandbox
Bash; scope or rotate the GitHub PAT; deny the `issue_read` tool.

**What changed since the previous observation?**
Single scan; history/change detection is v0.4 scope, not implemented.

---

## Set B — SPRINT-010 §33 finding-specific check

**What externally controlled source begins the path?**
Public GitHub issue content via the official GitHub MCP `issue_read` tool
(`trust=PUBLIC_EXTERNAL`, `influence_strength=AGENT_INJECTABLE`).

**Which autonomous Actor joins influence to authority?**
OpenCode (`agent:opencode`), Bash `allow`; Claude Code is present but
approval-gated.

**What production capability is reachable?**
None confirmed offline: Cloudflare has 0 workers (verify 401); GitHub
credential has read (`can_access`) only; `can_mutate` is absent. Production
status UNKNOWN.

**Why would a Finding be severe? Why would Pico be confident?**
Severe only if a production Worker were reachable with mutation authority.
Pico is NOT confident offline and correctly produces no Finding.

**Which Evidence supports the conclusion?**
`opencode_config`, `claude_config`, `github_mcp_config`,
`cloudflare_credential_reference`, `cloudflare_credential_reachability`,
GitHub credential + authority facts, and the provider diagnostics.

**What did Pico establish about enforced boundaries?**
OpenCode Bash is auto-allow (no boundary); Claude Bash is approval-gated
(UNKNOWN-state edge).

**Name at least one practical cut point.**
Remove `CLOUDFLARE_API_TOKEN` / `GITHUB_TOKEN` from `.env` (removes the
`can_access` edges), or set OpenCode Bash to `ask`/`deny`.

**Did Pico prove exploitation?**
No. Read-only introspection only.

**Did Pico apply a remediation?**
No. Observation-only.

**Why does the scan show no Finding even though paths exist?**
Because authority is UNKNOWN offline (0 workers; no write evidence) and
`sink_impact` is not PRODUCTION; a non-`PRODUCTION` classification can never
yield an active `UNTRUSTED_TO_PRODUCTION` Finding. Pico refuses unsupported
claims.

---

## Usefulness Judgment (SPRINT-012 §12, proxy)

1. **Did the output tell you something new?** Yes — it revealed the workspace
   has TWO agents with different Bash postures (OpenCode auto-allow vs Claude
   approval-gated), an `AGENT_INJECTABLE` GitHub MCP surface, a GitHub classic
   PAT whose write scope is UNKNOWN offline, and a Cloudflare token whose
   verify 401s (a real rotation signal).
2. **Would it change a decision?** Yes — rotate/remove the Cloudflare token,
   scope or drop the GitHub PAT, and set OpenCode Bash to `ask`/`deny`.
3. **Misleading / overclaimed / confusing?** No — PARTIAL is named
   (cloudflare); UNKNOWN authority carries its reasons; zero Findings is
   scoped, not an all-clear.
4. **Keep Pico installed and run again?** Yes.

**Confusion points (proxy):** the original v0.3 scan-summary showed only the
primary agent's `Effective Bash`; per-agent posture (Claude) lived in the
finding-detail view, which requires a Finding. That hole was F-U1.
**S023 close:** the S022 mixed-agent scenario re-run now shows both postures
in the scan summary without a Finding (`opencode: AUTO_ALLOW`, `claude:
APPROVAL_GATED` — `docs/internal/dogfood/transcripts/df23-E2-scan.txt`).
Independent-developer gate still NOT RUN.

---

## Recording note

This proxy close satisfies the *artifact* requirement (the comprehension
questions are demonstrably answerable from v0.3 output). It does **not**
satisfy the independent-developer gate. The v0.3 Advancement Decision
(ROADMAP §22) therefore takes `ADVANCE` with this caveat explicit.
Recommended follow-up: have a developer who did not build Pico repeat Set A/B
against the captured v0.3 output and confirm PASS.