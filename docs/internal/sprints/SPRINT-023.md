# Pico — Sprint 023: Per-Agent Effective Bash in Scan Summary (F-U1 Close)

**Status:** DONE

**Sprint:** 023
**Phase:** v0.3 — Exit-Review Follow-up (F-U1)
**Type:** Surfacing fix (security-significant UX)
**Baseline:** `3ce8512` (post-Sprint-022 main HEAD)
**Depends on:** Sprint 020 (per-agent Bash model), Sprint 022 (dogfood F-U1 observation)

---

# 1. Purpose

Sprint 022 dogfood found F-U1: a **mixed-agent, zero-finding scan summary
conceals non-primary agents' Bash posture**. The summary renders a single
`Effective Bash: ALLOW` line derived from the *first* Bash capability
(`src/application/scan.rs:347-349`, `src/cli/mod.rs:110-112`). In a two-agent
workspace where OpenCode is auto-allow and Claude Code is approval-gated, a
zero-finding scan (the common offline/PARTIAL case) shows only OpenCode's
posture, hiding Claude's approval gate from the developer.

This is security-significant: an operator reading the summary cannot see that a
second agent requires approval — the exact state that changes the risk
conclusion.

> **F-U1: the `pico scan` summary must show every detected agent's effective
> Bash posture, while preserving the single-agent OpenCode output contract.**

---

# 2. Scope

- **Carry per-agent Bash postures on the scan result**: `ScanResult` gains a
  list of `{ provider, effective_state }` populated from ALL discovered Bash
  capabilities (S020 model), not just the first.
- **CLI summary**: when more than one agent is detected, render each agent's
  effective Bash posture (e.g. `opencode: AUTO_ALLOW`, `claude:
  APPROVAL_GATED`). When exactly one agent is detected, keep the existing
  single `Effective Bash: ALLOW` line **byte-for-byte** (golden contract).
- **Mixed-agent/zero-finding CLI test**: the exact F-U1 scenario — two agents,
  zero findings — asserts both postures are visible in the summary.
- **Golden-path regression**: the single-agent OpenCode scan summary output is
  unchanged (sprint010/011 assertions stay green).
- **MCP parity**: confirm whether MCP exposes the scan summary. The finding
  detail (`get_finding`/`list_findings`) already carries per-agent Bash via
  `paths[].agents[]` (S020). If MCP has no scan-summary tool, record N/A with
  justification; do not add a new MCP surface.
- **Repeat the S022 comprehension scenario** against the new binary: confirm
  both agents' postures are now visible in the mixed workspace scan summary,
  closing the F-U1 confusion point.
- **Terminology correction**: rename the S022 dogfood from "offline" to
  **"offline-default / bounded-read"** in `docs/internal/dogfood/
  evidence-v0.3.md` and `SPRINT-022.md` (the Cloudflare verify made one
  allowlisted outbound request and degraded honestly on HTTP 401).

---

# 3. Non-goals

- New engine/analysis behavior, new adapters, or new findings.
- Changing the single-agent OpenCode summary contract.
- Adding a new MCP tool.
- Resolving the independent-developer comprehension gate (outside this sprint;
  recommended next, per ROADMAP §22).

---

# 4. Validation Matrix

```text
R1  ScanResult carries per-agent Bash postures (provider + effective state)
    → NEW-FIXTURE (scan_result_carries_per_agent_bash_postures)

R2  CLI summary shows every agent's effective Bash when >1 agent
    → NEW-FIXTURE (mixed_agent_summary_lists_every_agent_bash_posture)

R3  Single-agent OpenCode summary byte-identical (golden contract preserved)
    → FIXTURE-VERIFIED (sprint010/sprint011 summary assertions unchanged)

R4  Mixed-agent zero-finding CLI test asserts both postures visible
    → NEW-FIXTURE (sprint023_cli_test.rs; repeats the F-U1 scenario)

R5  MCP parity: finding detail already per-agent; no scan-summary tool => N/A (justify)
    → NOT-APPLICABLE (documented; S020 `paths[].agents[]` covers MCP)

R6  Determinism: identical scan => identical per-agent postures (ties S015/S020)
    → NEW-FIXTURE (per_agent_postures_stable_across_identical_scans)

R7  No secret leakage: synthetic tokens never appear in the summary
    → NEW-FIXTURE (secret_sweep_never_leaks_token_in_summary)
```

---

# 5. Controlled Environment

Reuse the S022 mixed workspace (OpenCode bash `allow` + Claude `ask` + synthetic
`cfut_`/`ghp_` tokens, offline-default/bounded-read). No real token, no new
live dogfood. The S022 comprehension scenario is re-run against the new
binary.

---

# 6. Design Notes

## 6.1 ScanResult per-agent postures (R1)
Add `agent_bash_postures: Vec<AgentBashPosture { provider, effective_state }>`
to `ScanResult` (populate from `discovered.bash_capabilities`, using
`effective_state.as_str()` — not the raw permission, so the summary matches the
finding-detail `agents[]` vocabulary: `AUTO_ALLOW` / `APPROVAL_GATED` /
`DENIED` / `SANDBOXED` / `UNKNOWN`).

## 6.2 CLI rendering (R2, R3)
In `src/cli/mod.rs` `run_scan`: when `agent_count > 1` and at least one Bash
posture was observed, render an `Effective Bash:` section with one line per
observed posture (`<provider>: <effective_state>`). Do not invent a posture
for an agent with no Bash capability. Otherwise render the existing single
`Effective Bash: ALLOW` line exactly as today (do NOT change the single-agent
path). Gating on agent count (not `postures.len() > 1`) is load-bearing for
F-U1: a two-agent workspace with only one Bash capability must not collapse
to the primary permission line.

## 6.3 Tests (R4, R6, R7)
New `tests/integration/sprint023_cli_test.rs`: mixed-agent zero-finding scan
asserts both postures in the summary; golden single-agent scan asserts the
legacy line; determinism across two runs; synthetic-token secret sweep.

---

# 7. Commit Policy

Authoring commit:

```text
docs(sprints): define Sprint 023 per-agent effective Bash in scan summary
```

Implementation commits conventional, each with its regression test. Do not
amend previous commits. Do not begin a v0.4 sprint.

---

# 8. Completion Evidence (filled at execution)

```text
completion date and verified baseline
  Date: 2026-08-27
  Authoring baseline: 5a7fdce (docs(sprints): define Sprint 023 …)
  Post-S022 main: 3ce8512
  Verified by: cargo test --lib (144 passed); cargo test --test integration
               sprint023 (7 passed) plus prior green golden-path suites

commits
  authored: 5a7fdce docs(sprints): define Sprint 023 per-agent effective Bash in scan summary
  impl:     (this sprint) feat(scan/cli): per-agent effective Bash in scan summary
            + tests/docs

repository state
  M src/application/scan.rs     (AgentBashPosture; ScanResult.agent_bash_postures)
  M src/application/mod.rs      (re-export)
  M src/cli/render.rs           (render_scan_effective_bash)
  M src/cli/mod.rs              (scan summary uses renderer)
  M tests/integration.rs
  ?? tests/integration/sprint023_cli_test.rs
  M docs: SPRINT-022.md, SPRINT-023.md, evidence-v0.3.md, comprehension-v0.3.md,
          ROADMAP.md §18/§22, ARCHITECTURE.md §28.4.1, SPRINT-020-support-note.md
  ?? docs/internal/dogfood/transcripts/df23-E2-scan.txt

new fixtures (R1–R7) and their assertions
  R1 scan_result_carries_per_agent_bash_postures
     — 2 postures: opencode AUTO_ALLOW, claude APPROVAL_GATED; bash_permission ALLOW
  R2 mixed_agent_summary_lists_every_agent_bash_posture
     — exact block "Effective Bash:\n  opencode: AUTO_ALLOW\n  claude: APPROVAL_GATED\n"
     — mixed_agents_with_one_bash_capability_use_per_agent_block (agent_count
       gate: one posture still uses the per-agent block)
  R3 single_agent_opencode_summary_keeps_legacy_effective_bash_line
     — "Effective Bash: ALLOW\n"; no per-agent opencode: line
     — sprint010/sprint020/opencode_scan still green
  R4 mixed_agent_zero_finding_summary_shows_both_bash_postures
     — finding_count == 0; exact per-agent block
  R5 MCP N/A — see below
  R6 per_agent_postures_stable_across_identical_scans
  R7 secret_sweep_never_leaks_token_in_summary

S022 comprehension scenario re-run result (F-U1 confusion point closed)
  PASS. Mixed workspace (OpenCode allow + Claude ask + synthetic tokens,
  offline-default/bounded-read): scan summary lists
    Effective Bash:
      opencode: AUTO_ALLOW
      claude: APPROVAL_GATED
  Transcript: docs/internal/dogfood/transcripts/df23-E2-scan.txt
  Proxy Set A/B answerable from that transcript; Claude's approval gate is
  visible with Findings = 0. Independent-developer gate: NOT RUN.

terminology correction (offline-default/bounded-read) locations
  docs/internal/sprints/SPRINT-022.md (purpose, G3, runbook heading, W1/W2/W4, G3 evidence)
  docs/internal/dogfood/evidence-v0.3.md (mode line; G3 label)

MCP parity N/A justification
  MCP tools are only list_findings and get_finding (src/mcp/tools.rs).
  No scan-summary tool. Per-agent Bash on MCP remains get_finding
  paths[].agents[] (S020). S023 does not add an MCP surface.

determinism + secret-sweep result
  R6 PASS (identical postures + rendered summary across two scans)
  R7 PASS (TEST_SECRET_SHOULD_NOT_PERSIST / cfut_TESTFAKE / ghp_TESTFAKE
     absent from summary, posture Debug, bash_permission)
  Dogfood re-run secret sweep: synthetic tokens and canary ZERO in DB and
  scan stdout.

advancement record (ROADMAP §22 note: F-U1 closed; independent gate still open)
  ROADMAP §18: F-U1 closed in S023; v0.3 exit review still PENDING
  ROADMAP §22: S023 follow-up paragraph appended
```

---

# 9. Final Report Contract

```text
Sprint: SPRINT-023 — Per-Agent Effective Bash in Scan Summary
Status: DONE
Baseline: 5a7fdce (authoring); 3ce8512 (post-S022)

Surfacing:
  per-agent postures on ScanResult: PASS
  multi-agent summary lists every agent: PASS
  single-agent contract preserved: PASS
  mixed zero-finding CLI test: PASS
  MCP parity: N/A (justified)

Fixtures:
  determinism: PASS
  secret sweep: PASS

S022 scenario re-run: PASS
Golden path: 1 finding intact (sprint010/sprint020/opencode_scan green)
```