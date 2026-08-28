# Sprint 022 Controlled Dogfood — Evidence Record (v0.3)

**Baseline:** `77e456e` (post-Sprint-021). **Binary:** `target/debug/pico` (built from baseline).
**Date:** 2026-08-26. **Mode:** controlled, offline-adjacent, synthetic tokens.
**Gates:** G1–G7 per SPRINT-022.md §2. **Result:** all gates PASS (G6 proxy; independent-developer gate NOT RUN).

---

## 1. Workspace (controlled)

Temp workspace (outside repo). Configs:

```text
opencode.json            {"permission":{"bash":"allow"},"mcp":{"servers":{"github":{
                         "type":"local","command":["ghcr.io/github/github-mcp-server"],
                         "environment":{"GITHUB_PERSONAL_ACCESS_TOKEN":"PICO-DF22-CANARY-a1b2c3d4e5"}}}}}
.claude/settings.json    {"permissions":{"ask":["Bash"]}}
.env                     CLOUDFLARE_API_TOKEN=cfut_TESTFAKE0000000000000000000000000000
                         GITHUB_TOKEN=ghp_TESTFAKE0000000000000000000000000000
```

No real token was used. The Sprint 012 live token (`cfut_…`, id `6b1a59bb84dd680a1dde77f49b3f357b`) was NOT used (revocation pending).

## 2. E2 — Scan result (timed)

Status **PARTIAL** (honest). Counters:

```text
Agents:        2         Resources: 9    Relationships: 9   Evidence: 17
Security Graph: PROJECTED    Graph Nodes: 9    Graph Edges: 9
State-Eligible Edges: 7    Non-Eligible Edges: 2
Analysis: COMPLETE    Disposition: NONE
Influence Paths: 1    Authority Paths: 0
Potentially Active: 0   Blocked: 0   Unresolved: 0   Findings: 0
Effective Bash: ALLOW
GitHub MCP: OBSERVED    Influence: AGENT_INJECTABLE
Cloudflare Credential: OBSERVED    Credential Reachability: REACHABLE
Cloudflare Accounts: 0    Cloudflare Workers: 0
Credential Value Stored: NO

GitHub credential authority:
  GitHub classic_pat authority: resolution=UNKNOWN permission=READ_OR_UNKNOWN
    reasons=[GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE]

Incomplete evidence
  Provider claude: reachable
  Provider opencode: reachable
  Provider cloudflare: FAILED
    - cloudflare read returned HTTP 401
  Provider github: reachable
  Scan status: PARTIAL (cloudflare)
```

Elapsed: `0.326s` total (0.02s user, 0.04s system).

**G3 nuance (recorded honestly):** the `.env` dotenv contract proves reachability and triggers the bounded allowlisted Cloudflare `/user/tokens/verify`. With the synthetic token this made ONE real outbound call that returned HTTP 401 → honest PARTIAL. The GitHub scope probe stayed offline (no outbound). So "offline" means: offline-default for authority probes; the only network activity is the allowlisted Cloudflare verify, which degrades honestly. No Authorization/secret leakage (error text only).

## 3. Graph projection (SQLite)

```text
agent:claude|can_execute|shell:bash                     UNKNOWN   (APPROVAL_GATED)
agent:opencode|can_execute|shell:bash                   DERIVED   (AUTO_ALLOW)
agent:opencode|configured_with|mcp:github:official      DERIVED
agent:opencode|can_call|mcp:github:official:tool:issue_read  DERIVED
mcp:github:official|exposes|mcp:github:official:tool:issue_read  DERIVED
mcp:github:official:tool:issue_read|can_retrieve|source:github:public:issue-content  DERIVED
shell:bash|can_access|credential:cloudflare:…           DERIVED
shell:bash|can_access|credential:github:…               DERIVED
credential:github:…|can_access|github:repository        UNKNOWN   (offline; can_mutate ABSENT)
```

Both agents, both credential types, GitHub MCP influence, and offline `UNKNOWN` authority are projected. `can_mutate` for GitHub is correctly ABSENT (no write evidence). Cloudflare has 0 workers (401) so no worker `can_mutate`.

## 4. E3 — Findings + not-found

```text
Pico Findings
  No COMPLETE scan exists in this workspace.
  Newest scan attempt: scan_18cfd6a8faa363f0_0 (PARTIAL)
  Run `pico scan` and let it complete to produce results.
  This is not an all-clear; no authoritative scan exists.
  exit=0

error: Finding fnd_does_not_exist0000000000000000000 was not found in this workspace
exit=1
```

Scoped zero-Finding language (NOT a global all-clear); clean not-found error, no traceback.

## 5. E4 — MCP parity

```text
negotiated: 2025-03-26 (supported set ["2025-06-18","2025-03-26","2024-11-05"])
tools: ['list_findings', 'get_finding']
list_findings: success (content; scoped PARTIAL language, matches CLI)
get_finding(bogus): error
malformed line: one JSON-RPC error; session still answered ping
ping: ok
exit: 0
```

Full CLI/MCP parity on the v0.3 surfaces.

## 6. E5 — Determinism (G4)

Two independent runs (fresh `.pico`). Normalized transcripts (ids/timestamps/scan_/res_/rel_/ev_/obs_ stripped) are identical — the only diff was the `time` shell line, which run2 did not wrap. DB structure hashes (relationships / resources / evidence queries) are IDENTICAL across the two DBs:

```text
relationships: 9bb28e8ba21f95c3dd70af5ee3865ec6e673a14d76d37434650568104f5be0b5
resources:     e2af0c0cc5aba81ab39b58bda1c30fcfa06cd93cc7f655b1e0e24d69ff3770ee
evidence:      7d6877baf1edffeec2068cf5a4bde63413cdad1feb564a3f27fb354fc88c640f
```

## 7. E6 — Secret sweep + zero-write (G5)

Patterns swept (full + first-8 + canary) across both DBs and every transcript/MCP frame:
`cfut_TESTFAKE…`, `ghp_TESTFAKE…`, `PICO-DF22-CANARY-a1b2c3d4e5` → **ZERO occurrences**. Zero-write proof: DB hash identical around `findings` + MCP reads (`4811d310…` both sides).

---

## 8. Gate summary

```text
G1  mixed-surface scan:         PASS  (2 agents, both credentials, GitHub influence, honest UNKNOWN)
G2  scan clarity:               PASS  (with observation: per-agent Bash in finding-detail view;
                                      scan summary shows primary; follow-up F-U1)
G3  offline + performance:      PASS  (0.326s; only allowlisted Cloudflare verify 401; GitHub probe offline)
G4  determinism:                PASS  (identical normalized output + identical DB structure hashes)
G5  secret sweep:               PASS  (ZERO; zero-write proof OK)
G6  comprehension proxy:        PASS  (proxy; independent-developer NOT RUN — see comprehension-v0.3.md)
G7  usefulness:                 PASS  (see comprehension-v0.3.md usefulness judgment)
```

## 9. Known observations / limitations

- **F-U1:** scan summary shows only the primary agent's `Effective Bash`; the per-agent view (S020 `agents[]`) renders in the finding-detail view, which requires a Finding. When a mixed-agent workspace yields zero Findings, the per-agent Bash posture is not visible at scan-summary level. Suggest surfacing per-agent Bash in the scan summary when `Agents > 1`.
- Cloudflare accounts/workers = 0 and `Findings = 0` are honest consequences of the synthetic-token 401 and offline `UNKNOWN` authority — not defects.
- GitHub `can_mutate` correctly absent (no write evidence) — honest per S021.

## 10. Transcripts

`docs/internal/dogfood/transcripts/df22-E2-scan.txt`, `df22-E3-findings.txt`, `df22-E3-notfound.txt`, `df22-E4-mcp.txt` (redacted; paths normalized to `$PICO`/`$WS`).