# Sprint 021 — GitHub Repository Mutation Authority Support Note

This note defines, for operators and downstream consumers, exactly what Pico's
GitHub authority surface (SPRINT-021) establishes about a GitHub credential's
ability to mutate repositories, what it deliberately does **not** establish, how
it fails, and how it behaves in the golden path. It is the authoritative scope
statement for the GitHub repository-mutation authority shipped in Sprint 021
(R1–R10).

## What Pico establishes

Pico classifies a GitHub credential **by its lexical shape** — deterministic and
format-based, never invented:

- `ghp_…` → classic personal access token (`classic_pat`),
- `github_pat_…` → fine-grained personal access token (`fine_grained_pat`),
- `gho_…` → OAuth user token (`oauth`),
- `ghs_…` / `ghr_…` → user-to-server / refresh token (`other`),
- anything unrecognized → `unknown` (the safe default; no write claim).

The credential is fingerprinted in a GitHub-namespaced SHA-256 digest; the raw
token value never enters the discovery result, the persisted metadata, the
rendered CLI output, or the MCP JSON.

## What Pico can and cannot establish about repository write authority

Repository **write** authority is established **only** through scope evidence
obtained by an optional, bounded live probe:

- **Classic PAT (type-aware).** A single allowlisted read `GET /user` against
  `https://api.github.com/user` returns the `X-OAuth-Scopes` response header.
  - `repo` or `public_repo` present → `EXACT` (or `SCOPED`) resolution,
    `REPO_WRITE` permission state — Pico emits a `can_mutate` edge.
  - only read scopes → `BEHAVIORAL_READ_ONLY` / `READ_ONLY` — read `can_access`
    edge only.
  - empty scope header → `BEHAVIORAL_READ_ONLY` / `READ_ONLY` — an absent header
    is **never** upgraded to write.
- **Fine-grained PAT.** Per-repository permissions are not exposed by the
  `X-OAuth-Scopes` header; even a `repo`-shaped header cannot prove them →
  resolution `UNKNOWN`, `READ_OR_UNKNOWN` permission state, and
  `GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE`. Pico never fabricates a write
  claim for a fine-grained token.
- **OAuth / other / unknown.** Scope is not observable through this probe →
  `UNKNOWN` + `GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE`.
- **Offline (default).** No transport is invoked by default. Repository write
  scope is **not observable from the credential value alone**, so the offline
  projection is `UNKNOWN` + `GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE` with a read
  `can_access` edge. This is the expected static posture, not a provider failure
  — no problem is recorded and the scan stays `COMPLETE`.

## Boundaries Pico does not cross

- **No write fabrication.** Pico emits `can_mutate` **only** when write authority
  is evidenced (`EXACT` / `SCOPED`); every other posture emits a read
  `can_access` edge with an honest `UNKNOWN` / `BEHAVIORAL_READ_ONLY`
  resolution and its `unknown_reasons`.
- **No non-allowlisted calls.** The only transport capability is the single
  allowlisted `GET /user`; redirects are rejected before an origin boundary can
  be crossed, responses are size-bounded, and the request budget is bounded.
  Any other path is refused before any network activity. Tests exercise the
  probe exclusively through fixture transports.
- **No runtime default network access.** The shipped CLI runs offline-safe; the
  live probe is optional and off by default.
- **No cross-provider leakage.** GitHub authority edges are namespaced
  (`credential:github:<fp>|can_*|github:repository`) and never duplicate or
  interfere with Cloudflare authority edges.
- **No enforcement / remediation / write probes.**

## Failure behavior

- A probe transport failure (or a rejected redirect, or a non-2xx response)
  records a problem, keeps authority `UNKNOWN` +
  `GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE`, never fabricates a write claim, and
  marks the scan `PARTIAL` with `partial_reason` naming `github`.
- The offline default records **no** problem; `provider_statuses` still reports
  a reachable `github` provider whenever a GitHub credential was observed, and
  the scan stays `COMPLETE`.

## Surfacing (Sprint 021 R6/R7)

Per observed GitHub credential, the CLI `pico scan` summary and the MCP
`list_findings` / `get_finding` JSON report only safe normalized facts:
credential type, authority resolution tier, permission state, and
`unknown_reasons` codes:

- CLI: a `GitHub credential authority:` block with one line per credential —
  `GitHub <credential_type> authority: resolution=<tier> permission=<permission_state>
  reasons=[<unknown_reasons>]`. When no GitHub credential is observed the block
  is empty (no noise on the golden path).
- MCP: a `github_credentials` array of
  `{credential_type, authority_resolution, permission_state, unknown_reasons}`
  on both the list and detail payloads; empty array on the golden path.
- The GitHub `github:repository` resource is **not** a consequential sink, so
  the GitHub authority edge never terminates an attack path and never changes
  the finding count; the facts are surfaced at the scan/credential level.

## Golden-path guarantee

The golden configuration (OpenCode `bash: allow` + a Cloudflare credential +
the official GitHub MCP server, with **no GitHub credential**) is unchanged: it
yields exactly one active Finding, its CLI and MCP output are byte-identical
(no GitHub authority block, empty `github_credentials`), and its scan stays
`COMPLETE`. A mixed workspace that adds a GitHub credential (including a live
`REPO_WRITE` classic PAT) keeps the single Finding while surfacing the GitHub
authority facts.

## Secret handling

The secret sweep (R10) asserts, across the classic live-repo / read-only /
fine-grained / offline postures, that the synthetic GitHub token value never
appears in the rendered CLI authority block, the explained finding output, the
MCP `list_findings` / `get_finding` JSON, or the persisted resources,
relationships, evidence, and observations. Config *paths* may appear as a
`source_locator`; token *values* never do.