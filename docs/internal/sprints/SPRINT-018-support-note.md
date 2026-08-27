# Sprint 018 — Cloudflare Authority Support Note

This note defines, for operators and downstream consumers, exactly what Pico can
and cannot establish about Cloudflare authority from a scan. It is the
authoritative scope statement for the per-edge Cloudflare authority surfacing
shipped in Sprint 018 (R6 / R7 / R10).

## What Pico can establish

Pico surfaces, per Cloudflare `can_mutate` edge on an explained finding path, a
credential-type-aware authority view built only from the safe, normalized
Cloudflare provider projection:

- **Credential type.** The kind of Cloudflare credential that produced the edge,
  classified from the lexical shape of the token presented to the scan
  (deterministic, never a substitute for live verification):
  - `api_token` — `cfut_` prefixed tokens, or any unrecognized token shape
    (the safe default: scoped, never assumed to carry global authority).
  - `api_key` — a long global API key shaped value.
  - `oauth` — `cwo_` / `fou_` prefixed tokens, or a long (>= 40) non-global-key
    token.
- **Granted permission groups.** The effective permission group names that
  actually grant the resolved authority. For a write grant this is the Workers
  write group(s) (e.g. `Workers Scripts Write`); for a read-only grant it is the
  read group(s) (e.g. `Workers Scripts Read`). Pico distinguishes read-only from
  write by these groups, never by the credential name or by inference.
- **Authority resolution tier.** One of `EXACT`, `SCOPED`, `BEHAVIORAL_READ_ONLY`,
  or `UNKNOWN`, as resolved by the provider adapter from the verified token
  policy, account scope, and the observed Worker.
- **Permission state.** The resolved permission posture, e.g.
  `WORKERS_SCRIPTS_WRITE`, `READ_OR_UNKNOWN`, `DENIED_OR_OUT_OF_SCOPE`, or
  `GLOBAL_API_KEY`.
- **Account scope state.** Whether the grant's account selector placed the target
  account `IN_SCOPE`, `OUT_OF_SCOPE`, or left scope `UNKNOWN`.
- **Zone-scoped flag.** Whether the authority was resolved through a zone-scoped
  (rather than account-wide) policy grant.

These fields are surfaced on the CLI explained-finding view as a
`Cloudflare <credential_type> authority:` block and on the MCP `get_finding`
JSON as the `cloudflare_authority` array, one entry per Cloudflare Worker edge.

## What Pico cannot establish

- **No non-allowlisted calls.** Pico's Cloudflare client is confined to a fixed
  allowlist of read-only endpoints (`/user/tokens/verify`,
  `/user/tokens/<id>`, `/user/tokens/permission_groups`, `/accounts`, and
  `/accounts/<id>/workers/scripts`). It never issues, and never can issue, any
  other Cloudflare API call. Pico does not mutate, deploy, or reconfigure any
  Worker or token.
- **Global API keys are unverified.** A global API key shape cannot be resolved
  through the scoped token endpoints, so Pico synthesizes a bounded,
  unverified authority projection (`permission_state = GLOBAL_API_KEY`,
  `unknown_reasons = ["GLOBAL_KEY_UNVERIFIED"]`). Pico does **not** confirm what
  a global key can do; it only records that an unverifiable global key shape was
  observed. The rendered view labels this `global-key-unverified`.
- **No enforcement.** Scope, resolution tier, and permission state are
  *observations of the token policy as normalized by the provider adapter*. They
  are not Pico's enforcement. Pico neither grants nor removes authority; it
  describes potential reachability. The finding is a potential-exposure
  statement, not a claim of exploitation or compromise.
- **No new provider trust.** Pico only interprets the single Cloudflare
  credential already reachable from the scanned environment. It does not
  discover, trust, or contact additional Cloudflare accounts, zones, or
  providers beyond what the credential's own policy enumerates.
- **No secret exposure.** Credential values, raw authorization headers, and
  token values are never persisted, rendered, or emitted. Only the
  classification facts above (credential type, granted groups, tier, scope) are
  surfaced; source locators may appear only when they pass the safe-locator
  filter. R10 verifies that token values never reach rendered output, MCP JSON,
  or persisted metadata across the api_token / api_key / oauth postures.
- **No runtime verification of effect.** Authority is resolved from the static
  token policy and the Worker inventory at scan time. Pico does not attempt to
  exercise the credential, and it does not re-verify liveness beyond the
  bounded, allowlisted read calls.
