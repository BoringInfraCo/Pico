# Sprint 019 — Scan Diagnostics Support Note

This note defines, for operators and downstream consumers, exactly what Pico's
structured scan diagnostics explain when evidence is incomplete, and the
invariants those diagnostics uphold. It is the authoritative scope statement for
the incomplete-evidence surfacing shipped in Sprint 019 (R6 / R7 / R10).

## What Pico's diagnostics explain

Pico emits a structured, machine-readable diagnostics view
(`ScanDiagnostics`) for every scan alongside the existing human-readable
messages. It explains precisely *which* evidence was incomplete and *why*,
never a bare "scan is not COMPLETE":

- **Provider failure.** For each provider (the local OpenCode adapter and, when
  a Cloudflare credential is reachable, the Cloudflare adapter), Pico reports
  whether the provider was reachable or failed, plus the sanitized problem
  message(s) the provider reported. A failed provider is surfaced as
  `Provider <name>: FAILED` on the CLI and `reachable: false` in the MCP
  `provider_statuses` array.
- **Partial scan.** When any provider failed or analysis was limited, the scan
  lifecycle is `PARTIAL` and `partial_reason` names the provider responsible.
  Under a partial scan, positive Findings are suppressed *because* of that
  incompleteness; Pico never implies the path is safe.
- **Stale / partial / unknown edges.** A security-critical edge whose evidence
  is `Stale`, `Unknown`, or observed under a `PARTIAL` scan is classified as
  unconfirmable and recorded as a suppression reason (`Suppressed
  <fingerprint>: <reason>` on the CLI; `suppressed` in MCP). An `Aging` edge is
  recorded as a confidence reduction instead.
- **Suppressed reasons.** For every candidate AttackPath that was Active but did
  not become a Finding, Pico records the precise reason (which critical edge
  could not be confirmed and why, e.g. `edge evidence is STALE; candidate not
  confirmed`).
- **Confidence reduction.** For every emitted Finding whose confidence was
  reduced, Pico records which edges contributed the penalty, the edge's
  evidence freshness, and the penalty itself (`Confidence reduced
  <fingerprint>: <edge_key> (<freshness>, -<penalty>)` on the CLI;
  `reduced_confidence` in MCP).

These facts are surfaced in the `pico scan` CLI summary as an
`Incomplete evidence` block and in the `list_findings` MCP payload as a
`diagnostics` object (`provider_statuses`, `scan_status`, `partial_reason`,
`suppressed`, `reduced_confidence`). On the golden path (Complete + Fresh, all
providers reachable, no suppression, no confidence reduction) the diagnostics
are clean and the CLI prints no incomplete-evidence noise.

## Invariants

- **Absence of evidence is never claimed safe.** Pico treats missing, stale,
  partial, or unknown evidence as `UNKNOWN`/`PARTIAL` and surfaces it; it never
  infers safety from the absence of evidence.
- **Provider problems never contain secret values.** Every provider `problem`
  string originates from discovery/provider code that already redacts tokens.
  Credential values, raw authorization headers, and token values are never
  persisted, rendered, or emitted. The secret sweep (R10) asserts across the
  partial, stale-edge, and unknown-authority postures that no secret-shaped
  value appears in the rendered CLI diagnostics block, the MCP diagnostics JSON,
  or any provider `problem`.
- **Diagnostics are a read-only projection.** They reuse only already-computed
  facts (scan status, edge freshness, authority resolution, unknown reasons)
  and add no new authority or confidence logic.