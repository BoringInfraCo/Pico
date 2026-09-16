# Sprint 034 — read-only MCP history and diff

**Status:** DONE — validated in S036 with no code changes (implementation `3618018` unchanged).
**Scope:** two additive tools; no protocol upgrade or write surface.

## Contract

Append `list_history` and `diff_scans` after the unchanged `list_findings`
and `get_finding` descriptors. Both new tools advertise `readOnlyHint`.
The server workspace is fixed; clients cannot supply paths or SQL.

`list_history` accepts omitted arguments or an empty object. `diff_scans`
accepts omitted arguments/an empty object for latest-two comparison, or
exactly two nonblank string keys `from` and `to`. Null, arrays, extra keys,
wrong types, and one-sided pairs are invalid parameters. Validation precedes
database access and does not echo rejected input.

Dispatch calls HistoryService/DiffService and S033's public projection.
Successful results use existing MCP text content framing. Query limitations
(insufficient history/NotComparable) are successful typed results, never an
all-clear. Application errors use the same redacted public error payload as
CLI JSON, framed with `isError: true`. Invalid tool parameters remain fixed
JSON-RPC `INVALID_PARAMS` errors. Existing tool behavior stays unchanged.

## Validation

- R1: exact appended descriptors and unchanged first two descriptors.
- R2: history/diff decoded payload equality with CLI JSON on empty, one-scan,
  and ready workspaces, including explicit pairs.
- R3: fixed rejection of invalid shapes/extra/one-sided/blank parameters;
  no sentinel leaks and no state initialization.
- R4: application error parity for missing/pruned IDs, incomplete/reversed
  pairs, unsupported schema, and missing state; `isError` is true.
- R5: NotComparable remains typed, with CLI parity and no fabricated delta.
- R6: identical database content before/after repeated query calls; secret
  sweep; stdio framing and clean EOF; previous MCP suites stay green.

No new scanning, attribution, or persistence logic belongs in MCP. The
release remains pending the S035 independent comprehension gate.

---

## Completion notes (S036 validation, HEAD `615e530`, 2026-09-16)

### Implemented

No code changes. Implementation `3618018` verified against R1–R6 as specified:
descriptors, CLI↔MCP parity, strict parameter rejection, redacted application
errors with `isError`, typed `NotComparable`, read-only digests, secret sweep,
stdio framing. No comparison, scanning, retention, or attribution logic in MCP
(`src/mcp` dispatches to `HistoryService`/`DiffService` + S033 public DTOs only).

### Deviations

None.

### Validation

- `tests/sprint034_mcp.rs`: 7/7 PASS.
- Full suite: 564 passed, 1 ignored, 0 failed; `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `git diff --check` clean.
- `git status -- src/mcp` clean; `src/mcp` tip is `3618018`.
- Manual verification in disposable workspace `/tmp/pico-036-20260916` (isolated
  HOME, scrubbed credential env): `init` (idempotent) → `scan` ×3 across an
  allow→deny change → `findings` / `history` / `diff` / `diff --json`
  (byte-identical repeat, valid JSON) / `history --json` (valid) / `doctor`
  (ok) / `prune --keep 2` (prunes 1, repeat no-op, health ok) / MCP
  `list_history` + `diff_scans` (schema v1 `ready` payloads). All PASS.

### Learnings

Strict parameter validation preceding database access plus projection through
the frozen S033 DTOs keeps the MCP surface a pure view; parity testing through
both transports catches framing drift that unit tests on either side miss.

### Canon Changes

None.
