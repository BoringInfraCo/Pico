# Sprint 034 — read-only MCP history and diff

**Status:** IMPLEMENTING. Depends on S032 attribution and S033 public output.
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
