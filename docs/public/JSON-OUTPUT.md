# Diff and history JSON

Use `pico history --json`, `pico diff --json`, or
`pico diff <older-id> <newer-id> --json`. Both commands read existing state
without migration. The [v1 schema](output-v1.schema.json) defines the public
payload shared with MCP `list_history` and `diff_scans`.

Read `schema_version`, `command`, and `status` first. A `ready` diff means
comparison was possible, not that the workspace is safe. `insufficient_history`
and `not_comparable` are successful query limitations (exit 0) and contain no
finding buckets. Application failures return `status: error`, a stable coarse
error code, and exit 1. IDs that are missing, pruned, incomplete, equal, or in
reverse order return `usage_error`. Invalid database/schema states return
`database_error`. Details that may contain secrets are intentionally absent.

Clap parsing failures (unknown flags, too many operands) remain text on stderr
and exit 2, with empty stdout. Help/version remain text. After successful
parsing, JSON mode writes one compact JSON document plus newline to stdout;
a failed query also emits a fixed diagnostic to stderr. No status banners
are interleaved with JSON. Broken output streams may prevent a full document.

Diff `findings` uses unchanged/appeared/not_observed/weakened/strengthened/uncertain
buckets. Graph resources and relationships use unchanged/first_seen/reappeared/
changed/not_observed. A finding disappearance only means it was not produced
in the destination observation set. Graph absence likewise does not prove
remediation. Read S032 `attribution`, including per-change classification,
coverage, reason codes, and `disappearance_confirmed`. `before`/`after` field
values distinguish missing, null, redacted, and typed JSON values; empty string and the
literal string `"null"` are neither null nor missing. Raw objects and non-allowlisted arrays are redacted, as are token-shaped strings. Legacy cause summaries
are preserved for human parity; attribution is the source of confirmation.
A Cause summary alone is insufficient to establish an environmental cause,
confirmation, or remediation; consult attribution classification, reasons,
coverage, and `disappearance_confirmed` plus `limitations`.

`compared_via` is latest_two or explicit_pair. Latest comparisons assess
newer incomplete attempts via `freshness`. Explicit pairs use not_assessed,
since the query does not assess whether the pair describes the newest state.
Side provenance keeps Pico build versions separate from comparison tuples.
Public schema version 1 is independent of both and of the SQLite schema.

All history is retained history: first-seen does not establish first-ever.
History reports its actual COMPLETE window, not a claimed configured prune
policy. The prune `--keep` argument selects a retention policy input; it does
not define the retained window. Consumers must read the actual window
(`retained_history_only`, `complete_scan_count`, oldest/newest COMPLETE) and
must not treat first-seen as first-ever. Catalog order is started_at then ID. COMPLETE window endpoints use
completed_at, started_at, then ID; diff uses that same COMPLETE chronology.
Finding/graph/attribution arrays preserve deterministic application ordering.
Repeated reads of unchanged state produce equal bytes and omit read-time clocks.

Nullable fields are present with null; arrays are present even when empty.
Treat IDs and fingerprints as opaque. Persisted strings use terminal-safe
escaping, so control characters appear as literal `\\xHH` text after JSON
decoding. No raw metadata or credential contents are exported. Consumers
should ignore unknown fields. Optional additive fields may retain v1;
changed meanings/types, removed fields, and new enum variants need a new
public version. The checked-in producer schema rejects unexpected fields to
catch accidental projection leaks.
