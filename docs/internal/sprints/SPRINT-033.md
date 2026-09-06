# Sprint 033 — stable diff/history JSON

Status: implemented and targeted validation passed, 2026-09-05. Depends on S032 attribution; full release gates are recorded in S035.

## Contract

`pico diff [<from> <to>] --json` and `pico history --json` emit exactly one
JSON document and a newline after successful parsing. Human command output
and exit semantics stay unchanged. Clap syntax/help errors remain clap text
on stderr (exit 2 for syntax errors); `--json` does not override parsing.
Application errors emit a redacted JSON error on stdout and return exit 1,
with a fixed safe diagnostic on stderr. Query limitations return exit 0.

Shared `output` DTOs are separate from application/persistence types.
Envelope fields are `schema_version: 1`, `command`, and `status`. Diff statuses
are `ready`, `insufficient_history`, `not_comparable`; history is `ready`
even when empty; application failures are `error`. Diff insufficient-history
reason is `no_complete_scan` or `need_previous_complete`. All nullable fields
are present with null, all collections are arrays, and successful branches
have only their documented fields. Enum values are lower snake case except
persisted domain values such as scan status/severity/confidence, which retain
uppercase spellings. Scan/finding IDs and fingerprints are opaque handles.

Public version is independent of SQLite, comparison, and build versions.
Removing/renaming fields, changing meanings/types, or adding enum variants
requires a new public version; optional additive fields may retain version 1.
Consumers must ignore unknown fields. The producer schema rejects extras to
catch accidental leakage; consumers may deliberately use a looser reader.

Ready diff includes pair, selection, freshness, side comparison provenance,
finding buckets, graph buckets, and S032 attribution. Explicit-pair freshness
is `not_assessed`: existing application explicit reads do not assess newest
attempts, so a historical pair must not imply current state. Latest reads
retain `latest_complete`/`newer_incomplete_attempt`. Missing-history context
has `not_assessed` freshness. First-seen/reappearance and absence are expressly
relative to retained COMPLETE observations at/before the destination scan.
Unconfirmed graph absence uses `not_observed`; finding disappearance remains
an observed finding-set difference and has an explicit qualification that
it does not establish remediation. S032 attribution carries confirmation.
History states `retained_history_only: true`, observed COMPLETE count and
oldest/newest retained COMPLETE IDs, without inventing a prune count or
asserting that earlier history never existed.

All projections allowlist fields. Persisted strings receive terminal-safe
escaping; raw metadata, snapshots, credential contents, and DB exception
messages are excluded. Coarse stable error codes are `usage_error`,
`database_error`, `io_error`, `internal_error`; messages are fixed constants.
No fragile parsing of English errors to manufacture granular error codes.

Ordering follows application deterministic order. History is persisted
chronological order; graph identities are canonical-key ordered; finding
and lifecycle ordering follows the application fingerprint order; attribution
and provenance retain their defined field/side ordering. Reads do not add
wall-clock timestamps. Repeated unchanged reads must be byte identical.

## Implementation and validation

Own shared output DTOs, CLI flags/dispatch, checked-in schema, consumer docs,
representative goldens and subprocess tests. MCP consumes the same DTOs in
S034. No comparison, discovery, retention, or database mutation in output.
Test all four application diff variants, empty/populated history, errors,
CLI actual parser behavior, deterministic output, null shape, unsafe text,
provenance and attribution projection, and retained history qualification.
S034 tests shared payload parity. Run targeted tests then full release gates.


## Evidence

`cargo test --test sprint033_output`: 10 tests pass. The six frozen JSON
outcomes cover all four application diff variants, empty history, and an error.
Additional populated-history and attribution fixtures cover chronological
window endpoints, all four attribution classes and coverage states, side IDs
and supported fields, all not-comparable reasons, nullable provenance, and
latest-vs-explicit freshness. Typed projection proves missing/null/string-null
remain distinct while raw objects and token-shaped values are redacted.

Every fixture is validated against `docs/public/output-v1.schema.json` by a
fail-closed validator for its exact keyword subset. Negative controls reject
missing/extra fields, wrong types, unknown status/classification/lifecycle
shapes, negative versions, raw typed objects, and invalid typed-value presence.
Unknown schema validation keywords panic rather than being silently ignored.
Subprocess tests verify deterministic bytes, database bytes unchanged, no
state creation on missing databases, safe application errors, and actual clap
parser stdout/stderr/exit behavior. S034 separately pins MCP parity.

In query output, legacy `Scan`/`Init` errors map to `database_error`: the shared
read-only database opener uses `Scan` for missing/unopenable state. The mapping
uses variants, never raw-message parsing, and retains fixed redacted messages.
