# v0.4 controlled evidence — 2026-09-05

**Technical packet: executed, partial scenario coverage. Independent comprehension: NOT RUN. Release: HOLD.**

The five tests in `tests/sprint035_dogfood.rs` passed with opt-in transcript capture.
The [build record](transcripts-v0.4/build-evidence.json) identifies the base commit,
uncommitted source file hashes, tracked patch digest, actual binary hash/version,
platform, command, and result. The source manifest includes untracked implementation
files that `git diff` alone omits. This is evidence for that recorded working-tree
build; later edits require rerunning capture and recording a new manifest.

[Capture manifest](transcripts-v0.4/capture-manifest.json) hashes all captures and
records the sentinel/control-byte sweep. Command records contain actual arguments
and exit codes; stdout and stderr are separate. MCP request/response files retain
actual JSON-RPC framing. Tests assert exact decoded CLI/MCP equality and repeated
CLI JSON byte equality. Captures were not rewritten to obtain a pass.

## Observation classes and coverage

The local sequence runs actual configuration discovery, graph construction,
analysis, and persistence through `ScanService`, with an empty temporary home and
explicit empty environment. It makes no provider network calls. Its allow/deny,
malformed configuration, recovery, pruning, doctor, and query outputs are product
execution. Scan-service reports identify this invocation seam; they are not
represented as shell `pico scan` stdout. Only the final contract mismatch is a
seeded persisted metadata mutation.

The second sequence discovers actual OpenCode/GitHub MCP fixture configuration
but injects a **synthetic Cloudflare provider result**. It creates a supported
production-rated finding, repeats it, captures CLI/MCP detail, and changes Bash to
deny. It does not prove live-provider correctness or actual production access.
Provider coverage remains unknown; the test rejects confirmed disappearance.

| S035 case | Observed evidence and limits |
| --- | --- |
| E1 | Captured empty history/diff and one-scan insufficient history; PASS. |
| E2 | Real local unchanged scan has no graph lifecycle/change deltas; synthetic provider finding remains unchanged; PASS for these fixtures. |
| E3 | Real local: isolated OpenCode allow→ask is Mixed (paired_field_observation + knowledge_changed per strict S032 DERIVED→UNKNOWN) and ask→deny is Mixed (latest-two UNKNOWN→BLOCKED is knowledge per strict S032); Claude allow→deny is observed_environment_change; MCP enabled→disabled has non-empty graph changes; PASS. Synthetic provider finding stable then not observed under deny with no disappearance_confirmed; PASS synthetic. |
| E4 | Synthetic provider variants (account scope, authority scope, credential status, authority resolution, resource identity, multiple simultaneous changes) each produce non-empty graph changes with no disappearance_confirmed; PASS synthetic. Real MCP enabled/disabled variation is captured in E3. |
| E5 | Malformed configuration gives PARTIAL, latest COMPLETE pair stays selected with newer-incomplete freshness, recovery has no disappearance; PASS. Other access-loss modes not executed here. |
| E6 | Real reduced-home-scope COMPLETE carries coverage_changed; seeded legacy missing coverage carries coverage_unavailable with no disappearance_confirmed; PASS. Synthetic provider coverage remains unknown with no confirmed disappearance; PASS synthetic. |
| E7 | Synthetic rating-only seeded mutation (severity LOW plus fingerprint-seeded, family unchanged) yields one weakened finding with no observed_environment_change; multiple simultaneous changes captured with no disappearance_confirmed; PASS synthetic. |
| E8 | Seeded comparison contract 999 produces not-comparable across human/JSON/MCP; PASS, not a real upgrade run. |
| E9 | Keep-two prune, no-op repeat, retained and removed pair queries, history, and doctor; PASS. |
| E10 | Full error/argument matrix captured: reversed/missing/incomplete pairs, five invalid MCP args (-32602), parser error, unsupported-schema history/diff, DB bytes unchanged; pruned-ID error; PASS. |
| E11 | Synthetic provider finding detail captured through CLI and existing MCP list/detail; PASS for fixture. Independent understanding not tested. |

## Retention and safety evidence

Each query's `*-read-only.json` proves SHA-256 equality of the closed main database
file before and after human, repeated JSON, and MCP reads. These disposable SQLite
fixtures use rollback journaling; this is not a general WAL or logical-content
claim. The retained-row digest uses canonical SQL `quote()` serialization across
all 16 tables, with retained unit/link filters and unfiltered globals, and remains
equal after real pruning. Second prune leaves database bytes equal.

Retained from/to, provenance, findings, attribution, and every graph field remain
equal except the deliberately window-relative `first_seen_scan_id`, which advances
to the oldest remaining witness. The test explicitly checks that exception and
compares the complete remaining graph. Earlier first-seen history cannot survive
its evidence being pruned. Doctor succeeds; removed IDs return an explicit error.

Retention terminology — keep distinct: (a) retained history window (what history
lists as the retained COMPLETE window), (b) retained-pair comparability (what a
retained diff pair establishes within that window, including window-relative
`first_seen_scan_id`), (c) removed-ID unavailability (explicit typed error for
pruned/missing IDs, not evidence of absence). Do not conflate the configured
prune keep argument with the actual retained window reported by history/doctor.

All capture writes check the synthetic malformed-config sentinel and raw control
bytes. Final database checks reject the sentinel and synthetic credential. The
artifact sweep additionally rejects both known synthetic secret strings. This is
specific fixture evidence, not a claim that arbitrary secret detection is complete.

## Remaining release work

The parent release review owns full-suite/fmt/clippy results. This packet does not
claim those gates from a narrower test run. Finish the unexecuted scenario variants
above or explicitly revise scope through release review. Administer the prepared
[comprehension protocol](comprehension-v0.4.md) to an eligible independent human,
record verbatim answers, and score both v0.4 and carried v0.3 gates. No participant,
answers, usefulness result, or sign-off has been fabricated. Protocol preparation
and automated tests do not satisfy that external gate.
