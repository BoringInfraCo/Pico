# v0.4 controlled evidence — 2026-09-05

**Technical packet: executed, partial scenario coverage. Independent comprehension: NOT RUN. Release: HOLD.**

The two tests in `tests/sprint035_dogfood.rs` passed with opt-in transcript capture.
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
| E3 | Captured OpenCode allow→deny and synthetic-provider boundary transition; PASS. Ask intermediate and equivalent Claude captures remain unexecuted. |
| E4 | No credential/resource/MCP/authority variation capture sequence executed here; field regressions are separate S032 evidence. |
| E5 | Malformed configuration gives PARTIAL, latest COMPLETE pair stays selected with newer-incomplete freshness, recovery has no disappearance; PASS. Other access-loss modes not executed here. |
| E6 | Synthetic provider coverage remains unknown and disappearance is not confirmed; reduced-scope/legacy complete captures remain unexecuted here. |
| E7 | Synthetic finding stable then not observed under deny; multiple-change ambiguity and rating movement captures remain unexecuted. |
| E8 | Seeded comparison contract 999 produces not-comparable across human/JSON/MCP; PASS, not a real upgrade run. |
| E9 | Keep-two prune, no-op repeat, retained and removed pair queries, history, and doctor; PASS. |
| E10 | Pruned-ID error captured; remaining argument/schema/error cases belong to S033/S034 regression tests, not this capture sequence. |
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
