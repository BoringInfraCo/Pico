# Pico — v0.4 Start: Finding-Set Memory (Sprint 024)

**Status:** reference note, not a sprint spec.  
**Phase:** v0.4 — Security Memory and Change Detection  
**Sprint:** 024 (`docs/internal/sprints/SPRINT-024.md`)  
**Audience:** operator / reviewer.  
**DOC-VERIFIED** by `tests/integration/sprint024_cli_test.rs` (R1–R7). R8 (MCP) is N/A.

This is the scope statement for the **start** of v0.4. It does not close the
phase.

---

## 1. Phase vs first slice

ROADMAP §8 central claim:

> Pico can tell a developer what dangerous path appeared, disappeared,
> weakened, strengthened, or became uncertain—and what observed change
> caused it.

That is the **phase** claim. Sprint 024 proves only the first half of
identity, as **finding-set memory**:

> `pico diff` compares Findings from the last two COMPLETE scans by
> S015 fingerprint. Unchanged, appeared, and disappeared are the only
> lifecycle words this slice uses. A newer PARTIAL/FAILED attempt is a
> freshness warning, never a disappearance.

v0.4 is **in progress**. Do not read a working `pico diff` as v0.4 complete,
as history/diff UX, or as runtime observation (v0.5).

A third coding agent remains architecture unless concrete demand outweighs
this sequence. Finding-set memory is the next distinct architectural
uncertainty: can Pico compare two honest snapshots without lying about
collection failure?

---

## 2. What this slice supports

### Command

```text
pico diff
```

No scan-id operands in this slice. The comparison is always the last two
COMPLETE scans, older → newer (`ScanRepo::list_complete`: `completed_at DESC,
started_at DESC, id DESC`).

### Join key

Cross-scan identity is `findings.fingerprint` (S015): a `sha256:` of
security-significant content (class, source/actor/sink keys, path
fingerprints including boundaries, severity, confidence, remediation rule
ids). It is **not** the finding row `id`, not `scan_id`, and not a timestamp.

Consequences:

- Identical COMPLETE environments → the same fingerprint on both sides →
  **Unchanged**.
- A later COMPLETE scan that no longer contains that fingerprint →
  **Disappeared** (the confirmed path is gone from the later snapshot).
- A later COMPLETE scan that contains a new fingerprint → **Appeared**.
- A security-significant change that still yields a Finding (new sink
  identity, boundary, severity, …) **flips** the fingerprint → one
  Disappeared and one Appeared. This slice does not invent a coarser
  “same path, different severity” identity. Severity and confidence already
  live in the S015 hash, so weaken/strengthen show as a fingerprint flip.

### Comparison sides

Only `ScanStatus::Complete` scans are operands. PARTIAL, FAILED, and RUNNING
attempts are never `From` or `To`. Findings are not a valid snapshot on a
non-COMPLETE scan (S019 fail-closed; query integrity rejects findings on
incomplete scans).

If a newer incomplete attempt exists, the diff still compares the last two
COMPLETE scans and surfaces S019 freshness:

```text
Freshness: NEWER INCOMPLETE ATTEMPT
Freshness: A newer scan <id> is PARTIAL.
Comparing the last two COMPLETE scans; these results may not describe current state.
```

That is the ROADMAP §8 rule: collection failure or reduced scan scope is
never presented as remediation or disappearance.

### Empty states

These are scoped, not all-clears:

| Workspace | Guidance |
|---|---|
| 0 COMPLETE scans | `No COMPLETE scan exists… This is not an all-clear.` |
| 1 COMPLETE scan | `A previous COMPLETE scan is required to compare.` Names the newest COMPLETE scan. `This is not an all-clear.` |
| 2+ COMPLETE, zero findings both sides | `No security-significant finding change.` plus `This is not an all-clear.` |
| 2+ COMPLETE, same finding fingerprints | `No security-significant finding change.` (no all-clear line) |

### Surfaces

- **CLI:** `pico diff` via `DiffService::latest` + `render_finding_diff`.
- **MCP:** no `diff` / `what_changed` tool. MCP remains `list_findings` and
  `get_finding`. The application service can be exposed later without a
  second comparison engine.
- **Schema:** no new tables. Read over existing `scans` and `findings`.
- **Secrets:** fingerprints, titles, and scan ids only. Synthetic token
  values must not appear in the rendered diff (R7).

### CLI contract (ready comparison)

```text
Pico diff

From: <older-id> (COMPLETE)
To:   <newer-id> (COMPLETE)
Compared: LAST TWO COMPLETE SCANS
Freshness: LATEST COMPLETE | NEWER INCOMPLETE ATTEMPT

Findings
  Unchanged: N
  Appeared:  N
  Disappeared: N

[Appeared / Disappeared blocks: severity · confidence, title,
 Fingerprint, ID]

No security-significant finding change.   # only if appeared = disappeared = 0
```

Unchanged Findings are counted, not listed. Appeared/disappeared entries
pass through `terminal_safe`.

---

## 3. What this slice reuses (do not rebuild)

- **S015 fingerprints** as the join key. Do not hash scan ids or SQLite
  internals.
- **Append-only scans** and `FindingRepo::list_for_scan`.
- **Newest-COMPLETE selection and freshness** from S010/S019
  (`ScanRepo::newest_complete` / `newest_attempt`, `Freshness`).
- **PARTIAL fail-closed diagnostics.** Do not invent a second “why no
  findings” channel. Empty findings on PARTIAL mean unconfirmable, not gone.
- **Canonical resource keys.** Identity churn detection is not this slice.
- **Resource `first_observed_at` / `last_observed_at`.** Those columns never
  record absence. They are not product first-seen / last-seen.

---

## 4. Remaining v0.4 (not this slice)

ROADMAP §8 still open after Sprint 024:

- `pico history` (catalog of scans).
- Explicit `pico diff <from> <to>` by scan id.
- Resource / relationship first-seen, last-seen, changed, disappeared,
  reappeared.
- Causal explanation from evidence on both sides (“Bash went from ALLOW to
  DENY caused this”).
- First-class weakened / strengthened / uncertain lifecycle (schema still
  `OPEN` only).
- Distinguishing environment change vs Pico evidence change vs analysis /
  `pico_version` change beyond printing scan status.
- Retention, pruning, database-health controls.
- Machine-readable / CI export as a public API (`Serialize` on the DTO is
  not a contract).
- MCP / agent-triggered “what changed?”.
- Notifications, dashboards, runtime observation (v0.5).

Exit criteria from ROADMAP §8 that this slice **does** meet, for Findings
only:

- Unchanged COMPLETE environments produce no security-significant finding
  diff.
- Collection failure is never presented as disappearance.

Exit criteria it **does not** meet: causal “smallest observed cause,”
retention window, analysis-version vs environment, machine-readable
automation API, first-seen of an active path as a product fact.

---

## 5. Honesty limits

- `No security-significant finding change` means the **confirmed Finding
  set** is the same, not that the graph, Bash posture, credentials, or
  MCP surface are unchanged.
- Zero Findings on both COMPLETE scans is not safety.
- A fingerprint flip is not yet a story about *why*.
- Default `pico diff` ignores older COMPLETE history (only the last two).
- Mixed-agent and GitHub-authority Findings use the same fingerprint join;
  this slice adds no provider-specific diff logic.

---

## 6. Fixtures

| Id | Test | Asserts |
|---|---|---|
| R1 | `unchanged_complete_scans_have_empty_finding_diff` | empty appeared/disappeared |
| R2 | `complete_scan_without_finding_reports_disappeared` | Bash deny → Disappeared |
| R3 | `fingerprint_flip_is_disappeared_and_appeared` | sink-identity change → one of each |
| R4 | `partial_attempt_does_not_fabricate_disappearance` | newer PARTIAL, still Unchanged + freshness warning |
| R5 | `diff_empty_states_are_scoped` | 0 and 1 COMPLETE, not all-clear |
| R6 | `diff_fingerprint_sets_stable_across_identical_pairs` | deterministic sets |
| R7 | `secret_sweep_never_leaks_token_in_diff` | no synthetic tokens |
| R8 | MCP | N/A — no diff tool |

---

**Scope boundary:** this note authorizes finding-set `pico diff` over
COMPLETE scans. It does not authorize retention, runtime monitoring, a
third agent, or a claim that v0.4 is complete. It contains **no secrets**.
