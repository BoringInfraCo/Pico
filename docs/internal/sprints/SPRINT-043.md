# Pico — Sprint 043: Claude Code Observability Probe (v0.5 slice 7)

**Status:** SPEC — frozen for implementation.
**Sprint:** 043
**Phase:** v0.5 — Continuous and Runtime Observation (slice 7)
**Type:** Vertical slice (small) — **probe only, no parsing**
**Baseline:** `f29de82`
**Depends on:** S039 (`pico runtime` survey + support note)
**Authority:** `docs/internal/ROADMAP.md` §9; `SPRINT-039-support-note.md` §2.2/§4;
`SPRINT-040-support-note.md` §6 (safe-read precedent); research recorded in
`SPRINT-043-support-note.md` (this sprint).

---

# 0. Decision this sprint records (and why)

Claude Code runtime **ingestion is deliberately NOT implemented**. Research
(`SPRINT-043-support-note.md`) found:

1. Upstream documents the per-line transcript format as **internal and
   version-varying**, explicitly warning that direct parsers can break on any
   release and recommending `/export` or script interfaces instead.
2. This machine has **zero transcripts** (`~/.claude/projects/` and
   `~/.claude/sessions/` are empty), so there is nothing to validate a parser
   against.
3. Field names (`parentUuid`, `uuid`, `isSidechain`, `timestamp`, `cwd`,
   `sessionId`, `tool_use`, `tool_result`, `tool_use_id`, `is_error`) were
   recoverable only as **minified strings inside one installed binary build**
   (2.1.260) — not from a published schema — and even the bundled `version`
   field's meaning is unverified.
4. Live hooks (`PreToolUse`/`PostToolUse`/`PermissionDenied`) would give
   reliable semantics but require **hook installation**, which is outside
   Pico's V0 boundary (`ARCHITECTURE.md` §28.2; Invariant 10).

Shipping a parser now would encode guessed field semantics as certainty,
violating Invariant 7 (`UNKNOWN` is valid) and the evidence-honesty foundation.

> **Therefore S043 extends the S039 observability survey to Claude Code
> transcript surfaces — presence, readability, and version facts only — and
> reports `UNKNOWN`/`AVAILABLE_UNREAD` honestly. No file contents are parsed.**

---

# 1. Purpose

> **`pico runtime` answers the same observability question for Claude Code that
> it already answers for OpenCode, and states plainly that Pico does not yet
> parse Claude transcripts — and why.**

---

# 2. Scope

## 2.1 Survey extensions (`src/application/runtime.rs`, metadata only)

Add to the existing Claude surface set (no change to OpenCode surfaces):

- Claude transcript directory presence + **count of `*.jsonl` files** under
  `<home>/.claude/projects/` (directory read only; **no file opened**, no
  content, no per-file metadata).
- Whether that directory is **present-but-empty** (the honest current state) vs
  absent, reported distinctly.
- Claude CLI **version string detected from the install layout** (e.g. the
  version directory name under `~/.local/share/claude/versions/<v>`), reported
  as a DECLARED fact; unresolved → `Unknown`. Never read the binary.

## 2.2 Distinction reporting (frozen)

For Claude Code the distinctions must be:

```text
(a) configured capability      → OBSERVABLE
(b) attempted use              → AVAILABLE_UNREAD  (format internal; parsing deferred)
(c) approved vs denied use     → NOT_AVAILABLE      (live hooks/OTel only — unchanged)
(d) completed consequential action → AVAILABLE_UNREAD  (format internal; parsing deferred)
```

The deferred-parsing reason must be a `notes` entry so the output explains
itself rather than implying Pico simply forgot.

## 2.3 Support note (required deliverable)

`docs/internal/sprints/SPRINT-043-support-note.md` records: local state found,
the verified-from-binary field names, upstream documentation of format
instability (with URLs), the derived (a)–(e) table, the absence of a reliable
version marker, and the explicit deferral decision with the conditions that
would unblock parsing (real transcripts at a known CLI version, or a published
entry schema).

---

# 3. Non-goals

- **No transcript parsing, no field extraction, no `json_extract`, no reading of
  any transcript file.**
- No Claude evidence, no graph/finding effect, no promotion, no runtime
  observation label for Claude.
- No hook installation, no OTel export consumption, no daemon.
- No version-gated parser scaffolding (explicitly deferred — do not lay
  speculative groundwork).
- No new dependencies, no CLI flag changes, no MCP changes, no schema change.

---

# 4. Acceptance

- [ ] `pico runtime` reports Claude transcript surfaces with presence and a
      `.jsonl` count; present-but-empty is distinguished from absent.
- [ ] Claude distinctions are exactly those in §2.2, with the deferred-parsing
      reason present in `notes`.
- [ ] Claude CLI version is reported when the install layout exposes it, else
      `Unknown`; the binary is never read.
- [ ] Read-only proof: `~/.claude` and the fake home directory listings are
      byte-identical before/after; **no transcript file is opened** (assert the
      code performs no file open for Claude surfaces).
- [ ] Sentinel sweep: sentinels placed in fake transcript/`todos`/`shell-snapshot`
      files never appear in stdout, JSON, or notes.
- [ ] No Claude evidence, observation, or "observed" claim is produced (assert
      absent).
- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
      `cargo test --all-targets`, `git diff --check` green; `git diff
      Cargo.toml Cargo.lock` empty.
- [ ] Manual verification with a synthetic fake home (present, present-but-empty,
      and absent cases) — never the real `~/.claude` for writes.

# 5. Completion notes (2026-09-16, HEAD `f29de82` + working tree)

## Implemented

One subagent (`src/application/runtime.rs` + tests), plus a coordinator fix.
- Claude transcript directory presence + `*.jsonl` count, present-but-empty
  distinguished from absent; Claude CLI version declared from the install layout;
  distinctions exactly per §2.2; a `notes` entry stating the deferred-parsing
  reason. `RuntimeReport.notes` became `Vec<String>` to carry dynamic facts.
- Support note written (`SPRINT-043-support-note.md`): local state, verified
  binary-string field names, upstream format-instability documentation with URLs,
  the (a)–(e) derivability table, the absence of a version marker, and the
  explicit deferral conditions.

## Deviations

1. **Coordinator defect fix.** The count was implemented as *direct* children of
   `projects/`, but the documented layout is `projects/<project>/<session>.jsonl`
   — so a real install would always report `0`. Found by manual verification, not
   by the agent's tests (which had encoded the flat layout, and even asserted
   that nested transcripts were *not* counted). Fixed to a depth-bounded,
   entry-capped walk; both the unit test and the integration fixture were
   corrected to the real nested layout so the regression is caught.
2. Raw counts appear in JSON `notes` (and structurally in `SurfaceReport`); the
   human survey output is unchanged because S039 notes are JSON-only.

## Validation

- New: 8 runtime unit + 4 binary-driven integration (S043) — all PASS; S039's
  suite unregressed.
- Full suite: **720 passed, 1 ignored, 0 failed**; `fmt`, `clippy -D warnings`,
  `git diff --check` clean; `git diff Cargo.toml Cargo.lock` empty.
- Manual (synthetic home, never the real `~/.claude` for writes): distinctions
  `OBSERVABLE / AVAILABLE_UNREAD / NOT_AVAILABLE / AVAILABLE_UNREAD`; notes report
  `contains 2 *.jsonl file(s)`, `Claude CLI version 2.1.260: DECLARED`, and the
  deferral reason; directory listing byte-identical before/after; 0 sentinel
  hits; no "observed" claim anywhere.

## Learnings

The probe was the right call: research showed the format is documented as
internal/version-varying with zero local transcripts to validate against, so a
parser would have encoded binary-string guesses as certainty. Manual verification
also proved its worth — a plausible-looking implementation reported `0` for a
real-shaped install, and only a hand-built nested fixture exposed it.

## Canon Changes

None. No Claude parsing, evidence, or "observed" claim exists; the deferral is
recorded as a support-note decision, not a canon change.
