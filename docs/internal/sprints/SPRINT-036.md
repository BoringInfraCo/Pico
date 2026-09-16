# Pico — Sprint 036: v0.4 Closeout Finish (no-human-gate)

**Status:** DONE (2026-09-16, HEAD `615e530`). Docs-only closeout; no `src/` or `tests/` changes.
**Sprint:** 036
**Phase:** v0.4 — Security Memory and Change Detection (closeout)
**Type:** Closeout-finish (small–medium)
**Baseline:** `615e530`
**Depends on:** S031 DONE, S032 DONE, S033 DONE, S034 code-done (`3618018`), S035 PARTIAL/HOLD (`3c7cfd7`, `c7626b8`)
**Authority:** `docs/internal/ROADMAP.md` §8; `docs/internal/sprints/V0.4-CLOSEOUT-PLAN.md` §8; `SPRINT-034.md` (R1–R6); `SPRINT-035.md` (§§2–4, §6); final implementation contracts take precedence over proposed names in the closeout plan.

---

# 1. Purpose

Close everything in v0.4 that does **not** require a human participant, so the only remaining open item is the independent comprehension gate.

> **S034 is validated to DONE, S035 automated evidence is finished to its synthetic limits, and §13 self-safety gates are packaged — with the human gate explicitly left NOT RUN.**

This sprint exists because S035 is HOLD pending recruitment that may never arrive. Per ROADMAP §17 the gate stays open; this sprint records an EXTEND path, never a proxy pass.

---

# 2. Scope

## T1 — S034 validation to DONE (no new tools)

- Run `SPRINT-034.md` R1–R6 against the final build: appended `list_history` / `diff_scans` descriptors, unchanged `list_findings` / `get_finding`, CLI JSON ↔ decoded MCP payload parity (empty / one-scan / ready, explicit pairs), strict invalid-param rejection without state init or input echo, application-error parity with `isError: true`, `NotComparable` typed parity, no-write digests, secret sweep, stdio framing + clean EOF.
- Existing suite `tests/sprint034_mcp.rs` (7 tests, green on `615e530`) is the vehicle; add tests only for gaps found.
- Flip `SPRINT-034.md` to DONE with Implemented / Deviations / Validation / Learnings. No new scanning, attribution, persistence, or write surface.

## T2 — S035 automated remainder (no human)

- Fill or explicitly bound the gaps in `dogfood/evidence-v0.4.md` "Remaining release work": remaining E5 access-loss variants or a stated bound, E4 unsupported-field explicitness, E6 legacy-provenance handling, E8 seeded-999 labeling (a real upgrade run is NOT required — label the seed as synthetic).
- Distinguish real local discovery from synthetic provider injection in every capture; never present a seeded scan as a live run.
- Recapture `transcripts-v0.4/build-evidence.json` + `capture-manifest.json` on the final build (commit, dirty status, binary SHA-256, `pico --version`, platform, digests, sanitization manifest, sweep result).
- `SPRINT-035.md` stays PARTIAL/HOLD with the human gate as the sole open item. `dogfood/comprehension-v0.4.md` stays NOT RUN.

## T3 — §13 self-safety packaging (no new product)

- Repeated-read byte equality for `history` / `diff --json`; read-only + retained-row digests; sentinel + control-byte sweeps across all new captures.
- `prune` / `doctor` UX check: actionable, secret-free errors (S031 contracts, no behavior change).
- Record offline scan perf note (S022 precedent ~0.3s) as a regression note, not an optimization project.
- Touch the S013 support-matrix appendix only if history/diff limits materially changed; otherwise leave canon docs untouched per SKILL.md documentation rules.

---

# 3. Non-goals

- No v0.5 runtime observation, daemon, triggers, or notifications.
- No new agents, providers, MCP tools, or write operations.
- No enforcement, remediation, hosted service, CI gates, or dashboards.
- No version bump (`Cargo.toml` stays `0.1.0` until release review decides).
- No proxy comprehension, no closing the human gate, no rewriting historic proxy results.
- No speculative abstractions (`RuntimeObserver`, `PolicyEngine`, etc. per SKILL.md anti-speculation rule).

---

# 4. Acceptance

- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`, `git diff --check` green on the recorded build; ignored tests listed, not counted as passes.
- [ ] `tests/sprint034_mcp.rs` + `tests/sprint035_dogfood.rs` green; any new gap test pinned.
- [ ] CLI JSON ↔ decoded MCP parity proved for all S033 outcomes on the final build; `NotComparable` stays typed, never an all-clear.
- [ ] Read-only digests equal before/after queries; retained-row digests equal after prune; second prune is a no-op on bytes.
- [ ] Secret/control-byte sweeps clean; no raw secret or rejected-input echo in outputs, errors, or diagnostics.
- [ ] `SPRINT-034.md` → DONE with completion notes; `SPRINT-035.md` execution record updated with remaining-gaps-or-bounds + HOLD (human-only); closeout plan progress line updated.
- [ ] Manual verification in a disposable workspace (`/tmp/pico-036-<date>`): `init / scan / findings / history / diff [--json] / prune / doctor` + MCP `list_history` / `diff_scans` parity spot-check.

---

# 5. Completion notes (2026-09-16, HEAD `615e530`)

## Implemented

- T1: S034 R1–R6 verified against implementation `3618018` via three
  read-only probes (subagents); zero drift (MCP dispatches to
  `HistoryService`/`DiffService` + S033 DTOs only). No code changes.
  `SPRINT-034.md` flipped to DONE with completion notes.
- T2: S035 E-coverage mapped (E1–E3/E9–E10 covered; E4–E8/E11 partial with
  stated synthetic limits preserved verbatim). Recapture proven unnecessary
  (`git diff d3c0d83 HEAD -- src tests` empty). E4 bound grounded in the S032
  contract (`tests/integration/sprint032_cli_test.rs`). `SPRINT-035.md` §7
  bound recorded; human gate untouched (NOT RUN).
- T3: §13 gates packaged GREEN across existing suites (determinism,
  secret-sweeps incl. per-sprint canaries, allowlist rejection, read-only
  digests, boundary honesty incl. `NotComparable`/no-false-disappearance).
  Doctor/prune redaction confirmed (`src/cli/render.rs`, pinned by S030/S031
  CLI tests). Perf precedent `0.326s` (SPRINT-022 G3) cited, not re-optimized.
  Support-matrix touch-up judged NOT NEEDED. Public JSON docs confirmed
  (`docs/public/output-v1.schema.json`, `docs/public/JSON-OUTPUT.md`).
- Status lines updated: ROADMAP (header, §8 paragraph, §18 block, slice
  scope), closeout plan (status + progress), AGENTS.md baseline.

## Deviations

None — sprint executed as spec'd; no new tests were needed (existing
`tests/sprint034_mcp.rs` 7/7 and `tests/sprint035_dogfood.rs` 5/5 already pin
the contracts).

## Validation

- `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --all-targets` (564 passed, 1 ignored, 0 failed),
  `git diff --check`: all clean.
- Manual verification in `/tmp/pico-036-20260916` (isolated HOME, scrubbed
  credential env): `init` (idempotent) → 3 `scan`s across allow→deny →
  `findings` / `history` / `diff` (observed environment change with paired
  before/after evidence; "not an all-clear" preserved) / `diff --json`
  (byte-identical repeat, valid JSON) / `history --json` (valid) / `doctor`
  (ok, schema 6) / `prune --keep 2` (prunes 1, repeat no-op, health ok) /
  MCP `list_history` + `diff_scans` (schema v1 `ready`). All PASS.

## Learnings

Closing a code-done slice by validation-only spec keeps the diff reviewable
and the frozen captures valid; the remaining v0.4 risk is purely the human
gate (recruitment), not technical. Per-field S032 acceptance plus stated
synthetic limits is a sufficient bound for E4 without new fixtures.

## Canon Changes

None (status lines only; no product, technical, architectural, or sequencing
change — v0.5 remains unauthorized until the S035 release decision).
