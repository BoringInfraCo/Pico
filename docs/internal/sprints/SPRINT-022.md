# Pico — Sprint 022: v0.3 Controlled Dogfood & Comprehension Close

**Status:** READY

**Sprint:** 022
**Phase:** v0.3 — Earned Agent and Provider Expansion
**Type:** Validation (controlled dogfood + comprehension)
**Baseline:** `77e456e` (post-Sprint-021 main HEAD)
**Depends on:** Sprint 020 (Claude Code), Sprint 021 (GitHub repository mutation authority), Sprint 019 (incomplete-evidence diagnostics), ROADMAP §7 v0.3 exit criteria

---

# 1. Purpose

Sprints 020–021 added the v0.3 surfaces (Claude Code; GitHub mutation authority) and proved them with **fixtures**. ROADMAP §7 v0.3 exit criteria also require **controlled dogfood** of the new end-to-end path, **preserved scan clarity / local performance**, and demonstrated **user usefulness** (`ROADMAP.md:426`). This sprint runs the controlled dogfood and the comprehension close, then records the v0.3 advancement decision per ROADMAP §17.

It is a **validation sprint**: it produces no new engine features; it exercises the shipped CLI against a controlled, offline workspace whose fixtures include the v0.3 surfaces, captures evidence, and evaluates the product gates.

**Critical constraint:** the Sprint 012 live token (`cfut_…`, id `6b1a59bb84dd680a1dde77f49b3f357b`) is **pending dashboard deletion and must not be used**. This dogfood is **offline** with **synthetic tokens** (`cfut_TESTFAKE…`, `ghp_TESTFAKE…`). Offline authority is `UNKNOWN` by design (S021/S018) — an honest, demonstrable outcome, not a defect.

---

# 2. Gates

```text
G1  Mixed-surface controlled scan: both agents (OpenCode + Claude Code), both
    credential types (Cloudflare + GitHub), GitHub MCP influence, offline
    authority UNKNOWN — honest counters, no fabrication.
G2  Scan clarity: output is parseable and understandable — per-agent effective
    Bash state, Cloudflare + GitHub credential authority, incomplete-evidence
    diagnostics — all present and self-explanatory.
G3  Local performance + offline core: elapsed time recorded; zero outbound
    network traffic (offline default transports).
G4  Determinism: two independent runs produce identical normalized output and
    identical DB-structure hashes (ties S015/S020/S021 stability).
G5  Secret sweep: synthetic token values and their first 8 chars appear ZERO
    times in DB bytes, transcripts, and CLI/MCP output.
G6  Comprehension proxy: ROADMAP §13.7 / SPRINT-010 §33 questions are
    answerable from the captured output alone. Independent-developer check:
    NOT RUN (recorded, gate stays open — same caveat as v0.1).
G7  Usefulness judgment: the output tells the user something new, would change
    a decision, contains no misleading/overclaimed claims, and merits a re-run.
```

---

# 3. Non-goals

- New engine features, new fixtures, or new adapters.
- Using the real Sprint 012 token or any live provider call.
- Claiming the independent-developer comprehension gate is closed.
- Claiming v0.3 `ADVANCE` if G1–G7 do not pass.

---

# 4. Controlled Dogfood Runbook (offline)

Machine: macOS, zsh. Repo baseline `77e456e`. Binary `target/debug/pico` (built from baseline).

## W0 — Baseline

```zsh
git rev-parse HEAD                      # 77e456e
git status --porcelain                  # clean except .DS_Store
cargo test 2>&1 | tail -1               # record totals (expected 349 passed)
```

## W1 — Workspace bootstrap

Create `$WS` (temp, outside repo). Write:

`opencode.json` (golden shape + GitHub MCP, S012 E1):
```json
{"permission":{"bash":"allow"},"mcp":{"servers":{"github":{"type":"local","command":["ghcr.io/github/github-mcp-server"],"environment":{"GITHUB_PERSONAL_ACCESS_TOKEN":"__CANARY__"}}}}}
```

`.claude/settings.json` (Claude actor, approval-gated Bash):
```json
{"permissions":{"ask":["Bash"]}}
```

`.env` (synthetic credentials, offline):
```text
CLOUDFLARE_API_TOKEN=cfut_TESTFAKE0000000000000000000000000000
GITHUB_TOKEN=ghp_TESTFAKE0000000000000000000000000000
```
`__CANARY__` = unique canary, e.g. `PICO-DF22-CANARY-<rand>`.

Export nothing (offline); the `.env` is the documented dotenv contract.

## W2 — Init + scan

```zsh
"$BIN" init
{ time "$BIN" scan ; } 2>&1 | tee transcript-E2-scan.txt
```
Record: status (expect PARTIAL — cloudflare provider offline/unreachable, honest), full counter block, `real` elapsed, provider diagnostics, per-agent Bash state, credential authority lines.

## W3 — Findings + detail

```zsh
"$BIN" findings | tee transcript-E3-findings.txt
"$BIN" finding fnd_does_not_exist0000000000000000000 2>&1 | tee transcript-E3-notfound.txt
```
Record scoped zero-Finding language (or the honest findings if any), clean not-found error.

## W4 — MCP parity (offline)

Newline-delimited JSON-RPC over stdio (SPRINT-011 §5): `initialize`, `tools/list`, `list_findings`, `get_finding` (bogus id), malformed line, `ping`. Record negotiated protocolVersion, tool set, list/detail semantics, malformed-line behavior, exit 0.

## W5 — Determinism repeat

Copy `$WS` → `$WS-run2` (fresh `.pico`), repeat W2. Diff the normalized transcripts (strip ids/timestamps/scan_/res_/rel_/ev_/obs_) — structure/counts/states/ordering must match. DB-structure hashes (relationships/resources/evidence queries) must match across the two DBs.

## W6 — Secret sweep + zero-write

```zsh
for pat in "cfut_TESTFAKE0000000000000000000000000000" "ghp_TESTFAKE0000000000000000000000000000" "PICO-DF22-CANARY-<rand>"; do
  grep -a -c -F "$pat" .pico/pico.db transcripts/* ; # expect 0
done
```
Also first-8-char patterns. Zero-write proof: DB hash identical across W3/W4 reads.

## W7 — Comprehension proxy

Hand ONLY the redacted W2/W3/W4 transcripts to the participant (proxy). Answer ROADMAP §13.7 Set A + SPRINT-010 §33 Set B verbatim. Record PASS/FAIL per question + confusion points. Independent developer: NOT RUN + reason.

## W8 — Usefulness judgment (G7)

Four questions (S012 §12): something new? would change a decision? misleading/overclaimed? keep installed? Record with evidence lines.

---

# 5. Advancement Decision Contract (ROADMAP §17 format)

```text
Phase: v0.3 — Earned Agent and Provider Expansion

Decision: ADVANCE / EXTEND / REFINE / STOP
Product claim proven:
Exit criteria met:   (ROADMAP §7 lines 426–435, each judged from G1–G7 + fixtures)
Exit criteria not met:
What users demonstrated:
What the evidence demonstrated:
Known false positives:
Known false negatives:
Known UNKNOWN states:
Self-security results:
Compatibility limits:
What was learned:
Why the next phase is justified:
```

---

# 6. Commit Policy

Authoring-only commit:

```text
docs(sprints): define Sprint 022 v0.3 controlled dogfood and comprehension close
```

Evidence commits (transcripts, evidence record, decision record) with conventional messages. Do not amend previous commits.

---

# 7. Completion Evidence (filled at execution)

```text
completion date and verified baseline
commits (authoring; dogfood evidence; decision record)
repository state
gate results G1–G7 (PASS/FAIL each, with evidence citations)
controlled dogfood transcripts location
comprehension proxy result + independent-developer gate status (NOT RUN + reason)
usefulness judgment
architecture/roadmap promotion made (see ROADMAP.md §§20–22 / ARCHITECTURE.md addendum)
defect list and dispositions (expected empty)
advancement decision record (ROADMAP §17 format)
```

---

# 8. Final Report Contract

```text
Sprint: SPRINT-022 — v0.3 Controlled Dogfood & Comprehension Close
Status: DONE | BLOCKED
Baseline: <verified SHA>

Gates:
  G1 mixed-surface scan: PASS | FAIL
  G2 scan clarity: PASS | FAIL
  G3 offline + performance: PASS | FAIL
  G4 determinism: PASS | FAIL
  G5 secret sweep: PASS | FAIL
  G6 comprehension proxy: PASS | NOT RUN
  G7 usefulness: PASS | FAIL

Independent-developer comprehension: NOT RUN (<reason>)
Secret sweep: ZERO | INCIDENT
Roadmap/architecture promotion: PENDING | DONE
```