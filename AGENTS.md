# AGENTS.md — Pico

Pico is a local-first, read-only developer security product for AI-native
engineering environments. Its thesis is **influence × authority = agent attack
surface**: Pico discovers coding agents, MCP capabilities, external influence,
credential reachability, and connected infrastructure; builds an
evidence-backed security graph; and explains dangerous potential attack paths
from untrusted influence to consequential authority. The V0 golden path is
`External GitHub Content → GitHub MCP → OpenCode → Bash → Cloudflare
Credential → Cloudflare Worker`, producing the `UNTRUSTED_TO_PRODUCTION`
finding. Security truth is deterministic (an LLM may explain a conclusion,
never create one); secrets are transient (facts stored, raw values never);
only enforced controls block paths; `UNKNOWN` is a valid honest result.

## Mandatory reading order before any substantive change

Per `skills/build-pico/SKILL.md` (the canonical Engineering Constitution), read in this order:

1. `skills/build-pico/SKILL.md`
2. `docs/internal/PRODUCT_DEFINITION.md`
3. `docs/internal/TECHNICAL.md`
4. `docs/internal/ARCHITECTURE.md`
5. `docs/internal/ROADMAP.md`
6. Active Sprint under `docs/internal/sprints/`
7. Relevant code and tests under `src/` and `tests/`

## Source-of-truth hierarchy

`PRODUCT_DEFINITION.md` → `TECHNICAL.md` → `ARCHITECTURE.md` → `ROADMAP.md` → Active Sprint → Code.

- If implementation conflicts with the Canon, **report the conflict — do not silently change the Canon or the code to mask it.**
- Do not create new permanent documents unless explicitly requested. Canon = PRODUCT_DEFINITION, TECHNICAL, ARCHITECTURE, ROADMAP, SKILL.
- Update only the canonical doc whose *material* content changed; otherwise leave docs untouched.
- `docs/internal/dogfood/` and sprint support notes are working records — never treat as canonical.

## Current baseline: v0.1–v0.3 complete; v0.4 in progress

- **v0.1 Golden-Path Proof COMPLETE** (SPRINT-001–012; ADVANCE with one open caveat: independent-developer comprehension was a proxy self-check, not an independent run).
- **v0.2 Evidence and Authority Depth COMPLETE** (SPRINT-013–019; ADVANCE).
- **v0.3 Earned Expansion COMPLETE** (SPRINT-020–023; ADVANCE). The v0.3 independent-developer comprehension gate stays open and is not closed by later work.
- **v0.4 Security Memory and Change Detection ADVANCE with open caveats** (S024–S036; independent v0.4 + carried v0.3 comprehension gates NOT RUN and carried into v0.5 — ROADMAP §23, recorded at founder direction to unblock development).
- **v0.5 Continuous and Runtime Observation IN PROGRESS** (S037 `pico watch`: opt-in foreground FILESYSTEM_CHANGE observer over adapter-read configs; S038 deterministic change notices + read-only `pico status`; S039 `pico runtime` observability survey — metadata-only, `approved vs denied use` reported `NOT_AVAILABLE`. No daemon, notifications delivery, or enforcement. Runtime evidence ingestion deferred to S040.) A third agent remains architecture unless concrete user demand outweighs this sequencing.

Product loop:

```text
pico init
pico scan
pico findings | pico finding <id>
pico history | pico diff [<from> <to>] [--json]
pico prune | pico doctor
pico mcp (read-only: list_findings, get_finding, list_history, diff_scans)
```

Compare coherent `COMPLETE` scans only; `PARTIAL`/`FAILED`/`RUNNING` are freshness context, never diff operands. Collection failure is never disappearance. MCP stays read-only; detection stays separate from enforcement (v0.7).

## Repository layout

```text
src/
  cli/                 CLI entry and commands (init, scan, findings, finding, history, diff, prune, doctor, mcp)
  application/         Application services (scan, diff, history, retention, findings query)
  domain/              Provider-independent Scan, Observation, Resource, Relationship, Evidence models
  discovery/           Agent, MCP, local, and provider discovery + adapters (OpenCode, GitHub, Cloudflare)
  graph/               Security graph projection over persisted state
  analysis/            Influence, authority, and boundary evaluation
  findings/            Attack paths, findings, severity/confidence, remediation cut points
  persistence/         Local SQLite store (.pico/pico.db)
  mcp/                 Local stdio read-only agent interface
  output/              Versioned public JSON projections (schema v1)
  shared/              Errors, version, terminal utils
tests/                 cargo integration tests (fixtures, goldens; no live credentials required)
docs/internal/         PRODUCT_DEFINITION, TECHNICAL, ARCHITECTURE, ROADMAP, sprints/, dogfood/
skills/build-pico/    Engineering Constitution (this file's authority)
```

## Conventions

- Stack: Rust + Cargo (rusqlite, clap, serde).
- TDD: Red → Green → Refactor; smallest implementation that satisfies the Sprint; provider-specific logic stays inside the adapter.
- Test suite must run **without live provider credentials** (fixtures/mocks; synthetic credentials only — never borrow ambient credentials).
- Secrets: transient inputs, never persisted in SQLite, evidence, logs, diagnostics, exports, or commits. Sweep for canaries; redact diagnostics.
- Read-only by default: provider operations stay inside explicit allowlists enforced in tests; never validate authority with destructive probes.
- `init` is idempotent and never resets existing state. Manual verification runs in a disposable workspace (e.g. `/tmp/pico-<sprint>-<date>`), never the founder store.
- Errors are actionable and secret-free; human output stays default, `--json` uses the versioned payload.
- Commits only when authorized; conventional style (`feat(scan): …`, `fix(retention): …`, `docs(sprints): …`).
- When a Sprint completes, record Implemented / Deviations / Validation / Learnings notes in the Sprint doc; never start the next Sprint. Automated success does not close a human comprehension gate.
- Never request credentials, authorization headers, unredacted state databases, or private resource names.

## Commands

```bash
cargo build
cargo test --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo run -- init
cargo run -- scan
cargo run -- findings
```
