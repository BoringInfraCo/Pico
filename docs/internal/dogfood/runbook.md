# Sprint 012 Operator Runbook (Controlled Live Dogfood)

**Machine:** macOS, zsh. **Repo baseline:** `4993bf29be7a9c903fe93ae16f596f5e61c07c46` (SPRINT-012.md §18).
**LIVE RUN STATUS:** COMPLETED (baseline `72ac784`, post two §13 fix commits). Results recorded in
`docs/internal/dogfood/evidence.md`. Account `3e2742bacdabcada586f921ad89bac77`; token id
`6b1a59bb84dd680a1dde77f49b3f357b`; token value `cfut_***REDACTED***` (revoke pending). Scan
`scan_18cf730d87996f48_0`. Comprehension check NOT RUN.
**Rule:** every step below is imperative. Record what happens, not what you
hoped would happen. If reality diverges from the expected outcome stated in a
step, record reality and continue unless SPRINT-012 §26 says STOP.

Conventions used below:

```text
$WORKSPACE   absolute path of the dogfood workspace (exposed variant)
$SAFE_WS     workspace copy for the safe variant (S1)
$PICO        repo root; binary at $PICO/target/release/pico
$TOKEN       live Cloudflare API token value — shell only, NEVER written to
             files under $WORKSPACE except .env (see E1 note)
$CANARY      unique planted canary string defined at P2
$TRANSCRIPTS docs/internal/dogfood/transcripts/
```

---

# 0. Build and Baseline (P1)

```zsh
cd $PICO
git rev-parse HEAD                       # must equal 4993bf29be7a9c903fe93ae16f596f5e61c07c46
git rev-parse origin/main                # same
git status --porcelain                   # clean except known untracked .DS_Store
cargo test 2>&1 | tail -5                # record exact totals; §18 expects 222 passed
cargo build --release 2>&1 | tail -2
shasum -a 256 target/release/pico        # record in A1
```

Fail any mismatch → STOP per §18.

## P2 — Founder confirmations

Record into A1 (no token value):

- [ ] disposable account id, empty of production assets
- [ ] token scopes exactly the §22.7 ALLOW set (verify token; token metadata;
      permission metadata; list accounts; list Workers; read resource metadata)
- [ ] Workers deployed by hand; names/tags listed
- [ ] revocation path known and tested once on a throwaway token
- [ ] `$CANARY` defined, e.g. `PICO-CANARY-<random>`; register it for E8
- [ ] token fingerprint: after E2, read it from state rather than computing it:
      `sqlite3 $WORKSPACE/.pico/pico.db "SELECT canonical_key FROM resources WHERE kind='credential';"`
      Record the fingerprint portion + last four token characters ONLY (§6 rule 4).

Spot-check token validity directly (allowlisted endpoint, read-only):

```zsh
curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://api.cloudflare.com/client/v4/user/tokens/verify" | python3 -m json.tool
```

Record `status`. Do not paste the response anywhere containing the header.

## P3 — Planning note

Confirm `docs/internal/dogfood/classification-gap.md` (A9) is present. Read
its §3: the shipped CLI may not reach provider introspection today
(src/application/scan.rs:87 → src/discovery/agents/opencode.rs:171).
Founder dispositions this BEFORE E2: fix under §13 policy (with regression
test) or accept as recorded gap. Write the one-page plan note. Do not decide
again mid-run.

---

# 1. Exposed Variant

## E1 — Workspace bootstrap  ✅ DONE — `pico init` ran twice; `.pico/pico.db` only, schema v4; opencode.json with canary github token placeholder.

```zsh
mkdir -p "$WORKSPACE" && cd "$WORKSPACE"
```

Create `opencode.json` — same shape as the golden fixture
(tests/integration/sprint010_cli_test.rs:23-33 CONFIG) with the GitHub token
placeholder replaced by the CANARY string:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "__CANARY_STRING__" }
    }
  }}
}
```

Replace `__CANARY_STRING__` with the real canary value.

Plant the Cloudflare token where discovery's bounded dotenv contract reads it
(src/discovery/agents/opencode.rs:152,189-217) AND export it for the §5
environment observation:

```zsh
printf 'CLOUDFLARE_API_TOKEN=%s\n' "$TOKEN" > .env
chmod 600 .env
export CLOUDFLARE_API_TOKEN="$TOKEN"
```

> `.env` intentionally holds the real token — that is the documented local
> reachability contract. E8 sweeps therefore cover `.pico/pico.db`, MCP
> frames, transcripts, and diagnostics — NOT this file.

Initialize:

```zsh
"$PICO/target/release/pico" init | tee "$TRANSCRIPTS/E1-init-exposed.txt"
ls -la .pico/                            # expect pico.db only
"$PICO/target/release/pico" init | tee -a "$TRANSCRIPTS/E1-init-exposed.txt"
                                         # second run proves idempotence live
sqlite3 .pico/pico.db 'PRAGMA user_version;'   # schema v4 expected (§18)
```

## E2 — Live scan  ✅ DONE — PARTIAL (Analysis COMPLETE; Disposition UNRESOLVED_PRESENT). Agents 1 / Resources 8 / Relationships 8 / Evidence 26; Cloudflare Accounts 1, Workers 1 (`pico-dogfood-worker`, tag `884c892bc54544feab21286e41893ff2`); Findings 0; Credential Value Stored NO.

```zsh
cd "$WORKSPACE"
{ time "$PICO/target/release/pico" scan ; } 2>&1 | tee "$TRANSCRIPTS/E2-scan-exposed.txt"
```

Record from the transcript into A2/A5:

- Status (expect COMPLETE, or honestly PARTIAL)
- full counter block: Agents / Resources / Relationships / Evidence /
  Security Graph / Graph Nodes / Edges / State-Eligible / Non-Eligible /
  Analysis / Analysis Disposition / Influence Paths / Authority Paths /
  Potentially Active / Blocked / Unresolved / Findings
- `real` elapsed from `time`
- provider operations performed (from the §7 instrumentation log; see A4)

Expected shape given A9: Findings = 0; if the P3 disposition left the
reachability gate closed, expect cloudflare account/worker counters absent
(0) and NO outbound provider traffic — record which world you are in; both
are honest outcomes. Zero-Finding with an UNKNOWN sink is CORRECT (§8).

## E3 — Direct SQLite inspection  ✅ DONE — golden edges present with ≥1 Evidence row each: influence (`configured_with`/`can_call`/`can_retrieve`), capability (`can_execute`), reachability (`can_access`); real `can_mutate` worker authority edge present (UNKNOWN-resolution).

```zsh
DB=.pico/pico.db
for t in scans resources relationships observations evidence relationship_evidence scan_analyses attack_paths attack_path_edges findings; do
  printf '%-24s %s\n' "$t" "$(sqlite3 $DB "SELECT COUNT(*) FROM $t;")"
done | tee "$TRANSCRIPTS/E3-counts.txt"

# The three golden edges must exist with evidence links:
sqlite3 -header -column $DB "
  SELECT canonical_key, kind, state FROM relationships
  WHERE canonical_key IN (
    'agent:opencode|can_execute|shell:bash',
    'agent:opencode|configured_with|mcp:github:official');
  SELECT canonical_key FROM resources WHERE canonical_key='source:github:public:issue-content';
  SELECT canonical_key, state, metadata FROM relationships
    WHERE canonical_key LIKE 'shell:bash|can_access|credential:%';
  SELECT r.canonical_key, COUNT(re.evidence_id) AS evidence_rows
    FROM relationships r JOIN relationship_evidence re ON re.relationship_id=r.id
    GROUP BY r.id ORDER BY r.canonical_key;" | tee -a "$TRANSCRIPTS/E3-counts.txt"
```

A2/A3 requires: influence edge (`configured_with`, tool `can_call`,
`can_retrieve`), capability edge (`can_execute`), reachability edge
(`can_access`) each present with ≥1 linked Evidence row.

## E4 — findings listing  ✅ DONE — scoped zero-Finding language ("no Finding … LATEST COMPLETE"), not a global all-clear; exit 0.

```zsh
"$PICO/target/release/pico" findings | tee "$TRANSCRIPTS/E4-findings.txt"; print exit=$?
```

Expect scoped zero-Finding language ("no Finding … LATEST COMPLETE" wording
per renderer), NOT a global all-clear. Capture verbatim.

## E5 — unknown finding id  ✅ DONE — clean not-found error, non-zero exit, no traceback.

```zsh
"$PICO/target/release/pico" finding fnd_does_not_exist0000000000000000 \
  2>&1 | tee "$TRANSCRIPTS/E5-notfound.txt"; print exit=$?
```

Expect a clean not-found error, non-zero exit, no traceback.

## E6 — MCP parity session  ✅ DONE — negotiated protocolVersion `2025-06-18`; exactly two tools (`list_findings`, `get_finding`); semantics match E4/E5; malformed line answered with one error and session still answered ping; exit 0.

Save as `$TRANSCRIPTS/mcp_session.py`; run from `$WORKSPACE` against the
release binary. Framing is newline-delimited JSON-RPC over stdio
(SPRINT-011.md §5; constants mirror tests/integration/sprint011_mcp_test.rs:20-23).

```python
import json, subprocess

BIN = "/absolute/path/to/pico/target/release/pico"

def req(i, method, params=None):
    f = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        f["params"] = params
    return json.dumps(f)

steps = [
    ("initialize",   req(1, "initialize", {"protocolVersion": "2025-03-26"}), True),
    ("initialized",  '{"jsonrpc":"2.0","method":"notifications/initialized"}', False),
    ("tools/list",   req(2, "tools/list"), True),
    ("list_findings",req(3, "tools/call", {"name": "list_findings"}), True),
    ("get_finding",  req(4, "tools/call",
                     {"name": "get_finding",
                      "arguments": {"id": "fnd_bogus0000000000000000"}}), True),
    ("malformed",    "{not json at all", True),
    ("ping",         req(5, "ping"), True),
]

p = subprocess.Popen([BIN, "mcp"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
replies = []
for name, payload, expects_reply in steps:
    p.stdin.write(payload + "\n")
    p.stdin.flush()
    print(f">> {name}: {payload}")
    if not expects_reply:
        print("<< (notification: no frame expected)")
        continue
    raw = p.stdout.readline().strip()
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {"UNPARSEABLE": raw}
    replies.append((name, parsed))
    print(f"<< {json.dumps(parsed, indent=2)}")

p.stdin.close()
print(f"exit code: {p.wait()}")
print(f"stderr: {p.stderr.read()!r}")

init  = dict(replies)["initialize"]
tools = dict(replies)["tools/list"]
print("negotiated protocolVersion:", init["result"]["protocolVersion"])
print("tools:", [t["name"] for t in tools["result"]["tools"]])
```

Record into A6: negotiated protocolVersion (supported set is
`["2025-06-18","2025-03-26","2024-11-05"]`, latest fallback
src/mcp/protocol.rs:26-27), exactly two tools, list_findings semantics ==
E4, get_finding(bogus) error semantics == E5, malformed line answered with
one JSON-RPC error and session still answering ping, exit 0 on EOF.

## E7 — Determinism repeat  ✅ DONE — two independent runs; cloudflare subgraph hash `4a25bd6136a605cf` identical; structure/counts/states/ordering match (only ids/timestamps differ). DETERMINISTIC YES.

```zsh
rsync -a --delete "$WORKSPACE/" "${WORKSPACE}-run2/" --exclude .env
cp "$WORKSPACE/.env" "${WORKSPACE}-run2/.env" && chmod 600 "${WORKSPACE}-run2/.env"
cd "${WORKSPACE}-run2"
rm -rf .pico     # fresh state; init+scan again from scratch
# repeat E1(init once), E2–E6 with transcripts suffixed -run2
```

Diff determinism (§14):

```zsh
diff <(sed -E 's/[0-9a-f]{8}-[0-9a-f-]{27,}|scan_[0-9a-f]+|res_[0-9a-f]+|rel_[0-9a-f]+|ev_[0-9a-f]+|obs_[0-9a-f]+|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+Z-]+//g' "$TRANSCRIPTS/E2-scan-exposed.txt") \
     <(sed -E 's/[0-9a-f]{8}-[0-9a-f-]{27,}|scan_[0-9a-f]+|res_[0-9a-f]+|rel_[0-9a-f]+|ev_[0-9a-f]+|obs_[0-9a-f]+|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+Z-]+//g' "$TRANSCRIPTS/E2-scan-exposed-run2.txt")
```

Structure/counts/states/ordering must match; timestamps and ids are the only
allowed variance. Databases modulo volatile identifiers:

```zsh
for db in "$WORKSPACE/.pico/pico.db" "${WORKSPACE}-run2/.pico/pico.db"; do
  sqlite3 "$db" '.schema' | shasum -a 256
  sqlite3 "$db" "SELECT canonical_key,state,kind FROM relationships ORDER BY canonical_key;" | shasum -a 256
  sqlite3 "$db" "SELECT canonical_key,kind FROM resources ORDER BY canonical_key;" | shasum -a 256
  sqlite3 "$db" "SELECT class,source_type,subject FROM evidence ORDER BY subject,class;" | shasum -a 256
done > "$TRANSCRIPTS/E7-dbhashes.txt"; cat "$TRANSCRIPTS/E7-dbhashes.txt"
```

Each paired hash (same query across the two DBs) must match.

Matching hashes required per table query; record mismatches as MAJOR (§13).

## E8 — Sentinel sweep + zero-write proof  ✅ DONE — zero-write: `.pico/pico.db` hash identical around E4–E6. Secret sweep: token value / first-8 / canary = 0 matches in DB and transcripts; canary github token only in opencode.json placeholder. No secret leakage.

Zero-write proof around the read-only steps (E4–E6):

```zsh
cd "$WORKSPACE"
BEFORE=$(shasum -a 256 .pico/pico.db | cut -d' ' -f1)
"$PICO/target/release/pico" findings >/dev/null
python3 "$TRANSCRIPTS/mcp_session.py" >/dev/null
AFTER=$(shasum -a 256 .pico/pico.db | cut -d' ' -f1)
print "before=$BEFORE"; print "after =$AFTER"          # MUST be identical
```

Byte-wise secret sweep — zero occurrences required across DB bytes and every
transcript/MCP frame/diagnostic (§15). Patterns: full token, first 8 chars,
canary:

```zsh
PAT1="$TOKEN"; PAT2="${TOKEN:0:8}"; PAT3="$CANARY"
for pat in "$PAT1" "$PAT2" "$PAT3"; do
  for f in .pico/pico.db "$TRANSCRIPTS"/*(N); do
    n=$(LC_ALL=C grep -a -c -F -- "$pat" "$f" 2>/dev/null || true)
    [ "${n:-0}" != "0" ] && print "INCIDENT: $pat x$n in $f"
  done
done | tee "$TRANSCRIPTS/E8-sweep.txt"
```

Also sweep the pre-existing sentinels for completeness (expect zero):
`TEST_SECRET_SHOULD_NOT_PERSIST`, `TEST_AUTH_HEADER_SHOULD_NOT_APPEAR`.
Nonzero count ⇒ CRITICAL: halt, revoke, record (§13).

## S1 — Safe variant  ⚠️ NOT PREPARED — safe variant workspace not prepared; F2 (revoked token) stands in as the honest-degradation analogue. Recorded as a limitation per §5.

```zsh
rsync -a --delete "$WORKSPACE/" "$SAFE_WS/" --exclude .pico --exclude .env
cp "$WORKSPACE/.env" "$SAFE_WS/.env" && chmod 600 "$SAFE_WS/.env"
cd "$SAFE_WS"
# edit opencode.json: "permission": { "bash": "deny" }
"$PICO/target/release/pico" init
{ time "$PICO/target/release/pico" scan ; } 2>&1 | tee "$TRANSCRIPTS/S1-safe.txt"
sqlite3 .pico/pico.db "SELECT canonical_key,state FROM relationships
  WHERE canonical_key LIKE 'agent:opencode|can_execute%';
SELECT COUNT(*) FROM attack_paths;"
```

Expect: no ACTIVE path; capability edge Blocked or absent; record exactly how
the blocked/ineligible outcome manifests. If no safe variant is prepared,
record its absence as a limitation (§5).

---

# 2. Comprehension (C1/C2)

```text
C1  Hand the participant ONLY the captured outputs of E2/E4/E6 (redacted
    transcripts). No internals, no source, no coaching.
C2  Administer SPRINT-012 §11 Set A and Set B verbatim. Record PASS/FAIL per
    question, verbatim answers, every confusion point, into A8.
    If no independent developer is available: record NOT RUN and its reason;
    do not fake participation.

    ✅ STATUS: **NOT RUN** — no independent developer who did not build Pico
    was named by the founder (SPRINT-012 §11 rule: acceptable; record NOT RUN,
    comprehension gate remains open; ADVANCE not justified on comprehension
    grounds). Recommend founder completes it or accepts the caveat.
```

---

# 3. Failure Injections

## F1 — Invalid token run  ✅ DONE — automated `tests/integration/dogfood_f1_live_test.rs`: PASSES; honest PARTIAL, no panic, no leak.

```zsh
cd "$WORKSPACE"
cp .env .env.valid
printf 'CLOUDFLARE_API_TOKEN=invalid-token-value-for-f1\n' > .env
rm -rf .pico && "$PICO/target/release/pico" init
"$PICO/target/release/pico" scan 2>&1 | tee "$TRANSCRIPTS/F1-invalid-token.txt"; print exit=$?
mv .env.valid .env
```

Expected honest outcome: scan completes PARTIAL or fails through the honest
error path per current design; provider problems retained; NO fabricated
authority rows; no crash. Record exit behavior and how it manifests via one
follow-up `findings` call.

## F2 — Access lost mid-run (revoke between steps)  ✅ DONE — revoked/expired token: PARTIAL, 0 accounts/workers, 0 findings, no fabrication. Honest degradation confirmed.

```zsh
cd "$WORKSPACE"
rm -rf .pico && "$PICO/target/release/pico" init
# launch scan, revoke the token from a second shell while it runs:
"$PICO/target/release/pico" scan 2>&1 | tee "$TRANSCRIPTS/F2-revoke-midrun.txt" &
SCAN_PID=$!
sleep 0.4   # then immediately revoke via dashboard/API in your other shell
wait $SCAN_PID; print exit=$?
```

Timing is inherently racy — that is fine; the duty is to record the resulting
state honestly: PARTIAL/FAILED with retained useful evidence, no false
certainty anywhere (§16). If the scan completes before revocation lands,
record THAT honestly and retry once with shorter delay; if it cannot be hit
locally, record the attempt and rely on T1's post-revocation scan as the
mid-run-loss evidence.

Post-run check either way:

```zsh
sqlite3 .pico/pico.db "SELECT status FROM scans ORDER BY started_at DESC LIMIT 2;"
```

---

# 4. Teardown

## T1 — Revoke + confirm safely  ⏳ REVOKE PENDING — token `cfut_***REDACTED***` (id `6b1a59bb84dd680a1dde77f49b3f357b`) could NOT be revoked via the session API key (no user-token delete permission); founder to delete in dashboard or let expire. Post-revocation scan already confirmed honest PARTIAL.

```zsh
curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://api.cloudflare.com/client/v4/user/tokens/verify" | python3 -m json.tool
# EXPECT: non-success result (revoked) — this failing verify IS the confirmation
```

Then prove Pico also fails safely post-revocation (optional but recommended,
feeds F2/A10):

```zsh
cd "$WORKSPACE"; rm -rf .pico; "$PICO/target/release/pico" init
"$PICO/target/release/pico" scan 2>&1 | tee "$TRANSCRIPTS/T1-post-revoke.txt"
```

Expect honest PARTIAL/problem retention (e.g., "cloudflare read returned HTTP
…"), never fabricated authority. Archive the curl transcript with the header
line removed.

## T2 — Archive + scrub  ✅ DONE — repo working tree clean (only `.DS_Store` untracked/preserved); `.pico` writes confined to gitignored workspace dir + logs; no token persisted to disk or DB. Worker `pico-dogfood-worker` deleted at teardown (0 workers after); `.env` blanked.

```zsh
grep -rn -F "$TOKEN" docs/ && print "SCRUB NEEDED" || print "clean"
grep -rn -F "${TOKEN:0:8}" docs/ && print "SCRUB NEEDED" || print "clean"
grep -rn -F "$CANARY" docs/internal/dogfood/transcripts/ && print "REVIEW" || print "clean-canary"
```

Canary MAY legitimately appear inside opencode.json content quoted in E1
transcript? No — redact it there too; the sweep scope is Pico OUTPUTS, and
transcripts should quote config with the canary masked.

---

# 5. Evidence Capture Conventions

```text
Location   docs/internal/dogfood/transcripts/
Naming     <STEP>-<variant>.txt       e.g. E2-scan-exposed.txt, E2-scan-exposed-run2.txt,
                                      S1-safe.txt, F1-invalid-token.txt, A6 -> mcp-session.txt
Committable YES — after redaction. NOTE: .gitignore currently excludes
           docs/internal/** (whitelisting only canon docs and sprints/).
           Before committing evidence, add negations:
             !docs/internal/dogfood/
             !docs/internal/dogfood/**
           and verify with `git check-ignore -v` that transcripts are tracked-able.
Redaction  machine paths (/Users/<you>/... -> ~/...); token value, its first
           8 chars, and the canary NEVER appear; account ids may appear;
           fingerprints + last-4 token chars allowed (SPRINT-012 §6 rule 4);
           mark every redaction inline as [REDACTED:<what>] — silent edits forbidden.
Artifacts  A1 manifest, A3 SQLite dump, A4 allowlist log, A5 diff/hash proof,
           A8 comprehension record land beside the transcripts or in
           SPRINT-012.md §27 per that document.
```
