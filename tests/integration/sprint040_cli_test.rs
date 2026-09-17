//! Sprint 040 `pico scan --runtime` CLI + integration tests
//! (SPRINT-040.md §§1, 4, 5).
//!
//! Drives the compiled binary (`env!("CARGO_BIN_EXE_pico")`) with an isolated
//! temp workspace + temp HOME, following the `tests/integration/sprint037_cli_test.rs`
//! and `sprint039_cli_test.rs` binary-driving patterns. Every fixture is a
//! **synthetic** OpenCode-shaped SQLite store built inline with `rusqlite` in a
//! temp dir — never the real `~/.local/share/opencode` store. The store
//! location is passed through the HOME seam
//! (`$HOME/.local/share/opencode/opencode.db`) exactly as the CLI resolves it.
//!
//! Covered contracts:
//!
//! - `scan --help` documents the opt-in/read-only/content-free/window/stale
//!   snapshot contract (§1.1–§1.3, §1.2).
//! - The default `pico scan` never opens the store: the store listing and
//!   `-wal`/`-shm` state are unchanged, and the scan-level coverage/scope JSON
//!   is byte-identical to a baseline scan run with no store present (§1.1).
//! - `--runtime` with a fresh completed `bash` invocation promotes the
//!   golden-path `can_execute` edge to `CONFIRMED` with same-scan `DIRECT`
//!   evidence (§1.6).
//! - pending-only records the attempt honestly without promotion (§1.6).
//! - an invocation older than 24 h is `STALE` and never promotes (§1.8).
//! - an invocation in a different `session.directory` does not affect the
//!   scanned workspace (§1.4).
//! - an unsupported migration version yields honest `Unknown` coverage, no
//!   promotion, and an actionable diagnostic (§1.5).
//! - the forbidden-field sentinel never appears in stdout/stderr/JSON/DB
//!   (§1.3).
//! - the store directory (including `-wal`/`-shm`) is byte-identical before and
//!   after `--runtime` (§1.2).
//! - two `--runtime` runs over a fixed store produce byte-equal deterministic
//!   JSON (coverage, scope, runtime evidence) with no wall-clock assertions.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pico::application::InitService;
use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Sentinel placed only in forbidden paths (`part.data.$.state.input|output|text`,
/// `session.title`, `message.data`, `session_input.prompt`). It must never reach
/// Pico output or the Pico database.
const SENTINEL: &str = "SENTINEL_S040";

const RUNTIME_SOURCE_TYPE: &str = "opencode_runtime_observer";
const GOLDEN_BASH_KEY: &str = "agent:opencode|can_execute|shell:bash";
const OPERATION_RUNTIME_ARTIFACTS: &str = "runtime_artifacts";

const WORKSPACE_CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "SENTINEL_S040" }
    }
  }}
}"#;

/// Scrubbed ambient credential variables so binary-driven scans stay hermetic
/// and offline regardless of the developer's environment.
const SCRUBBED_ENV: &[&str] = &[
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
];

struct Env {
    workspace: tempfile::TempDir,
    home: tempfile::TempDir,
}

fn setup() -> Env {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), WORKSPACE_CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    Env { workspace, home }
}

fn pico_command(env: &Env, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pico"));
    cmd.args(args)
        .current_dir(env.workspace.path())
        .env("HOME", env.home.path());
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    cmd
}

fn run_pico(env: &Env, args: &[&str]) -> std::process::Output {
    pico_command(env, args).output().unwrap()
}

fn stdout_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_no_sentinel(label: &str, text: &str) {
    assert!(!text.contains(SENTINEL), "{label} leaked {SENTINEL}");
}

// ---------------------------------------------------------------------------
// Synthetic store fixture
// ---------------------------------------------------------------------------

fn store_path(env: &Env) -> PathBuf {
    env.home.path().join(".local/share/opencode/opencode.db")
}

/// Create the OpenCode-shaped store with the minimum required tables plus the
/// forbidden content tables used by the sentinel sweep.
fn open_store(env: &Env) -> Connection {
    let path = store_path(env);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, time_created INTEGER, title TEXT);
         CREATE TABLE part (id TEXT PRIMARY KEY, session_id TEXT, time_created INTEGER, data TEXT);
         CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER);
         CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT);
         CREATE TABLE session_input (id TEXT PRIMARY KEY, session_id TEXT, prompt TEXT);",
    )
    .unwrap();
    conn
}

/// The frozen supported range at v1.18.31 is exactly 38; the reader interprets
/// numeric ids as a version and non-numeric ids as a count. A single numeric
/// `38` row is unambiguous for both.
fn supported_migration(conn: &Connection) {
    conn.execute(
        "INSERT INTO migration (id, time_completed) VALUES ('38', 0)",
        [],
    )
    .unwrap();
}

fn unsupported_migration(conn: &Connection, id: &str) {
    conn.execute(
        "INSERT INTO migration (id, time_completed) VALUES (?1, 0)",
        params![id],
    )
    .unwrap();
}

fn canonical(path: &Path) -> String {
    path.canonicalize().unwrap().to_string_lossy().into_owned()
}

fn insert_session(conn: &Connection, id: &str, directory: &str, created_ms: i64) {
    conn.execute(
        "INSERT INTO session (id, directory, time_created, title) VALUES (?1, ?2, ?3, ?4)",
        params![id, directory, created_ms, SENTINEL],
    )
    .unwrap();
}

fn insert_tool(
    conn: &Connection,
    id: &str,
    session_id: &str,
    created_ms: i64,
    tool: &str,
    status: &str,
    call_id: &str,
) {
    let data = serde_json::json!({
        "type": "tool",
        "tool": tool,
        "callID": call_id,
        "state": {
            "status": status,
            "input": SENTINEL,
            "output": SENTINEL,
            "text": SENTINEL,
            "metadata": { "note": SENTINEL }
        },
        "text": SENTINEL
    });
    conn.execute(
        "INSERT INTO part (id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        params![id, session_id, created_ms, data.to_string()],
    )
    .unwrap();
}

/// Seed forbidden content tables so the sweep proves the reader never selects
/// their columns.
fn seed_forbidden_content(conn: &Connection, session_id: &str) {
    conn.execute(
        "INSERT INTO message (id, session_id, data) VALUES ('m1', ?1, ?2)",
        params![
            session_id,
            format!("{{\"role\":\"user\",\"text\":\"{SENTINEL}\"}}")
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO session_input (id, session_id, prompt) VALUES ('si1', ?1, ?2)",
        params![session_id, SENTINEL],
    )
    .unwrap();
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

const ONE_HOUR_MS: i64 = 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Store + Pico state inspection
// ---------------------------------------------------------------------------

/// Recursive `relative path -> (bytes, sha256)` snapshot of a directory tree,
/// used to prove the runtime read is byte-identical and creates no sidecars.
fn tree_snapshot(root: &Path) -> BTreeMap<String, (u64, String)> {
    let mut entries = BTreeMap::new();
    collect_tree(root, root, &mut entries);
    entries
}

fn collect_tree(root: &Path, dir: &Path, out: &mut BTreeMap<String, (u64, String)>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            out.insert(rel, (0, "dir".to_string()));
            collect_tree(root, &path, out);
        } else {
            let bytes = fs::read(&path).unwrap_or_default();
            out.insert(
                rel,
                (bytes.len() as u64, format!("{:x}", Sha256::digest(&bytes))),
            );
        }
    }
}

fn store_dir(env: &Env) -> PathBuf {
    env.home.path().join(".local/share/opencode")
}

fn pico_db(env: &Env) -> Connection {
    Connection::open_with_flags(
        env.workspace.path().join(".pico/pico.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

/// Newest scan row: `(metadata, scope)` as JSON values.
fn newest_scan(env: &Env) -> (Value, Value) {
    let conn = pico_db(env);
    let (metadata, scope): (String, Option<String>) = conn
        .query_row(
            "SELECT metadata, scope FROM scans ORDER BY rowid DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (
        serde_json::from_str(&metadata).unwrap(),
        scope
            .map(|raw| serde_json::from_str(&raw).unwrap())
            .unwrap_or(Value::Null),
    )
}

fn relationship_state(env: &Env, key: &str) -> String {
    pico_db(env)
        .query_row(
            "SELECT state FROM relationships WHERE canonical_key = ?1",
            [key],
            |row| row.get(0),
        )
        .unwrap()
}

fn has_runtime_coverage(metadata: &Value) -> bool {
    metadata["coverage"]["entries"]
        .as_array()
        .is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry["operation"] == OPERATION_RUNTIME_ARTIFACTS)
        })
}

fn runtime_coverage_state(metadata: &Value) -> Option<String> {
    metadata["coverage"]["entries"]
        .as_array()?
        .iter()
        .find(|entry| entry["operation"] == OPERATION_RUNTIME_ARTIFACTS)
        .and_then(|entry| entry["state"].as_str())
        .map(str::to_string)
}

#[derive(Debug)]
struct RuntimeEvidence {
    class: String,
    source_type: String,
    observation: String,
    freshness: Option<String>,
    captured_at: String,
    metadata: Value,
}

fn read_evidence(row: &rusqlite::Row<'_>) -> rusqlite::Result<RuntimeEvidence> {
    let metadata: String = row.get(5)?;
    Ok(RuntimeEvidence {
        class: row.get(0)?,
        source_type: row.get(1)?,
        observation: row.get(2)?,
        freshness: row.get(3)?,
        captured_at: row.get(4)?,
        metadata: serde_json::from_str(&metadata).unwrap(),
    })
}

/// The newest same-scan `DIRECT` runtime evidence, linked or not.
fn latest_runtime_evidence(env: &Env) -> Option<RuntimeEvidence> {
    pico_db(env)
        .query_row(
            "SELECT class, source_type, observation, freshness, captured_at, metadata
             FROM evidence WHERE source_type = ?1 ORDER BY rowid DESC LIMIT 1",
            [RUNTIME_SOURCE_TYPE],
            read_evidence,
        )
        .ok()
}

/// The same-scan `DIRECT` runtime evidence linked to the golden-path edge; the
/// application links it only on a real promotion.
fn promoted_runtime_evidence(env: &Env) -> Option<RuntimeEvidence> {
    pico_db(env)
        .query_row(
            "SELECT e.class, e.source_type, e.observation, e.freshness, e.captured_at, e.metadata
             FROM evidence e
             JOIN relationship_evidence re ON re.evidence_id = e.id
             JOIN relationships r ON r.id = re.relationship_id
             WHERE r.canonical_key = ?1 AND e.source_type = ?2",
            params![GOLDEN_BASH_KEY, RUNTIME_SOURCE_TYPE],
            read_evidence,
        )
        .ok()
}

fn first_finding_id(findings_output: &str) -> Option<String> {
    findings_output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pico finding ")
            .map(|id| id.trim().to_string())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn s040_scan_help_documents_runtime_contract() {
    let env = setup();
    let out = run_pico(&env, &["scan", "--help"]);
    assert!(out.status.success());
    let help = stdout_text(&out);
    let lower = help.to_lowercase();
    for needle in [
        "opt-in",
        "read-only",
        "content-free",
        "window",
        "stale",
        "wal",
    ] {
        assert!(
            lower.contains(needle),
            "scan --help must document {needle:?}; got:\n{help}"
        );
    }
    assert_no_sentinel("scan --help", &help);
}

#[test]
fn s040_default_scan_never_opens_store_and_is_unchanged() {
    let env = setup();
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_tool(&conn, "p1", "ses_1", now_ms(), "bash", "completed", "c1");
    }
    let before = tree_snapshot(&store_dir(&env));
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        vec![&"opencode.db".to_string()],
        "fixture store must start with a single main db and no sidecars"
    );

    // Default scan with the store present: untouched store, no runtime surface.
    let out = run_pico(&env, &["scan"]);
    assert!(out.status.success());
    let scan_stdout = stdout_text(&out);
    assert!(
        !scan_stdout.to_lowercase().contains("runtime"),
        "a default scan must not surface runtime coverage; got:\n{scan_stdout}"
    );
    assert_no_sentinel("default scan stdout", &scan_stdout);
    assert_eq!(
        tree_snapshot(&store_dir(&env)),
        before,
        "default scan must not create -wal/-shm or touch the store"
    );

    let (metadata_with_store, scope_with_store) = newest_scan(&env);
    assert_eq!(scope_with_store, Value::Null, "default scan has no scope");
    assert!(
        !has_runtime_coverage(&metadata_with_store),
        "default scan must not add a runtime_artifacts coverage entry: {metadata_with_store}"
    );
    assert_eq!(relationship_state(&env, GOLDEN_BASH_KEY), "DERIVED");

    // Baseline with no store present must produce byte-identical scan metadata.
    fs::remove_file(store_path(&env)).unwrap();
    let baseline = run_pico(&env, &["scan"]);
    assert!(baseline.status.success());
    let (metadata_without_store, scope_without_store) = newest_scan(&env);
    assert_eq!(scope_without_store, Value::Null);
    assert_eq!(
        serde_json::to_string(&metadata_with_store).unwrap(),
        serde_json::to_string(&metadata_without_store).unwrap(),
        "store presence must not change default scan metadata"
    );
}

#[test]
fn s040_runtime_promotes_fresh_completed_bash() {
    let env = setup();
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_tool(
            &conn,
            "p1",
            "ses_1",
            now_ms() - 5 * 60_000,
            "bash",
            "completed",
            "c1",
        );
        seed_forbidden_content(&conn, "ses_1");
    }

    let out = run_pico(&env, &["scan", "--runtime"]);
    assert!(
        out.status.success(),
        "runtime scan failed: {}",
        stderr_text(&out)
    );
    assert_no_sentinel("runtime scan stdout", &stdout_text(&out));
    assert_no_sentinel("runtime scan stderr", &stderr_text(&out));

    assert_eq!(
        relationship_state(&env, GOLDEN_BASH_KEY),
        "CONFIRMED",
        "a fresh completed bash invocation must promote can_execute"
    );

    let (metadata, scope) = newest_scan(&env);
    assert_eq!(
        runtime_coverage_state(&metadata).as_deref(),
        Some("inspected")
    );
    assert_eq!(scope["runtime"]["enabled"], true);
    assert_eq!(scope["runtime"]["store_present"], true);
    assert_eq!(scope["runtime"]["read_mode"], "ro+immutable");
    assert_eq!(scope["runtime"]["wal_note"], "possibly_stale");

    let evidence = promoted_runtime_evidence(&env).expect("same-scan runtime DIRECT evidence");
    assert_eq!(evidence.class, "DIRECT");
    assert_eq!(evidence.source_type, RUNTIME_SOURCE_TYPE);
    assert_eq!(evidence.freshness.as_deref(), Some("FRESH"));
    assert_eq!(evidence.metadata["classification"], "observed_execution");
    assert_eq!(evidence.metadata["tool"], "bash");
    assert!(
        evidence.observation.contains("invoked Bash"),
        "observation must name the observed invocation: {}",
        evidence.observation
    );
    assert_no_sentinel(
        "runtime evidence",
        &serde_json::to_string(&evidence.metadata).unwrap(),
    );

    // The CLI can list findings without leaking content.
    let findings = run_pico(&env, &["findings"]);
    assert!(findings.status.success());
    assert_no_sentinel("findings stdout", &stdout_text(&findings));
}

#[test]
fn s040_pending_only_records_attempt_without_promotion() {
    let env = setup();
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_tool(
            &conn,
            "p1",
            "ses_1",
            now_ms() - 60_000,
            "bash",
            "pending",
            "c1",
        );
    }

    let out = run_pico(&env, &["scan", "--runtime"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    assert_eq!(relationship_state(&env, GOLDEN_BASH_KEY), "DERIVED");

    let (metadata, _) = newest_scan(&env);
    assert_eq!(
        runtime_coverage_state(&metadata).as_deref(),
        Some("inspected")
    );

    let evidence = latest_runtime_evidence(&env).expect("attempted evidence is recorded");
    assert_eq!(
        evidence.metadata["classification"],
        "attempted_not_executed"
    );
    assert!(
        evidence.observation.to_lowercase().contains("attempt"),
        "pending-only wording must be honest: {}",
        evidence.observation
    );
    assert!(
        !evidence.observation.to_lowercase().contains("invoked bash"),
        "pending-only must not claim execution: {}",
        evidence.observation
    );
}

#[test]
fn s040_stale_invocation_does_not_promote() {
    let env = setup();
    let stale_ms = now_ms() - 25 * ONE_HOUR_MS;
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), stale_ms);
        insert_tool(&conn, "p1", "ses_1", stale_ms, "bash", "completed", "c1");
    }

    let out = run_pico(&env, &["scan", "--runtime"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    assert_eq!(
        relationship_state(&env, GOLDEN_BASH_KEY),
        "DERIVED",
        "a stale invocation must not launder into a current CONFIRMED claim"
    );

    let evidence = latest_runtime_evidence(&env).expect("stale invocation is recorded honestly");
    assert_eq!(evidence.freshness.as_deref(), Some("STALE"));
    assert_eq!(evidence.metadata["classification"], "observed_execution");
    // `captured_at` is the invocation's fact time, not the scan wall clock.
    let captured: chrono::DateTime<chrono::Utc> = evidence
        .captured_at
        .parse()
        .expect("captured_at is an RFC 3339 timestamp");
    assert!(
        captured < chrono::Utc::now() - chrono::Duration::hours(24),
        "stale evidence must be timestamped at the old invocation, got {}",
        evidence.captured_at
    );
}

#[test]
fn s040_other_workspace_invocation_has_no_effect() {
    let env = setup();
    let other = tempfile::tempdir().unwrap();
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_other", &canonical(other.path()), now_ms());
        insert_tool(
            &conn,
            "p1",
            "ses_other",
            now_ms() - 60_000,
            "bash",
            "completed",
            "c1",
        );
    }

    let out = run_pico(&env, &["scan", "--runtime"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    assert_eq!(
        relationship_state(&env, GOLDEN_BASH_KEY),
        "DERIVED",
        "an invocation in another workspace must not affect this workspace"
    );
    assert!(
        latest_runtime_evidence(&env).is_none(),
        "out-of-scope invocations must not be attributed to this workspace"
    );

    let (metadata, scope) = newest_scan(&env);
    assert_eq!(
        runtime_coverage_state(&metadata).as_deref(),
        Some("inspected")
    );
    assert!(
        scope["runtime"]["rows_scanned"].as_u64().unwrap_or(0) >= 1,
        "the store was scanned; the row was scoped out, not missed"
    );
}

#[test]
fn s040_unsupported_migration_is_unknown_with_diagnostic() {
    let env = setup();
    {
        let conn = open_store(&env);
        unsupported_migration(&conn, "39");
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_tool(
            &conn,
            "p1",
            "ses_1",
            now_ms() - 60_000,
            "bash",
            "completed",
            "c1",
        );
    }

    let out = run_pico(&env, &["scan", "--runtime"]);
    let combined = format!("{}{}", stdout_text(&out), stderr_text(&out));
    assert_no_sentinel("unsupported-migration output", &combined);

    assert_eq!(
        relationship_state(&env, GOLDEN_BASH_KEY),
        "DERIVED",
        "an unsupported schema must not promote any edge"
    );
    assert!(latest_runtime_evidence(&env).is_none());

    // The actionable signal for an unsupported schema is both structural (the
    // honest coverage state plus the observed migration version and a
    // zero-row read) and rendered (SPRINT-040 §4), so an operator sees it
    // without inspecting the database.
    let (metadata, scope) = newest_scan(&env);
    assert_eq!(
        runtime_coverage_state(&metadata).as_deref(),
        Some("unknown"),
        "unsupported schema must not be reported as an inspected read"
    );
    assert_eq!(scope["runtime"]["store_present"], true);
    assert_eq!(scope["runtime"]["migrations"], 39);
    assert_eq!(
        scope["runtime"]["rows_scanned"], 0,
        "an unsupported schema must fail closed before reading any row"
    );
    assert!(
        combined.contains("Runtime evidence: UNSUPPORTED"),
        "an unsupported schema must render an actionable diagnostic:\n{combined}"
    );
    assert!(
        combined.contains("observed migrations: 39"),
        "the diagnostic must name the observed migration version:\n{combined}"
    );
}

#[test]
fn s040_sentinel_never_appears_in_output_or_database() {
    let env = setup();
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_tool(
            &conn,
            "p1",
            "ses_1",
            now_ms() - 60_000,
            "bash",
            "completed",
            "c1",
        );
        seed_forbidden_content(&conn, "ses_1");
        // A non-bash tool call also carries the sentinel in forbidden fields.
        insert_tool(
            &conn,
            "p2",
            "ses_1",
            now_ms() - 30_000,
            "write",
            "completed",
            "c2",
        );
    }

    let mut outputs = Vec::new();
    for args in [vec!["scan", "--runtime"], vec!["findings"]] {
        let out = run_pico(&env, &args);
        assert!(out.status.success(), "{}", stderr_text(&out));
        let stdout = stdout_text(&out);
        let stderr = stderr_text(&out);
        assert_no_sentinel(&format!("{args:?} stdout"), &stdout);
        assert_no_sentinel(&format!("{args:?} stderr"), &stderr);
        outputs.push(stdout);
    }
    if let Some(id) = first_finding_id(&outputs[1]) {
        let out = run_pico(&env, &["finding", &id]);
        assert!(out.status.success(), "{}", stderr_text(&out));
        assert_no_sentinel("finding detail stdout", &stdout_text(&out));
        assert_no_sentinel("finding detail stderr", &stderr_text(&out));
    }

    let db_bytes = fs::read(env.workspace.path().join(".pico/pico.db")).unwrap();
    assert!(
        !db_bytes
            .windows(SENTINEL.len())
            .any(|window| window == SENTINEL.as_bytes()),
        "the Pico database must never persist forbidden content"
    );
    // The fixture really does carry the sentinel: it lives only in forbidden
    // fields, never in the selected columns, so the store itself necessarily
    // contains it while Pico's output and state do not.
    let store_bytes = fs::read(store_path(&env)).unwrap();
    assert!(
        store_bytes
            .windows(SENTINEL.len())
            .any(|window| window == SENTINEL.as_bytes()),
        "fixture store must contain the sentinel in forbidden fields"
    );
}

#[test]
fn s040_runtime_read_is_read_only_and_creates_no_sidecars() {
    let env = setup();
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_tool(
            &conn,
            "p1",
            "ses_1",
            now_ms() - 60_000,
            "bash",
            "completed",
            "c1",
        );
    }
    let before = tree_snapshot(&store_dir(&env));

    let out = run_pico(&env, &["scan", "--runtime"]);
    assert!(out.status.success(), "{}", stderr_text(&out));

    let after = tree_snapshot(&store_dir(&env));
    assert_eq!(before, after, "runtime read must not mutate the store");
    assert_eq!(after.len(), 1, "no -wal/-shm or temp files may be created");
    assert!(after.contains_key("opencode.db"));
}

#[test]
fn s040_runtime_runs_are_deterministic() {
    let env = setup();
    let fixed_ms = now_ms() - 5 * 60_000;
    {
        let conn = open_store(&env);
        supported_migration(&conn);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), fixed_ms);
        insert_tool(&conn, "p1", "ses_1", fixed_ms, "bash", "completed", "c1");
    }

    assert!(run_pico(&env, &["scan", "--runtime"]).status.success());
    let (first_metadata, first_scope) = newest_scan(&env);
    let first_evidence = latest_runtime_evidence(&env).expect("runtime evidence");
    let first_state = relationship_state(&env, GOLDEN_BASH_KEY);

    assert!(run_pico(&env, &["scan", "--runtime"]).status.success());
    let (second_metadata, second_scope) = newest_scan(&env);
    let second_evidence = latest_runtime_evidence(&env).expect("runtime evidence");
    let second_state = relationship_state(&env, GOLDEN_BASH_KEY);

    assert_eq!(
        serde_json::to_string(&first_metadata["coverage"]).unwrap(),
        serde_json::to_string(&second_metadata["coverage"]).unwrap(),
        "coverage JSON must be byte-equal across fixed-fixture runs"
    );
    assert_eq!(
        first_scope, second_scope,
        "scope.runtime must be deterministic"
    );
    assert_eq!(first_state, second_state);
    assert_eq!(first_evidence.class, second_evidence.class);
    assert_eq!(first_evidence.source_type, second_evidence.source_type);
    assert_eq!(first_evidence.observation, second_evidence.observation);
    assert_eq!(first_evidence.freshness, second_evidence.freshness);
    assert_eq!(
        serde_json::to_string(&first_evidence.metadata).unwrap(),
        serde_json::to_string(&second_evidence.metadata).unwrap()
    );
}
