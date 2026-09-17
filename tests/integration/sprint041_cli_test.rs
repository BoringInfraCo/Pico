//! Sprint 041 `pico scan --runtime` summary-line tests (SPRINT-041.md
//! §1.3/§1.4).
//!
//! Drives the compiled binary with an isolated temp workspace + temp HOME,
//! following the `tests/integration/sprint040_cli_test.rs` binary pattern. The
//! runtime store is a **synthetic** OpenCode-shaped SQLite database built in a
//! temp dir; the real `~/.local/share/opencode` store is never touched. These
//! tests only cover the `pico scan` summary line (the finding-detail section is
//! covered by the finding-rendering owner).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pico::application::InitService;
use rusqlite::{params, Connection};

const SENTINEL: &str = "SENTINEL_S041";
const OBSERVED_LINE: &str = "Observed execution: can_execute via runtime evidence (FRESH)";
const EFFECTIVE_BASH_LINE: &str = "Effective Bash: ALLOW";

const WORKSPACE_CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "SENTINEL_S041" }
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

fn run_pico(env: &Env, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_pico"));
    cmd.args(args)
        .current_dir(env.workspace.path())
        .env("HOME", env.home.path());
    for var in SCRUBBED_ENV {
        cmd.env_remove(var);
    }
    cmd.output().unwrap()
}

fn stdout_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Every summary line that reports an observed execution, in output order.
fn observed_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|line| line.starts_with("Observed execution:"))
        .collect()
}

// ---------------------------------------------------------------------------
// Synthetic store fixture (no forbidden content except the sweep test)
// ---------------------------------------------------------------------------

fn store_path(env: &Env) -> PathBuf {
    env.home.path().join(".local/share/opencode/opencode.db")
}

fn canonical(path: &Path) -> String {
    path.canonicalize().unwrap().to_string_lossy().into_owned()
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

const ONE_HOUR_MS: i64 = 60 * 60 * 1000;

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
    conn.execute(
        "INSERT INTO migration (id, time_completed) VALUES ('38', 0)",
        [],
    )
    .unwrap();
    conn
}

fn insert_session(conn: &Connection, id: &str, directory: &str, created_ms: i64) {
    conn.execute(
        "INSERT INTO session (id, directory, time_created, title) VALUES (?1, ?2, ?3, ?4)",
        params![id, directory, created_ms, SENTINEL],
    )
    .unwrap();
}

fn insert_bash(conn: &Connection, id: &str, session_id: &str, created_ms: i64, status: &str) {
    let data = serde_json::json!({
        "type": "tool",
        "tool": "bash",
        "callID": "c1",
        "state": { "status": status, "input": SENTINEL, "output": SENTINEL },
    });
    conn.execute(
        "INSERT INTO part (id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        params![id, session_id, created_ms, data.to_string()],
    )
    .unwrap();
}

/// Seed the forbidden content tables so the sentinel sweep proves the reader
/// never selects their columns.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A promoted runtime observation adds exactly one `Observed execution:` line
/// and does not disturb the frozen `Effective Bash: ALLOW` line.
#[test]
fn s041_promoted_runtime_prints_one_observed_execution_line() {
    let env = setup();
    {
        let conn = open_store(&env);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_bash(&conn, "p1", "ses_1", now_ms() - 5 * 60_000, "completed");
    }

    let out = run_pico(&env, &["scan", "--runtime"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    let stdout = stdout_text(&out);

    let lines = observed_lines(&stdout);
    assert_eq!(
        lines.len(),
        1,
        "a promotion must emit exactly one observed-execution line; got:\n{stdout}"
    );
    assert_eq!(lines[0], OBSERVED_LINE);

    assert!(
        stdout.contains(EFFECTIVE_BASH_LINE),
        "the frozen Effective Bash line must remain: {stdout}"
    );
}

/// The default (non-runtime) scan never opens the store and never claims an
/// observation, even when a promotable invocation exists on disk.
#[test]
fn s041_default_scan_prints_no_observed_execution_line() {
    let env = setup();
    {
        let conn = open_store(&env);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_bash(&conn, "p1", "ses_1", now_ms() - 5 * 60_000, "completed");
    }

    let out = run_pico(&env, &["scan"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    let stdout = stdout_text(&out);

    assert!(
        observed_lines(&stdout).is_empty(),
        "a default scan must not claim an observed execution; got:\n{stdout}"
    );
    assert!(stdout.contains(EFFECTIVE_BASH_LINE));
}

/// A runtime scan that records an attempt or a stale invocation but does not
/// promote it must stay silent about observed execution.
#[test]
fn s041_non_promoting_runtime_scan_prints_no_observed_execution_line() {
    // Pending-only: an attempt is recorded, never a promotion.
    {
        let env = setup();
        {
            let conn = open_store(&env);
            insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
            insert_bash(&conn, "p1", "ses_1", now_ms() - 60_000, "pending");
        }
        let out = run_pico(&env, &["scan", "--runtime"]);
        assert!(out.status.success(), "{}", stderr_text(&out));
        assert!(
            observed_lines(&stdout_text(&out)).is_empty(),
            "a pending-only observation must not claim execution"
        );
        // SPRINT-041 §1.3: an attempt without execution is surfaced as such.
        assert!(
            stdout_text(&out)
                .contains("Attempted (not executed): can_execute via runtime evidence (FRESH)"),
            "a pending-only observation must be surfaced as an attempt:\n{}",
            stdout_text(&out)
        );
    }

    // Stale invocation: recorded honestly, never laundered into a current claim.
    {
        let env = setup();
        let stale_ms = now_ms() - 25 * ONE_HOUR_MS;
        {
            let conn = open_store(&env);
            insert_session(&conn, "ses_1", &canonical(env.workspace.path()), stale_ms);
            insert_bash(&conn, "p1", "ses_1", stale_ms, "completed");
        }
        let out = run_pico(&env, &["scan", "--runtime"]);
        assert!(out.status.success(), "{}", stderr_text(&out));
        assert!(
            observed_lines(&stdout_text(&out)).is_empty(),
            "a stale observation must not claim current execution"
        );
    }
}

/// The sentinel carried only by forbidden store fields never reaches the
/// summary output.
#[test]
fn s041_sentinel_never_appears_in_runtime_summary() {
    let env = setup();
    {
        let conn = open_store(&env);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), now_ms());
        insert_bash(&conn, "p1", "ses_1", now_ms() - 60_000, "completed");
        seed_forbidden_content(&conn, "ses_1");
    }

    let out = run_pico(&env, &["scan", "--runtime"]);
    assert!(out.status.success(), "{}", stderr_text(&out));
    let combined = format!("{}{}", stdout_text(&out), stderr_text(&out));
    assert!(!combined.contains(SENTINEL), "output leaked {SENTINEL}");
}

/// The observed-execution line is byte-identical across repeated runs over a
/// fixed store (the surrounding scan id differs run to run, so only the line is
/// compared).
#[test]
fn s041_observed_execution_line_is_byte_identical_across_runs() {
    let env = setup();
    let fixed_ms = now_ms() - 5 * 60_000;
    {
        let conn = open_store(&env);
        insert_session(&conn, "ses_1", &canonical(env.workspace.path()), fixed_ms);
        insert_bash(&conn, "p1", "ses_1", fixed_ms, "completed");
    }

    let first = run_pico(&env, &["scan", "--runtime"]);
    assert!(first.status.success(), "{}", stderr_text(&first));
    let second = run_pico(&env, &["scan", "--runtime"]);
    assert!(second.status.success(), "{}", stderr_text(&second));

    let first_stdout = stdout_text(&first);
    let second_stdout = stdout_text(&second);
    let first_lines = observed_lines(&first_stdout);
    let second_lines = observed_lines(&second_stdout);
    assert_eq!(first_lines.len(), 1);
    assert_eq!(second_lines.len(), 1);
    assert_eq!(
        first_lines[0].as_bytes(),
        second_lines[0].as_bytes(),
        "the observed-execution line must be byte-identical across runs"
    );
}
