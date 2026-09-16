//! Sprint 037 `pico watch` CLI + integration tests (SPRINT-037.md §4).
//!
//! Drives the compiled binary (`env!("CARGO_BIN_EXE_pico")`) with an
//! isolated temp workspace + temp HOME, following the
//! `tests/sprint034_mcp.rs` binary-driving pattern:
//!
//! - `--help` documents what is watched, budgets, the `watch.jsonl`
//!   location, and how to stop.
//! - `--interval-secs 0` is rejected with an actionable usage error.
//! - Exactly ONE timing-tolerant test: short interval, generous timeout,
//!   mutate `opencode.json` allow→deny, then assert one
//!   `FILESYSTEM_CHANGE` scan + one frozen-shape `watch.jsonl` event whose
//!   finding counters match a manual `diff --json` over the same pair.
//! - One deterministic quiet-watch test through the binary: no mutation →
//!   zero new scans, zero DB writes, zero JSONL events.
//! - Secret sweep: a sentinel config VALUE in the watched file never
//!   appears in CLI stdout or `watch.jsonl` (nor in the DB bytes).
//!
//! The CLI always passes `max_events=None` (run until killed), so the
//! timing/quiet tests spawn `pico watch` as a child, capture stdout/stderr
//! to files (never pipes, so no fill-deadlock), and kill the child when
//! done. Trigger assertions read the raw `trigger` column as text so these
//! tests do not depend on the domain seam owned by the parallel agent.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pico::application::InitService;
use sha2::{Digest, Sha256};

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST_037";

const ALLOW: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST_037" }
    }
  }}
}"#;

const DENY: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "deny" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST_037" }
    }
  }}
}"#;

/// Scrubbed ambient credential variables so binary-driven scans stay
/// hermetic and offline regardless of the developer's environment.
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
    out_dir: tempfile::TempDir,
}

fn setup() -> Env {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), ALLOW).unwrap();
    InitService::run(workspace.path()).unwrap();
    Env {
        workspace,
        home,
        out_dir: tempfile::tempdir().unwrap(),
    }
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

struct Watched {
    child: std::process::Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

fn spawn_watch(env: &Env, interval_secs: u64) -> Watched {
    let stdout_path = env.out_dir.path().join("watch.out");
    let stderr_path = env.out_dir.path().join("watch.err");
    let stdout_file = fs::File::create(&stdout_path).unwrap();
    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let mut cmd = pico_command(
        env,
        &["watch", "--interval-secs", &interval_secs.to_string()],
    );
    cmd.stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    let child = cmd.spawn().unwrap();
    Watched {
        child,
        stdout_path,
        stderr_path,
    }
}

/// Kill the watcher and return its captured (stdout, stderr) text.
fn stop_watch(watched: &mut Watched) -> (String, String) {
    watched.child.kill().unwrap();
    watched.child.wait().unwrap();
    (
        fs::read_to_string(&watched.stdout_path).unwrap_or_default(),
        fs::read_to_string(&watched.stderr_path).unwrap_or_default(),
    )
}

fn watch_jsonl_path(env: &Env) -> PathBuf {
    env.workspace.path().join(".pico/watch.jsonl")
}

fn read_stdout(watched: &Watched) -> String {
    fs::read_to_string(&watched.stdout_path).unwrap_or_default()
}

fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    ready()
}

fn wait_for_stdout(watched: &Watched, needle: &str, timeout: Duration) -> String {
    let found = wait_until(timeout, || read_stdout(watched).contains(needle));
    let out = read_stdout(watched);
    assert!(
        found,
        "timed out waiting for watch stdout to contain {needle:?}; got:\n{out}"
    );
    out
}

fn wait_for_jsonl(env: &Env, timeout: Duration) -> Vec<String> {
    let path = watch_jsonl_path(env);
    let found = wait_until(timeout, || {
        fs::read_to_string(&path)
            .map(|text| text.lines().any(|line| !line.trim().is_empty()))
            .unwrap_or(false)
    });
    let text = fs::read_to_string(&path).unwrap_or_default();
    assert!(
        found,
        "timed out waiting for .pico/watch.jsonl events; file contents:\n{text}"
    );
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Raw `(id, trigger)` rows in scan-start order; the trigger is read as
/// plain text so this helper needs no domain-seam access.
fn scan_rows(workspace: &Path) -> Vec<(String, String)> {
    let conn =
        rusqlite::Connection::open(workspace.join(".pico/pico.db")).expect("open state database");
    let mut stmt = conn
        .prepare("SELECT id, trigger FROM scans ORDER BY started_at, id")
        .unwrap();
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<(String, String)>, _>>()
        .unwrap()
}

fn db_digest(workspace: &Path) -> String {
    let bytes = fs::read(workspace.join(".pico/pico.db")).unwrap();
    format!("{:x}", Sha256::digest(&bytes))
}

fn assert_secret_free(label: &str, text: &str) {
    assert!(
        !text.contains(SECRET_SENTINEL),
        "{label} leaked the sentinel config value"
    );
}

#[test]
fn s037_watch_help_documents_contract() {
    let env = setup();
    let out = run_pico(&env, &["watch", "--help"]);
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    for needle in [
        "opencode.json",
        ".pico/watch.jsonl",
        "Ctrl-C",
        "interval",
        "stat",
        "daemon",
    ] {
        assert!(
            help.to_lowercase().contains(&needle.to_lowercase()),
            "--help must document {needle:?}; got:\n{help}"
        );
    }
    assert_secret_free("watch --help", &help);
}

#[test]
fn s037_watch_rejects_zero_interval() {
    let env = setup();
    let before = scan_rows(env.workspace.path());
    let out = run_pico(&env, &["watch", "--interval-secs", "0"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("--interval-secs") && stderr.contains(">= 1"),
        "zero interval must fail with an actionable error; got:\n{stderr}"
    );
    assert_secret_free("zero-interval stderr", &stderr);
    // Rejection happens before any service work: no scans, no JSONL.
    assert_eq!(scan_rows(env.workspace.path()), before);
    assert!(!watch_jsonl_path(&env).exists());
}

#[test]
fn s037_watch_triggers_scan_on_allow_to_deny() {
    let env = setup();

    // Baseline MANUAL scan through the binary.
    let baseline = run_pico(&env, &["scan"]);
    assert!(baseline.status.success());
    let baseline_stdout = String::from_utf8(baseline.stdout).unwrap();
    let scan1 = baseline_stdout
        .lines()
        .find_map(|line| line.strip_prefix("Scan: "))
        .expect("scan output names the scan id")
        .trim()
        .to_string();
    assert_secret_free("baseline scan stdout", &baseline_stdout);

    // Start the watcher; readiness = the frozen startup watch-set print
    // (§2.1: resolved set printed watch-root-relative at start).
    let mut watched = spawn_watch(&env, 1);
    let startup = wait_for_stdout(&watched, "opencode.json", Duration::from_secs(30));
    assert_secret_free("watch startup stdout", &startup);

    // The one adversarial mutation: allow → deny.
    fs::write(env.workspace.path().join("opencode.json"), DENY).unwrap();

    // Generous timeout: one poll interval to notice + one bounded scan.
    let events = wait_for_jsonl(&env, Duration::from_secs(90));
    let (watch_stdout, watch_stderr) = stop_watch(&mut watched);

    assert_secret_free("watch stdout", &watch_stdout);
    assert_secret_free("watch stderr", &watch_stderr);
    let jsonl_text = fs::read_to_string(watch_jsonl_path(&env)).unwrap();
    assert_secret_free("watch.jsonl", &jsonl_text);

    // Exactly one trigger event for the single mutation batch.
    assert_eq!(events.len(), 1, "expected one event; got:\n{jsonl_text}");
    let event: serde_json::Value = serde_json::from_str(&events[0]).unwrap();

    // Frozen event shape (SPRINT-037 §2.4).
    assert_eq!(event["v"], 1);
    assert!(event["ts"].as_str().is_some_and(|ts| !ts.is_empty()));
    assert_eq!(event["trigger"], "FILESYSTEM_CHANGE");
    assert_eq!(event["changed"], serde_json::json!(["opencode.json"]));
    let scan2 = event["scan_id"].as_str().unwrap().to_string();
    assert!(!scan2.is_empty() && scan2 != scan1);
    assert_eq!(event["scan_status"], "COMPLETE");
    assert_eq!(event["contracts_match"], true);
    for key in [
        "appeared",
        "disappeared",
        "weakened",
        "strengthened",
        "uncertain",
    ] {
        assert!(
            event["findings"][key].as_u64().is_some(),
            "event findings must carry u64 counter {key:?}; got: {}",
            event["findings"]
        );
    }
    // Relative paths only: never absolute, never a HOME leak.
    let event_text = events[0].to_string();
    assert!(!event_text.contains(env.home.path().to_str().unwrap()));
    assert!(!event_text.contains(env.workspace.path().to_str().unwrap()));

    // The triggered scan persisted with the FILESYSTEM_CHANGE trigger.
    let rows = scan_rows(env.workspace.path());
    let triggered: Vec<_> = rows.iter().filter(|(id, _)| *id == scan2).collect();
    assert_eq!(triggered.len(), 1);
    assert_eq!(triggered[0].1, "FILESYSTEM_CHANGE");
    assert!(rows
        .iter()
        .any(|(id, trigger)| id == &scan1 && trigger == "MANUAL"));

    // The event's counters equal a manual `scan` + `diff` over the same
    // pair: the same diff the watcher printed.
    let diff = run_pico(&env, &["diff", &scan1, &scan2, "--json"]);
    assert!(diff.status.success());
    let manual: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(
        event["findings"]["appeared"].as_u64().unwrap(),
        manual["findings"]["appeared"].as_array().unwrap().len() as u64
    );
    assert_eq!(
        event["findings"]["disappeared"].as_u64().unwrap(),
        manual["findings"]["not_observed"].as_array().unwrap().len() as u64
    );
    assert_eq!(
        event["findings"]["weakened"].as_u64().unwrap(),
        manual["findings"]["weakened"].as_array().unwrap().len() as u64
    );
    assert_eq!(
        event["findings"]["strengthened"].as_u64().unwrap(),
        manual["findings"]["strengthened"].as_array().unwrap().len() as u64
    );
    assert_eq!(
        event["findings"]["uncertain"].as_u64().unwrap(),
        manual["findings"]["uncertain"].as_array().unwrap().len() as u64
    );
    assert_secret_free(
        "manual diff stdout",
        &String::from_utf8(diff.stdout).unwrap(),
    );

    // The sentinel config value reached neither the DB bytes nor any
    // captured output.
    let db_bytes = fs::read(env.workspace.path().join(".pico/pico.db")).unwrap();
    assert_secret_free("state database", &String::from_utf8_lossy(&db_bytes));
}

#[test]
fn s037_quiet_watch_performs_zero_scans() {
    let env = setup();
    let baseline = run_pico(&env, &["scan"]);
    assert!(baseline.status.success());

    let scans_before = scan_rows(env.workspace.path());
    let digest_before = db_digest(env.workspace.path());

    // Watch briefly with zero mutations: no scan, no writes, no events.
    let mut watched = spawn_watch(&env, 1);
    wait_for_stdout(&watched, "opencode.json", Duration::from_secs(30));
    std::thread::sleep(Duration::from_secs(4));
    let (watch_stdout, watch_stderr) = stop_watch(&mut watched);

    assert_eq!(scan_rows(env.workspace.path()), scans_before);
    assert_eq!(db_digest(env.workspace.path()), digest_before);
    let jsonl = watch_jsonl_path(&env);
    assert!(
        !jsonl.exists() || fs::read_to_string(&jsonl).unwrap().trim().is_empty(),
        "quiet watch must append zero JSONL events"
    );
    assert_secret_free("quiet watch stdout", &watch_stdout);
    assert_secret_free("quiet watch stderr", &watch_stderr);
}
