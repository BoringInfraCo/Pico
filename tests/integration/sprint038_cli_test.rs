//! Sprint 038 `pico status` CLI + integration tests (SPRINT-038.md §§2.3/4/5).
//!
//! Drives the compiled binary (`env!("CARGO_BIN_EXE_pico")`) with an
//! isolated temp workspace + temp HOME, following the
//! `tests/integration/sprint037_cli_test.rs` binary-driving pattern:
//!
//! - `status --help` documents the read-only contract.
//! - Fresh scan + empty/missing log → honest fresh status, `nothing flagged`.
//! - Exactly ONE timing-tolerant test: short interval, generous timeout,
//!   mutate `opencode.json` allow→deny, then assert `status` surfaces the
//!   real trigger event. Notice expectations are read off the real event:
//!   `total` counts every parseable JSONL object, URGENT/INFO only the
//!   case-exact `notice` levels (S038 §2.2 `notice` emission is owned by the
//!   parallel core agent; this test stays green before it lands and exercises
//!   the URGENT path after it lands without modification).
//! - Missing log / empty log / no COMPLETE scan / missing state: explicit
//!   honest states, never blank reassurance (all deterministic, no timing).
//! - Read-only: DB digest (and `watch.jsonl` length) equal across `status`.
//! - Secret sweep: a sentinel config VALUE never appears in status output
//!   (nor in `watch.jsonl` nor in the DB bytes).

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pico::application::InitService;
use sha2::{Digest, Sha256};

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST_038";

const ALLOW: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST_038" }
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
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST_038" }
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

const NOT_AN_ALL_CLEAR: &str =
    "This is not an all-clear: Pico reports what it observed, not safety.";

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

/// Bare workspace with no Pico state at all (no `pico init`).
fn setup_no_init() -> Env {
    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), ALLOW).unwrap();
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

fn stdout_text(out: &std::process::Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr_text(out: &std::process::Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
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

fn db_digest(env: &Env) -> String {
    let bytes = fs::read(env.workspace.path().join(".pico/pico.db")).unwrap();
    format!("{:x}", Sha256::digest(&bytes))
}

fn assert_secret_free(label: &str, text: &str) {
    assert!(
        !text.contains(SECRET_SENTINEL),
        "{label} leaked the sentinel config value"
    );
}

/// The `Watch events (retained log tail): <n> total, <u> URGENT, <i> INFO`
/// counts line, parsed without regex.
fn tail_counts(status: &str) -> (u64, u64, u64) {
    let line = status
        .lines()
        .find(|line| line.starts_with("Watch events (retained log tail):"))
        .expect("status must carry the watch-events counts line");
    let numbers: Vec<u64> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse().unwrap())
        .collect();
    assert_eq!(
        numbers.len(),
        3,
        "counts line must carry exactly three numbers; got:\n{line}"
    );
    (numbers[0], numbers[1], numbers[2])
}

#[test]
fn s038_status_help_documents_read_only_contract() {
    let env = setup();
    let out = run_pico(&env, &["status", "--help"]);
    assert!(out.status.success());
    let help = stdout_text(&out);
    assert!(
        help.to_lowercase().contains("read-only") || help.to_lowercase().contains("read only"),
        "--help must document the read-only contract; got:\n{help}"
    );
    assert_secret_free("status --help", &help);
}

#[test]
fn s038_fresh_scan_without_notices_reports_nothing_flagged() {
    let env = setup();
    let scan = run_pico(&env, &["scan"]);
    assert!(scan.status.success());
    let scan_id = stdout_text(&scan)
        .lines()
        .find_map(|line| line.strip_prefix("Scan: "))
        .expect("scan output names the scan id")
        .trim()
        .to_string();

    let out = run_pico(&env, &["status"]);
    assert!(out.status.success(), "fresh status must succeed");
    let status = stdout_text(&out);
    assert_secret_free("fresh status", &status);

    assert!(status.starts_with("Pico status\n"));
    assert!(
        status.contains(&format!("Last COMPLETE scan: {scan_id} (")),
        "fresh status must name the newest COMPLETE scan; got:\n{status}"
    );
    assert!(
        !status.contains("STALE"),
        "a just-completed scan is never STALE; got:\n{status}"
    );
    assert_eq!(tail_counts(&status), (0, 0, 0));
    assert!(
        status.contains("(no watch log yet)"),
        "a missing log must say so explicitly; got:\n{status}"
    );
    assert!(status.contains("Last URGENT: none recorded"));
    assert!(status.contains("Next step: nothing flagged"));
    assert!(status.contains(NOT_AN_ALL_CLEAR));
}

#[test]
fn s038_status_without_complete_scan_points_at_scan() {
    let env = setup();
    // Initialized but never scanned: no COMPLETE scan, no watch log.
    let out = run_pico(&env, &["status"]);
    assert!(out.status.success(), "no-scan status must succeed");
    let status = stdout_text(&out);
    assert_secret_free("no-scan status", &status);

    assert!(status.starts_with("Pico status\n"));
    assert!(
        status.contains("Last COMPLETE scan: none recorded"),
        "missing COMPLETE state must be explicit; got:\n{status}"
    );
    assert_eq!(tail_counts(&status), (0, 0, 0));
    assert!(status.contains("(no watch log yet)"));
    assert!(status.contains("Last URGENT: none recorded"));
    assert!(
        status.contains("Next step: run `pico scan`"),
        "with no COMPLETE scan the next step is a scan; got:\n{status}"
    );
    assert!(status.contains(NOT_AN_ALL_CLEAR));
}

#[test]
fn s038_status_with_empty_log_says_so_explicitly() {
    let env = setup();
    // A present-but-empty log is tolerated and reported honestly.
    fs::write(watch_jsonl_path(&env), "").unwrap();
    let out = run_pico(&env, &["status"]);
    assert!(out.status.success());
    let status = stdout_text(&out);
    assert_eq!(tail_counts(&status), (0, 0, 0));
    assert!(
        status.contains("(no events recorded yet)"),
        "an empty log must say so explicitly; got:\n{status}"
    );
    assert!(status.contains("Last URGENT: none recorded"));
    assert!(status.contains(NOT_AN_ALL_CLEAR));
    assert_secret_free("empty-log status", &status);
}

#[test]
fn s038_status_without_state_names_init() {
    let env = setup_no_init();
    let out = run_pico(&env, &["status"]);
    assert!(
        !out.status.success(),
        "status without Pico state must fail, not reassure"
    );
    let stderr = stderr_text(&out);
    assert!(
        stderr.contains("pico init"),
        "missing state must name the remedy; got:\n{stderr}"
    );
    assert_secret_free("missing-state stderr", &stderr);
    assert!(
        !env.workspace.path().join(".pico").exists(),
        "a failed status must not init state itself"
    );
}

/// THE timing test: a real watch-triggered event is surfaced by `status`,
/// read-only (DB digest and JSONL length equal across the query).
#[test]
fn s038_watch_triggered_event_is_surfaced_by_status() {
    let env = setup();

    // Baseline MANUAL scan through the binary.
    let baseline = run_pico(&env, &["scan"]);
    assert!(baseline.status.success());

    // Start the watcher; readiness = the frozen startup watch-set print.
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
    assert_eq!(events.len(), 1, "expected one event");

    let event: serde_json::Value = serde_json::from_str(&events[0]).unwrap();
    let scan_id = event["scan_id"].as_str().unwrap().to_string();
    let ts = event["ts"].as_str().unwrap().to_string();
    // Notice expectations read off the REAL event: total counts every
    // parseable object; URGENT/INFO only case-exact notice levels.
    let expected_urgent = u64::from(event["notice"].as_str() == Some("urgent"));
    let expected_info = u64::from(event["notice"].as_str() == Some("info"));

    // Read-only proof: digest + log length equal across `status`.
    let digest_before = db_digest(&env);
    let jsonl_len_before = fs::read(watch_jsonl_path(&env)).unwrap().len();
    let out = run_pico(&env, &["status"]);
    assert!(out.status.success());
    assert_eq!(db_digest(&env), digest_before, "status must be read-only");
    assert_eq!(
        fs::read(watch_jsonl_path(&env)).unwrap().len(),
        jsonl_len_before,
        "status must not append to the watch log"
    );

    let status = stdout_text(&out);
    assert_secret_free("triggered status", &status);
    assert!(status.starts_with("Pico status\n"));
    assert!(
        status.contains(&format!("Last COMPLETE scan: {scan_id} (")),
        "status must surface the triggered COMPLETE scan; got:\n{status}"
    );
    assert_eq!(
        tail_counts(&status),
        (1, expected_urgent, expected_info),
        "status tail must match the real event; got:\n{status}"
    );
    if expected_urgent == 1 {
        assert!(
            status.contains(&format!("Last URGENT: {ts} (")),
            "an URGENT event must be surfaced with its timestamp; got:\n{status}"
        );
        assert!(status.contains("Next step: run `pico findings`"));
    } else {
        assert!(status.contains("Last URGENT: none recorded"));
    }
    assert!(status.contains(NOT_AN_ALL_CLEAR));

    // The sentinel config value reached neither the DB bytes nor the log.
    let db_bytes = fs::read(env.workspace.path().join(".pico/pico.db")).unwrap();
    assert_secret_free("state database", &String::from_utf8_lossy(&db_bytes));
    assert_secret_free(
        "watch.jsonl",
        &fs::read_to_string(watch_jsonl_path(&env)).unwrap(),
    );
}
