//! SPRINT-044 T3 — opt-in measurement harness (ROADMAP §24 item 1; §9 exit
//! criteria #1 "measured latency and accuracy" and #4 "overhead within explicit
//! budgets").
//!
//! Numbers, not assertions. The harness is **opt-in** and follows the S035
//! capture pattern:
//!
//! - `PICO_S044_MEASURE=1` enables measurement; any other value (or absence)
//!   makes this test do nothing extra and pass, so default runs stay fast and
//!   hermetic.
//! - `PICO_S044_MEASURE_OUT=<path>` additionally writes the JSON artifact to
//!   that path. The artifact is always printed to stdout too.
//!
//! It measures, at minimum: idle observation cost (one real watch stat round),
//! detection latency (real `watch` code path, interval 1s), runtime ingest
//! cost (synthetic OpenCode-shaped store), and budget adherence. Everything is
//! synthetic and local: no real OpenCode store, no real `~/.claude`, no
//! network.
//!
//! Only loose, non-flaky invariants are asserted while enabled (detection
//! within `3 × interval`; ingest well under its wall-clock cap; every recorded
//! number present and finite). Nothing is asserted when disabled.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use pico::application::watch::{self, WatchConfig};
use pico::application::watch_log;
use pico::application::InitService;
use pico::discovery::runtime::{self, RuntimeIngestConfig, RuntimeReadOutcome};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

const MEASURE_ENV: &str = "PICO_S044_MEASURE";
const MEASURE_OUT_ENV: &str = "PICO_S044_MEASURE_OUT";

/// Idle stat-round samples. Larger than the latency sample count because each
/// sample is microseconds; this does not materially extend runtime.
const IDLE_SAMPLES: usize = 25;
/// Detection-latency samples. Kept small (3-5) and bounded: this is a
/// measurement, not a benchmark suite. Each sample costs ~one interval.
const LATENCY_SAMPLES: usize = 3;
/// Watch poll interval used for the latency measurement.
const LATENCY_INTERVAL_SECS: u64 = 1;
/// Synthetic OpenCode `part` rows for the ingest measurement.
const INGEST_ROWS: usize = 10_000;
/// Trim samples; each regenerates a cap+10-line log before timing a rewrite.
const LOG_TRIM_SAMPLES: usize = 5;
/// Extra whole lines above the cap so every trim sample actually rewrites.
const LOG_TRIM_OVER_CAP: usize = 10;
/// Generous, non-flaky multiple of the declared wall-clock cap for ingest.
const INGEST_CAP_MULTIPLE: f64 = 10.0;
/// How long to wait for the watcher's initial baseline snapshot to be taken
/// before mutating the watched config.
const BASELINE_SETTLE: Duration = Duration::from_millis(400);
/// Poll granularity while waiting for `watch.jsonl` to grow. Bounds the added
/// measurement error and is far below the poll interval being measured.
const LINE_POLL_INTERVAL: Duration = Duration::from_millis(10);

fn measure_enabled() -> bool {
    match std::env::var(MEASURE_ENV) {
        Ok(value) => {
            let value = value.trim();
            value == "1" || value.eq_ignore_ascii_case("true")
        }
        Err(_) => false,
    }
}

#[test]
fn s044_measurement_harness() {
    if !measure_enabled() {
        // Disabled path: no measurement, no artifact, no assertions.
        return;
    }

    let workspace = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    InitService::run(workspace.path()).unwrap();
    // A watched config must exist so the first latency sample has a baseline
    // and every mutation is a genuine size/mtime change.
    write_posture(workspace.path(), "allow", 0);

    let idle = measure_idle_observation_cost(workspace.path(), home.path());
    let latency = measure_detection_latency(workspace.path(), home.path());
    let ingest = measure_runtime_ingest_cost(workspace.path());
    let trim = measure_log_trim_cost();

    let mut measurements = serde_json::Map::new();
    measurements.insert("idle_observation_cost".to_string(), idle);
    measurements.insert("detection_latency".to_string(), latency);
    measurements.insert("runtime_ingest_cost".to_string(), ingest);
    measurements.insert("log_trim_cost".to_string(), trim);
    let budget_adherence = measure_budget_adherence(&measurements);
    measurements.insert("budget_adherence".to_string(), budget_adherence);

    let artifact = json!({
        "sprint": "SPRINT-044",
        "task": "T3 measurement harness",
        "harness": "tests/integration/sprint044_measurements.rs",
        "enabled_by": "PICO_S044_MEASURE=1",
        "build": build_record(),
        "method_notes": [
            "idle_observation_cost times pico::application::watch::snapshot (the watcher's real stat round) over the resolved watch set; watch-set resolution is mirrored in-test because application::watch::resolve_watch_set is private.",
            "detection_latency uses the real pico::application::watch::run loop with interval_secs=1 and max_events=1 per sample; latency is wall-clock from config mutation to the appended .pico/watch.jsonl line becoming visible, so it includes up to one poll interval plus line-poll granularity.",
            "runtime_ingest_cost times pico::discovery::runtime::ingest_with_summary over a synthetic OpenCode-shaped SQLite store in a temp dir; no real store and no network.",
            "log_trim_cost times pico::application::watch_log::trim at the declared cap over a synthetic .pico/watch.jsonl, regenerating a cap+10-line log before each sample.",
            "All invariants asserted here are loose and non-flaky; measured values are recorded, not used as tight gates."
        ],
        "measurements": Value::Object(measurements),
        "unmeasured": [
            "Observer downtime visibility, real-world detection latency under load, and long-running overhead are not exercised here.",
            "Runtime ingest accuracy (only wall-clock cost is measured, not correctness).",
            "Idle cost reports a median to absorb scheduler and IO jitter; it is a micro-measurement, not a sustained load test."
        ]
    });

    assert_all_finite(&artifact, "artifact");
    for key in [
        "idle_observation_cost",
        "detection_latency",
        "runtime_ingest_cost",
        "log_trim_cost",
        "budget_adherence",
    ] {
        assert!(
            artifact["measurements"][key].is_object(),
            "measurement {key} missing from artifact"
        );
    }
    assert!(
        artifact["build"]["commit"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "build record must carry a commit"
    );

    emit(&artifact);
}

/// One real watcher stat round over the resolved watch set, timed across
/// `IDLE_SAMPLES` iterations.
fn measure_idle_observation_cost(workspace: &Path, home: &Path) -> Value {
    let watch_set = resolved_watch_set(workspace, Some(home));
    let mut samples = Vec::with_capacity(IDLE_SAMPLES);
    for _ in 0..IDLE_SAMPLES {
        let started = Instant::now();
        let snapshot = watch::snapshot(&watch_set);
        samples.push(started.elapsed().as_secs_f64() * 1_000_000.0);
        // Keep the snapshot live across the timing boundary.
        assert_eq!(snapshot.entries.len(), watch_set.len());
    }
    let (min, median, max) = min_median_max(&samples);
    json!({
        "method": "one real pico::application::watch::snapshot (mtime+len stat round) over the resolved watch set",
        "watch_set_source": "resolved_watch_set() mirrors application::watch::resolve_watch_set() with identical candidate rules",
        "paths": watch_set.len(),
        "samples": IDLE_SAMPLES,
        "min_us": round(min, 3),
        "median_us": round(median, 3),
        "max_us": round(max, 3),
        "median_ms": round(median / 1_000.0, 4)
    })
}

fn measure_detection_latency(workspace: &Path, home: &Path) -> Value {
    let interval = Duration::from_secs(LATENCY_INTERVAL_SECS);
    let bound = interval * 3;
    let mut samples = Vec::with_capacity(LATENCY_SAMPLES);
    let mut observed = Vec::with_capacity(LATENCY_SAMPLES);

    for index in 0..LATENCY_SAMPLES {
        let cfg = WatchConfig {
            interval_secs: LATENCY_INTERVAL_SECS,
            max_events: Some(1),
        };
        let workspace_path = workspace.to_path_buf();
        let home_path = home.to_path_buf();
        let handle =
            std::thread::spawn(move || watch::run(&workspace_path, Some(&home_path), &cfg));

        // Let the run loop take its initial baseline snapshot before mutating.
        std::thread::sleep(BASELINE_SETTLE);
        let lines_before = watch_jsonl_lines(workspace);
        let started = Instant::now();
        write_posture(workspace, "allow", index + 1);
        let latency = wait_for_watch_line(workspace, lines_before, started, interval * 5);

        assert!(
            latency <= bound,
            "detection latency {:.1}ms exceeded 3x interval ({:.1}ms)",
            latency.as_secs_f64() * 1_000.0,
            bound.as_secs_f64() * 1_000.0
        );

        let report = handle.join().unwrap().unwrap();
        assert!(
            !report.events.is_empty(),
            "watch run recorded no event for sample {index}"
        );

        let observed_ms = latency.as_secs_f64() * 1_000.0;
        samples.push(observed_ms);
        observed.push(json!({"sample": index, "observed_ms": round(observed_ms, 2)}));
    }

    let (min, median, max) = min_median_max(&samples);
    json!({
        "method": "real pico::application::watch::run with interval_secs=1, max_events=1; wall-clock from config mutation to appended .pico/watch.jsonl line visible",
        "interval_secs": LATENCY_INTERVAL_SECS,
        "samples": LATENCY_SAMPLES,
        "line_poll_interval_ms": LINE_POLL_INTERVAL.as_millis(),
        "min_ms": round(min, 2),
        "median_ms": round(median, 2),
        "max_ms": round(max, 2),
        "observed": observed,
        "bound_asserted": "each sample <= 3 * interval_secs"
    })
}

fn measure_runtime_ingest_cost(workspace: &Path) -> Value {
    let store_dir = tempfile::tempdir().unwrap();
    let store_path = store_dir.path().join("opencode.db");
    seed_synthetic_opencode_store(&store_path, workspace, INGEST_ROWS);

    let cfg = RuntimeIngestConfig {
        store: Some(store_path),
        workspace: workspace.to_path_buf(),
        ..RuntimeIngestConfig::default()
    };
    let started = Instant::now();
    let (outcome, summary) = runtime::ingest_with_summary(&cfg).unwrap();
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1_000.0;

    let (kept, truncated) = match &outcome {
        RuntimeReadOutcome::Ingested {
            invocations,
            truncated,
        } => (invocations.len(), *truncated),
        other => panic!("expected Ingested from synthetic store, got {other:?}"),
    };
    let cap_ms = runtime::DEFAULT_WALL_CLOCK_MS as f64;
    assert!(
        elapsed_ms <= cap_ms * INGEST_CAP_MULTIPLE,
        "runtime ingest {elapsed_ms:.1}ms exceeded {INGEST_CAP_MULTIPLE}x wall-clock cap ({cap_ms}ms)"
    );

    json!({
        "method": "pico::discovery::runtime::ingest_with_summary over a synthetic OpenCode-shaped SQLite store in a temp dir",
        "window_secs": runtime::DEFAULT_WINDOW_SECS,
        "max_rows": runtime::DEFAULT_MAX_ROWS,
        "wall_clock_ms": runtime::DEFAULT_WALL_CLOCK_MS,
        "store_rows_seeded": INGEST_ROWS,
        "samples": 1,
        "elapsed_ms": round(elapsed_ms, 3),
        "rows_scanned": summary.rows_scanned,
        "invocations_kept": kept,
        "excluded_other_workspace": summary.excluded_other_workspace,
        "truncated": truncated,
        "cap_multiple_asserted": INGEST_CAP_MULTIPLE
    })
}

fn measure_log_trim_cost() -> Value {
    let dir = tempfile::tempdir().unwrap();
    let pico_dir = dir.path().join(".pico");
    fs::create_dir_all(&pico_dir).unwrap();
    let path = pico_dir.join("watch.jsonl");
    let lines_before = watch_log::WATCH_LOG_MAX_EVENTS + LOG_TRIM_OVER_CAP;

    let mut samples = Vec::with_capacity(LOG_TRIM_SAMPLES);
    let mut report = watch_log::TrimReport::default();
    for _ in 0..LOG_TRIM_SAMPLES {
        write_log_lines(&path, lines_before);
        let started = Instant::now();
        report = watch_log::trim(&path, watch_log::WATCH_LOG_TRIM_TARGET).unwrap();
        samples.push(started.elapsed().as_secs_f64() * 1_000.0);
    }

    // Deterministic invariants: whole-line hysteresis trims to the target.
    assert_eq!(report.before, lines_before);
    assert_eq!(report.after, watch_log::WATCH_LOG_TRIM_TARGET);
    assert_eq!(
        report.removed,
        lines_before - watch_log::WATCH_LOG_TRIM_TARGET
    );
    assert_eq!(
        watch_log::len(&path).unwrap(),
        watch_log::WATCH_LOG_TRIM_TARGET
    );

    let (min, median, max) = min_median_max(&samples);
    json!({
        "method": "pico::application::watch_log::trim at the declared cap over a synthetic .pico/watch.jsonl; each sample regenerates cap+10 whole lines before timing the atomic rewrite",
        "declared_cap_events": watch_log::WATCH_LOG_MAX_EVENTS,
        "declared_trim_target": watch_log::WATCH_LOG_TRIM_TARGET,
        "samples": LOG_TRIM_SAMPLES,
        "lines_before": report.before,
        "lines_after": report.after,
        "lines_removed": report.removed,
        "min_ms": round(min, 4),
        "median_ms": round(median, 4),
        "max_ms": round(max, 4)
    })
}

fn write_log_lines(path: &Path, count: usize) {
    use std::io::Write;
    let mut text = String::with_capacity(count * 16);
    for index in 0..count {
        text.push_str("{\"v\":1,\"i\":");
        text.push_str(&index.to_string());
        text.push_str("}\n");
    }
    let mut file = fs::File::create(path).unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

fn measure_budget_adherence(measurements: &serde_json::Map<String, Value>) -> Value {
    let ingest = &measurements["runtime_ingest_cost"];
    let latency = &measurements["detection_latency"];
    let log = &measurements["log_trim_cost"];
    json!({
        "method": "declared constants compared against the observed values recorded above",
        "runtime_ingest": {
            "window_secs": {"declared": runtime::DEFAULT_WINDOW_SECS, "observed": runtime::DEFAULT_WINDOW_SECS},
            "max_rows": {"declared": runtime::DEFAULT_MAX_ROWS, "observed_rows_scanned": ingest["rows_scanned"]},
            "wall_clock_ms": {"declared": runtime::DEFAULT_WALL_CLOCK_MS, "observed_ms": ingest["elapsed_ms"]}
        },
        "watch": {
            "poll_interval_secs": {"declared": LATENCY_INTERVAL_SECS, "observed": latency["interval_secs"]},
            "detection_max_ms_observed": latency["max_ms"],
            "detection_bound_ms": LATENCY_INTERVAL_SECS * 3 * 1_000
        },
        "watch_log": {
            "cap_events": {"declared": watch_log::WATCH_LOG_MAX_EVENTS, "observed_after_trim": log["lines_after"]},
            "trim_target": {"declared": watch_log::WATCH_LOG_TRIM_TARGET, "observed_removed": log["lines_removed"]},
            "trim_max_ms_observed": log["max_ms"]
        }
    })
}

fn build_record() -> Value {
    let commit = git(&["rev-parse", "HEAD"]);
    let porcelain = git(&["status", "--porcelain"]);
    let dirty_entries: usize = porcelain.lines().filter(|line| !line.is_empty()).count();
    let version = Command::new(env!("CARGO_BIN_EXE_pico"))
        .arg("--version")
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default();
    json!({
        "commit": commit.trim(),
        "dirty_tree": dirty_entries > 0,
        "dirty_entries": dirty_entries,
        "pico_version": version,
        "crate_version": env!("CARGO_PKG_VERSION"),
        "platform_os": std::env::consts::OS,
        "platform_arch": std::env::consts::ARCH
    })
}

fn git(args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default()
}

fn emit(artifact: &Value) {
    let text = serde_json::to_string_pretty(artifact).unwrap();
    println!("{text}");
    if let Some(path) = std::env::var_os(MEASURE_OUT_ENV) {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&path, text.as_bytes()).unwrap();
    }
}

/// Write a watched OpenCode config whose serialized length changes with
/// `variant`, so consecutive samples always differ in (mtime, len).
fn write_posture(workspace: &Path, posture: &str, variant: usize) {
    let note = "x".repeat(variant);
    let payload = json!({
        "permission": {"bash": posture},
        "s044_variant": note
    });
    fs::write(workspace.join("opencode.json"), payload.to_string()).unwrap();
}

fn watch_jsonl_lines(workspace: &Path) -> usize {
    let path = workspace.join(".pico").join("watch.jsonl");
    fs::read_to_string(&path)
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

fn wait_for_watch_line(
    workspace: &Path,
    before: usize,
    started: Instant,
    timeout: Duration,
) -> Duration {
    loop {
        if watch_jsonl_lines(workspace) > before {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < timeout,
            "watch event was not recorded within {timeout:?}"
        );
        std::thread::sleep(LINE_POLL_INTERVAL);
    }
}

/// Seed a minimal but schema-valid synthetic OpenCode store: the frozen
/// migration/tables/columns the reader requires, one in-scope session, and
/// `rows` tool parts inside the retained window. No content or secret columns
/// beyond the minimal shape.
fn seed_synthetic_opencode_store(path: &Path, workspace: &Path, rows: usize) {
    let mut conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, title TEXT);
         CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, time_created INTEGER, data TEXT);
         CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT);
         CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER);
         CREATE TABLE session_input (id TEXT PRIMARY KEY, session_id TEXT, prompt TEXT);",
    )
    .unwrap();
    let transaction = conn.transaction().unwrap();
    for index in 1..=runtime::SUPPORTED_MIGRATION_MAX {
        transaction
            .execute(
                "INSERT INTO migration (id, time_completed) VALUES (?1, 0)",
                params![format!("{index:04}")],
            )
            .unwrap();
    }
    transaction
        .execute(
            "INSERT INTO session (id, directory, title) VALUES (?1, ?2, NULL)",
            params!["ses_s044", workspace.to_string_lossy()],
        )
        .unwrap();
    let base = chrono::Utc::now().timestamp_millis() - 1_000;
    for index in 0..rows {
        let data = json!({
            "type": "tool",
            "tool": "bash",
            "callID": format!("call_{index}"),
            "state": {"status": "completed"}
        });
        transaction
            .execute(
                "INSERT INTO part (id, message_id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    format!("part_{index:08}"),
                    "msg_s044",
                    "ses_s044",
                    base - (index as i64),
                    data.to_string()
                ],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
}

/// Mirror of `application::watch::resolve_watch_set` (private): workspace-chain
/// project candidates, user candidates only when a home seam exists, plus the
/// single `.env` at the git root (else the workspace). Kept identical so the
/// measured stat round covers the same paths the service would stat.
fn resolved_watch_set(workspace: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    const OPENCODE_CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];
    const CLAUDE_SETTINGS_NAMES: [&str; 2] = ["settings.json", "settings.local.json"];

    let mut set = BTreeSet::new();
    for directory in workspace_chain(workspace) {
        for name in OPENCODE_CONFIG_NAMES {
            set.insert(directory.join(name));
            set.insert(directory.join(".opencode").join(name));
        }
        for name in CLAUDE_SETTINGS_NAMES {
            set.insert(directory.join(".claude").join(name));
        }
        set.insert(directory.join(".mcp.json"));
    }
    if let Some(home) = home {
        for name in OPENCODE_CONFIG_NAMES {
            set.insert(home.join(".config").join("opencode").join(name));
        }
        set.insert(home.join(".claude").join("settings.json"));
    }
    set.insert(dotenv_root(workspace).join(".env"));
    set.into_iter().collect()
}

fn workspace_chain(workspace: &Path) -> Vec<PathBuf> {
    match git_root(workspace) {
        Some(root) => {
            let mut chain: Vec<PathBuf> = workspace
                .ancestors()
                .take_while(|candidate| *candidate != root)
                .map(Path::to_path_buf)
                .collect();
            chain.push(root);
            chain.reverse();
            chain
        }
        None => vec![workspace.to_path_buf()],
    }
}

fn git_root(workspace: &Path) -> Option<PathBuf> {
    workspace
        .ancestors()
        .find(|candidate| candidate.join(".git").exists())
        .map(Path::to_path_buf)
}

fn dotenv_root(workspace: &Path) -> PathBuf {
    git_root(workspace).unwrap_or_else(|| workspace.to_path_buf())
}

fn min_median_max(samples: &[f64]) -> (f64, f64, f64) {
    assert!(!samples.is_empty(), "at least one sample is required");
    let mut sorted = samples.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).unwrap());
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let midpoint = sorted.len() / 2;
    let median = if sorted.len().is_multiple_of(2) {
        (sorted[midpoint - 1] + sorted[midpoint]) / 2.0
    } else {
        sorted[midpoint]
    };
    (min, median, max)
}

fn round(value: f64, places: i32) -> f64 {
    let factor = 10f64.powi(places);
    (value * factor).round() / factor
}

fn assert_all_finite(value: &Value, path: &str) {
    match value {
        Value::Number(number) => {
            if let Some(float) = number.as_f64() {
                assert!(float.is_finite(), "non-finite number at {path}: {number}");
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_all_finite(item, &format!("{path}[{index}]"));
            }
        }
        Value::Object(entries) => {
            for (key, entry) in entries {
                assert_all_finite(entry, &format!("{path}.{key}"));
            }
        }
        _ => {}
    }
}
