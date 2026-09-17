//! Foreground filesystem watcher (SPRINT-037).
//!
//! Opt-in `pico watch` observation over the adapter-read config files: poll
//! `(mtime, len)` snapshots at a fixed interval, run the unchanged bounded
//! scan pipeline with trigger `FILESYSTEM_CHANGE` when a watched file
//! appears, disappears, or changes size/mtime, reuse `DiffService::latest`,
//! and append one JSONL event per trigger to `.pico/watch.jsonl`.
//!
//! No daemon, no notifications, no content capture, no new dependencies.
//! Read-only until v0.7: the watcher never mutates the target environment;
//! the only writes are `.pico/watch.jsonl` appends, the `.pico/watch.state.json`
//! continuity record, plus normal scan persistence. `PARTIAL`/`FAILED` scans
//! are freshness context, never diff operands (Invariant 9).
//!
//! SPRINT-044 §2.1 adds the continuity record: evidence *of observation*, not
//! process introspection. It is written atomically (temp file in `.pico/` +
//! rename), at most once per [`HEARTBEAT_SECS`] while idle and always when an
//! event is recorded. It carries no pid or process field; `pico status` reads
//! it to tell "watching" from "NOT OBSERVING" from "no record" (S038's
//! no-pidfile rule is preserved).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::application::diff::{DiffService, FindingDiff, FindingDiffResult};
use crate::application::scan::ScanService;
use crate::application::watch_log;
use crate::domain::{ScanStatus, ScanTrigger};
use crate::persistence::{require_schema_version, Database};
use crate::shared::PicoError;

/// Poll configuration for [`run`]: fixed interval plus an optional event
/// budget. `max_events: None` runs until killed (Ctrl-C); `Some(n)` stops
/// after `n` trigger events. `Some(0)` performs zero scans and zero writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchConfig {
    pub interval_secs: u64,
    pub max_events: Option<u64>,
}

/// Mtime+length snapshot over the watch set. `None` marks a path with no
/// statable regular file, so creation of a previously absent file is itself
/// a change. File contents are never read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub entries: BTreeMap<PathBuf, Option<(SystemTime, u64)>>,
}

/// Pure (mtime, len) snapshot over `paths` via `std::fs::metadata` only.
pub fn snapshot(paths: &[PathBuf]) -> Snapshot {
    let mut entries = BTreeMap::new();
    for path in paths {
        entries.insert(path.clone(), file_signature(path));
    }
    Snapshot { entries }
}

fn file_signature(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Pure deterministic diff of two snapshots: every path whose signature
/// (including absence) differs, in sorted order. Covers appeared,
/// disappeared, mtime-only, and len-only changes.
pub fn detect_changes(before: &Snapshot, after: &Snapshot) -> Vec<PathBuf> {
    // BTreeMap iteration is key-sorted, so this union is deterministic.
    let mut keys: Vec<&PathBuf> = before.entries.keys().chain(after.entries.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut changed = Vec::new();
    for key in keys {
        if before.entries.get(key) != after.entries.get(key) {
            changed.push(key.clone());
        }
    }
    changed
}

/// Persisted display form for a watched path: workspace-relative when under
/// the workspace, `~/`-prefixed home-relative when under home only, and the
/// bare file name when outside both roots (never an absolute HOME path).
pub fn relativize(path: &Path, workspace: &Path, home: Option<&Path>) -> String {
    if let Ok(relative) = path.strip_prefix(workspace) {
        return relative.to_string_lossy().into_owned();
    }
    if let Some(home) = home {
        if let Ok(relative) = path.strip_prefix(home) {
            let relative = relative.to_string_lossy();
            if relative.is_empty() {
                return "~".to_string();
            }
            return format!("~/{relative}");
        }
    }
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

/// Finding-delta counts carried by a watch event. All zero when no
/// contract-matched comparison was produced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchFindingDelta {
    pub appeared: u64,
    pub disappeared: u64,
    pub weakened: u64,
    pub strengthened: u64,
    pub uncertain: u64,
}

impl WatchFindingDelta {
    fn from_diff(diff: &FindingDiff) -> Self {
        WatchFindingDelta {
            appeared: diff.appeared.len() as u64,
            disappeared: diff.disappeared.len() as u64,
            weakened: diff.weakened.len() as u64,
            strengthened: diff.strengthened.len() as u64,
            uncertain: diff.uncertain.len() as u64,
        }
    }
}

/// Deterministic notice level for a watch event (SPRINT-038 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Notice {
    Urgent,
    Info,
    Quiet,
}

impl Notice {
    /// Machine-readable lowercase form used in `watch.jsonl`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Notice::Urgent => "urgent",
            Notice::Info => "info",
            Notice::Quiet => "quiet",
        }
    }
}

impl std::str::FromStr for Notice {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urgent" => Ok(Notice::Urgent),
            "info" => Ok(Notice::Info),
            "quiet" => Ok(Notice::Quiet),
            other => Err(format!(
                "unknown notice level: {other} (expected urgent|info|quiet)"
            )),
        }
    }
}

impl std::fmt::Display for Notice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Flat, Copy-friendly facts for [`classify`]: finding-delta counts plus the
/// scan and environment booleans. Counts and reason codes only — never
/// values or contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventFacts {
    pub appeared: usize,
    pub disappeared: usize,
    pub weakened: usize,
    pub strengthened: usize,
    pub uncertain: usize,
    pub contracts_match: bool,
    pub scan_partial: bool,
    pub env_change_observed: bool,
}

/// Pure deterministic notice rules (SPRINT-038 §2.1, frozen). Priority
/// URGENT > INFO > QUIET; reasons accumulate across levels so an overlap
/// like appeared + weakened reports URGENT with both codes. Stable order:
/// appeared, strengthened, weakened, uncertain, disappeared, scan_partial,
/// contracts_mismatch, env_change_no_finding_delta.
pub fn classify(event_facts: &EventFacts) -> (Notice, Vec<&'static str>) {
    let mut reasons: Vec<&'static str> = Vec::new();
    if event_facts.appeared > 0 {
        reasons.push("finding_appeared");
    }
    if event_facts.strengthened > 0 {
        reasons.push("finding_strengthened");
    }
    let urgent = !reasons.is_empty();
    if event_facts.weakened > 0 {
        reasons.push("finding_weakened");
    }
    if event_facts.uncertain > 0 {
        reasons.push("finding_uncertain");
    }
    if event_facts.disappeared > 0 {
        reasons.push("disappearance_unconfirmed");
    }
    if event_facts.scan_partial {
        reasons.push("scan_partial");
    }
    if !event_facts.contracts_match {
        reasons.push("contracts_mismatch");
    }
    let zero_deltas = event_facts.appeared == 0
        && event_facts.disappeared == 0
        && event_facts.weakened == 0
        && event_facts.strengthened == 0
        && event_facts.uncertain == 0;
    if event_facts.env_change_observed && zero_deltas {
        reasons.push("env_change_no_finding_delta");
    }
    if urgent {
        (Notice::Urgent, reasons)
    } else if !reasons.is_empty() {
        (Notice::Info, reasons)
    } else {
        (Notice::Quiet, vec!["no_significant_change"])
    }
}

/// One `.pico/watch.jsonl` record. Field order is the frozen SPRINT-037
/// §2.4 shape: watch-root-relative `changed` paths only — never contents,
/// never absolute HOME paths; `scan_id` is the only opaque identifier.
/// SPRINT-038 appends `notice` + `reasons`; `"v"` stays 1.
/// Readers MUST tolerate unknown fields (serde ignores them by default) so
/// future event extensions never break older status readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchEvent {
    pub v: u32,
    pub ts: String,
    pub trigger: String,
    pub changed: Vec<String>,
    pub scan_id: String,
    pub scan_status: String,
    pub contracts_match: bool,
    pub findings: WatchFindingDelta,
    pub notice: Notice,
    pub reasons: Vec<String>,
}

impl WatchEvent {
    fn new(
        ts: String,
        changed: Vec<String>,
        scan_id: String,
        scan_status: ScanStatus,
        contracts_match: bool,
        findings: WatchFindingDelta,
        classified: (Notice, Vec<String>),
    ) -> Self {
        WatchEvent {
            v: 1,
            ts,
            trigger: ScanTrigger::FilesystemChange.as_str().to_string(),
            changed,
            scan_id,
            scan_status: scan_status.as_str().to_string(),
            contracts_match,
            findings,
            notice: classified.0,
            reasons: classified.1,
        }
    }
}

/// Exactly one human notice line per event. URGENT names `pico findings`;
/// QUIET keeps the not-an-all-clear. Counts plus reason codes only — never
/// values or contents.
fn notice_line(facts: &EventFacts, notice: Notice, reasons: &[&'static str]) -> String {
    match notice {
        Notice::Quiet => "Pico watch: [QUIET] no significant change (no_significant_change). This is not an all-clear.".to_string(),
        Notice::Urgent => format!(
            "Pico watch: [URGENT] {} appeared, {} disappeared, {} weakened, {} strengthened, {} uncertain ({}) — run `pico findings`",
            facts.appeared,
            facts.disappeared,
            facts.weakened,
            facts.strengthened,
            facts.uncertain,
            reasons.join(", ")
        ),
        Notice::Info => format!(
            "Pico watch: [INFO] {} appeared, {} disappeared, {} weakened, {} strengthened, {} uncertain ({})",
            facts.appeared,
            facts.disappeared,
            facts.weakened,
            facts.strengthened,
            facts.uncertain,
            reasons.join(", ")
        ),
    }
}

/// Outcome of [`run`]: one event per trigger scan, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchReport {
    pub events: Vec<WatchEvent>,
}

/// Run the foreground watch loop (SPRINT-037 §2.3): resolve the watch set,
/// print the set plus budgets, then sequentially sleep → snapshot → diff.
/// A change batch runs one `FILESYSTEM_CHANGE` scan, reuses
/// `DiffService::latest`, prints the human summary, and appends one JSONL
/// event; quiet intervals perform zero scans and zero writes.
pub fn run(
    workspace: &Path,
    home: Option<&Path>,
    cfg: &WatchConfig,
) -> Result<WatchReport, PicoError> {
    // A zero interval would busy-loop; the CLI validates this too, and the
    // service guards the contract so a programming error fails loudly.
    if cfg.interval_secs == 0 {
        return Err(PicoError::usage(
            "watch requires --interval-secs >= 1 (got 0); rerun with e.g. `pico watch --interval-secs 2`",
        ));
    }
    // Fatal states fail fast with actionable errors and no init side
    // effects: a missing store names `pico init`, an unsupported schema
    // names its remedy. The store opens read-only so validation writes
    // nothing.
    let db_path = workspace.join(".pico").join("pico.db");
    let db = Database::open_read_only(&db_path)?;
    require_schema_version(db.connection())?;
    drop(db);

    let watch_set = resolve_watch_set(workspace, home);
    println!(
        "Pico watch: watching {} path(s) every {}s:",
        watch_set.len(),
        cfg.interval_secs
    );
    for path in &watch_set {
        println!("  {}", relativize(path, workspace, home));
    }
    println!(
        "Pico watch: one stat round per interval while idle; one bounded scan per change batch; no content capture."
    );
    println!("Pico watch: events append to .pico/watch.jsonl; stop with Ctrl-C.");

    let mut report = WatchReport::default();
    let mut state_written_at: Option<DateTime<Utc>> = None;
    let mut before = snapshot(&watch_set);
    loop {
        if budget_reached(&report, cfg.max_events) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(cfg.interval_secs));
        let after = snapshot(&watch_set);
        let changed = detect_changes(&before, &after);
        if changed.is_empty() {
            before = after;
            // Idle continuity heartbeat: at most one record write per
            // HEARTBEAT_SECS so `pico status` can tell silence from safety.
            let now = Utc::now();
            if heartbeat_due(state_written_at, now) {
                write_continuity(workspace, cfg.interval_secs, report.events.len(), now)?;
                state_written_at = Some(now);
            }
            continue;
        }
        // Primary pass for this change batch.
        if let Some(fresh) = scan_and_record(workspace, home, &watch_set, &changed, &mut report)? {
            // An event was recorded: always refresh the continuity record, and
            // keep the observation log bounded (SPRINT-044 §2.2). Trimming is
            // amortized: it only rewrites once the cap is exceeded, down to the
            // lower watermark, so a long run cannot grow the log without bound.
            trim_log_if_needed(workspace)?;
            let now = Utc::now();
            write_continuity(workspace, cfg.interval_secs, report.events.len(), now)?;
            state_written_at = Some(now);
            before = fresh;
            // Files changed again mid-scan: exactly one follow-up pass, then
            // re-baseline. Anything newer is picked up next interval (or next
            // run), never by unbounded chasing.
            let raced = snapshot(&watch_set);
            let raced_changed = detect_changes(&before, &raced);
            if !raced_changed.is_empty() {
                if budget_reached(&report, cfg.max_events) {
                    break;
                }
                if let Some(fresh) =
                    scan_and_record(workspace, home, &watch_set, &raced_changed, &mut report)?
                {
                    trim_log_if_needed(workspace)?;
                    let now = Utc::now();
                    write_continuity(workspace, cfg.interval_secs, report.events.len(), now)?;
                    state_written_at = Some(now);
                    before = fresh;
                }
            }
        } else {
            // A change was detected but no event could be recorded (for example
            // a failing scan). The observer is still alive: refresh the
            // heartbeat (rate-limited) so `pico status` does not report a live
            // watcher as NOT OBSERVING, and re-baseline to the observed state so
            // the next interval compares against reality rather than looping on
            // the same change.
            before = after;
            let now = Utc::now();
            if heartbeat_due(state_written_at, now) {
                write_continuity(workspace, cfg.interval_secs, report.events.len(), now)?;
                state_written_at = Some(now);
            }
        }
    }
    Ok(report)
}

/// Keep `.pico/watch.jsonl` bounded (SPRINT-044 §2.2): once the log exceeds
/// `WATCH_LOG_MAX_EVENTS`, trim to `WATCH_LOG_TRIM_TARGET`. Hysteresis makes the
/// rewrite amortized (~every 500 events) rather than per event.
fn trim_log_if_needed(workspace: &Path) -> Result<(), PicoError> {
    let path = workspace.join(".pico").join("watch.jsonl");
    if watch_log::len(&path)? > watch_log::WATCH_LOG_MAX_EVENTS {
        watch_log::trim(&path, watch_log::WATCH_LOG_TRIM_TARGET)?;
    }
    Ok(())
}

fn budget_reached(report: &WatchReport, max_events: Option<u64>) -> bool {
    max_events.is_some_and(|max| report.events.len() as u64 >= max)
}

/// Idle heartbeat cadence for `.pico/watch.state.json` (SPRINT-044 §2.1):
/// while idle the continuity record is rewritten at most this often.
pub const HEARTBEAT_SECS: u64 = 15;

/// `.pico/watch.state.json` continuity record (SPRINT-044 §2.1). This is
/// evidence *of observation*, never process introspection: it carries no pid
/// or process field. Field declaration order is the frozen v1 shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatchState {
    pub v: u32,
    pub interval_secs: u64,
    pub last_check_at: String,
    pub events_total: u64,
}

impl WatchState {
    /// The frozen `"v":1` record for one completed check.
    pub fn new(interval_secs: u64, last_check_at: String, events_total: u64) -> Self {
        WatchState {
            v: 1,
            interval_secs,
            last_check_at,
            events_total,
        }
    }
}

/// Current instant in the same second-precision RFC3339/UTC form used by
/// `watch.jsonl` events.
fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Atomic continuity write: serialize, write a temp file inside `.pico/`, then
/// rename over `.pico/watch.state.json`. The target directory already exists
/// (watch requires `pico init`); the temp file is removed if the rename fails
/// so only a complete record is ever visible.
fn write_state(workspace: &Path, state: &WatchState) -> Result<(), PicoError> {
    let dir = workspace.join(".pico");
    let path = dir.join("watch.state.json");
    let temp = dir.join("watch.state.json.tmp");
    let json = serde_json::to_string(state)
        .map_err(|error| PicoError::scan(format!("watch state serialization failed: {error}")))?;
    std::fs::write(&temp, json.as_bytes())
        .map_err(|error| PicoError::io(format!("cannot write {}: {error}", temp.display())))?;
    if let Err(error) = std::fs::rename(&temp, &path) {
        let _ = std::fs::remove_file(&temp);
        return Err(PicoError::io(format!(
            "cannot replace {}: {error}",
            path.display()
        )));
    }
    Ok(())
}

/// Write the continuity record for a completed check at `now`.
fn write_continuity(
    workspace: &Path,
    interval_secs: u64,
    events_total: usize,
    now: DateTime<Utc>,
) -> Result<(), PicoError> {
    let state = WatchState::new(
        interval_secs,
        now.to_rfc3339_opts(SecondsFormat::Secs, true),
        events_total as u64,
    );
    write_state(workspace, &state)
}

/// True when the idle heartbeat is due: at most one write per
/// [`HEARTBEAT_SECS`]. `last` is the previous continuity write time; `None`
/// (no write yet this run) is always due.
fn heartbeat_due(last: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match last {
        None => true,
        Some(last) => {
            now.signed_duration_since(last) >= chrono::Duration::seconds(HEARTBEAT_SECS as i64)
        }
    }
}

/// One trigger cycle: run the unchanged bounded pipeline with
/// `FILESYSTEM_CHANGE`, reuse `DiffService::latest`, print the human
/// summary, and append exactly one JSONL event. Returns the fresh post-scan
/// baseline, or `None` when the scan failed transiently (stderr note, watch
/// continues, caller keeps its baseline so the change is retried next
/// interval). Migration failures propagate as fatal errors.
fn scan_and_record(
    workspace: &Path,
    home: Option<&Path>,
    watch_set: &[PathBuf],
    changed: &[PathBuf],
    report: &mut WatchReport,
) -> Result<Option<Snapshot>, PicoError> {
    let mut changed_rel: Vec<String> = changed
        .iter()
        .map(|path| relativize(path, workspace, home))
        .collect();
    changed_rel.sort();
    changed_rel.dedup();
    println!(
        "Pico watch: change detected ({}): {}",
        changed_rel.len(),
        changed_rel.join(", ")
    );
    let result = match ScanService::run_with_trigger(workspace, home, ScanTrigger::FilesystemChange)
    {
        Ok(result) => result,
        Err(PicoError::Migration(message)) => return Err(PicoError::Migration(message)),
        Err(error) => {
            // External concurrent `pico scan` failures (e.g. lock
            // contention) must not kill the watch: note to stderr and retry
            // next interval without advancing the baseline.
            eprintln!("Pico watch: scan failed ({error}); continuing to watch.");
            return Ok(None);
        }
    };
    println!(
        "Pico watch: scan {} {}",
        result.scan_id,
        result.status.as_str()
    );
    let (contracts_match, findings) = if result.status == ScanStatus::Complete {
        match DiffService::latest(workspace) {
            Ok(FindingDiffResult::Ready(diff)) => {
                print_ready_summary(&diff);
                (true, WatchFindingDelta::from_diff(&diff))
            }
            Ok(other) => {
                // Only Ready verifies both contracts Some, equal, and
                // current; anything else records a zeroed, non-matching
                // event rather than an invented comparison.
                println!(
                    "Pico watch: {} — freshness context only.",
                    describe_non_ready(&other)
                );
                (false, WatchFindingDelta::default())
            }
            Err(error) => {
                eprintln!(
                    "Pico watch: diff failed ({error}); recording trigger without comparison."
                );
                (false, WatchFindingDelta::default())
            }
        }
    } else {
        // PARTIAL/FAILED scans are freshness context, never diff operands.
        println!(
            "Pico watch: scan {} is {} — freshness context only, never a diff operand; continuing to watch.",
            result.scan_id,
            result.status.as_str()
        );
        (false, WatchFindingDelta::default())
    };
    let facts = EventFacts {
        appeared: findings.appeared as usize,
        disappeared: findings.disappeared as usize,
        weakened: findings.weakened as usize,
        strengthened: findings.strengthened as usize,
        uncertain: findings.uncertain as usize,
        contracts_match,
        scan_partial: result.status == ScanStatus::Partial,
        // Every recorded event follows an attributed watch-set change batch,
        // so a non-empty relative change list marks the env observation.
        env_change_observed: !changed_rel.is_empty(),
    };
    let (notice, reason_codes) = classify(&facts);
    let reasons: Vec<String> = reason_codes.iter().map(|code| code.to_string()).collect();
    let event = WatchEvent::new(
        now_rfc3339(),
        changed_rel,
        result.scan_id.clone(),
        result.status,
        contracts_match,
        findings,
        (notice, reasons),
    );
    append_event(workspace, &event)?;
    report.events.push(event);
    println!("{}", notice_line(&facts, notice, &reason_codes));
    Ok(Some(snapshot(watch_set)))
}

/// Compact deterministic human summary of a Ready diff. The full
/// `pico diff` rendering lives in the CLI; this carries the same diff
/// facts (pair, counts, titles) in watcher-output form.
fn print_ready_summary(diff: &FindingDiff) {
    println!(
        "Pico watch: diff {}..{}: {} appeared, {} disappeared, {} weakened, {} strengthened, {} uncertain",
        diff.from.id,
        diff.to.id,
        diff.appeared.len(),
        diff.disappeared.len(),
        diff.weakened.len(),
        diff.strengthened.len(),
        diff.uncertain.len()
    );
    for finding in &diff.appeared {
        println!("  + {} {}", finding.id, finding.title);
    }
    for finding in &diff.disappeared {
        println!("  - {} {}", finding.id, finding.title);
    }
}

fn describe_non_ready(result: &FindingDiffResult) -> &'static str {
    match result {
        FindingDiffResult::NoCompleteScan => "no COMPLETE scan yet",
        FindingDiffResult::NeedPrevious { .. } => "only one COMPLETE scan yet",
        FindingDiffResult::NotComparable(_) => "newest COMPLETE pair is not comparable",
        FindingDiffResult::Ready(_) => "comparison ready",
    }
}

fn append_event(workspace: &Path, event: &WatchEvent) -> Result<(), PicoError> {
    let path = workspace.join(".pico").join("watch.jsonl");
    let mut line = serde_json::to_string(event)
        .map_err(|error| PicoError::scan(format!("watch event serialization failed: {error}")))?;
    line.push('\n');
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| PicoError::io(format!("cannot append {}: {error}", path.display())))?
        .write_all(line.as_bytes())
        .map_err(|error| PicoError::io(format!("cannot append {}: {error}", path.display())))?;
    Ok(())
}

const OPENCODE_CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];
const CLAUDE_SETTINGS_NAMES: [&str; 2] = ["settings.json", "settings.local.json"];

/// Re-derive the candidate config paths using the adapters' own resolution
/// rules (SPRINT-037 §2.1; mirrors `discovery/agents/opencode.rs` and
/// `discovery/agents/claude.rs`): workspace-chain project files, user files
/// only when `home` is `Some`, plus the single `.env` at the git root (else
/// the workspace). Missing files are included so creation is observed.
/// Provider *policy* logic stays in the adapters; only path resolution is
/// mirrored here.
fn resolve_watch_set(workspace: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    use std::collections::BTreeSet;
    let mut set = BTreeSet::new();
    for directory in workspace_chain(workspace) {
        // OpenCode project candidates: `<dir>/opencode.json[c]`, then
        // `<dir>/.opencode/opencode.json[c]`.
        for name in OPENCODE_CONFIG_NAMES {
            set.insert(directory.join(name));
            set.insert(directory.join(".opencode").join(name));
        }
        // Claude project candidates: `<dir>/.claude/settings*.json`, plus
        // the workspace-chain `.mcp.json`.
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
    // Single `.env` at the git root, else the workspace (mirrors the
    // OpenCode adapter's project-dotenv root).
    set.insert(dotenv_root(workspace).join(".env"));
    set.into_iter().collect()
}

/// Workspace chain from the outermost ancestor down to the workspace:
/// ancestors up to and including the nearest `.git` holder (mirrors the
/// adapter project-candidate traversal), or just the workspace itself.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SENTINEL: &str = "PICO_SWEEP_SENTINEL_7f3a9c_VALUE";

    fn sig(secs: u64, len: u64) -> Option<(SystemTime, u64)> {
        Some((SystemTime::UNIX_EPOCH + Duration::from_secs(secs), len))
    }

    fn snap(entries: Vec<(PathBuf, Option<(SystemTime, u64)>)>) -> Snapshot {
        Snapshot {
            entries: entries.into_iter().collect(),
        }
    }

    #[test]
    fn snapshot_records_mtime_and_len_for_present_files_and_none_for_missing() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("opencode.json");
        std::fs::write(&present, r#"{"permission":{"bash":"allow"}}"#).unwrap();
        let missing = dir.path().join("opencode.jsonc");
        let snap = snapshot(&[present.clone(), missing.clone()]);
        let (mtime, len) = snap.entries[&present].expect("present file snapshotted");
        assert_eq!(len, std::fs::metadata(&present).unwrap().len());
        assert!(mtime <= SystemTime::now());
        assert_eq!(snap.entries[&missing], None);
    }

    #[test]
    fn detect_changes_covers_appeared_disappeared_mtime_only_and_len_only() {
        let appeared = PathBuf::from("/ws/opencode.json");
        let disappeared = PathBuf::from("/ws/opencode.jsonc");
        let mtime_only = PathBuf::from("/ws/.mcp.json");
        let len_only = PathBuf::from("/ws/.env");
        let steady = PathBuf::from("/ws/stable.json");
        let before = snap(vec![
            (appeared.clone(), None),
            (disappeared.clone(), sig(10, 100)),
            (mtime_only.clone(), sig(10, 100)),
            (len_only.clone(), sig(10, 100)),
            (steady.clone(), sig(10, 100)),
        ]);
        let after = snap(vec![
            (appeared.clone(), sig(20, 50)),
            (disappeared.clone(), None),
            (mtime_only.clone(), sig(30, 100)),
            (len_only.clone(), sig(10, 120)),
            (steady.clone(), sig(10, 100)),
        ]);
        assert_eq!(
            detect_changes(&before, &after),
            // Sorted PathBuf order ('.' sorts before alphanumerics).
            vec![len_only, mtime_only, appeared, disappeared]
        );
    }

    #[test]
    fn detect_changes_is_empty_for_identical_snapshots() {
        let path = PathBuf::from("/ws/opencode.json");
        let snapshot = snap(vec![(path, sig(10, 100))]);
        assert!(detect_changes(&snapshot, &snapshot.clone()).is_empty());
        assert!(detect_changes(&Snapshot::default(), &Snapshot::default()).is_empty());
    }

    #[test]
    fn relativize_prefers_workspace_then_home_then_filename() {
        let workspace = Path::new("/repo/proj");
        let home = Some(Path::new("/home/dev"));
        assert_eq!(
            relativize(Path::new("/repo/proj/opencode.json"), workspace, home),
            "opencode.json"
        );
        assert_eq!(
            relativize(
                Path::new("/repo/proj/.opencode/opencode.jsonc"),
                workspace,
                home
            ),
            ".opencode/opencode.jsonc"
        );
        assert_eq!(
            relativize(
                Path::new("/home/dev/.config/opencode/opencode.json"),
                workspace,
                home
            ),
            "~/.config/opencode/opencode.json"
        );
        // Workspace wins when nested under home.
        assert_eq!(
            relativize(
                Path::new("/home/dev/proj/.mcp.json"),
                Path::new("/home/dev/proj"),
                home
            ),
            ".mcp.json"
        );
        // Under home but outside the workspace: home-relative, never absolute.
        let nested_home = relativize(Path::new("/home/dev/other.json"), workspace, home);
        assert_eq!(nested_home, "~/other.json");
        assert!(!nested_home.starts_with('/'));
        // Outside both roots: bare filename fallback.
        assert_eq!(
            relativize(Path::new("/tmp/stray/other.json"), workspace, home),
            "other.json"
        );
        // No home seam: home files also fall back to filenames.
        assert_eq!(
            relativize(
                Path::new("/home/dev/.config/opencode/opencode.json"),
                workspace,
                None
            ),
            "opencode.json"
        );
    }

    #[test]
    fn resolve_watch_set_mirrors_adapter_candidate_rules() {
        let workspace = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        // A git root above the workspace pulls the chain outward.
        let git_root = workspace.path().join("outer");
        std::fs::create_dir_all(git_root.join(".git")).unwrap();
        let proj = git_root.join("proj");
        std::fs::create_dir_all(&proj).unwrap();

        let set = resolve_watch_set(&proj, Some(home.path()));
        let has = |suffix: &str| set.iter().any(|p| p.ends_with(suffix));
        // OpenCode project + user candidates.
        assert!(set.contains(&proj.join("opencode.json")));
        assert!(set.contains(&proj.join(".opencode").join("opencode.jsonc")));
        assert!(set.contains(&git_root.join("opencode.json")));
        assert!(set.contains(
            &home
                .path()
                .join(".config")
                .join("opencode")
                .join("opencode.json")
        ));
        // Claude project + user candidates.
        assert!(
            has(".claude/settings.json")
                || set.contains(&proj.join(".claude").join("settings.json"))
        );
        assert!(set.contains(&proj.join(".claude").join("settings.local.json")));
        assert!(set.contains(&home.path().join(".claude").join("settings.json")));
        assert!(set.contains(&proj.join(".mcp.json")));
        // Single .env at the git root, not the workspace.
        assert!(set.contains(&git_root.join(".env")));
        assert!(!set.contains(&proj.join(".env")));
        // Sorted and deduplicated.
        let mut sorted = set.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(set, sorted);
    }

    #[test]
    fn resolve_watch_set_without_home_skips_user_files() {
        let workspace = tempfile::tempdir().unwrap();
        let set = resolve_watch_set(workspace.path(), None);
        assert!(set.contains(&workspace.path().join("opencode.json")));
        assert!(set.contains(&workspace.path().join(".env")));
        assert!(
            !set.iter().any(|p| {
                p.to_string_lossy().contains(".config/opencode")
                    || p.to_string_lossy().contains(".claude/settings.json")
                        && !p.starts_with(workspace.path())
            }),
            "user files must be skipped without a home seam: {set:?}"
        );
    }

    #[test]
    fn watch_event_matches_frozen_shape_golden() {
        let event = WatchEvent::new(
            "2026-09-16T00:00:00Z".to_string(),
            vec!["opencode.json".to_string()],
            "scan_abc123".to_string(),
            ScanStatus::Complete,
            true,
            WatchFindingDelta {
                appeared: 0,
                disappeared: 0,
                weakened: 0,
                strengthened: 0,
                uncertain: 0,
            },
            (Notice::Quiet, vec!["no_significant_change".to_string()]),
        );
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"v":1,"ts":"2026-09-16T00:00:00Z","trigger":"FILESYSTEM_CHANGE","changed":["opencode.json"],"scan_id":"scan_abc123","scan_status":"COMPLETE","contracts_match":true,"findings":{"appeared":0,"disappeared":0,"weakened":0,"strengthened":0,"uncertain":0},"notice":"quiet","reasons":["no_significant_change"]}"#
        );
    }

    // SPRINT-038 Red: frozen §2.1 matrix + Notice round-trip + tolerance + wording.
    fn quiet_baseline() -> EventFacts {
        EventFacts {
            appeared: 0,
            disappeared: 0,
            weakened: 0,
            strengthened: 0,
            uncertain: 0,
            contracts_match: true,
            scan_partial: false,
            env_change_observed: false,
        }
    }

    #[test]
    fn notice_round_trips_lowercase() {
        use std::str::FromStr;
        for (notice, text) in [
            (Notice::Urgent, "urgent"),
            (Notice::Info, "info"),
            (Notice::Quiet, "quiet"),
        ] {
            assert_eq!(notice.as_str(), text);
            assert_eq!(Notice::from_str(text).unwrap(), notice);
        }
        assert!(Notice::from_str("URGENT").is_err());
        assert!(Notice::from_str("").is_err());
        assert!(Notice::from_str("nope").is_err());
    }

    #[test]
    fn classify_full_matrix() {
        let base = quiet_baseline();
        // URGENT
        assert_eq!(
            classify(&EventFacts {
                appeared: 1,
                ..base
            }),
            (Notice::Urgent, vec!["finding_appeared"])
        );
        assert_eq!(
            classify(&EventFacts {
                strengthened: 2,
                ..base
            }),
            (Notice::Urgent, vec!["finding_strengthened"])
        );
        // INFO: one reason each in isolation
        assert_eq!(
            classify(&EventFacts {
                weakened: 1,
                ..base
            }),
            (Notice::Info, vec!["finding_weakened"])
        );
        assert_eq!(
            classify(&EventFacts {
                uncertain: 1,
                ..base
            }),
            (Notice::Info, vec!["finding_uncertain"])
        );
        assert_eq!(
            classify(&EventFacts {
                disappeared: 1,
                ..base
            }),
            (Notice::Info, vec!["disappearance_unconfirmed"])
        );
        assert_eq!(
            classify(&EventFacts {
                scan_partial: true,
                ..base
            }),
            (Notice::Info, vec!["scan_partial"])
        );
        assert_eq!(
            classify(&EventFacts {
                contracts_match: false,
                ..base
            }),
            (Notice::Info, vec!["contracts_mismatch"])
        );
        assert_eq!(
            classify(&EventFacts {
                env_change_observed: true,
                ..base
            }),
            (Notice::Info, vec!["env_change_no_finding_delta"])
        );
        // QUIET otherwise
        assert_eq!(
            classify(&quiet_baseline()),
            (Notice::Quiet, vec!["no_significant_change"])
        );
        // Env change with non-zero deltas carries no env reason.
        assert_eq!(
            classify(&EventFacts {
                weakened: 1,
                env_change_observed: true,
                ..base
            }),
            (Notice::Info, vec!["finding_weakened"])
        );
        // PARTIAL scans also record the non-matching contracts.
        assert_eq!(
            classify(&EventFacts {
                contracts_match: false,
                scan_partial: true,
                ..base
            }),
            (Notice::Info, vec!["scan_partial", "contracts_mismatch"])
        );
    }

    #[test]
    fn classify_priority_overlap_keeps_both_reasons() {
        let base = quiet_baseline();
        assert_eq!(
            classify(&EventFacts {
                appeared: 1,
                weakened: 1,
                ..base
            }),
            (Notice::Urgent, vec!["finding_appeared", "finding_weakened"])
        );
        assert_eq!(
            classify(&EventFacts {
                strengthened: 1,
                contracts_match: false,
                scan_partial: true,
                ..base
            }),
            (
                Notice::Urgent,
                vec!["finding_strengthened", "scan_partial", "contracts_mismatch"]
            )
        );
    }

    #[test]
    fn watch_jsonl_reader_tolerates_unknown_fields() {
        let line = r#"{"v":1,"ts":"2026-09-16T00:00:00Z","trigger":"FILESYSTEM_CHANGE","changed":["opencode.json"],"scan_id":"scan_abc123","scan_status":"COMPLETE","contracts_match":true,"findings":{"appeared":0,"disappeared":0,"weakened":0,"strengthened":0,"uncertain":0},"notice":"quiet","reasons":["no_significant_change"],"future_field":"tolerate-me"}"#;
        let event: WatchEvent = serde_json::from_str(line).unwrap();
        assert_eq!(event.v, 1);
        assert_eq!(event.notice, Notice::Quiet);
        assert_eq!(event.reasons, vec!["no_significant_change".to_string()]);
    }

    #[test]
    fn notice_line_wording_family() {
        let base = quiet_baseline();
        let urgent_facts = EventFacts {
            appeared: 1,
            env_change_observed: true,
            ..base
        };
        let (notice, reasons) = classify(&urgent_facts);
        let line = notice_line(&urgent_facts, notice, &reasons);
        assert!(line.contains("[URGENT]"), "got: {line}");
        assert!(line.contains("pico findings"), "got: {line}");
        assert!(line.contains("finding_appeared"), "got: {line}");

        let quiet_facts = quiet_baseline();
        let (notice, reasons) = classify(&quiet_facts);
        let line = notice_line(&quiet_facts, notice, &reasons);
        assert!(line.contains("[QUIET]"), "got: {line}");
        assert!(line.contains("not an all-clear"), "got: {line}");

        let info_facts = EventFacts {
            weakened: 1,
            ..base
        };
        let (notice, reasons) = classify(&info_facts);
        let line = notice_line(&info_facts, notice, &reasons);
        assert!(line.contains("[INFO]"), "got: {line}");
        assert!(line.contains("finding_weakened"), "got: {line}");
    }

    #[test]
    fn zero_interval_is_rejected_before_any_work() {
        let workspace = tempfile::tempdir().unwrap();
        let cfg = WatchConfig {
            interval_secs: 0,
            max_events: Some(0),
        };
        let error = run(workspace.path(), None, &cfg).unwrap_err();
        assert!(
            error.to_string().contains("--interval-secs >= 1"),
            "actionable usage error, got: {error}"
        );
        assert!(
            !workspace.path().join(".pico").exists(),
            "rejection must have no side effects"
        );
    }

    #[test]
    fn missing_state_is_actionable_with_no_init_side_effects() {
        let workspace = tempfile::tempdir().unwrap();
        let cfg = WatchConfig {
            interval_secs: 5,
            max_events: Some(0),
        };
        let error = run(workspace.path(), None, &cfg).unwrap_err();
        assert!(
            error.to_string().contains("pico init"),
            "must name the remedy, got: {error}"
        );
        assert!(
            !workspace.path().join(".pico").exists(),
            "watch must never init state itself"
        );
    }

    #[test]
    fn zero_event_budget_runs_zero_scans_and_writes_nothing() {
        use crate::persistence::{Database, ScanRepo};

        let workspace = tempfile::tempdir().unwrap();
        crate::application::InitService::run(workspace.path()).unwrap();
        // A pending change must not matter: the budget is exhausted already.
        std::fs::write(
            workspace.path().join("opencode.json"),
            r#"{"permission":{"bash":"allow"}}"#,
        )
        .unwrap();
        let db_path = workspace.path().join(".pico").join("pico.db");
        let count_before = {
            let db = Database::open_read_only(&db_path).unwrap();
            ScanRepo::new(db.connection()).count().unwrap()
        };
        let cfg = WatchConfig {
            interval_secs: 5,
            max_events: Some(0),
        };
        let report = run(workspace.path(), None, &cfg).unwrap();
        assert!(report.events.is_empty());
        let db = Database::open_read_only(&db_path).unwrap();
        assert_eq!(
            ScanRepo::new(db.connection()).count().unwrap(),
            count_before
        );
        assert!(
            !workspace.path().join(".pico").join("watch.jsonl").exists(),
            "zero budget must append no events"
        );
        assert!(
            !workspace
                .path()
                .join(".pico")
                .join("watch.state.json")
                .exists(),
            "zero budget must not write a continuity record"
        );
    }

    #[test]
    fn sentinel_config_values_never_reach_watch_artifacts() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(
            workspace.path().join("opencode.json"),
            format!(r#"{{"permission":{{"bash":"allow"}},"token":"{SENTINEL}"}}"#),
        )
        .unwrap();

        let set = resolve_watch_set(workspace.path(), None);
        for path in &set {
            assert!(
                !path.to_string_lossy().contains(SENTINEL),
                "watch paths carry locations, never values"
            );
        }
        let snap = snapshot(&set);
        assert!(
            !format!("{snap:?}").contains(SENTINEL),
            "snapshots carry mtime+len only"
        );
        let rel: Vec<String> = set
            .iter()
            .map(|path| relativize(path, workspace.path(), None))
            .collect();
        assert!(!rel.join("\n").contains(SENTINEL));
        let event = WatchEvent::new(
            "2026-09-16T00:00:00Z".to_string(),
            rel,
            "scan_sweep".to_string(),
            ScanStatus::Complete,
            true,
            WatchFindingDelta::default(),
            (Notice::Quiet, vec!["no_significant_change".to_string()]),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains(SENTINEL), "events carry paths and IDs only");
    }

    // SPRINT-044 §2.1: continuity-record shape, atomic write, heartbeat gate.
    #[test]
    fn watch_state_json_shape_is_frozen_without_process_fields() {
        let state = WatchState::new(2, "2026-09-16T00:00:00Z".to_string(), 3);
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(
            json,
            r#"{"v":1,"interval_secs":2,"last_check_at":"2026-09-16T00:00:00Z","events_total":3}"#
        );
        // Exactly the four frozen fields: no pid, no process detection.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["v", "interval_secs", "last_check_at", "events_total"],
            "the record is evidence of observation, not process introspection"
        );
    }

    #[test]
    fn write_state_is_atomic_valid_json_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let pico = dir.path().join(".pico");
        std::fs::create_dir_all(&pico).unwrap();
        let path = pico.join("watch.state.json");
        let temp = pico.join("watch.state.json.tmp");

        write_state(dir.path(), &WatchState::new(2, "t0".to_string(), 1)).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["v"], 1);
        assert!(!temp.exists(), "temp file must be renamed away");

        // Atomic replace is idempotent and never leaves the temp behind.
        write_state(dir.path(), &WatchState::new(5, "t1".to_string(), 9)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(r#""interval_secs":5"#));
        assert!(text.contains(r#""events_total":9"#));
        assert!(!temp.exists());
    }

    #[test]
    fn heartbeat_gate_fires_at_most_once_per_heartbeat_secs() {
        let now = Utc::now();
        assert!(heartbeat_due(None, now), "first idle check writes");
        assert!(!heartbeat_due(
            Some(now - chrono::Duration::seconds(14)),
            now
        ));
        assert!(heartbeat_due(
            Some(now - chrono::Duration::seconds(15)),
            now
        ));
        assert!(heartbeat_due(
            Some(now - chrono::Duration::seconds(31)),
            now
        ));
    }

    // SPRINT-044 §2.2: the observer itself keeps its log bounded, so a long run
    // cannot grow `.pico/watch.jsonl` without bound between prunes.
    #[test]
    fn watch_trims_its_own_log_once_the_cap_is_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let pico = dir.path().join(".pico");
        std::fs::create_dir_all(&pico).unwrap();
        let log = pico.join("watch.jsonl");
        let line = |n: usize| format!("{{\"v\":1,\"n\":{n}}}\n");

        // Under the cap: untouched.
        let under = watch_log::WATCH_LOG_MAX_EVENTS;
        std::fs::write(&log, (0..under).map(line).collect::<String>()).unwrap();
        trim_log_if_needed(dir.path()).unwrap();
        assert_eq!(
            watch_log::len(&log).unwrap(),
            under,
            "under cap: no rewrite"
        );

        // Over the cap: trimmed to the watermark, newest lines kept in order.
        let over = watch_log::WATCH_LOG_MAX_EVENTS + 1;
        std::fs::write(&log, (0..over).map(line).collect::<String>()).unwrap();
        trim_log_if_needed(dir.path()).unwrap();
        let kept = watch_log::len(&log).unwrap();
        assert_eq!(
            kept,
            watch_log::WATCH_LOG_TRIM_TARGET,
            "the cap is enforced by the observer itself"
        );
        let text = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.last().copied(),
            Some(line(over - 1).trim_end()),
            "the newest event always survives its own trim"
        );

        // A long synthetic series never exceeds the cap after each trim.
        for n in 0..(watch_log::WATCH_LOG_TRIM_TARGET * 3) {
            let mut existing = std::fs::read_to_string(&log).unwrap();
            existing.push_str(&line(over + n));
            std::fs::write(&log, existing).unwrap();
            trim_log_if_needed(dir.path()).unwrap();
            assert!(
                watch_log::len(&log).unwrap() <= watch_log::WATCH_LOG_MAX_EVENTS,
                "the log must never grow past the cap"
            );
        }

        // Absent log: no file is created by the bound check.
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir2.path().join(".pico")).unwrap();
        let absent = dir2.path().join(".pico").join("watch.jsonl");
        trim_log_if_needed(dir2.path()).unwrap();
        assert!(!absent.exists(), "an absent log is never created");
        assert_eq!(watch_log::len(&absent).unwrap(), 0);
    }
}
