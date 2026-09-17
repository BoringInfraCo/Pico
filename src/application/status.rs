//! `pico status` application service (SPRINT-038).
//!
//! Answers "what needs my attention right now?" from local state alone:
//! the newest COMPLETE scan (freshness heuristic: STALE when older than
//! 24h) plus the retained `.pico/watch.jsonl` tail (last 200 lines).
//!
//! Read-only: the state database is opened read-only and the watch log is
//! only read, never created or appended. A missing or empty log and the
//! absence of COMPLETE scans are honest report states, never errors and
//! never blank reassurance.
//!
//! Notice levels are parsed as case-exact STRINGS (`"urgent"` / `"info"` /
//! `"quiet"`) so this reader stays decoupled from the `watch.rs` half owned
//! by the parallel core agent (which emits `notice` + `reasons` per
//! SPRINT-038 §2.2). Forward compatibility rules:
//!
//! - Readers MUST tolerate unknown JSON fields (serde `Value`, named fields
//!   only).
//! - A line that is not a JSON object is skipped, never fatal.
//! - An entry whose `notice` is missing or not exactly one of the three
//!   levels still counts toward the retained `total` (it IS a retained
//!   event, e.g. a pre-notice S037-era record) but toward neither the
//!   URGENT nor the INFO bucket, and never toward Last URGENT.
//! - `total` therefore counts parseable event objects, not notice levels.
//!
//! Every URGENT event in the retained tail is treated as unreviewed: Pico
//! tracks no review state in this slice.

use std::path::Path;

use chrono::{DateTime, Utc};

use crate::application::watch::WatchState;
use crate::persistence::{require_schema_version, Database, ScanRepo};
use crate::shared::PicoError;

/// Retained watch-log lines considered by [`status`]. Bounds idle memory on
/// long-running watch histories; the render labels counts as the retained
/// tail so the cap is never mistaken for the full history.
const WATCH_TAIL_LINES: usize = 200;

/// Freshness heuristic (SPRINT-038 §2.3): a last COMPLETE scan older than
/// this is STALE. A heuristic about observation recency, never a safety
/// claim.
const STALE_AFTER: chrono::Duration = chrono::Duration::hours(24);

/// Frozen next-step sentences (SPRINT-038 §2.3).
pub const NEXT_STEP_FINDINGS: &str = "run `pico findings`";
pub const NEXT_STEP_SCAN: &str = "run `pico scan`";
pub const NEXT_STEP_NOTHING_FLAGGED: &str = "nothing flagged";

/// Observation-continuity verdict (SPRINT-044 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationState {
    /// A parseable continuity record whose last check is within the fresh
    /// window.
    Watching,
    /// A parseable continuity record whose last check is older than the
    /// fresh window.
    NotObserving,
    /// No record, or an unparseable/malformed record, or missing/invalid
    /// fields. An unreadable or malformed record is never "watching".
    NoRecord,
}

/// Observation-continuity report fact: the verdict plus the coarse human age
/// of the last check (`None` only for [`ObservationState::NoRecord`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub state: ObservationState,
    pub age: Option<String>,
}

impl Observation {
    fn no_record() -> Self {
        Observation {
            state: ObservationState::NoRecord,
            age: None,
        }
    }
}

/// Freshness + last notices + next step for `pico status`. All display facts
/// are Strings/ints; the CLI renders them without further queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    /// Newest COMPLETE scan id, if any scan ever completed.
    pub last_complete_scan_id: Option<String>,
    /// Human age of the newest COMPLETE scan (`"3h ago"`, `"just now"`);
    /// `"unknown"` when no COMPLETE scan exists or its timestamp is absent.
    pub last_complete_age: String,
    /// True when no COMPLETE scan exists or the newest is older than 24h.
    pub stale: bool,
    /// False when `.pico/watch.jsonl` does not exist at all.
    pub watch_log_present: bool,
    /// Parseable event objects in the retained tail (cap 200 lines).
    pub watch_total: u64,
    /// Tail events with case-exact `notice == "urgent"`.
    pub watch_urgent: u64,
    /// Tail events with case-exact `notice == "info"`.
    pub watch_info: u64,
    /// Timestamp of the last URGENT event in tail order, if any.
    pub last_urgent_ts: Option<String>,
    /// Reason codes of that last URGENT event, in log order.
    pub last_urgent_reasons: Vec<String>,
    /// One of the frozen `NEXT_STEP_*` sentences.
    pub next_step: String,
    /// Observation-continuity verdict from `.pico/watch.state.json`
    /// (SPRINT-044 §2.1). Additive: never affects the lines above.
    pub observation: Observation,
}

/// Read-only status query over the workspace state directory.
pub fn status(workspace: &Path) -> Result<StatusReport, PicoError> {
    // Same read-only open convention as `HistoryService::list`: a missing
    // store names `pico init`, an unsupported schema names its remedy, and
    // nothing is created or migrated here.
    let db_path = workspace.join(".pico").join("pico.db");
    let db = Database::open_read_only(&db_path)?;
    require_schema_version(db.connection())?;
    let newest = ScanRepo::new(db.connection()).newest_complete()?;
    drop(db);

    let now = Utc::now();
    let observation = observation_for(read_watch_state(workspace)?.as_ref(), now);
    let (last_complete_scan_id, last_complete_age, stale) = match &newest {
        Some(scan) => {
            let id = Some(scan.id.clone());
            match scan.completed_at {
                Some(completed_at) => {
                    let age = completed_at;
                    (id, format_age(age, now), is_stale(age, now))
                }
                // A COMPLETE scan without a completion timestamp cannot
                // prove freshness; say unknown and recommend a scan rather
                // than claim either state.
                None => (id, "unknown".to_string(), true),
            }
        }
        None => (None, "unknown".to_string(), true),
    };

    let watch = read_watch_tail(workspace)?;

    let next_step = if watch.urgent > 0 {
        NEXT_STEP_FINDINGS
    } else if stale {
        NEXT_STEP_SCAN
    } else {
        NEXT_STEP_NOTHING_FLAGGED
    }
    .to_string();

    Ok(StatusReport {
        last_complete_scan_id,
        last_complete_age,
        stale,
        watch_log_present: watch.present,
        watch_total: watch.total,
        watch_urgent: watch.urgent,
        watch_info: watch.info,
        last_urgent_ts: watch.last_urgent_ts,
        last_urgent_reasons: watch.last_urgent_reasons,
        next_step,
        observation,
    })
}

/// STALE iff `completed_at` is more than 24h before `now`. Exactly 24h is
/// fresh (`older than 24h`, SPRINT-038 §2.3); future timestamps (clock skew)
/// are fresh.
fn is_stale(completed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(completed_at) > STALE_AFTER
}

/// Compact human age at query time. Coarse units only; exact instants stay
/// in scan/history views.
fn format_age(completed_at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    if completed_at > now {
        return "just now".to_string();
    }
    let secs = now.signed_duration_since(completed_at).num_seconds();
    if secs < 60 {
        return format!("{secs}s ago");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m ago");
    }
    let hours = mins / 60;
    if hours < 48 {
        return format!("{hours}h ago");
    }
    format!("{}d ago", hours / 24)
}

/// Freshness window for the continuity record (SPRINT-044 §2.1, frozen):
/// `max(3 × interval_secs, 60s)`, capped at one day.
///
/// A record is Pico-authored, but `interval_secs` is read back from disk and
/// must be treated as hostile input: it is saturated before conversion and the
/// result is clamped to a sane horizon, so a corrupt or adversarial value can
/// never overflow or panic `chrono::Duration`.
fn fresh_window(interval_secs: u64) -> chrono::Duration {
    const MAX_WINDOW_SECS: u64 = 86_400;
    let secs = interval_secs.saturating_mul(3).clamp(60, MAX_WINDOW_SECS);
    chrono::Duration::seconds(i64::try_from(secs).unwrap_or(MAX_WINDOW_SECS as i64))
}

/// Pure observation verdict (SPRINT-044 §2.1): fresh when
/// `now - last_check_at <= max(3 × interval_secs, 60s)`, else NOT OBSERVING.
/// `None` (absent or malformed) is always `NoRecord` — never watching. The
/// injected `now` keeps tests sleep-free.
fn observation_for(record: Option<&WatchState>, now: DateTime<Utc>) -> Observation {
    let Some(record) = record else {
        return Observation::no_record();
    };
    // Defensive re-check: a record can only reach here through the strict
    // parser, but an unparseable timestamp must still never read as watching.
    let Ok(last) = DateTime::parse_from_rfc3339(&record.last_check_at) else {
        return Observation::no_record();
    };
    let last = last.with_timezone(&Utc);
    let fresh = now.signed_duration_since(last) <= fresh_window(record.interval_secs);
    Observation {
        state: if fresh {
            ObservationState::Watching
        } else {
            ObservationState::NotObserving
        },
        age: Some(format_age(last, now)),
    }
}

/// Read `.pico/watch.state.json`. A missing file is an honest `None`; any
/// other read failure is an actionable, path-only (secret-free) IO error.
fn read_watch_state(workspace: &Path) -> Result<Option<WatchState>, PicoError> {
    let path = workspace.join(".pico").join("watch.state.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PicoError::io(format!(
                "cannot read {}: {error}",
                path.display()
            )));
        }
    };
    Ok(parse_watch_state(&text))
}

/// Strictly parse the continuity record. Absent, unparseable, wrong `v`, or
/// missing/invalid fields all yield `None` (SPRINT-044 §2.1): a malformed
/// record must never be reported as watching. Unknown extra fields are
/// tolerated (forward compatibility). `interval_secs = 0` is accepted and
/// falls back to the 60s floor of the frozen verdict rule; an implausibly large
/// interval is rejected rather than trusted, so a corrupt record cannot widen
/// the freshness window into a false "watching".
fn parse_watch_state(text: &str) -> Option<WatchState> {
    /// Longest interval Pico will believe: an hour. Beyond this the record is
    /// treated as corrupt (no record) instead of widening liveness.
    const MAX_PLAUSIBLE_INTERVAL_SECS: u64 = 3_600;

    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    if object.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return None;
    }
    let interval_secs = object
        .get("interval_secs")
        .and_then(serde_json::Value::as_u64)?;
    if interval_secs > MAX_PLAUSIBLE_INTERVAL_SECS {
        return None;
    }
    let events_total = object
        .get("events_total")
        .and_then(serde_json::Value::as_u64)?;
    let last_check_at = object
        .get("last_check_at")
        .and_then(serde_json::Value::as_str)?
        .to_string();
    // The timestamp shape is part of the contract: a record whose time cannot
    // be established is no record at all.
    DateTime::parse_from_rfc3339(&last_check_at).ok()?;
    Some(WatchState {
        v: 1,
        interval_secs,
        last_check_at,
        events_total,
    })
}

/// Tally of the retained watch-log tail.
#[derive(Debug, Default, PartialEq, Eq)]
struct WatchTally {
    present: bool,
    total: u64,
    urgent: u64,
    info: u64,
    last_urgent_ts: Option<String>,
    last_urgent_reasons: Vec<String>,
}

/// Read at most the last 200 lines of `.pico/watch.jsonl`. A missing log is
/// an honest state (`present: false`), never an error; any other read
/// failure is an actionable, path-only (secret-free) IO error. Unparseable
/// lines are skipped, never fatal.
fn read_watch_tail(workspace: &Path) -> Result<WatchTally, PicoError> {
    let path = workspace.join(".pico").join("watch.jsonl");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WatchTally::default());
        }
        Err(error) => {
            return Err(PicoError::io(format!(
                "cannot read {}: {error}",
                path.display()
            )));
        }
    };
    let mut tally = WatchTally {
        present: true,
        ..WatchTally::default()
    };
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let start = lines.len().saturating_sub(WATCH_TAIL_LINES);
    for line in &lines[start..] {
        tally_event(&mut tally, line);
    }
    Ok(tally)
}

/// Fold one JSONL line into the tally. Case-exact notice strings only:
/// `"URGENT"` / `"Urgent"` / numbers / null / missing notice count toward
/// the retained total but toward neither bucket.
fn tally_event(tally: &mut WatchTally, line: &str) {
    let value: serde_json::Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => return,
    };
    let event = match value.as_object() {
        Some(event) => event,
        None => return,
    };
    tally.total += 1;
    let notice = event.get("notice").and_then(serde_json::Value::as_str);
    match notice {
        Some("urgent") => {
            tally.urgent += 1;
            tally.last_urgent_ts = event
                .get("ts")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            tally.last_urgent_reasons = event
                .get("reasons")
                .and_then(serde_json::Value::as_array)
                .map(|reasons| {
                    reasons
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
        }
        Some("info") => tally.info += 1,
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(hours_ago: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0).unwrap() + chrono::Duration::hours(hours_ago)
    }

    #[test]
    fn stale_boundary_is_older_than_24h() {
        let now = utc(0);
        assert!(!is_stale(utc(-1), now));
        assert!(!is_stale(utc(-24), now), "exactly 24h is fresh");
        assert!(is_stale(utc(-25), now));
        assert!(!is_stale(utc(1), now), "future timestamps are fresh");
    }

    #[test]
    fn format_age_uses_coarse_units() {
        let now = utc(0);
        assert_eq!(format_age(utc(0), now), "0s ago");
        assert_eq!(
            format_age(now - chrono::Duration::seconds(90), now),
            "1m ago"
        );
        assert_eq!(format_age(now - chrono::Duration::hours(3), now), "3h ago");
        assert_eq!(format_age(now - chrono::Duration::hours(72), now), "3d ago");
        assert_eq!(
            format_age(now + chrono::Duration::hours(1), now),
            "just now"
        );
    }

    #[test]
    fn tally_matrix_covers_notice_levels_case_exactness_and_tolerance() {
        let mut tally = WatchTally::default();
        // URGENT with reasons + an unknown extra field (tolerated).
        tally_event(
            &mut tally,
            r#"{"v":1,"ts":"2026-09-16T00:00:00Z","trigger":"FILESYSTEM_CHANGE","notice":"urgent","reasons":["finding_appeared"],"future_field":{"nested":true}}"#,
        );
        // INFO.
        tally_event(
            &mut tally,
            r#"{"v":1,"ts":"2026-09-16T00:01:00Z","notice":"info","reasons":["scan_partial"]}"#,
        );
        // QUIET.
        tally_event(
            &mut tally,
            r#"{"v":1,"ts":"2026-09-16T00:02:00Z","notice":"quiet","reasons":["no_significant_change"]}"#,
        );
        // Pre-notice S037-era event: retained in total, in neither bucket.
        tally_event(
            &mut tally,
            r#"{"v":1,"ts":"2026-09-16T00:03:00Z","trigger":"FILESYSTEM_CHANGE","scan_id":"scan_abc"}"#,
        );
        // Wrong-case notice: same treatment, never fatal.
        tally_event(&mut tally, r#"{"v":1,"ts":"t","notice":"URGENT"}"#);
        // Non-string notice + non-string reasons items: tolerated.
        tally_event(
            &mut tally,
            r#"{"v":1,"ts":"t","notice":7,"reasons":["finding_appeared",9,null]}"#,
        );
        // Garbage and non-object lines: skipped entirely.
        tally_event(&mut tally, "not json at all");
        tally_event(&mut tally, "");
        tally_event(&mut tally, "[1,2,3]");
        assert_eq!(tally.total, 6);
        assert_eq!(tally.urgent, 1);
        assert_eq!(tally.info, 1);
        assert_eq!(
            tally.last_urgent_ts.as_deref(),
            Some("2026-09-16T00:00:00Z")
        );
        assert_eq!(tally.last_urgent_reasons, vec!["finding_appeared"]);
    }

    #[test]
    fn last_urgent_tracks_tail_order() {
        let mut tally = WatchTally::default();
        tally_event(
            &mut tally,
            r#"{"v":1,"ts":"first","notice":"urgent","reasons":["finding_appeared"]}"#,
        );
        tally_event(
            &mut tally,
            r#"{"v":1,"ts":"second","notice":"urgent","reasons":["finding_strengthened"]}"#,
        );
        assert_eq!(tally.last_urgent_ts.as_deref(), Some("second"));
        assert_eq!(tally.last_urgent_reasons, vec!["finding_strengthened"]);
    }

    #[test]
    fn status_on_init_only_state_is_honest_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        crate::application::InitService::run(dir.path()).unwrap();
        let db_path = dir.path().join(".pico").join("pico.db");
        let before = std::fs::read(&db_path).unwrap();

        let report = status(dir.path()).unwrap();
        assert_eq!(report.last_complete_scan_id, None);
        assert_eq!(report.last_complete_age, "unknown");
        assert!(report.stale);
        assert!(!report.watch_log_present);
        assert_eq!(report.watch_total, 0);
        assert_eq!(report.watch_urgent, 0);
        assert_eq!(report.watch_info, 0);
        assert_eq!(report.last_urgent_ts, None);
        assert!(report.last_urgent_reasons.is_empty());
        assert_eq!(report.next_step, NEXT_STEP_SCAN);

        assert_eq!(std::fs::read(&db_path).unwrap(), before);
        assert!(
            !dir.path().join(".pico").join("watch.jsonl").exists(),
            "status must never create the watch log"
        );
    }

    #[test]
    fn status_after_real_scan_is_fresh_with_unreviewed_urgent_next_step() {
        let dir = tempfile::tempdir().unwrap();
        crate::application::InitService::run(dir.path()).unwrap();
        let scan = crate::application::ScanService::run_with_home(dir.path(), None).unwrap();
        std::fs::write(
            dir.path().join(".pico").join("watch.jsonl"),
            "{\"v\":1,\"ts\":\"2026-09-16T00:00:00Z\",\"notice\":\"urgent\",\"reasons\":[\"finding_appeared\"]}\n{\"v\":1,\"ts\":\"2026-09-16T00:01:00Z\",\"notice\":\"quiet\",\"reasons\":[\"no_significant_change\"]}\n",
        )
        .unwrap();

        let report = status(dir.path()).unwrap();
        assert_eq!(
            report.last_complete_scan_id.as_deref(),
            Some(scan.scan_id.as_str())
        );
        assert!(!report.stale, "a just-completed scan is fresh");
        assert!(report.watch_log_present);
        assert_eq!(
            (report.watch_total, report.watch_urgent, report.watch_info),
            (2, 1, 0)
        );
        assert_eq!(
            report.last_urgent_ts.as_deref(),
            Some("2026-09-16T00:00:00Z")
        );
        assert_eq!(report.last_urgent_reasons, vec!["finding_appeared"]);
        assert_eq!(report.next_step, NEXT_STEP_FINDINGS);
    }

    #[test]
    fn status_after_real_scan_without_notices_flags_nothing() {
        let dir = tempfile::tempdir().unwrap();
        crate::application::InitService::run(dir.path()).unwrap();
        let scan = crate::application::ScanService::run_with_home(dir.path(), None).unwrap();

        let report = status(dir.path()).unwrap();
        assert_eq!(
            report.last_complete_scan_id.as_deref(),
            Some(scan.scan_id.as_str())
        );
        assert!(!report.stale);
        assert_eq!(report.next_step, NEXT_STEP_NOTHING_FLAGGED);
    }

    #[test]
    fn status_without_state_names_init() {
        let dir = tempfile::tempdir().unwrap();
        let error = status(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("pico init"),
            "missing state must name the remedy, got: {error}"
        );
        assert!(
            !dir.path().join(".pico").exists(),
            "status must never init state itself"
        );
    }

    // SPRINT-044 §2.1: strict record parsing + pure verdict matrix.

    fn state(interval_secs: u64, last: DateTime<Utc>, events_total: u64) -> WatchState {
        WatchState::new(
            interval_secs,
            last.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            events_total,
        )
    }

    #[test]
    fn parse_watch_state_accepts_valid_and_tolerates_unknown_fields() {
        let parsed = parse_watch_state(
            r#"{"v":1,"interval_secs":2,"last_check_at":"2026-09-01T12:00:00Z","events_total":3,"future":"ok"}"#,
        )
        .expect("valid record parses");
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.interval_secs, 2);
        assert_eq!(parsed.last_check_at, "2026-09-01T12:00:00Z");
        assert_eq!(parsed.events_total, 3);
    }

    #[test]
    fn parse_watch_state_rejects_malformed_missing_and_invalid_fields() {
        for bad in [
            "",
            "{",
            "[]",
            "null",
            "42",
            r#"{"v":1,"interval_secs":2,"last_check_at":"2026-09-01T12:00:00Z"}"#,
            r#"{"v":1,"interval_secs":2,"events_total":3}"#,
            r#"{"v":1,"last_check_at":"2026-09-01T12:00:00Z","events_total":3}"#,
            r#"{"v":2,"interval_secs":2,"last_check_at":"2026-09-01T12:00:00Z","events_total":3}"#,
            r#"{"v":"1","interval_secs":2,"last_check_at":"2026-09-01T12:00:00Z","events_total":3}"#,
            r#"{"v":1,"interval_secs":-1,"last_check_at":"2026-09-01T12:00:00Z","events_total":3}"#,
            r#"{"v":1,"interval_secs":2.5,"last_check_at":"2026-09-01T12:00:00Z","events_total":3}"#,
            r#"{"v":1,"interval_secs":2,"last_check_at":"not-a-time","events_total":3}"#,
            r#"{"v":1,"interval_secs":2,"last_check_at":7,"events_total":3}"#,
            r#"{"v":1,"interval_secs":2,"last_check_at":"2026-09-01T12:00:00Z","events_total":"3"}"#,
        ] {
            assert!(parse_watch_state(bad).is_none(), "must reject: {bad}");
        }
    }

    /// A hostile or corrupt `interval_secs` must never panic (chrono's
    /// `Duration::seconds` panics above `i64::MAX/1000`) and must never widen
    /// the freshness window into a false "watching": it is rejected outright.
    #[test]
    fn hostile_interval_secs_is_rejected_and_never_panics() {
        for hostile in [
            u64::MAX,
            4_000_000_000_000_000,
            3_601, // just past the believable horizon
        ] {
            let record = format!(
                r#"{{"v":1,"interval_secs":{hostile},"last_check_at":"2026-09-01T12:00:00Z","events_total":3}}"#
            );
            assert!(
                parse_watch_state(&record).is_none(),
                "an implausible interval must not be trusted: {hostile}"
            );
        }
        // The believable horizon still parses and confines the window to a day.
        let ok = parse_watch_state(
            r#"{"v":1,"interval_secs":3600,"last_check_at":"2026-09-01T12:00:00Z","events_total":3}"#,
        )
        .expect("the horizon itself is believable");
        assert_eq!(fresh_window(ok.interval_secs), chrono::Duration::hours(3));
        assert_eq!(fresh_window(u64::MAX), chrono::Duration::hours(24));
    }

    #[test]
    fn observation_verdict_boundary_is_exactly_the_fresh_window() {
        let now = utc(0);
        let at = |interval: u64, secs: i64| {
            observation_for(
                Some(&state(interval, now - chrono::Duration::seconds(secs), 0)),
                now,
            )
            .state
        };
        // interval 2 → max(6, 60) = 60s; the boundary is inclusive.
        assert_eq!(at(2, 0), ObservationState::Watching);
        assert_eq!(at(2, 60), ObservationState::Watching, "exactly fresh");
        assert_eq!(at(2, 61), ObservationState::NotObserving);
        // interval 30 → max(90, 60) = 90s.
        assert_eq!(at(30, 90), ObservationState::Watching);
        assert_eq!(at(30, 91), ObservationState::NotObserving);
        // interval 0 is handled sanely: the 60s floor applies, no panic.
        assert_eq!(at(0, 60), ObservationState::Watching);
        assert_eq!(at(0, 61), ObservationState::NotObserving);
        // Future timestamps (clock skew) are fresh.
        let future = state(2, now + chrono::Duration::seconds(5), 0);
        assert_eq!(
            observation_for(Some(&future), now).state,
            ObservationState::Watching
        );
    }

    #[test]
    fn observation_verdict_is_no_record_for_absent_and_malformed() {
        let now = utc(0);
        assert_eq!(observation_for(None, now), Observation::no_record());
        let malformed = parse_watch_state("{ not json");
        assert_eq!(
            observation_for(malformed.as_ref(), now),
            Observation::no_record(),
            "a malformed record must never be watching"
        );
        assert_eq!(observation_for(None, now).age, None);
    }

    #[test]
    fn observation_age_uses_coarse_units() {
        let now = utc(0);
        let fresh = state(2, now - chrono::Duration::seconds(4), 1);
        assert_eq!(
            observation_for(Some(&fresh), now).age.as_deref(),
            Some("4s ago")
        );
        let stale = state(2, now - chrono::Duration::minutes(12), 1);
        assert_eq!(
            observation_for(Some(&stale), now).age.as_deref(),
            Some("12m ago")
        );
    }

    #[test]
    fn status_reports_observation_continuity_states_read_only() {
        let dir = tempfile::tempdir().unwrap();
        crate::application::InitService::run(dir.path()).unwrap();
        let state_path = dir.path().join(".pico").join("watch.state.json");

        // Absent: honest no-record, file never created.
        let report = status(dir.path()).unwrap();
        assert_eq!(report.observation.state, ObservationState::NoRecord);
        assert!(!state_path.exists(), "status must never create the record");

        // Fresh: watching, and status leaves the bytes untouched.
        let fresh = state(2, Utc::now() - chrono::Duration::seconds(3), 7);
        std::fs::write(&state_path, serde_json::to_string(&fresh).unwrap()).unwrap();
        let before = std::fs::read(&state_path).unwrap();
        let report = status(dir.path()).unwrap();
        assert_eq!(report.observation.state, ObservationState::Watching);
        assert_eq!(std::fs::read(&state_path).unwrap(), before);

        // Stale: NOT OBSERVING.
        let stale = state(2, Utc::now() - chrono::Duration::hours(1), 7);
        std::fs::write(&state_path, serde_json::to_string(&stale).unwrap()).unwrap();
        let report = status(dir.path()).unwrap();
        assert_eq!(report.observation.state, ObservationState::NotObserving);

        // Malformed (wrong version): no record, never watching.
        std::fs::write(
            &state_path,
            r#"{"v":2,"interval_secs":2,"last_check_at":"2026-09-01T12:00:00Z","events_total":1}"#,
        )
        .unwrap();
        let report = status(dir.path()).unwrap();
        assert_eq!(report.observation.state, ObservationState::NoRecord);
    }
}
