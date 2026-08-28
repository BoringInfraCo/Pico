//! `pico diff` application service (SPRINT-024.md).
//!
//! Compares Findings from the last two COMPLETE scans by fingerprint.
//! Incomplete attempts never participate as a comparison side.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use crate::application::{Freshness, ScanBrief};
use crate::domain::Scan;
use crate::persistence::{
    codec, require_schema_version, Database, FindingRecord, FindingRepo, ScanRepo,
};
use crate::shared::PicoError;

/// One Finding identity in a diff side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffFinding {
    pub id: String,
    pub fingerprint: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
}

/// Fingerprint-set comparison of two COMPLETE scans.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingDiff {
    pub from: ScanBrief,
    pub to: ScanBrief,
    pub newest_attempt: Option<ScanBrief>,
    pub freshness: Freshness,
    pub freshness_warning: Option<String>,
    pub unchanged: Vec<DiffFinding>,
    pub appeared: Vec<DiffFinding>,
    pub disappeared: Vec<DiffFinding>,
}

/// Outcome of `pico diff` when two COMPLETE scans may not exist yet.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum FindingDiffResult {
    NoCompleteScan,
    NeedPrevious {
        newest_complete: ScanBrief,
        newest_attempt: Option<ScanBrief>,
    },
    Ready(FindingDiff),
}

/// Read-only comparison of persisted COMPLETE scans.
pub struct DiffService;

impl DiffService {
    /// Diff Findings from the last two COMPLETE scans in `workspace`.
    pub fn latest(workspace: &Path) -> Result<FindingDiffResult, PicoError> {
        with_read_snapshot(workspace, |conn| {
            let scans = ScanRepo::new(conn);
            let complete = scans.list_complete()?;
            let newest_attempt = scans.newest_attempt()?;
            match complete.as_slice() {
                [] => Ok(FindingDiffResult::NoCompleteScan),
                [newest] => Ok(FindingDiffResult::NeedPrevious {
                    newest_complete: scan_brief(newest),
                    newest_attempt: newest_attempt.as_ref().map(scan_brief),
                }),
                [to, from, ..] => {
                    let (freshness, freshness_warning) =
                        freshness_context(to, newest_attempt.as_ref());
                    let from_findings = findings_by_fingerprint(conn, &from.id)?;
                    let to_findings = findings_by_fingerprint(conn, &to.id)?;
                    Ok(FindingDiffResult::Ready(compare(
                        scan_brief(from),
                        scan_brief(to),
                        newest_attempt.as_ref().map(scan_brief),
                        freshness,
                        freshness_warning,
                        from_findings,
                        to_findings,
                    )))
                }
            }
        })
    }
}

fn with_read_snapshot<T>(
    workspace: &Path,
    compose: impl FnOnce(&Connection) -> Result<T, PicoError>,
) -> Result<T, PicoError> {
    let db_path = workspace.join(".pico").join("pico.db");
    let db = Database::open_read_only(&db_path)?;
    require_schema_version(db.connection())?;
    let tx = db
        .connection()
        .unchecked_transaction()
        .map_err(|e| PicoError::database(e.to_string()))?;
    let outcome = compose(&tx);
    match outcome {
        Ok(value) => {
            tx.commit()
                .map_err(|e| PicoError::database(e.to_string()))?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback();
            Err(error)
        }
    }
}

fn findings_by_fingerprint(
    conn: &Connection,
    scan_id: &str,
) -> Result<BTreeMap<String, DiffFinding>, PicoError> {
    let records: Vec<FindingRecord> = FindingRepo::new(conn).list_for_scan(scan_id)?;
    let mut by_fingerprint = BTreeMap::new();
    for record in records {
        by_fingerprint
            .entry(record.fingerprint.clone())
            .or_insert(DiffFinding {
                id: record.id,
                fingerprint: record.fingerprint,
                title: record.title,
                severity: record.severity,
                confidence: record.confidence,
            });
    }
    Ok(by_fingerprint)
}

fn compare(
    from: ScanBrief,
    to: ScanBrief,
    newest_attempt: Option<ScanBrief>,
    freshness: Freshness,
    freshness_warning: Option<String>,
    from_findings: BTreeMap<String, DiffFinding>,
    to_findings: BTreeMap<String, DiffFinding>,
) -> FindingDiff {
    let mut unchanged = Vec::new();
    let mut appeared = Vec::new();
    let mut disappeared = Vec::new();
    for (fingerprint, finding) in &to_findings {
        if from_findings.contains_key(fingerprint) {
            unchanged.push(finding.clone());
        } else {
            appeared.push(finding.clone());
        }
    }
    for (fingerprint, finding) in &from_findings {
        if !to_findings.contains_key(fingerprint) {
            disappeared.push(finding.clone());
        }
    }
    sort_findings(&mut unchanged);
    sort_findings(&mut appeared);
    sort_findings(&mut disappeared);
    FindingDiff {
        from,
        to,
        newest_attempt,
        freshness,
        freshness_warning,
        unchanged,
        appeared,
        disappeared,
    }
}

fn sort_findings(findings: &mut [DiffFinding]) {
    findings.sort_by(|left, right| {
        left.fingerprint
            .cmp(&right.fingerprint)
            .then(left.id.cmp(&right.id))
    });
}

fn scan_brief(scan: &Scan) -> ScanBrief {
    ScanBrief {
        id: scan.id.clone(),
        status: scan.status.as_str().to_string(),
        completed_at: scan.completed_at.map(codec::ts_to_text),
    }
}

fn freshness_context(
    newest_complete: &Scan,
    newest_attempt: Option<&Scan>,
) -> (Freshness, Option<String>) {
    if let Some(attempt) = newest_attempt {
        let incomplete = matches!(
            attempt.status,
            crate::domain::ScanStatus::Running
                | crate::domain::ScanStatus::Partial
                | crate::domain::ScanStatus::Failed
        );
        if incomplete && attempt_is_newer(attempt, newest_complete) {
            return (
                Freshness::NewerIncomplete,
                Some(format!(
                    "Freshness: A newer scan {} is {}.\nComparing the last two COMPLETE scans; these results may not describe current state.",
                    attempt.id,
                    attempt.status.as_str()
                )),
            );
        }
    }
    (Freshness::LatestComplete, None)
}

fn attempt_is_newer(attempt: &Scan, complete: &Scan) -> bool {
    (attempt.started_at, attempt.id.as_str()) > (complete.started_at, complete.id.as_str())
}
