//! `pico history` application service (SPRINT-025.md).
//!
//! Lists all scans with status, finding count, and timestamps.

use std::path::Path;

use rusqlite::Connection;
use serde::Serialize;

use crate::persistence::{codec, require_schema_version, Database, FindingRepo, ScanRepo};
use crate::shared::PicoError;

/// Summary of one scan for the history view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub status: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub finding_count: u64,
}

/// Full scan history.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScanHistory {
    pub scans: Vec<ScanSummary>,
}

/// Read-only catalog of persisted scans.
pub struct HistoryService;

impl HistoryService {
    /// List all scans in chronological order with finding counts.
    pub fn list(workspace: &Path) -> Result<ScanHistory, PicoError> {
        let db_path = workspace.join(".pico").join("pico.db");
        let db = Database::open_read_only(&db_path)?;
        require_schema_version(db.connection())?;
        let tx = db
            .connection()
            .unchecked_transaction()
            .map_err(|e| PicoError::database(e.to_string()))?;
        let result = list_scans(&tx);
        match result {
            Ok(history) => {
                tx.commit()
                    .map_err(|e| PicoError::database(e.to_string()))?;
                Ok(history)
            }
            Err(error) => {
                let _ = tx.rollback();
                Err(error)
            }
        }
    }
}

fn list_scans(conn: &Connection) -> Result<ScanHistory, PicoError> {
    let scans = ScanRepo::new(conn).list()?;
    let finding_repo = FindingRepo::new(conn);
    let summaries = scans
        .iter()
        .map(|scan| {
            let finding_count = finding_repo.count_for_scan(&scan.id)?;
            Ok(ScanSummary {
                id: scan.id.clone(),
                status: scan.status.as_str().to_string(),
                started_at: Some(codec::ts_to_text(scan.started_at)),
                completed_at: scan.completed_at.map(codec::ts_to_text),
                finding_count,
            })
        })
        .collect::<Result<Vec<_>, PicoError>>()?;
    Ok(ScanHistory { scans: summaries })
}
