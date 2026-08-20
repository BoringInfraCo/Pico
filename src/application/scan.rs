//! `pico scan` application service (SPRINT-001.md §12).

use std::path::Path;

use crate::domain::{Scan, ScanStatus};
use crate::persistence::{Database, EvidenceRepo, RelationshipRepo, ResourceRepo, ScanRepo};
use crate::shared::{PicoError, PICO_VERSION};

/// Structured result of a scan, rendered by the CLI.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub scan_id: String,
    pub status: ScanStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub resource_count: u64,
    pub relationship_count: u64,
    pub evidence_count: u64,
    pub finding_count: u64,
}

/// Runs a bounded, empty scan in an initialized workspace.
///
/// Sprint 001 performs no discovery: the scan is created as RUNNING,
/// persisted, completed as COMPLETE, persisted again, and the empty
/// counts are returned.
pub struct ScanService;

impl ScanService {
    pub fn run(workspace: &Path) -> Result<ScanResult, PicoError> {
        let mut db = Database::open_existing(&workspace.join(".pico").join("pico.db"))?;
        db.migrate()?;

        let scan_repo = ScanRepo::new(db.connection());
        let scan = Scan::start(PICO_VERSION)?;
        scan_repo.insert(&scan)?;

        let completed = scan.complete()?;
        scan_repo.update(&completed)?;

        let resource_count = ResourceRepo::new(db.connection()).count()?;
        let relationship_count = RelationshipRepo::new(db.connection()).count()?;
        let evidence_count = EvidenceRepo::new(db.connection()).count()?;

        Ok(ScanResult {
            scan_id: completed.id,
            status: completed.status,
            started_at: completed.started_at,
            completed_at: completed.completed_at,
            resource_count,
            relationship_count,
            evidence_count,
            finding_count: 0,
        })
    }
}
