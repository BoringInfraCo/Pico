//! Sprint 029 COMPLETE-summary immutability (SPRINT-029.md §5.2).
//!
//! `ScanAnalysisRepo::upsert` stays usable while the parent scan is RUNNING,
//! PARTIAL, or FAILED and refuses replacement once the parent is COMPLETE.
//! The summary is the authoritative comparison-provenance input and must not
//! be rewritten after completion.

use chrono::Utc;
use pico::domain::Scan;
use pico::persistence::{Database, ScanAnalysisRecord, ScanAnalysisRepo, ScanRepo};
use pico::shared::{PicoError, PICO_VERSION};

fn test_db() -> Database {
    let dir = tempfile::tempdir().unwrap();
    // Keep the directory alive for the database connection's lifetime.
    let path = dir.keep().join("pico.db");
    let mut db = Database::open(&path).unwrap();
    db.migrate().unwrap();
    db
}

fn summary(scan_id: &str) -> ScanAnalysisRecord {
    ScanAnalysisRecord {
        scan_id: scan_id.to_string(),
        analysis_version: "1".to_string(),
        status: "COMPLETE".to_string(),
        overall_disposition: Some("NONE".to_string()),
        influence_path_count: 0,
        authority_path_count: 0,
        active_path_count: 0,
        blocked_path_count: 0,
        unresolved_candidate_count: 0,
        limit_reasons: None,
        diagnostics: None,
        created_at: Utc::now(),
    }
}

#[test]
fn summary_is_rewritable_until_scan_completes_then_immutable() {
    let db = test_db();
    let repo = ScanAnalysisRepo::new(db.connection());

    // RUNNING: the summary may be written and replaced.
    let running = Scan::start(PICO_VERSION).unwrap();
    ScanRepo::new(db.connection()).insert(&running).unwrap();
    repo.upsert(&summary(&running.id)).unwrap();
    repo.upsert(&summary(&running.id)).unwrap();

    // PARTIAL: still mutable.
    let partial = Scan::start(PICO_VERSION).unwrap();
    ScanRepo::new(db.connection()).insert(&partial).unwrap();
    let partial = partial.partial().unwrap();
    ScanRepo::new(db.connection()).update(&partial).unwrap();
    repo.upsert(&summary(&partial.id)).unwrap();

    // COMPLETE: the persisted summary is immutable.
    let completed = running.complete().unwrap();
    ScanRepo::new(db.connection()).update(&completed).unwrap();
    let error = repo.upsert(&summary(&completed.id)).unwrap_err();
    assert!(matches!(error, PicoError::Database(_)));
    assert!(error
        .to_string()
        .contains("scan analysis summary is immutable once its scan is COMPLETE"));
}

#[test]
fn failed_scan_summary_stays_rewritable() {
    let db = test_db();
    let scan = Scan::start(PICO_VERSION).unwrap().fail().unwrap();
    ScanRepo::new(db.connection()).insert(&scan).unwrap();
    ScanAnalysisRepo::new(db.connection())
        .upsert(&summary(&scan.id))
        .unwrap();
}

#[test]
fn summary_upsert_to_unknown_scan_fails_closed() {
    let db = test_db();
    let error = ScanAnalysisRepo::new(db.connection())
        .upsert(&summary("scan_missing"))
        .unwrap_err();
    assert!(matches!(error, PicoError::Database(_)));
    assert!(error
        .to_string()
        .contains("scan scan_missing does not exist"));
}
