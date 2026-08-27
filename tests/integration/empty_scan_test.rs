//! The Sprint 001 golden path: init, empty scan, reload from SQLite,
//! scan history, and scan without init.

use pico::application::{InitService, ScanService};
use pico::domain::ScanStatus;
use pico::persistence::{Database, ScanRepo};
use pico::shared::PicoError;
use tempfile::tempdir;

#[test]
fn init_creates_workspace_at_schema_version_5() {
    let dir = tempdir().unwrap();
    let result = InitService::run(dir.path()).unwrap();
    assert_eq!(result.schema_version, 5);
    assert_eq!(result.workspace, dir.path());
    assert_eq!(result.db_path, dir.path().join(".pico").join("pico.db"));
    assert!(result.db_path.exists());
}

#[test]
fn init_is_idempotent_and_does_not_reset() {
    let dir = tempdir().unwrap();
    let first = InitService::run(dir.path()).unwrap();
    let second = InitService::run(dir.path()).unwrap();
    assert_eq!(second.schema_version, 5);
    assert_eq!(second.schema_version, first.schema_version);
    assert_eq!(second.db_path, first.db_path);
    assert!(second.db_path.exists());
}

#[test]
fn empty_scan_completes_persists_and_accumulates_history() {
    let dir = tempdir().unwrap();
    InitService::run(dir.path()).unwrap();

    let result = ScanService::run_with_home(dir.path(), None).unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert!(result.started_at.timestamp() > 0);
    assert!(result.completed_at.is_some());
    assert_eq!(result.resource_count, 0);
    assert_eq!(result.relationship_count, 0);
    assert_eq!(result.evidence_count, 0);
    assert_eq!(result.finding_count, 0);

    let mut db = Database::open(&dir.path().join(".pico").join("pico.db")).unwrap();
    db.migrate().unwrap();
    let repo = ScanRepo::new(db.connection());
    let scans = repo.list().unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].id, result.scan_id);
    assert_eq!(scans[0].status, ScanStatus::Complete);
    assert!(scans[0].completed_at.is_some());
    let first_started_at = scans[0].started_at;

    let second = ScanService::run_with_home(dir.path(), None).unwrap();
    assert_ne!(second.scan_id, result.scan_id);
    let scans = repo.list().unwrap();
    assert_eq!(scans.len(), 2);
    let first = scans.iter().find(|s| s.id == result.scan_id).unwrap();
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(first.started_at, first_started_at);
    assert_eq!(first.id, result.scan_id);
    let second_loaded = scans.iter().find(|s| s.id == second.scan_id).unwrap();
    assert_eq!(second_loaded.status, ScanStatus::Complete);
    assert_eq!(second_loaded.completed_at, second.completed_at);
}

#[test]
fn scan_without_init_fails_with_scan_error() {
    let dir = tempdir().unwrap();
    let err = ScanService::run(dir.path()).expect_err("scan without init must fail");
    assert!(matches!(err, PicoError::Scan(_)));
}
