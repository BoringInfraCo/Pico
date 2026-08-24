//! Sprint 002 end-to-end OpenCode observation tests using only local fixtures.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::domain::ScanStatus;
use pico::persistence::Database;
use tempfile::tempdir;

#[test]
fn supported_opencode_is_observed_safely_and_stably_across_scans() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(
        workspace.path().join("opencode.json"),
        include_str!("../fixtures/opencode/present/opencode.json"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();

    let first = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(first.agent_count, 1);
    assert_eq!(first.resource_count, 1);
    assert_eq!(first.relationship_count, 0);
    assert_eq!(first.evidence_count, 1);
    assert_eq!(first.finding_count, 0);

    let second = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(second.status, ScanStatus::Complete);
    assert_eq!(second.agent_count, 1);
    assert_eq!(second.resource_count, 1);
    assert_eq!(second.relationship_count, 0);
    assert_eq!(second.evidence_count, 2);

    let mut db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    db.migrate().unwrap();
    let conn = db.connection();
    let resources: i64 = conn
        .query_row("SELECT COUNT(*) FROM resources", [], |row| row.get(0))
        .unwrap();
    let observations: i64 = conn
        .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
        .unwrap();
    let evidence: i64 = conn
        .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
        .unwrap();
    let first_resource_id: String = conn
        .query_row("SELECT id FROM resources", [], |row| row.get(0))
        .unwrap();
    let second_observation_resource_id: String = conn
        .query_row(
            "SELECT subject_id FROM observations WHERE scan_id = ?1",
            [&second.scan_id],
            |row| row.get(0),
        )
        .unwrap();
    let sentinel: i64 = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM resources WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
                (SELECT COUNT(*) FROM evidence WHERE observation LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
                (SELECT COUNT(*) FROM observations WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(resources, 1);
    assert_eq!(observations, 2);
    assert_eq!(evidence, 2);
    assert_eq!(first_resource_id, second_observation_resource_id);
    assert_eq!(sentinel, 0);
}

#[test]
fn opencode_absence_completes_without_actor_state() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(workspace.path().join("opencode-notes.txt"), "opencode").unwrap();
    InitService::run(workspace.path()).unwrap();
    let result = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.agent_count, 0);
    assert_eq!(result.resource_count, 0);
    assert_eq!(result.relationship_count, 0);
    assert_eq!(result.evidence_count, 0);
    assert_eq!(result.finding_count, 0);
}

#[test]
fn malformed_supported_opencode_config_completes_partial_without_persistence() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(
        workspace.path().join("opencode.json"),
        include_str!("../fixtures/opencode/malformed/opencode.json"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();
    let result = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(result.status, ScanStatus::Partial);
    assert_eq!(result.agent_count, 0);
    assert_eq!(result.resource_count, 0);
    assert_eq!(result.evidence_count, 0);
}
