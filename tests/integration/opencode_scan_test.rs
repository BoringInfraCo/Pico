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
        include_str!("../fixtures/opencode/allow/opencode.json"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();

    let first = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(first.agent_count, 1);
    assert_eq!(first.resource_count, 2);
    assert_eq!(first.relationship_count, 1);
    assert_eq!(first.evidence_count, 2);
    assert_eq!(first.finding_count, 0);
    assert_eq!(first.bash_permission.as_deref(), Some("ALLOW"));

    let second = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(second.status, ScanStatus::Complete);
    assert_eq!(second.agent_count, 1);
    assert_eq!(second.resource_count, 2);
    assert_eq!(second.relationship_count, 1);
    assert_eq!(second.evidence_count, 4);
    assert_eq!(second.bash_permission.as_deref(), Some("ALLOW"));

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
    let evidence_links: i64 = conn
        .query_row("SELECT COUNT(*) FROM relationship_evidence", [], |row| {
            row.get(0)
        })
        .unwrap();
    let relationship_id: String = conn
        .query_row("SELECT id FROM relationships", [], |row| row.get(0))
        .unwrap();
    let second_observation_relationship_id: String = conn
        .query_row(
            "SELECT subject_id FROM observations
             WHERE scan_id = ?1 AND subject_type = 'relationship'",
            [&second.scan_id],
            |row| row.get(0),
        )
        .unwrap();
    let sentinel: i64 = conn
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM resources WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
                (SELECT COUNT(*) FROM relationships WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
                (SELECT COUNT(*) FROM evidence WHERE observation LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%' OR CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
                (SELECT COUNT(*) FROM observations WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(resources, 2);
    assert_eq!(observations, 6);
    assert_eq!(evidence, 4);
    assert_eq!(evidence_links, 2);
    assert_eq!(relationship_id, second_observation_relationship_id);
    assert_eq!(sentinel, 0);
}

#[test]
fn bash_policy_states_remain_distinct() {
    for (fixture, expected, state) in [
        (
            include_str!("../fixtures/opencode/allow/opencode.json"),
            "ALLOW",
            "DERIVED",
        ),
        (
            include_str!("../fixtures/opencode/ask/opencode.json"),
            "ASK",
            "UNKNOWN",
        ),
        (
            include_str!("../fixtures/opencode/deny/opencode.json"),
            "DENY",
            "BLOCKED",
        ),
        (
            include_str!("../fixtures/opencode/bounded/opencode.json"),
            "UNKNOWN",
            "UNKNOWN",
        ),
    ] {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        fs::write(workspace.path().join("opencode.json"), fixture).unwrap();
        InitService::run(workspace.path()).unwrap();
        let result = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.bash_permission.as_deref(), Some(expected));
        assert_eq!(result.resource_count, 2);
        assert_eq!(result.relationship_count, 1);
        assert_eq!(result.finding_count, 0);

        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let (stored_state, metadata): (String, String) = db
            .connection()
            .query_row("SELECT state, metadata FROM relationships", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(stored_state, state);
        assert!(metadata.contains(&format!("\"effective_permission\":\"{expected}\"")));
        if expected == "ASK" {
            assert!(metadata.contains("\"runtime_mode\":\"UNKNOWN\""));
        }
        if expected == "UNKNOWN" {
            assert!(metadata.contains("\"scope\":\"BOUNDED\""));
        }
    }
}

#[test]
fn permission_change_preserves_identity_and_scan_history() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    let config = workspace.path().join("opencode.json");
    fs::write(
        &config,
        include_str!("../fixtures/opencode/ask/opencode.json"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();
    let first = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    fs::write(
        &config,
        include_str!("../fixtures/opencode/allow/opencode.json"),
    )
    .unwrap();
    let second = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let conn = db.connection();
    let relationships: i64 = conn
        .query_row("SELECT COUNT(*) FROM relationships", [], |row| row.get(0))
        .unwrap();
    let ask_history: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE scan_id = ?1 AND observation LIKE '%ASK%'",
            [&first.scan_id],
            |row| row.get(0),
        )
        .unwrap();
    let allow_history: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE scan_id = ?1 AND observation LIKE '%ALLOW%'",
            [&second.scan_id],
            |row| row.get(0),
        )
        .unwrap();
    let relationship_observations: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM observations WHERE subject_type = 'relationship'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(relationships, 1);
    assert_eq!(ask_history, 1);
    assert_eq!(allow_history, 1);
    assert_eq!(relationship_observations, 2);
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
    assert_eq!(result.bash_permission, None);
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
