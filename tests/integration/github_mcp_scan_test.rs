//! Sprint 004 bounded GitHub MCP influence tests. These fixtures are static;
//! Pico must never execute their local command or contact their remote URL.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::domain::ScanStatus;
use pico::persistence::Database;
use tempfile::tempdir;

#[test]
fn official_v2_github_mcp_is_normalized_with_safe_influence_facts() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(
        workspace.path().join("opencode.json"),
        include_str!("../fixtures/opencode/github-mcp-v2.json"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();

    let first = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(first.agent_count, 1);
    assert!(first.github_mcp_observed);
    assert_eq!(
        first.influence_strength.as_deref(),
        Some("AGENT_RETRIEVABLE")
    );
    assert_eq!(first.resource_count, 5);
    assert_eq!(first.relationship_count, 5);
    assert_eq!(first.finding_count, 0);

    let second = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(second.resource_count, 5);
    assert_eq!(second.relationship_count, 5);

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let conn = db.connection();
    let resources: i64 = conn
        .query_row("SELECT COUNT(*) FROM resources", [], |r| r.get(0))
        .unwrap();
    let relationships: i64 = conn
        .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
        .unwrap();
    let observations: i64 = conn
        .query_row("SELECT COUNT(*) FROM observations", [], |r| r.get(0))
        .unwrap();
    let scans: i64 = conn
        .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
        .unwrap();
    let stable_server: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE canonical_key = 'mcp:github:official'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        (resources, relationships, scans, stable_server),
        (5, 5, 2, 1)
    );
    assert_eq!(observations, 20);

    let tool_state: String = conn.query_row(
        "SELECT state FROM relationships WHERE canonical_key = 'agent:opencode|can_call|mcp:github:official:tool:issue_read'",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(tool_state, "DERIVED");
    let secret: i64 = conn.query_row(
        "SELECT
          (SELECT COUNT(*) FROM resources WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
          (SELECT COUNT(*) FROM relationships WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
          (SELECT COUNT(*) FROM evidence WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%' OR observation LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%') +
          (SELECT COUNT(*) FROM observations WHERE CAST(metadata AS TEXT) LIKE '%TEST_SECRET_SHOULD_NOT_PERSIST%')",
        [],
        |r| r.get(0),
    ).unwrap();
    assert_eq!(secret, 0);
}

#[test]
fn remote_official_server_preserves_deny_and_spoof_is_ignored() {
    for (fixture, observed, expected_state) in [
        (
            include_str!("../fixtures/opencode/github-mcp-remote.json"),
            true,
            "BLOCKED",
        ),
        (
            include_str!("../fixtures/opencode/github-mcp-spoof.json"),
            false,
            "",
        ),
    ] {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        fs::write(workspace.path().join("opencode.json"), fixture).unwrap();
        InitService::run(workspace.path()).unwrap();
        let result = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.github_mcp_observed, observed);
        if observed {
            assert_eq!(result.relationship_count, 5);
            let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
            let state: String = db
                .connection()
                .query_row(
                    "SELECT state FROM relationships WHERE kind = 'can_call'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(state, expected_state);
        } else {
            assert_eq!(result.resource_count, 2);
            assert_eq!(result.relationship_count, 1);
        }
    }
}

#[test]
fn disabled_official_server_is_observed_but_has_no_influence_edges() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    fs::write(
        workspace.path().join("opencode.json"),
        include_str!("../fixtures/opencode/github-mcp-disabled.json"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();
    let result = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert!(result.github_mcp_observed);
    assert_eq!(result.influence_strength, None);
    assert_eq!(result.resource_count, 3);
    assert_eq!(result.relationship_count, 2);
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let can_call: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE kind = 'can_call'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(can_call, 0);
}
