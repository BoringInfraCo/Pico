//! Sprint 005 credential reachability tests. The explicit environment input is
//! a controlled fixture projection; production scans do not assume Pico's own
//! environment is automatically OpenCode's Bash environment.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::discovery::EnvironmentReachability;
use pico::domain::ScanStatus;
use pico::persistence::Database;
use tempfile::tempdir;

const SENTINEL: &str = "TEST_CLOUDFLARE_SECRET_SHOULD_NOT_PERSIST";

fn write_opencode(workspace: &std::path::Path, fixture: &str) {
    fs::write(workspace.join("opencode.json"), fixture).unwrap();
}

fn allow_fixture() -> &'static str {
    include_str!("../fixtures/opencode/allow/opencode.json")
}

#[test]
fn allow_reachability_is_stable_and_secret_safe_across_scans() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), allow_fixture());
    InitService::run(workspace.path()).unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", SENTINEL)];

    let first = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    assert_eq!(first.status, ScanStatus::Complete);
    assert!(first.cloudflare_credential_observed);
    assert_eq!(first.credential_reachability.as_deref(), Some("REACHABLE"));
    assert_eq!(first.resource_count, 3);
    assert_eq!(first.relationship_count, 2);
    assert_eq!(first.finding_count, 0);

    let second = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    assert_eq!(second.resource_count, 3);
    assert_eq!(second.relationship_count, 2);

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let conn = db.connection();
    let credential_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE kind = 'credential'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let credential_key: String = conn
        .query_row(
            "SELECT canonical_key FROM resources WHERE kind = 'credential'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let observations: i64 = conn
        .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
        .unwrap();
    let evidence: i64 = conn
        .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
        .unwrap();
    let leaks: i64 = conn
        .query_row(
            "SELECT
              (SELECT COUNT(*) FROM resources WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
              (SELECT COUNT(*) FROM relationships WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
              (SELECT COUNT(*) FROM evidence WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%' OR observation LIKE '%' || ?1 || '%') +
              (SELECT COUNT(*) FROM observations WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%')",
            [SENTINEL],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(credential_count, 1);
    assert!(credential_key.starts_with("credential:cloudflare:"));
    assert_eq!(credential_key.len(), "credential:cloudflare:".len() + 64);
    assert!(!credential_key.contains(SENTINEL));
    assert_eq!(observations, 10);
    assert_eq!(evidence, 8);
    assert_eq!(leaks, 0);
}

#[test]
fn ask_and_deny_preserve_distinct_reachability_states() {
    for (fixture, expected_permission, expected_state, expected_reachability) in [
        (
            include_str!("../fixtures/opencode/ask/opencode.json"),
            "ASK",
            "DERIVED",
            "APPROVAL_GATED",
        ),
        (
            include_str!("../fixtures/opencode/deny/opencode.json"),
            "DENY",
            "BLOCKED",
            "BLOCKED",
        ),
    ] {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_opencode(workspace.path(), fixture);
        InitService::run(workspace.path()).unwrap();
        let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
        let result = ScanService::run_with_home_and_environment(
            workspace.path(),
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
        )
        .unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        assert_eq!(result.bash_permission.as_deref(), Some(expected_permission));
        assert_eq!(
            result.credential_reachability.as_deref(),
            Some(expected_reachability)
        );
        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let (state, metadata): (String, String) = db
            .connection()
            .query_row(
                "SELECT state, metadata FROM relationships WHERE kind = 'can_access'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, expected_state);
        assert!(metadata.contains(&format!(
            "\"effective_bash_permission\":\"{expected_permission}\""
        )));
    }
}

#[test]
fn unknown_environment_does_not_create_positive_reachability() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), allow_fixture());
    InitService::run(workspace.path()).unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let result = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Unknown,
    )
    .unwrap();
    assert_eq!(result.credential_reachability.as_deref(), Some("UNKNOWN"));
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let state: String = db
        .connection()
        .query_row(
            "SELECT state FROM relationships WHERE kind = 'can_access'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "UNKNOWN");
}

#[test]
fn absent_actor_or_empty_source_does_not_create_credential_state() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), allow_fixture());
    InitService::run(workspace.path()).unwrap();
    let empty: [(&str, &str); 0] = [];
    let result = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&empty),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    assert!(!result.cloudflare_credential_observed);
    assert_eq!(result.resource_count, 2);

    let absent_workspace = tempdir().unwrap();
    let absent_home = tempdir().unwrap();
    InitService::run(absent_workspace.path()).unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let absent = ScanService::run_with_home_and_environment(
        absent_workspace.path(),
        Some(absent_home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    assert!(!absent.cloudflare_credential_observed);
    assert_eq!(absent.resource_count, 0);
    assert_eq!(absent.relationship_count, 0);
}

#[test]
fn credential_rotation_preserves_distinct_safe_identity_history() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), allow_fixture());
    InitService::run(workspace.path()).unwrap();
    let first_env = [("CLOUDFLARE_API_TOKEN", "token-alpha")];
    ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&first_env),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let second_env = [("CLOUDFLARE_API_TOKEN", "token-beta")];
    let second = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&second_env),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    assert_eq!(second.resource_count, 4);
    assert_eq!(second.relationship_count, 3);
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let count: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE kind = 'credential'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn exact_project_dotenv_is_supported_without_recursive_file_crawling() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), allow_fixture());
    fs::write(
        workspace.path().join(".env"),
        format!("# supported local dotenv\nCLOUDFLARE_API_TOKEN=\"{SENTINEL}\"\n"),
    )
    .unwrap();
    fs::write(
        workspace.path().join("notes.txt"),
        format!("CLOUDFLARE_API_TOKEN={SENTINEL}"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();
    let empty: [(&str, &str); 0] = [];
    let result = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&empty),
        EnvironmentReachability::Unknown,
    )
    .unwrap();
    assert!(result.cloudflare_credential_observed);
    assert_eq!(result.credential_reachability.as_deref(), Some("REACHABLE"));
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let leaks: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%'",
            [SENTINEL],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(leaks, 0);
}
