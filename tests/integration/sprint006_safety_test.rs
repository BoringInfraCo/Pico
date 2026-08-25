//! Sprint 006 safety invariants at the application/persistence boundary.
//!
//! These tests intentionally use only synthetic credentials and the public
//! ScanService API.  They prove that provider-facing credential material is
//! not copied into normalized state or diagnostics, and that repeated scans
//! retain stable resources while recording scan-scoped history.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::EnvironmentReachability;
use pico::domain::ScanStatus;
use pico::persistence::Database;
use tempfile::tempdir;

const TOKEN_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const HEADER_SENTINEL: &str = "TEST_AUTHORIZATION_HEADER_SHOULD_NOT_PERSIST";

fn setup_workspace() -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(
        workspace.path().join("opencode.json"),
        include_str!("../fixtures/opencode/allow/opencode.json"),
    )
    .unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

/// Search every persisted text-bearing field rather than only the fields
/// currently used by the credential adapter. This catches accidental leaks
/// through future metadata, evidence, observations, diagnostics, or scan
/// summaries.
fn persisted_occurrences(db: &Database, needle: &str) -> i64 {
    let connection = db.connection();
    connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM scans WHERE
                    CAST(id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(status AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(trigger AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(scope AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(pico_version AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(environment_fingerprint AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
                (SELECT COUNT(*) FROM resources WHERE
                    CAST(id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(canonical_key AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(kind AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(provider AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(name AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
                (SELECT COUNT(*) FROM relationships WHERE
                    CAST(id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(canonical_key AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(from_resource_id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(to_resource_id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(kind AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(state AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
                (SELECT COUNT(*) FROM evidence WHERE
                    CAST(id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(scan_id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(class AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(source_type AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(source_locator AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(subject AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(observation AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
                (SELECT COUNT(*) FROM observations WHERE
                    CAST(id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(scan_id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(subject_type AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(subject_id AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(observation_type AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(source AS TEXT) LIKE '%' || ?1 || '%' OR
                    CAST(metadata AS TEXT) LIKE '%' || ?1 || '%')",
            [needle],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn credential_and_authorization_sentinels_never_enter_persisted_state() {
    let workspace = setup_workspace();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", TOKEN_SENTINEL)];

    let result = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    assert_eq!(persisted_occurrences(&db, TOKEN_SENTINEL), 0);
    assert_eq!(persisted_occurrences(&db, HEADER_SENTINEL), 0);
}

#[test]
fn repeated_scans_keep_one_credential_resource_and_add_history() {
    let workspace = setup_workspace();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", TOKEN_SENTINEL)];

    let first = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let second = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(second.status, ScanStatus::Complete);

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let connection = db.connection();
    let resource_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE kind = 'credential'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let scan_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
        .unwrap();
    let credential_id: String = connection
        .query_row(
            "SELECT id FROM resources WHERE kind = 'credential'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let credential_observation_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM observations
             WHERE subject_type = 'resource' AND subject_id = ?1",
            [&credential_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(resource_count, 1);
    assert_eq!(scan_count, 2);
    assert_eq!(credential_observation_count, 2);
}

#[test]
fn local_unknown_reachability_does_not_create_positive_access_state() {
    let workspace = setup_workspace();
    let home = tempdir().unwrap();
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
    let positive_access: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM relationships
             WHERE kind = 'can_access' AND state IN ('CONFIRMED', 'DERIVED')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(positive_access, 0);
}

#[test]
fn worker_identity_is_account_scoped_and_prefers_immutable_tag() {
    let tagged = ObservedWorker {
        account_id: "account-a".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("immutable-1".to_string()),
        source_locator: "cloudflare_api".to_string(),
    };
    assert_eq!(
        tagged.canonical_key(),
        "cloudflare:worker:account-a:immutable-1"
    );
    assert_eq!(tagged.identity_precision(), "IMMUTABLE_TAG");

    let fallback = ObservedWorker {
        account_id: "account-a".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: None,
        source_locator: "cloudflare_api".to_string(),
    };
    assert_eq!(
        fallback.canonical_key(),
        "cloudflare:worker:account-a:name:checkout"
    );
    assert_eq!(fallback.identity_precision(), "NAME_SCOPED");

    let same_name_other_account = ObservedWorker {
        account_id: "account-b".to_string(),
        ..fallback.clone()
    };
    assert_ne!(
        fallback.canonical_key(),
        same_name_other_account.canonical_key()
    );
}

#[test]
fn authority_resolution_and_scope_vocabulary_remain_explicit() {
    assert_eq!(AuthorityResolution::Exact.as_str(), "EXACT");
    assert_eq!(AuthorityResolution::Scoped.as_str(), "SCOPED");
    assert_eq!(
        AuthorityResolution::BehavioralReadOnly.as_str(),
        "BEHAVIORAL_READ_ONLY"
    );
    assert_eq!(AuthorityResolution::Unknown.as_str(), "UNKNOWN");
    assert_eq!(ScopeState::InScope.as_str(), "IN_SCOPE");
    assert_eq!(ScopeState::OutOfScope.as_str(), "OUT_OF_SCOPE");
    assert_eq!(ScopeState::Unknown.as_str(), "UNKNOWN");
}

#[test]
fn injected_provider_result_persists_exact_worker_authority() {
    let workspace = setup_workspace();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = pico::discovery::discover_with_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let credential_fingerprint = discovered.credentials[0].fingerprint.clone();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
    };
    let worker_key = worker.canonical_key();
    let provider = ProviderResult {
        credential_fingerprint,
        credential_status: Some(CredentialStatus::Active),
        accounts: vec![ObservedAccount {
            account_id: "account-1234567890123456".to_string(),
            name: Some("Synthetic Account".to_string()),
            account_type: Some("standard".to_string()),
            scope: ScopeState::InScope,
            source_locator: "/accounts".to_string(),
        }],
        workers: vec![worker],
        authorities: vec![AuthorityObservation {
            account_id: "account-1234567890123456".to_string(),
            worker_key,
            state: pico::domain::RelationshipState::Derived,
            resolution: AuthorityResolution::Exact,
            permission_state: "WORKERS_SCRIPTS_WRITE".to_string(),
            scope_state: ScopeState::InScope,
            unknown_reasons: Vec::new(),
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    };
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider),
    )
    .unwrap();
    assert_eq!(
        result.worker_mutation_authority.as_deref(),
        Some("CONFIRMED")
    );
    assert_eq!(result.authority_resolution.as_deref(), Some("EXACT"));

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let can_mutate: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE kind = 'can_mutate' AND state = 'DERIVED'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(can_mutate, 1);
}
