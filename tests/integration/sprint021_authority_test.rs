//! Sprint 021 GitHub repository mutation authority fixtures (R4, R5, R8).
//!
//! R4 asserts `can_mutate` is emitted only when write authority is evidenced
//! (EXACT/SCOPED from a live classic-PAT scope probe) and only `can_access`
//! otherwise. R5 asserts a mixed Cloudflare + GitHub credential workspace
//! coexists without regressing the golden finding count or duplicating edges.
//! R8 is a broad sanitized battery: credential types, offline vs live,
//! fine-grained, mixed, and provider-failure (probe unavailable => PARTIAL).
//! All probes run through fixture transports / injected normalized results;
//! no network access is involved.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::github::{self, GitHubAuthorityResult};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::persistence::Database;
use tempfile::tempdir;

const GOLDEN_OPENCODE: &str = include_str!("../fixtures/mixed/opencode.json");
const ALLOW_OPENCODE: &str = include_str!("../fixtures/opencode/allow/opencode.json");

const GITHUB_PAT: &str = "ghp_TESTFAKE0000000000000000000000000000";
const GITHUB_FINE_GRAINED: &str = "github_pat_TESTFAKE00000000000000000000";
const GITHUB_OAUTH: &str = "gho_TESTFAKE0000000000000000000000000000";
const CLOUDFLARE_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";

fn write_opencode(workspace: &std::path::Path, contents: &str) {
    fs::write(workspace.join("opencode.json"), contents).unwrap();
}

/// Simulate a successful live scope probe result for a credential type and the
/// observed OAuth scopes.
fn live_result(fingerprint: &str, credential_type: &str, scopes: &[&str]) -> GitHubAuthorityResult {
    let scopes = scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect::<Vec<_>>();
    let (state, resolution, permission_state, unknown_reasons) =
        github::resolve_authority(credential_type, &scopes);
    GitHubAuthorityResult {
        credential_fingerprint: fingerprint.to_string(),
        credential_type: Some(credential_type.to_string()),
        state,
        resolution,
        permission_state: permission_state.to_string(),
        unknown_reasons,
        source_locator: "github:scope_probe:/user".to_string(),
        problems: Vec::new(),
    }
}

/// Simulate a failed live probe (transport unavailable): UNKNOWN authority, the
/// unobservable reason, and a recorded problem so the scan is PARTIAL-aware.
fn failure_result(
    fingerprint: &str,
    credential_type: &str,
    problem: &str,
) -> GitHubAuthorityResult {
    GitHubAuthorityResult {
        credential_fingerprint: fingerprint.to_string(),
        credential_type: Some(credential_type.to_string()),
        state: RelationshipState::Unknown,
        resolution: AuthorityResolution::Unknown,
        permission_state: "READ_OR_UNKNOWN".to_string(),
        unknown_reasons: vec!["GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE".to_string()],
        source_locator: "github:scope_probe:/user".to_string(),
        problems: vec![problem.to_string()],
    }
}

fn cloudflare_fingerprint(workspace: &std::path::Path, home: &std::path::Path) -> String {
    let environment = [("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN)];
    discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap()
    .credentials[0]
        .fingerprint
        .clone()
}

fn production_worker() -> ObservedWorker {
    ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
    }
}

fn valid_cloudflare_provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
) -> ProviderResult {
    let worker = production_worker();
    let worker_key = worker.canonical_key();
    ProviderResult {
        credential_fingerprint: cloudflare_fingerprint(workspace, home),
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
            state: RelationshipState::Derived,
            resolution: AuthorityResolution::Exact,
            permission_state: "WORKERS_SCRIPTS_WRITE".to_string(),
            scope_state: ScopeState::InScope,
            unknown_reasons: Vec::new(),
            granted_permissions: Vec::new(),
            zone_scoped: false,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn count_relationships(workspace: &std::path::Path, key: &str) -> i64 {
    let db = Database::open(&workspace.join(".pico/pico.db")).unwrap();
    db.connection()
        .query_row(
            "SELECT COUNT(*) FROM relationships WHERE canonical_key = ?1",
            [key],
            |row| row.get(0),
        )
        .unwrap()
}

fn count_resources(workspace: &std::path::Path, kind: &str, provider: &str) -> i64 {
    let db = Database::open(&workspace.join(".pico/pico.db")).unwrap();
    db.connection()
        .query_row(
            "SELECT COUNT(*) FROM resources WHERE kind = ?1 AND provider = ?2",
            rusqlite::params![kind, provider],
            |row| row.get(0),
        )
        .unwrap()
}

/// R4: `can_mutate` is emitted only on evidenced write authority (EXACT/SCOPED);
/// a read-only or offline credential only gets `can_access`.
#[test]
fn r4_github_mutation_edge_only_on_write_evidence() {
    // Write evidence (classic PAT + repo scope) => can_mutate exists.
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let environment = [("GITHUB_TOKEN", GITHUB_PAT)];
    let result = ScanService::run_with_home_and_environment_and_github(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(live_result(
            &github::fingerprint(GITHUB_PAT),
            "classic_pat",
            &["repo"],
        )),
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    let credential_key = format!("credential:github:{}", github::fingerprint(GITHUB_PAT));
    let mutate_key = format!("{credential_key}|can_mutate|github:repository");
    let access_key = format!("{credential_key}|can_access|github:repository");
    assert_eq!(count_relationships(workspace.path(), &mutate_key), 1);
    assert_eq!(count_relationships(workspace.path(), &access_key), 0);
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let metadata: String = db
        .connection()
        .query_row(
            "SELECT metadata FROM relationships WHERE canonical_key = ?1",
            [&mutate_key],
            |row| row.get(0),
        )
        .unwrap();
    assert!(metadata.contains("\"authority_resolution\":\"EXACT\""));
    assert!(metadata.contains("\"permission_state\":\"REPO_WRITE\""));
    assert!(metadata.contains("\"credential_type\":\"classic_pat\""));

    // Read-only evidence => only can_access, never can_mutate.
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let result = ScanService::run_with_home_and_environment_and_github(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(live_result(
            &github::fingerprint(GITHUB_PAT),
            "classic_pat",
            &["read:user", "read:org"],
        )),
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    let credential_key = format!("credential:github:{}", github::fingerprint(GITHUB_PAT));
    let mutate_key = format!("{credential_key}|can_mutate|github:repository");
    let access_key = format!("{credential_key}|can_access|github:repository");
    assert_eq!(count_relationships(workspace.path(), &mutate_key), 0);
    assert_eq!(count_relationships(workspace.path(), &access_key), 1);

    // Offline default (no probe) => only can_access (read).
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let result = ScanService::run_with_home_and_environment_and_github(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        None,
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    let credential_key = format!("credential:github:{}", github::fingerprint(GITHUB_PAT));
    let mutate_key = format!("{credential_key}|can_mutate|github:repository");
    let access_key = format!("{credential_key}|can_access|github:repository");
    assert_eq!(count_relationships(workspace.path(), &mutate_key), 0);
    assert_eq!(count_relationships(workspace.path(), &access_key), 1);
}

/// R5: a Cloudflare + GitHub credential workspace coexists without regressing
/// the golden finding count and without duplicating edges.
#[test]
fn r5_mixed_cloudflare_plus_github_credentials() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), GOLDEN_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let environment = [
        ("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN),
        ("GITHUB_TOKEN", GITHUB_PAT),
    ];
    // The offline github default carries no problems, so the scan stays
    // COMPLETE and the golden finding count is unchanged.
    let result = ScanService::run_with_home_and_environment_and_providers(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(valid_cloudflare_provider(workspace.path(), home.path())),
        None,
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.agent_count, 1);
    assert_eq!(result.finding_count, 1, "golden finding count unchanged");

    // Both credential resources coexist.
    assert_eq!(
        count_resources(workspace.path(), "credential", "cloudflare"),
        1
    );
    assert_eq!(count_resources(workspace.path(), "credential", "github"), 1);
    // The provider-scoped repository resource exists.
    assert_eq!(count_resources(workspace.path(), "repository", "github"), 1);

    // No duplicate edges: exactly one cloudflare worker can_mutate and exactly
    // one github repository can_access.
    let github_credential_key = format!("credential:github:{}", github::fingerprint(GITHUB_PAT));
    assert_eq!(
        count_relationships(
            workspace.path(),
            &format!("{github_credential_key}|can_access|github:repository")
        ),
        1
    );
    assert_eq!(
        count_relationships(
            workspace.path(),
            &format!("{github_credential_key}|can_mutate|github:repository")
        ),
        0
    );
    assert_eq!(
        count_relationships(
            workspace.path(),
            "credential:cloudflare:not-a-real-fingerprint|can_mutate|cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456"
        ),
        0
    );
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let cloudflare_mutate: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM relationships
             WHERE canonical_key LIKE 'credential:cloudflare:%' AND kind = 'can_mutate'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        cloudflare_mutate, 1,
        "no duplicate cloudflare mutation edge"
    );

    // Both providers are reported in the diagnostics surface (S019).
    let detail = result.diagnostics_detail.expect("diagnostics populated");
    let names: Vec<&str> = detail
        .provider_statuses
        .iter()
        .map(|provider| provider.name.as_str())
        .collect();
    assert!(names.contains(&"github"));
    assert!(names.contains(&"cloudflare"));
    assert!(detail
        .provider_statuses
        .iter()
        .all(|provider| provider.reachable));
}

/// R8: broad sanitized battery — types, offline vs live, fine-grained, mixed,
/// and provider-failure (probe unavailable => UNKNOWN + PARTIAL-aware).
#[test]
fn r8_battery_github_types_live_offline_finegrained_mixed_failure() {
    // (a) Fine-grained PAT: even with a repo scope header the per-repo
    // permissions are unobservable => UNKNOWN + reason, read-only edge.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_opencode(workspace.path(), ALLOW_OPENCODE);
        InitService::run(workspace.path()).unwrap();
        let environment = [("GITHUB_PERSONAL_ACCESS_TOKEN", GITHUB_FINE_GRAINED)];
        let result = ScanService::run_with_home_and_environment_and_github(
            workspace.path(),
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
            Some(live_result(
                &github::fingerprint(GITHUB_FINE_GRAINED),
                "fine_grained_pat",
                &["repo"],
            )),
        )
        .unwrap();
        assert_eq!(result.status, ScanStatus::Complete);
        let credential_key = format!(
            "credential:github:{}",
            github::fingerprint(GITHUB_FINE_GRAINED)
        );
        assert_eq!(
            count_relationships(
                workspace.path(),
                &format!("{credential_key}|can_mutate|github:repository")
            ),
            0,
            "fine-grained never fabricates write"
        );
        assert_eq!(
            count_relationships(
                workspace.path(),
                &format!("{credential_key}|can_access|github:repository")
            ),
            1
        );
        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let metadata: String = db
            .connection()
            .query_row(
                "SELECT metadata FROM relationships WHERE canonical_key = ?1",
                [format!("{credential_key}|can_access|github:repository")],
                |row| row.get(0),
            )
            .unwrap();
        assert!(metadata.contains("\"authority_resolution\":\"UNKNOWN\""));
        assert!(metadata.contains("GITHUB_FINE_GRAINED_PERMISSIONS_UNOBSERVABLE"));
    }

    // (b) Type classification surfaces on the credential resource (classic /
    // fine-grained / oauth / unknown).
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_opencode(workspace.path(), ALLOW_OPENCODE);
        InitService::run(workspace.path()).unwrap();
        let environment = [
            ("GITHUB_TOKEN", GITHUB_PAT),
            ("GH_TOKEN", GITHUB_FINE_GRAINED),
            ("GITHUB_PERSONAL_ACCESS_TOKEN", GITHUB_OAUTH),
        ];
        let discovered = discover_with_environment(
            workspace.path(),
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
        )
        .unwrap();
        let github_types: Vec<&str> = discovered
            .credentials
            .iter()
            .filter(|credential| credential.provider == "github")
            .map(|credential| credential.credential_type)
            .collect();
        assert_eq!(github_types, ["classic_pat", "fine_grained_pat", "oauth"]);
        // OAuth is offline-unknown, never a write claim.
        let github = discovered.github.expect("github result present");
        assert_eq!(github.resolution, AuthorityResolution::Unknown);
    }

    // (c) Mixed Cloudflare + GitHub live write: both coexist; finding count
    // stays at the golden single finding.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_opencode(workspace.path(), GOLDEN_OPENCODE);
        InitService::run(workspace.path()).unwrap();
        let environment = [
            ("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN),
            ("GITHUB_TOKEN", GITHUB_PAT),
        ];
        let result = ScanService::run_with_home_and_environment_and_providers(
            workspace.path(),
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
            Some(valid_cloudflare_provider(workspace.path(), home.path())),
            Some(live_result(
                &github::fingerprint(GITHUB_PAT),
                "classic_pat",
                &["repo"],
            )),
        )
        .unwrap();
        assert_eq!(result.finding_count, 1);
        let github_credential_key =
            format!("credential:github:{}", github::fingerprint(GITHUB_PAT));
        assert_eq!(
            count_relationships(
                workspace.path(),
                &format!("{github_credential_key}|can_mutate|github:repository")
            ),
            1
        );
    }

    // (d) Provider failure: probe unavailable => UNKNOWN + PARTIAL-aware.
    {
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_opencode(workspace.path(), ALLOW_OPENCODE);
        InitService::run(workspace.path()).unwrap();
        let environment = [("GITHUB_TOKEN", GITHUB_PAT)];
        let result = ScanService::run_with_home_and_environment_and_github(
            workspace.path(),
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
            Some(failure_result(
                &github::fingerprint(GITHUB_PAT),
                "classic_pat",
                "github provider transport unavailable",
            )),
        )
        .unwrap();
        assert_eq!(
            result.status,
            ScanStatus::Partial,
            "probe failure is PARTIAL"
        );
        let detail = result.diagnostics_detail.expect("diagnostics populated");
        assert_eq!(detail.scan_status, "PARTIAL");
        assert_eq!(detail.partial_reason.as_deref(), Some("github"));
        let github = detail
            .provider_statuses
            .iter()
            .find(|provider| provider.name == "github")
            .expect("github provider status present");
        assert!(!github.reachable);
        // The authority edge stays read/UNKNOWN, never a fabricated write.
        let credential_key = format!("credential:github:{}", github::fingerprint(GITHUB_PAT));
        assert_eq!(
            count_relationships(
                workspace.path(),
                &format!("{credential_key}|can_mutate|github:repository")
            ),
            0
        );
        assert_eq!(
            count_relationships(
                workspace.path(),
                &format!("{credential_key}|can_access|github:repository")
            ),
            1
        );
    }
}

/// R10: secret sweep — the synthetic GitHub token never leaks into persisted
/// metadata, relationship keys, evidence, or observations.
#[test]
fn r10_secret_sweep_never_leaks_github_token() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let environment = [("GITHUB_TOKEN", GITHUB_PAT)];
    let result = ScanService::run_with_home_and_environment_and_github(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(live_result(
            &github::fingerprint(GITHUB_PAT),
            "classic_pat",
            &["repo"],
        )),
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let leaks: i64 = db
        .connection()
        .query_row(
            "SELECT
              (SELECT COUNT(*) FROM resources WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
              (SELECT COUNT(*) FROM relationships WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
              (SELECT COUNT(*) FROM evidence WHERE observation LIKE '%' || ?1 || '%' OR CAST(metadata AS TEXT) LIKE '%' || ?1 || '%') +
              (SELECT COUNT(*) FROM observations WHERE CAST(metadata AS TEXT) LIKE '%' || ?1 || '%')",
            [GITHUB_PAT],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(leaks, 0);
}
