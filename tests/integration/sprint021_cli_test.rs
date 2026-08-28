//! Sprint 021 CLI surfacing fixtures (R6 / R10).
//!
//! R6 asserts the `pico scan` summary renders a per-GitHub-credential
//! `GitHub credential authority:` block carrying the resolved tier
//! (`GitHub <credential_type> authority: resolution=<tier> permission=<state>
//! reasons=[...]`), for both a live classic-PAT repo-scope probe (EXACT /
//! REPO_WRITE) and the offline path (UNKNOWN +
//! GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE), while the golden path (no GitHub
//! token) renders no GitHub block. R10 asserts that across the github postures
//! (classic live repo, read-only, fine-grained, offline) the rendered authority
//! block, the explained finding output, and the persisted metadata never
//! contain a synthetic GitHub token value. All scans run through fixture
//! transports / injected normalized results; no network access is involved.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanService};
use pico::cli::render::{render_finding_detail, render_github_credential_authority};
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

/// Synthetic fake GitHub classic PAT used only to prove it never reaches output.
const GITHUB_PAT: &str = "ghp_TESTFAKE0000000000000000000000000000";
/// Synthetic fake GitHub fine-grained PAT used only to prove it never leaks.
const GITHUB_FINE_GRAINED: &str = "github_pat_TESTFAKE00000000000000000000";
/// Synthetic fake Cloudflare token used for the golden-style provider scan.
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

/// Scan an OpenCode `allow` workspace with a synthetic GitHub credential and an
/// optional injected normalized GitHub result (None => offline default).
fn scan_github(
    github_result: Option<GitHubAuthorityResult>,
) -> (tempfile::TempDir, pico::application::ScanResult) {
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
        github_result,
    )
    .unwrap();
    (workspace, result)
}

/// A Cloudflare provider projection producing the golden-style single active
/// finding, so a scan that mixes a GitHub credential with it keeps the golden
/// finding count while still observing the GitHub authority.
fn cloudflare_provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN)];
    let discovered = discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
    };
    let worker_key = worker.canonical_key();
    ProviderResult {
        credential_fingerprint: discovered.credentials[0].fingerprint.clone(),
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

/// R6 (live): the scan summary renders a per-GitHub-credential authority block
/// with the resolved EXACT tier for a live classic-PAT repo-scope probe.
#[test]
fn cli_scan_summary_surfaces_github_credential_authority_live_exact() {
    let (workspace, scan) = scan_github(Some(live_result(
        &github::fingerprint(GITHUB_PAT),
        "classic_pat",
        &["repo"],
    )));
    assert_eq!(scan.status, ScanStatus::Complete);

    let rendered = render_github_credential_authority(&scan.github_credentials);
    assert!(
        rendered.contains("GitHub credential authority:"),
        "expected a GitHub credential authority block in:\n{rendered}"
    );
    assert!(
        rendered.contains("GitHub classic_pat authority:"),
        "expected credential_type=classic_pat in:\n{rendered}"
    );
    assert!(
        rendered.contains("resolution=EXACT"),
        "expected the EXACT tier in:\n{rendered}"
    );
    assert!(
        rendered.contains("permission=REPO_WRITE"),
        "expected permission_state=REPO_WRITE in:\n{rendered}"
    );
    assert!(
        !rendered.contains(GITHUB_PAT),
        "rendered block leaked the synthetic GitHub token in:\n{rendered}"
    );
    let _ = workspace;
}

/// R6 (offline): a GitHub credential without a probe resolves UNKNOWN and the
/// rendered block carries the unobservable reason instead of a fabricated write.
#[test]
fn cli_scan_summary_surfaces_github_credential_authority_offline_unknown() {
    let (workspace, scan) = scan_github(None);
    assert_eq!(scan.status, ScanStatus::Complete);

    let rendered = render_github_credential_authority(&scan.github_credentials);
    assert!(
        rendered.contains("GitHub credential authority:"),
        "expected a GitHub credential authority block in:\n{rendered}"
    );
    assert!(
        rendered.contains("resolution=UNKNOWN"),
        "offline authority must resolve UNKNOWN in:\n{rendered}"
    );
    assert!(
        rendered.contains("permission=READ_OR_UNKNOWN"),
        "offline permission state must be READ_OR_UNKNOWN in:\n{rendered}"
    );
    assert!(
        rendered.contains("reasons=[GITHUB_REPO_WRITE_SCOPE_UNOBSERVABLE]"),
        "offline reason must be surfaced in:\n{rendered}"
    );
    assert!(
        !rendered.contains("permission=REPO_WRITE"),
        "offline must never fabricate a write permission state in:\n{rendered}"
    );
    let _ = workspace;
}

/// R6 (golden path): a scan without a GitHub credential renders no GitHub
/// block, and the golden-style scan still yields exactly one active finding.
#[test]
fn cli_scan_summary_golden_path_has_no_github_block() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), GOLDEN_OPENCODE);
    InitService::run(workspace.path()).unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", CLOUDFLARE_TOKEN)];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(cloudflare_provider(workspace.path(), home.path())),
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(
        result.finding_count, 1,
        "golden path must stay at 1 finding (SPRINT-021 golden path)"
    );
    assert!(
        result.github_credentials.is_empty(),
        "golden path must observe no GitHub credential"
    );
    let rendered = render_github_credential_authority(&result.github_credentials);
    assert!(
        rendered.is_empty(),
        "golden path must render no GitHub block, got:\n{rendered}"
    );
    assert!(!rendered.contains("GitHub credential authority"));
}

/// R10 (CLI): across the github postures (classic live repo scope, read-only,
/// fine-grained, offline) the rendered authority block, the explained finding
/// output, and the persisted metadata never contain the synthetic token value.
#[test]
fn r10_cli_surfacing_never_leaks_github_token_across_postures() {
    // (environment token, injected normalized result) per posture.
    let postures: Vec<(&str, Option<GitHubAuthorityResult>)> = vec![
        // classic PAT, live repo scope => EXACT / REPO_WRITE.
        (
            GITHUB_PAT,
            Some(live_result(
                &github::fingerprint(GITHUB_PAT),
                "classic_pat",
                &["repo"],
            )),
        ),
        // classic PAT, read-only scopes => BEHAVIORAL_READ_ONLY / READ_ONLY.
        (
            GITHUB_PAT,
            Some(live_result(
                &github::fingerprint(GITHUB_PAT),
                "classic_pat",
                &["read:user", "read:org"],
            )),
        ),
        // fine-grained PAT => UNKNOWN + unobservable reason.
        (
            GITHUB_FINE_GRAINED,
            Some(live_result(
                &github::fingerprint(GITHUB_FINE_GRAINED),
                "fine_grained_pat",
                &["repo"],
            )),
        ),
        // offline (no probe) => UNKNOWN + unobservable reason.
        (GITHUB_PAT, None),
    ];
    let mut posture_index = 0;
    for (token, github_result) in postures {
        posture_index += 1;
        let workspace = tempdir().unwrap();
        let home = tempdir().unwrap();
        write_opencode(workspace.path(), ALLOW_OPENCODE);
        InitService::run(workspace.path()).unwrap();
        let environment = [("GITHUB_TOKEN", token)];
        let scan = ScanService::run_with_home_and_environment_and_github(
            workspace.path(),
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
            github_result,
        )
        .unwrap();
        assert_eq!(scan.status, ScanStatus::Complete);

        let authority_block = render_github_credential_authority(&scan.github_credentials);
        assert!(
            !authority_block.contains(GITHUB_PAT)
                && !authority_block.contains(GITHUB_FINE_GRAINED),
            "posture {posture_index}: authority block leaked a synthetic token in:\n{authority_block}"
        );

        // Any finding (e.g. a mixed scan) must also stay token-free.
        let list = FindingQueryService::list_latest(workspace.path()).unwrap();
        let mut rendered_findings = String::new();
        for summary in &list.findings {
            let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();
            rendered_findings.push_str(&render_finding_detail(&detail));
        }
        assert!(
            !rendered_findings.contains(GITHUB_PAT)
                && !rendered_findings.contains(GITHUB_FINE_GRAINED),
            "posture {posture_index}: explained finding leaked a synthetic token in:\n{rendered_findings}"
        );

        // Persisted metadata must also be token-free.
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
        assert_eq!(
            leaks, 0,
            "posture {posture_index}: persisted metadata leaked a synthetic token"
        );
    }
}
