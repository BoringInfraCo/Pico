//! Sprint 018 CLI surfacing fixtures (R6 / R7 / R10).
//!
//! R6 asserts the explained finding view lists a per-Cloudflare-edge authority
//! block (`Cloudflare <credential_type> authority: resolution=... granted=[...] scope=...`)
//! carrying the resolved credential type and the granted permission groups, and
//! (for a global API key) an unverified marker. R10 asserts the rendered output
//! and the persisted metadata never leak a synthetic Cloudflare token value
//! across the api_token / api_key / oauth credential postures.

use std::fs;

use pico::application::findings::CloudflareAuthorityView;
use pico::application::{
    ExplainedPath, FindingDetail, FindingQueryService, InitService, PathStep, ResourceView,
    ScanBrief, ScanResult, ScanService,
};
use pico::cli::render::render_finding_detail;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use tempfile::tempdir;

/// Synthetic fake Cloudflare API token (cfut_ => api_token). Never a real secret.
const FAKE_CF_API_TOKEN: &str = "cfut_TESTFAKE0000000000000000000000000000";
/// Synthetic fake Cloudflare OAuth token (cwo_ => oauth). Never a real secret.
const FAKE_CF_OAUTH: &str = "cwo_TESTFAKE0000000000000000000000000000";
/// Synthetic fake Cloudflare global API key shape (api_key). Never a real secret.
const FAKE_CF_API_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcd";

fn golden_config(token: &str) -> String {
    format!(
        r#"{{ "$schema": "https://opencode.ai/config.json", "permission": {{ "bash": "allow" }}, "mcp": {{ "servers": {{ "github": {{ "type": "local", "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"], "environment": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "{token}" }} }} }} }} }}"#
    )
}

fn setup_with(config: &str) -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), config).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

/// A Cloudflare provider projection whose single Worker is classified
/// PRODUCTION and whose authority carries the supplied granted permission groups
/// and zone-scoped flag, so the scan produces an active finding with a
/// `can_mutate` edge in the path.
fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
    granted_permissions: Vec<String>,
    zone_scoped: bool,
) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_CF_API_TOKEN)];
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
            granted_permissions,
            zone_scoped,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn scan_with(
    workspace: tempfile::TempDir,
    granted_permissions: Vec<String>,
    zone_scoped: bool,
) -> (tempfile::TempDir, ScanResult) {
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_CF_API_TOKEN)];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            home.path(),
            granted_permissions,
            zone_scoped,
        )),
    )
    .unwrap();
    (workspace, result)
}

/// R6: the explained finding for the golden config lists a per-Cloudflare-edge
/// authority block with the resolved api_token credential type and the granted
/// permission groups.
#[test]
fn cloudflare_authority_surfaces_in_cli_explain() {
    let workspace = setup_with(&golden_config(FAKE_CF_API_TOKEN));
    let (workspace, scan) = scan_with(workspace, vec!["Workers Scripts Write".to_string()], false);
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(
        scan.finding_count, 1,
        "golden-style path must stay at 1 finding (SPRINT-018 golden path)"
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    let rendered = render_finding_detail(&detail);

    assert!(
        rendered.contains("Cloudflare authority:"),
        "expected a Cloudflare authority block in:\n{rendered}"
    );
    assert!(
        rendered.contains("Cloudflare api_token authority:"),
        "expected credential_type=api_token in:\n{rendered}"
    );
    assert!(
        rendered.contains("resolution=EXACT"),
        "expected EXACT authority resolution in:\n{rendered}"
    );
    assert!(
        rendered.contains("granted=[Workers Scripts Write]"),
        "expected granted permission group in:\n{rendered}"
    );
    assert!(
        rendered.contains("scope=IN_SCOPE"),
        "expected account scope state in:\n{rendered}"
    );
    assert!(
        !rendered.contains(FAKE_CF_API_TOKEN),
        "rendered explain leaked the synthetic Cloudflare token in:\n{rendered}"
    );
}

/// R6 (zone-scoped variant): a zone-scoped grant appends the `zone-scoped`
/// marker to the authority line.
#[test]
fn cloudflare_authority_zone_scoped_marker_surfaces() {
    let workspace = setup_with(&golden_config(FAKE_CF_API_TOKEN));
    let (workspace, scan) = scan_with(workspace, vec!["Workers Scripts Write".to_string()], true);
    assert_eq!(scan.status, ScanStatus::Complete);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    let rendered = render_finding_detail(&detail);

    assert!(
        rendered.contains("zone-scoped"),
        "expected zone-scoped marker in:\n{rendered}"
    );
}

/// R6 (global-key variant): a global API key authority is labeled unverified in
/// the rendered block. The synthetic global key never produces a PRODUCTION
/// finding path, so the block is exercised through the renderer directly with a
/// constructed authority entry.
#[test]
fn cloudflare_global_key_marks_unverified_in_cli() {
    let detail = FindingDetail {
        id: "finding_x".to_string(),
        fingerprint: "sha256:x".to_string(),
        attack_path_fingerprints: vec!["sha256:x".to_string()],
        finding_version: 1,
        scan: ScanBrief {
            id: "scan_x".to_string(),
            status: "COMPLETE".to_string(),
            completed_at: Some("2025-01-01T00:00:00Z".to_string()),
        },
        currentness: pico::application::Currentness::LatestComplete,
        freshness_warning: None,
        finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
        status: "OPEN".to_string(),
        title: "Synthetic".to_string(),
        summary: "Synthetic".to_string(),
        severity: "HIGH".to_string(),
        confidence: "HIGH".to_string(),
        scope_note: "note".to_string(),
        severity_basis: "basis".to_string(),
        confidence_basis: "basis".to_string(),
        weakest_evidence: "none".to_string(),
        reasons: vec![],
        paths: vec![ExplainedPath {
            id: "attack_path_x".to_string(),
            fingerprint: "sha256:x".to_string(),
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_INJECTABLE".to_string(),
            capability: "EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "PRODUCTION".to_string(),
            source_resource_id: "s".to_string(),
            actor_resource_id: "a".to_string(),
            sink_resource_id: "k".to_string(),
            steps: vec![],
            boundaries: vec![],
            effective_bash_capability: None,
            bash_boundary: None,
            agents: vec![],
            github_influence: vec![],
            cloudflare_authority: vec![CloudflareAuthorityView {
                worker_key: "cloudflare:worker:global:*".to_string(),
                credential_type: "api_key".to_string(),
                granted_permissions: vec![],
                authority_resolution: "EXACT".to_string(),
                permission_state: "GLOBAL_API_KEY".to_string(),
                account_scope_state: "IN_SCOPE".to_string(),
                zone_scoped: false,
            }],
        }],
        evidence: vec![],
        boundary_summary: "none".to_string(),
        uncertainties: vec![],
        remediations: vec![],
        remediation_note: "note".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };
    let rendered = render_finding_detail(&detail);
    assert!(
        rendered.contains("Cloudflare api_key authority:"),
        "expected api_key credential type in:\n{rendered}"
    );
    assert!(
        rendered.contains("global-key-unverified"),
        "expected global-key-unverified marker in:\n{rendered}"
    );
    assert!(
        !rendered.contains(FAKE_CF_API_KEY),
        "rendered explain leaked the synthetic global key in:\n{rendered}"
    );
}

/// R10: across the api_token / api_key / oauth credential postures the rendered
/// CLI output and the persisted metadata never contain a Cloudflare token value.
#[test]
fn secret_sweep_never_leaks_cloudflare_token_across_postures() {
    // api_token posture, end to end.
    let workspace = setup_with(&golden_config(FAKE_CF_API_TOKEN));
    let (workspace, scan) = scan_with(workspace, vec!["Workers Scripts Write".to_string()], false);
    assert_eq!(scan.status, ScanStatus::Complete);

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let mut rendered = String::new();
    for summary in &list.findings {
        let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();
        rendered.push_str(&render_finding_detail(&detail));
    }
    assert!(
        !rendered.contains(FAKE_CF_API_TOKEN),
        "rendered explain leaked the synthetic api_token in:\n{rendered}"
    );

    let db_connection =
        pico::persistence::Database::open_existing(&workspace.path().join(".pico").join("pico.db"))
            .unwrap();
    let conn = db_connection.connection();
    let metadata_dump: String = conn
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM relationships",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let resource_dump: String = conn
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM resources",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let evidence_dump: String = conn
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(observation), '') FROM evidence",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !metadata_dump.contains(FAKE_CF_API_TOKEN),
        "relationship metadata leaked the synthetic api_token"
    );
    assert!(
        !resource_dump.contains(FAKE_CF_API_TOKEN),
        "resource metadata leaked the synthetic api_token"
    );
    assert!(
        !evidence_dump.contains(FAKE_CF_API_TOKEN),
        "evidence observation leaked the synthetic api_token"
    );

    // oauth posture: the credential_type is derived from the token shape, but the
    // token value must still never reach output or metadata.
    let workspace = setup_with(&golden_config(FAKE_CF_API_TOKEN));
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", FAKE_CF_OAUTH)];
    let oauth_result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            home.path(),
            vec!["Workers Scripts Write".to_string()],
            false,
        )),
    )
    .unwrap();
    assert_eq!(oauth_result.status, ScanStatus::Complete);
    let oauth_list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let mut oauth_rendered = String::new();
    for summary in &oauth_list.findings {
        let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();
        oauth_rendered.push_str(&render_finding_detail(&detail));
    }
    assert!(
        !oauth_rendered.contains(FAKE_CF_OAUTH),
        "rendered explain leaked the synthetic oauth token in:\n{oauth_rendered}"
    );

    // api_key posture: renderer only, asserting neither the key nor any token
    // shape is echoed by the authority block.
    let detail = FindingDetail {
        id: "finding_k".to_string(),
        fingerprint: "sha256:k".to_string(),
        attack_path_fingerprints: vec!["sha256:k".to_string()],
        finding_version: 1,
        scan: ScanBrief {
            id: "scan_k".to_string(),
            status: "COMPLETE".to_string(),
            completed_at: Some("2025-01-01T00:00:00Z".to_string()),
        },
        currentness: pico::application::Currentness::LatestComplete,
        freshness_warning: None,
        finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
        status: "OPEN".to_string(),
        title: "Synthetic".to_string(),
        summary: "Synthetic".to_string(),
        severity: "HIGH".to_string(),
        confidence: "HIGH".to_string(),
        scope_note: "note".to_string(),
        severity_basis: "basis".to_string(),
        confidence_basis: "basis".to_string(),
        weakest_evidence: "none".to_string(),
        reasons: vec![],
        paths: vec![ExplainedPath {
            id: "attack_path_k".to_string(),
            fingerprint: "sha256:k".to_string(),
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_INJECTABLE".to_string(),
            capability: "EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "PRODUCTION".to_string(),
            source_resource_id: "s".to_string(),
            actor_resource_id: "a".to_string(),
            sink_resource_id: "k".to_string(),
            steps: vec![PathStep {
                position: 0,
                phase: "AUTHORITY".to_string(),
                traversal: "FORWARD".to_string(),
                relationship_id: "r".to_string(),
                relationship_kind: "can_mutate".to_string(),
                from_resource: ResourceView {
                    id: "c".to_string(),
                    canonical_key: "credential:cloudflare:x".to_string(),
                    kind: "credential".to_string(),
                    provider: "cloudflare".to_string(),
                    name: "Cloudflare API Token".to_string(),
                },
                to_resource: ResourceView {
                    id: "w".to_string(),
                    canonical_key: "cloudflare:worker:global:*".to_string(),
                    kind: "worker".to_string(),
                    provider: "cloudflare".to_string(),
                    name: "*".to_string(),
                },
                relationship_state: "DERIVED".to_string(),
                evidence_ids: vec![],
                supporting_evidence: vec![],
            }],
            boundaries: vec![],
            effective_bash_capability: None,
            bash_boundary: None,
            agents: vec![],
            github_influence: vec![],
            cloudflare_authority: vec![CloudflareAuthorityView {
                worker_key: "cloudflare:worker:global:*".to_string(),
                credential_type: "api_key".to_string(),
                granted_permissions: vec![],
                authority_resolution: "EXACT".to_string(),
                permission_state: "GLOBAL_API_KEY".to_string(),
                account_scope_state: "IN_SCOPE".to_string(),
                zone_scoped: false,
            }],
        }],
        evidence: vec![],
        boundary_summary: "none".to_string(),
        uncertainties: vec![],
        remediations: vec![],
        remediation_note: "note".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
    };
    let api_key_rendered = render_finding_detail(&detail);
    assert!(
        !api_key_rendered.contains(FAKE_CF_API_KEY),
        "rendered explain leaked the synthetic global key in:\n{api_key_rendered}"
    );
}
