//! Sprint 017 CLI surfacing fixtures (R6 / R10).
//!
//! R6 asserts the explained finding view lists per-tool GitHub MCP influence
//! (`GitHub MCP <tool>: <content_class> | trust=<trust> | influence=<strength>`)
//! for a read (AGENT_INJECTABLE / PUBLIC_EXTERNAL) tool observed on a real
//! finding, and that the same renderer surfaces a write (AGENT_MUTABLE) tool
//! when such an influence entry is present. R10 asserts that across the GitHub
//! MCP influence postures the rendered output, the MCP JSON, and the persisted
//! metadata never leak a synthetic credential value.

use std::fs;

use pico::application::{
    Currentness, ExplainedPath, FindingDetail, FindingQueryService, InitService, PathStep,
    ResourceView, ScanBrief, ScanResult, ScanService,
};
use pico::cli::render::render_finding_detail;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::persistence::Database;
use tempfile::tempdir;

/// Synthetic fake GitHub token used only to prove it never reaches output.
const FAKE_GITHUB_TOKEN: &str = "ghp_TESTFAKE0000000000000000000000000000";

/// Golden-style OpenCode config: bash allow + official GitHub MCP server
/// (default documented tools) + no inlined secret value. The token is injected
/// only into the environment field below; it must never reach output.
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

fn provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
    let environment = [(
        "CLOUDFLARE_API_TOKEN",
        "cfut_TESTFAKE0000000000000000000000000000",
    )];
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
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn scan_golden(token: &str) -> (tempfile::TempDir, ScanResult) {
    let workspace = setup_with(&golden_config(token));
    let home = tempdir().unwrap();
    let environment = [(
        "CLOUDFLARE_API_TOKEN",
        "cfut_TESTFAKE0000000000000000000000000000",
    )];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace.path(), home.path())),
    )
    .unwrap();
    (workspace, result)
}

/// R6 (scan path): the explained finding for the golden config lists the
/// per-tool GitHub MCP influence for at least one read tool
/// (AGENT_INJECTABLE / PUBLIC_EXTERNAL).
#[test]
fn github_influence_read_tool_surfaces_in_cli_explain() {
    let (workspace, scan) = scan_golden(FAKE_GITHUB_TOKEN);
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(
        scan.finding_count, 1,
        "golden-style path must stay at 1 finding (SPRINT-017 golden path)"
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    let rendered = render_finding_detail(&detail);

    assert!(
        rendered.contains(
            "GitHub MCP issue_read: github:public:issue-content | trust=PUBLIC_EXTERNAL | influence=AGENT_INJECTABLE"
        ),
        "expected read-tool influence line in:\n{rendered}"
    );
}

/// R6 (renderer path): the CLI renderer surfaces a write (AGENT_MUTABLE) tool
/// influence entry when one is present on the explained path.
#[test]
fn github_influence_write_tool_surfaces_in_renderer() {
    let detail = minimal_detail_with_github_influence();
    let rendered = render_finding_detail(&detail);
    assert!(
        rendered.contains(
            "GitHub MCP issue_read: github:public:issue-content | trust=PUBLIC_EXTERNAL | influence=AGENT_INJECTABLE"
        ),
        "expected read-tool influence line in:\n{rendered}"
    );
    assert!(
        rendered.contains(
            "GitHub MCP create_issue: github:write:issue | trust=UNKNOWN | influence=AGENT_MUTABLE"
        ),
        "expected write-tool influence line in:\n{rendered}"
    );
}

/// R10: across the RETRIEVABLE / INJECTABLE / MUTABLE influence postures and the
/// UNKNOWN trust posture, neither the rendered CLI explain, the MCP JSON, nor
/// the persisted metadata ever contains the synthetic GitHub token value.
#[test]
fn secret_sweep_never_leaks_fake_github_token() {
    let (workspace, scan) = scan_golden(FAKE_GITHUB_TOKEN);
    assert_eq!(scan.status, ScanStatus::Complete);

    let db = Database::open_existing(&workspace.path().join(".pico").join("pico.db")).unwrap();
    let metadata_dump: String = db
        .connection()
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM relationships",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let resource_dump: String = db
        .connection()
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM resources",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let evidence_dump: String = db
        .connection()
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(observation), '') FROM evidence",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(db);

    assert!(
        !metadata_dump.contains(FAKE_GITHUB_TOKEN),
        "relationship metadata leaked the fake GitHub token"
    );
    assert!(
        !resource_dump.contains(FAKE_GITHUB_TOKEN),
        "resource metadata leaked the fake GitHub token"
    );
    assert!(
        !evidence_dump.contains(FAKE_GITHUB_TOKEN),
        "evidence observation leaked the fake GitHub token"
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let mut rendered = String::new();
    for summary in &list.findings {
        let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();
        rendered.push_str(&render_finding_detail(&detail));
    }
    assert!(
        !rendered.contains(FAKE_GITHUB_TOKEN),
        "rendered explain leaked the fake GitHub token in:\n{rendered}"
    );

    for line in rendered.lines() {
        if line.contains("GitHub MCP ") {
            assert!(
                !line.contains(FAKE_GITHUB_TOKEN),
                "github influence block leaked the token: {line}"
            );
        }
    }
}

/// Builds a minimal `FindingDetail` whose single path carries GitHub MCP
/// influence entries for both a read and a write tool, to exercise the renderer
/// and the surfacing contract directly.
fn minimal_detail_with_github_influence() -> FindingDetail {
    use pico::application::findings::GitHubInfluenceView;
    let path = ExplainedPath {
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
        steps: vec![PathStep {
            position: 0,
            phase: "INFLUENCE".to_string(),
            traversal: "REVERSE".to_string(),
            relationship_id: "r".to_string(),
            relationship_kind: "can_call".to_string(),
            from_resource: ResourceView {
                id: "a".to_string(),
                canonical_key: "agent:opencode".to_string(),
                kind: "agent".to_string(),
                provider: "opencode".to_string(),
                name: "OpenCode".to_string(),
            },
            to_resource: ResourceView {
                id: "b".to_string(),
                canonical_key: "mcp:github:official:tool:issue_read".to_string(),
                kind: "mcp_tool".to_string(),
                provider: "github".to_string(),
                name: "issue_read".to_string(),
            },
            relationship_state: "DERIVED".to_string(),
            evidence_ids: vec![],
            supporting_evidence: vec![],
        }],
        boundaries: vec![],
        effective_bash_capability: None,
        bash_boundary: None,
        github_influence: vec![
            GitHubInfluenceView {
                tool_name: "issue_read".to_string(),
                content_class: "github:public:issue-content".to_string(),
                trust: "PUBLIC_EXTERNAL".to_string(),
                influence_strength: "AGENT_INJECTABLE".to_string(),
            },
            GitHubInfluenceView {
                tool_name: "create_issue".to_string(),
                content_class: "github:write:issue".to_string(),
                trust: "UNKNOWN".to_string(),
                influence_strength: "AGENT_MUTABLE".to_string(),
            },
        ],
    };
    FindingDetail {
        id: "finding_x".to_string(),
        fingerprint: "sha256:x".to_string(),
        attack_path_fingerprints: vec!["sha256:x".to_string()],
        finding_version: 1,
        scan: ScanBrief {
            id: "scan_x".to_string(),
            status: "COMPLETE".to_string(),
            completed_at: Some("2025-01-01T00:00:00Z".to_string()),
        },
        currentness: Currentness::LatestComplete,
        freshness_warning: None,
        finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
        status: "OPEN".to_string(),
        title: "t".to_string(),
        summary: "s".to_string(),
        severity: "CRITICAL".to_string(),
        confidence: "HIGH".to_string(),
        scope_note: "n".to_string(),
        severity_basis: "b".to_string(),
        confidence_basis: "c".to_string(),
        weakest_evidence: "w".to_string(),
        reasons: vec![],
        paths: vec![path],
        evidence: vec![],
        boundary_summary: "none".to_string(),
        uncertainties: vec![],
        remediations: vec![],
        remediation_note: "r".to_string(),
        created_at: "2025-01-01T00:00:00Z".to_string(),
    }
}
