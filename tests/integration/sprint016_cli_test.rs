//! Sprint 016 CLI surfacing fixtures (R6/R10).
//!
//! R6 asserts the explained finding view states the OpenCode effective Bash
//! capability (`AUTO_ALLOW` / `APPROVAL_GATED` / `DENIED` / `SANDBOXED`) plus the
//! interrupting boundary kind on the `can_execute` edge. R10 asserts the
//! rendered output and persisted metadata never leak a synthetic credential
//! value for any resolved effective state.

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
use pico::persistence::{Database, RelationshipRepo};
use tempfile::tempdir;

/// Synthetic fake Cloudflare token used only to prove it never reaches output.
const FAKE_TOKEN: &str = "cfut_TESTFAKE000000000000000000000000000000";
const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";

fn opencode_config(permission_bash: &str, sandbox: bool) -> String {
    let sandbox_field = if sandbox { r#", "sandbox": true"# } else { "" };
    format!(
        r#"{{ "$schema": "https://opencode.ai/config.json", "permission": {{ "bash": "{permission_bash}" }}{sandbox_field}, "mcp": {{ "servers": {{ "github": {{ "type": "local", "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"], "environment": {{ "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST" }} }} }} }} }}"#
    )
}

fn setup_with(config: &str) -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), config).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
    classification: Option<&str>,
    fake_token: &str,
) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", fake_token)];
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
        sink_impact: classification.map(str::to_string),
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

fn scan_with_bash(
    permission_bash: &str,
    sandbox: bool,
    fake_token: &str,
) -> (tempfile::TempDir, ScanResult) {
    let workspace = setup_with(&opencode_config(permission_bash, sandbox));
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", fake_token)];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            home.path(),
            Some("PRODUCTION"),
            fake_token,
        )),
    )
    .unwrap();
    (workspace, result)
}

/// The `can_execute` edge carries `effective_state`; only AUTO_ALLOW and
/// SANDBOXED yield an active production path (and thus a finding). The other two
/// resolved postures block/uncertainty the path, so they are asserted against
/// the normalized relationship metadata instead of a rendered finding.
#[test]
fn effective_bash_capability_surfaces_in_explain_for_auto_allow_and_sandbox() {
    for (bash, sandbox, label, boundary) in [
        ("allow", false, "AUTO_ALLOW", "none"),
        ("allow", true, "SANDBOXED", "SANDBOX"),
    ] {
        let (workspace, scan) = scan_with_bash(bash, sandbox, FAKE_TOKEN);
        assert_eq!(scan.status, ScanStatus::Complete);
        assert_eq!(
            scan.finding_count, 1,
            "golden-style path must stay at 1 finding"
        );

        let list = FindingQueryService::list_latest(workspace.path()).unwrap();
        let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
        let rendered = render_finding_detail(&detail);

        assert!(
            rendered.contains(&format!("Effective Bash capability: {label}")),
            "expected '{label}' in:\n{rendered}"
        );
        assert!(
            rendered.contains(&format!("Bash interrupting boundary: {boundary}")),
            "expected boundary '{boundary}' in:\n{rendered}"
        );
        assert!(rendered.contains(label));
    }
}

/// Every resolved effective state must render its label and interrupting
/// boundary in the explained view, independent of whether the resolved posture
/// still produces an active finding. This exercises the renderer directly for
/// the APPROVAL_GATED and DENIED postures, which block/uncertainty the path.
#[test]
fn rendered_explain_shows_effective_bash_capability_for_each_state() {
    let cases = [
        ("AUTO_ALLOW", "none"),
        ("APPROVAL_GATED", "MANDATORY_APPROVAL"),
        ("DENIED", "HARD_DENY"),
        ("SANDBOXED", "SANDBOX"),
    ];
    for (label, boundary) in cases {
        let detail = minimal_detail_with_capability(label, boundary);
        let rendered = render_finding_detail(&detail);
        assert!(
            rendered.contains(&format!("Effective Bash capability: {label}")),
            "expected '{label}' in:\n{rendered}"
        );
        assert!(
            rendered.contains(&format!("Bash interrupting boundary: {boundary}")),
            "expected boundary '{boundary}' for '{label}' in:\n{rendered}"
        );
    }
}

#[test]
fn approval_gated_and_denied_persist_effective_state_on_can_execute() {
    for (bash, label) in [("ask", "APPROVAL_GATED"), ("deny", "DENIED")] {
        let (workspace, scan) = scan_with_bash(bash, false, FAKE_TOKEN);
        assert_eq!(scan.status, ScanStatus::Complete);

        let db = Database::open_existing(&workspace.path().join(".pico").join("pico.db")).unwrap();
        let relationships = RelationshipRepo::new(db.connection());
        let can_execute: Vec<_> = relationships
            .list()
            .unwrap()
            .into_iter()
            .filter(|relationship| relationship.kind == "can_execute")
            .collect();
        assert_eq!(can_execute.len(), 1, "exactly one can_execute edge");
        let metadata = can_execute[0]
            .metadata
            .as_ref()
            .expect("can_execute must carry metadata");
        let persisted = metadata
            .get("effective_state")
            .and_then(serde_json::Value::as_str)
            .expect("effective_state must be present");
        assert_eq!(
            persisted, label,
            "persisted effective_state for bash={bash}"
        );
        drop(db);
    }
}

/// R10: for every supported effective-state fixture, no rendered line and no
/// persisted metadata contains the synthetic credential value.
#[test]
fn secret_sweep_never_leaks_fake_token_across_effective_states() {
    for (bash, sandbox) in [
        ("allow", false),
        ("allow", true),
        ("ask", false),
        ("deny", false),
    ] {
        let (workspace, scan) = scan_with_bash(bash, sandbox, FAKE_TOKEN);
        assert_eq!(scan.status, ScanStatus::Complete);

        let db = Database::open_existing(&workspace.path().join(".pico").join("pico.db")).unwrap();

        let locators: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(source_locator), '') FROM evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !locators.contains(FAKE_TOKEN),
            "evidence source_locators leaked the fake token for bash={bash}/sandbox={sandbox}"
        );
        assert!(
            !locators.contains(SECRET_SENTINEL),
            "evidence source_locators leaked the secret sentinel for bash={bash}/sandbox={sandbox}"
        );

        let metadata_dump: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM relationships",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !metadata_dump.contains(FAKE_TOKEN),
            "relationship metadata leaked the fake token for bash={bash}/sandbox={sandbox}"
        );

        let resource_dump: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(metadata), '') FROM resources",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !resource_dump.contains(FAKE_TOKEN),
            "resource metadata leaked the fake token for bash={bash}/sandbox={sandbox}"
        );
        drop(db);

        let list = FindingQueryService::list_latest(workspace.path()).unwrap();
        if let Some(finding) = list.findings.first() {
            let detail = FindingQueryService::get(workspace.path(), &finding.id).unwrap();
            let rendered = render_finding_detail(&detail);
            assert!(
                !rendered.contains(FAKE_TOKEN),
                "rendered detail leaked the fake token for bash={bash}/sandbox={sandbox}"
            );
            assert!(
                !rendered.contains(SECRET_SENTINEL),
                "rendered detail leaked the secret sentinel for bash={bash}/sandbox={sandbox}"
            );
        }
    }
}

fn minimal_detail_with_capability(label: &str, boundary: &str) -> FindingDetail {
    let path = ExplainedPath {
        id: "attack_path_x".to_string(),
        fingerprint: "sha256:x".to_string(),
        disposition: "ACTIVE".to_string(),
        source_trust: "PUBLIC_EXTERNAL".to_string(),
        influence_strength: "AGENT_RETRIEVABLE".to_string(),
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
            relationship_kind: "can_execute".to_string(),
            from_resource: ResourceView {
                id: "a".to_string(),
                canonical_key: "agent:opencode".to_string(),
                kind: "agent".to_string(),
                provider: "opencode".to_string(),
                name: "OpenCode".to_string(),
            },
            to_resource: ResourceView {
                id: "b".to_string(),
                canonical_key: "shell:bash".to_string(),
                kind: "shell".to_string(),
                provider: "local".to_string(),
                name: "Bash".to_string(),
            },
            relationship_state: "DERIVED".to_string(),
            evidence_ids: vec![],
            supporting_evidence: vec![],
        }],
        boundaries: vec![],
        effective_bash_capability: Some(label.to_string()),
        bash_boundary: if boundary == "none" {
            None
        } else {
            Some(boundary.to_string())
        },
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
