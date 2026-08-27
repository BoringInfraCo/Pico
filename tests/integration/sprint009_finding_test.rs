//! Sprint 009 controlled classification fixtures.
//!
//! These fixtures provide only normalized, sanitized provider facts. They do
//! not contact Cloudflare and never put a token or provider response into the
//! graph. Production is accepted only when the explicit normalized seam says
//! `PRODUCTION`; names and account labels are deliberately insufficient.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::RelationshipState;
use pico::persistence::Database;
use tempfile::tempdir;

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST" }
    }
  }}
}"#;

fn setup() -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
    sink_impact: Option<&str>,
    script_name: &str,
) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: script_name.to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: sink_impact.map(str::to_string),
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

fn scan_with_classification(
    classification: Option<&str>,
    script_name: &str,
) -> (tempfile::TempDir, pico::application::ScanResult) {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            home.path(),
            classification,
            script_name,
        )),
    )
    .unwrap();
    (workspace, result)
}

#[test]
fn explicit_production_classification_is_persisted_as_safe_metadata() {
    let (workspace, result) = scan_with_classification(Some("PRODUCTION"), "checkout");
    assert_eq!(result.status, pico::domain::ScanStatus::Complete);
    assert_eq!(result.finding_count, 1);
    let generated = pico::findings::generate_with_scan_status(
        result.graph.as_ref().unwrap(),
        result.analysis.as_ref().unwrap(),
        result.status,
        &pico::findings::FindingLimits::default(),
    );
    assert_eq!(
        generated.status,
        pico::findings::FindingGenerationStatus::Complete
    );
    assert_eq!(generated.findings.len(), 1);
    assert_eq!(
        generated.findings[0].finding_class,
        pico::findings::FindingClass::UntrustedToProduction
    );
    assert_eq!(
        generated.findings[0].severity,
        pico::findings::Severity::Critical
    );
    assert_eq!(
        generated.findings[0].confidence,
        pico::findings::Confidence::High
    );
    let limited_limits = pico::findings::FindingLimits {
        maximum_attack_paths_examined: 0,
        ..pico::findings::FindingLimits::default()
    };
    let limited = pico::findings::generate(
        result.graph.as_ref().unwrap(),
        result.analysis.as_ref().unwrap(),
        &limited_limits,
    );
    assert_eq!(
        limited.status,
        pico::findings::FindingGenerationStatus::Limited
    );
    assert!(limited.findings.is_empty());
    let finding = &generated.findings[0];
    assert!(!finding.evidence_ids.is_empty());
    assert!(finding
        .evidence_ids
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
    assert_eq!(finding.reasons.len(), 6);
    assert_eq!(finding.remediations.len(), 4);
    assert!(finding
        .evidence_ids
        .iter()
        .all(|id| !id.contains(SECRET_SENTINEL)));
    assert!(!serde_json::to_string(finding)
        .unwrap()
        .contains(SECRET_SENTINEL));
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let finding_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
        .unwrap();
    let path_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM finding_paths", [], |row| row.get(0))
        .unwrap();
    let finding_evidence_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM finding_evidence", [], |row| {
            row.get(0)
        })
        .unwrap();
    let reason_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM finding_reasons", [], |row| row.get(0))
        .unwrap();
    let remediation_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM finding_remediations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(finding_rows, 1);
    assert_eq!(path_rows, 1);
    assert!(finding_evidence_rows >= 1);
    assert_eq!(reason_rows, 6);
    assert_eq!(remediation_rows, 4);
    let metadata: String = db
        .connection()
        .query_row(
            "SELECT metadata FROM resources WHERE canonical_key = ?1",
            ["cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(metadata.contains("PRODUCTION"));
    assert!(!metadata.contains(SECRET_SENTINEL));
    let finding_counts: (i64, i64, i64, i64, i64) = db
        .connection()
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM findings),
                (SELECT COUNT(*) FROM finding_paths),
                (SELECT COUNT(*) FROM finding_evidence),
                (SELECT COUNT(*) FROM finding_reasons),
                (SELECT COUNT(*) FROM finding_remediations)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(finding_counts.0, 1);
    assert_eq!(finding_counts.1, 1);
    assert!(finding_counts.2 >= 1);
    assert_eq!(finding_counts.3, 6);
    assert_eq!(finding_counts.4, 4);
}

#[test]
fn absent_or_unsupported_classification_stays_unknown_even_for_production_named_worker() {
    for classification in [None, Some("UNSUPPORTED")] {
        let (workspace, _) = scan_with_classification(classification, "production-worker");
        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let metadata: String = db
            .connection()
            .query_row(
                "SELECT metadata FROM resources WHERE canonical_key = ?1",
                ["cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(metadata.contains("UNKNOWN"));
        assert!(!metadata.contains("PRODUCTION"));
    }
}

#[test]
fn staging_and_local_dev_are_not_production_and_secret_sentinel_is_absent() {
    for classification in ["STAGING", "LOCAL_DEV"] {
        let (workspace, _) = scan_with_classification(Some(classification), "checkout");
        let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
        let serialized: String = db
            .connection()
            .query_row(
                "SELECT COALESCE(GROUP_CONCAT(metadata, '|'), '') FROM resources",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(serialized.contains(classification));
        assert!(!serialized.contains(SECRET_SENTINEL));
    }
}

#[test]
fn blocked_and_unresolved_authority_never_emit_a_finding() {
    for (state, resolution) in [
        (RelationshipState::Blocked, AuthorityResolution::Exact),
        (RelationshipState::Derived, AuthorityResolution::Unknown),
    ] {
        let workspace = setup();
        let home = tempdir().unwrap();
        let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
        let mut normalized = provider(
            workspace.path(),
            home.path(),
            Some("PRODUCTION"),
            "checkout",
        );
        normalized.authorities[0].state = state;
        normalized.authorities[0].resolution = resolution;
        let result = ScanService::run_with_home_and_environment_and_provider(
            workspace.path(),
            Some(home.path()),
            Some(&environment),
            EnvironmentReachability::Proven,
            Some(normalized),
        )
        .unwrap();
        assert_eq!(result.finding_count, 0);
        let generated = pico::findings::generate_with_scan_status(
            result.graph.as_ref().unwrap(),
            result.analysis.as_ref().unwrap(),
            result.status,
            &pico::findings::FindingLimits::default(),
        );
        assert!(generated.findings.is_empty());
    }
}

#[test]
fn partial_provider_scan_never_emits_a_positive_finding() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let mut normalized = provider(
        workspace.path(),
        home.path(),
        Some("PRODUCTION"),
        "checkout",
    );
    normalized
        .problems
        .push("bounded fixture problem".to_string());
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(normalized),
    )
    .unwrap();
    assert_eq!(result.status, pico::domain::ScanStatus::Partial);
    assert_eq!(result.finding_count, 0);
    let generated = pico::findings::generate_with_scan_status(
        result.graph.as_ref().unwrap(),
        result.analysis.as_ref().unwrap(),
        result.status,
        &pico::findings::FindingLimits::default(),
    );
    assert!(generated.findings.is_empty());
}

#[test]
fn equivalent_production_scans_keep_finding_fingerprint_and_scope_ids() {
    let workspace = setup();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let first_home = tempdir().unwrap();
    let first = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(first_home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            first_home.path(),
            Some("PRODUCTION"),
            "checkout",
        )),
    )
    .unwrap();
    let second_home = tempdir().unwrap();
    let second = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(second_home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(
            workspace.path(),
            second_home.path(),
            Some("PRODUCTION"),
            "checkout",
        )),
    )
    .unwrap();
    let first_finding = pico::findings::generate(
        first.graph.as_ref().unwrap(),
        first.analysis.as_ref().unwrap(),
        &pico::findings::FindingLimits::default(),
    )
    .findings
    .pop()
    .unwrap();
    let second_finding = pico::findings::generate(
        second.graph.as_ref().unwrap(),
        second.analysis.as_ref().unwrap(),
        &pico::findings::FindingLimits::default(),
    )
    .findings
    .pop()
    .unwrap();
    assert_eq!(first_finding.fingerprint, second_finding.fingerprint);
    assert_ne!(first_finding.id, second_finding.id);
    assert_ne!(first_finding.scan_id, second_finding.scan_id);
    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let persisted_findings: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
        .unwrap();
    assert_eq!(persisted_findings, 2);
}
