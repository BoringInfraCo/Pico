//! S032 real collection and attribution regressions.

use std::fs;

use pico::application::{
    AttributionClass, DiffService, FindingDiff, FindingDiffResult, InitService, ScanService,
};
use pico::cli::render::render_finding_diff;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use tempfile::tempdir;

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const ALLOW: &str = r#"{
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

fn write_opencode(workspace: &std::path::Path, contents: &str) {
    fs::write(workspace.join("opencode.json"), contents).unwrap();
}

fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW);
    InitService::run(workspace.path()).unwrap();
    (workspace, home)
}

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
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
        worker_tag: Some(format!("worker-tag-{script_name}")),
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

fn scan_named(
    workspace: &std::path::Path,
    home: &std::path::Path,
    script_name: &str,
) -> pico::application::ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace, home, script_name)),
    )
    .unwrap()
}

fn latest(workspace: &std::path::Path) -> FindingDiff {
    match DiffService::latest(workspace).unwrap() {
        FindingDiffResult::Ready(diff) => diff,
        other => panic!("{other:?}"),
    }
}

#[test]
fn s032_real_bash_allow_deny_has_paired_environment_attribution() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "production-worker");
    write_opencode(workspace.path(), &ALLOW.replace("\"allow\"", "\"deny\""));
    scan_named(workspace.path(), home.path(), "production-worker");
    let diff = latest(workspace.path());
    let bash = diff
        .attribution
        .graph_changes
        .iter()
        .find(|c| c.key.contains("can_execute"))
        .unwrap();
    assert_eq!(
        bash.classification,
        AttributionClass::ObservedEnvironmentChange,
        "{bash:?}"
    );
    assert!(!bash.before.evidence_ids.is_empty());
    assert!(!bash.after.evidence_ids.is_empty());
    assert!(bash
        .before
        .supported_fields
        .contains(&"effective_state".into()));
    assert!(!diff.disappeared.is_empty());
    assert!(diff
        .attribution
        .finding_changes
        .iter()
        .all(|c| !c.disappearance_confirmed));
    let finding = diff.attribution.finding_changes.first().unwrap();
    assert_eq!(finding.classification, AttributionClass::Mixed);
    assert!(finding.reasons.contains(&"multiple_possible_causes".into()));
    assert!(!finding.before.evidence_ids.is_empty());
    assert!(!finding.after.evidence_ids.is_empty());
    let rendered = render_finding_diff(&FindingDiffResult::Ready(diff));
    assert!(rendered.contains("observed environment change"));
    assert!(rendered.contains("remediation is not established"));
    assert!(!rendered.contains(SECRET_SENTINEL));
}

#[test]
fn s032_reduced_scope_complete_does_not_prove_environment_change() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "production-worker");
    write_opencode(workspace.path(), &ALLOW.replace("\"allow\"", "\"deny\""));
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        None,
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace.path(), home.path(), "production-worker")),
    )
    .unwrap();
    let diff = latest(workspace.path());
    let bash = diff
        .attribution
        .graph_changes
        .iter()
        .find(|c| c.key.contains("can_execute"))
        .unwrap();
    assert_eq!(bash.classification, AttributionClass::EvidenceChange);
    assert!(bash.reasons.contains(&"coverage_changed".into()));
    assert!(diff
        .attribution
        .graph_changes
        .iter()
        .all(|c| !c.disappearance_confirmed));
}

#[test]
fn s032_real_coverage_records_missing_home_and_never_raw_paths() {
    let (workspace, _) = setup();
    let scan = ScanService::run_with_home(workspace.path(), None).unwrap();
    let conn = rusqlite::Connection::open(workspace.path().join(".pico/pico.db")).unwrap();
    let persisted = pico::persistence::ScanRepo::new(&conn)
        .get(&scan.scan_id)
        .unwrap()
        .unwrap();
    let coverage = &persisted.metadata.unwrap()["coverage"];
    assert_eq!(coverage["version"], 1);
    let entries = coverage["entries"].as_array().unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e["state"] == "not_attempted")
            .count(),
        2
    );
    assert!(entries
        .iter()
        .any(|e| e["scope"] == "project:opencode.json" && e["state"] == "inspected"));
    assert_eq!(coverage["provider_enumeration"], "unknown");
    assert!(!coverage
        .to_string()
        .contains(workspace.path().to_str().unwrap()));
    assert!(!coverage.to_string().contains(SECRET_SENTINEL));
}

#[test]
fn s032_real_malformed_configuration_records_incomplete_coverage() {
    let (workspace, home) = setup();
    write_opencode(workspace.path(), "{");
    let scan = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(scan.status, ScanStatus::Partial);
    let conn = rusqlite::Connection::open(workspace.path().join(".pico/pico.db")).unwrap();
    let persisted = pico::persistence::ScanRepo::new(&conn)
        .get(&scan.scan_id)
        .unwrap()
        .unwrap();
    assert!(persisted.metadata.unwrap()["coverage"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["scope"] == "project:opencode.json" && e["state"] == "incomplete"));
}

#[test]
fn s032_real_mcp_disabled_is_paired_environment_observation() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "production-worker");
    let disabled = ALLOW.replace(
        "\"type\": \"local\"",
        "\"enabled\": false, \"type\": \"local\"",
    );
    write_opencode(workspace.path(), &disabled);
    scan_named(workspace.path(), home.path(), "production-worker");
    let diff = latest(workspace.path());
    let server = diff
        .attribution
        .graph_changes
        .iter()
        .find(|c| c.key == "mcp:github:official")
        .unwrap();
    assert_eq!(
        server.classification,
        AttributionClass::ObservedEnvironmentChange,
        "{server:?}"
    );
    assert!(server.before.supported_fields.contains(&"enabled".into()));
    assert!(server.after.supported_fields.contains(&"enabled".into()));
}
