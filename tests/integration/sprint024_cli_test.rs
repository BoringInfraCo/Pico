//! Sprint 024 CLI finding-set diff fixtures (R1–R7).
//!
//! `pico diff` compares Findings from the last two COMPLETE scans by
//! fingerprint. Incomplete attempts never participate as a comparison side.

use std::fs;

use pico::application::{DiffService, FindingDiffResult, Freshness, InitService, ScanService};
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
const DENY: &str = include_str!("../fixtures/opencode/deny/opencode.json");
const MALFORMED: &str = include_str!("../fixtures/opencode/malformed/opencode.json");

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

fn diff(workspace: &std::path::Path) -> FindingDiffResult {
    DiffService::latest(workspace).unwrap()
}

fn ready(result: FindingDiffResult) -> pico::application::FindingDiff {
    match result {
        FindingDiffResult::Ready(value) => value,
        other => panic!("expected Ready diff, got {other:?}"),
    }
}

/// R5: no COMPLETE scan is distinct from an all-clear.
#[test]
fn diff_empty_states_are_scoped() {
    let workspace = tempdir().unwrap();
    InitService::run(workspace.path()).unwrap();
    let rendered = render_finding_diff(&diff(workspace.path()));
    assert!(
        rendered.contains("No COMPLETE scan exists"),
        "expected no-scan guidance in:\n{rendered}"
    );
    assert!(
        rendered.contains("This is not an all-clear."),
        "empty diff must not read as safety:\n{rendered}"
    );

    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW);
    let first = scan_named(workspace.path(), home.path(), "checkout");
    assert_eq!(first.status, ScanStatus::Complete);
    let rendered = render_finding_diff(&diff(workspace.path()));
    assert!(
        rendered.contains("A previous COMPLETE scan is required to compare."),
        "expected single-scan guidance in:\n{rendered}"
    );
    assert!(
        rendered.contains(&first.scan_id),
        "single-scan guidance should name the COMPLETE scan:\n{rendered}"
    );
    assert!(rendered.contains("This is not an all-clear."));
}

/// R1: two identical COMPLETE scans produce an empty security-significant diff.
#[test]
fn unchanged_complete_scans_have_empty_finding_diff() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");
    let second = scan_named(workspace.path(), home.path(), "checkout");
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(second.status, ScanStatus::Complete);
    assert_eq!(first.finding_count, 1);
    assert_eq!(second.finding_count, 1);

    let comparison = ready(diff(workspace.path()));
    assert_eq!(comparison.from.id, first.scan_id);
    assert_eq!(comparison.to.id, second.scan_id);
    assert_eq!(comparison.freshness, Freshness::LatestComplete);
    assert_eq!(comparison.unchanged.len(), 1);
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    assert!(comparison.unchanged[0].fingerprint.starts_with("sha256:"));

    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison.clone()));
    assert!(rendered.contains("No security-significant finding change."));
    assert!(!rendered.contains("This is not an all-clear."));
    assert!(!rendered.contains(SECRET_SENTINEL));
}

/// R2: a later COMPLETE scan that no longer contains the finding reports
/// disappearance, not an all-clear.
#[test]
fn complete_scan_without_finding_reports_disappeared() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");
    assert_eq!(first.finding_count, 1);
    write_opencode(workspace.path(), DENY);
    let second = scan_named(workspace.path(), home.path(), "checkout");
    assert_eq!(second.status, ScanStatus::Complete);
    assert_eq!(second.finding_count, 0);

    let comparison = ready(diff(workspace.path()));
    assert_eq!(comparison.unchanged.len(), 0);
    assert_eq!(comparison.appeared.len(), 0);
    assert_eq!(comparison.disappeared.len(), 1);
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("Not observed"));
    assert!(!rendered.contains("No security-significant finding change."));
}

/// R3: a security-significant change that still yields a Finding is a
/// fingerprint flip (disappeared + appeared).
#[test]
fn fingerprint_flip_is_disappeared_and_appeared() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");
    let second = scan_named(workspace.path(), home.path(), "billing");
    assert_eq!(first.finding_count, 1);
    assert_eq!(second.finding_count, 1);

    let comparison = ready(diff(workspace.path()));
    assert_eq!(comparison.unchanged.len(), 0);
    assert_eq!(comparison.appeared.len(), 1);
    assert_eq!(comparison.disappeared.len(), 1);
    assert_ne!(
        comparison.appeared[0].fingerprint,
        comparison.disappeared[0].fingerprint
    );
}

/// R4: a newer PARTIAL attempt does not fabricate disappearance.
#[test]
fn partial_attempt_does_not_fabricate_disappearance() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), MALFORMED);
    let partial = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(partial.status, ScanStatus::Partial);

    let comparison = ready(diff(workspace.path()));
    assert_eq!(comparison.freshness, Freshness::NewerIncomplete);
    assert_eq!(comparison.unchanged.len(), 1);
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    let warning = comparison.freshness_warning.as_deref().unwrap();
    assert!(warning.contains(&partial.scan_id));
    assert!(warning.contains("PARTIAL"));
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("Freshness: NEWER INCOMPLETE ATTEMPT"));
    assert!(rendered.contains("No security-significant finding change."));
}

/// R6: fingerprint sets are stable across an identical comparison pair.
#[test]
fn diff_fingerprint_sets_stable_across_identical_pairs() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let first = ready(diff(workspace.path()));
    let second = ready(diff(workspace.path()));
    assert_eq!(first.unchanged, second.unchanged);
    assert_eq!(first.appeared, second.appeared);
    assert_eq!(first.disappeared, second.disappeared);
}

/// R7: synthetic tokens never appear in the rendered diff.
#[test]
fn secret_sweep_never_leaks_token_in_diff() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "billing");
    let rendered = render_finding_diff(&diff(workspace.path()));
    assert!(!rendered.contains(SECRET_SENTINEL));
    assert!(!rendered.contains("synthetic-token"));
}
