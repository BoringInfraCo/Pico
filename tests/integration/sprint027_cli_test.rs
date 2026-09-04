//! Sprint 027 CLI causal-explanation fixtures (R1–R9).

use std::fs;

use pico::application::{
    ComparedVia, DiffService, FindingDiff, FindingDiffResult, Freshness, InitService, ScanService,
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

fn diff_latest(workspace: &std::path::Path) -> FindingDiffResult {
    DiffService::latest(workspace).unwrap()
}

fn ready(result: FindingDiffResult) -> FindingDiff {
    match result {
        FindingDiffResult::Ready(value) => value,
        other => panic!("expected Ready diff, got {other:?}"),
    }
}

fn findings_section(rendered: &str) -> &str {
    let start = rendered
        .find("\nFindings\n")
        .expect("Findings section missing");
    rendered[start..]
        .split("\nResources\n")
        .next()
        .expect("Resources section missing")
}

#[test]
fn unchanged_diff_has_no_cause_lines() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("No security-significant finding change."));
    assert!(!rendered.contains("Cause:"));
}

#[test]
fn bash_deny_cause_is_effective_state_not_mcp() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), DENY);
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.disappeared.len(), 1);
    let cause = comparison.disappeared[0]
        .cause
        .as_ref()
        .expect("disappeared Finding needs a Cause");
    assert!(
        cause.summary.contains("Bash effective state")
            && cause.summary.contains("AUTO_ALLOW")
            && cause.summary.contains("DENIED"),
        "expected Bash effective-state cause, got {}",
        cause.summary
    );
    assert!(!cause.summary.contains("GitHub MCP"));
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("Cause: Bash effective state"));
    assert!(!findings_section(&rendered).contains("GitHub MCP influence is no longer present"));
}

#[test]
fn worker_churn_cause_is_sink_identity_on_both_sides() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "billing");
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.appeared.len(), 1);
    assert_eq!(comparison.disappeared.len(), 1);
    let disappeared = comparison.disappeared[0]
        .cause
        .as_ref()
        .expect("disappeared Cause");
    let appeared = comparison.appeared[0]
        .cause
        .as_ref()
        .expect("appeared Cause");
    assert_eq!(disappeared.summary, appeared.summary);
    assert!(disappeared.summary.starts_with("Sink identity changed:"));
    assert!(disappeared.summary.contains("worker-tag-checkout"));
    assert!(disappeared.summary.contains("worker-tag-billing"));
}

#[test]
fn partial_attempt_does_not_invent_cause() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), MALFORMED);
    let partial = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(partial.status, ScanStatus::Partial);
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.freshness, Freshness::NewerIncomplete);
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("No security-significant finding change."));
    assert!(!rendered.contains("Cause:"));
}

#[test]
fn cause_summaries_stable_across_identical_pairs() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), DENY);
    scan_named(workspace.path(), home.path(), "checkout");
    let first = ready(diff_latest(workspace.path()));
    let second = ready(diff_latest(workspace.path()));
    assert_eq!(
        first.disappeared[0].cause.as_ref().map(|c| &c.summary),
        second.disappeared[0].cause.as_ref().map(|c| &c.summary)
    );
}

#[test]
fn secret_sweep_never_leaks_in_cause() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "billing");
    let rendered = render_finding_diff(&diff_latest(workspace.path()));
    assert!(!rendered.contains(SECRET_SENTINEL));
    assert!(!rendered.contains("synthetic-token"));
    assert!(!rendered.contains("ghp_"));
}

#[test]
fn findings_counts_contract_with_optional_cause_lines() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.compared_via, ComparedVia::LatestTwo);
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    let findings = findings_section(&rendered);
    assert!(findings.contains("Unchanged: 1"));
    assert!(findings.contains("Appeared:  0"));
    assert!(findings.contains("Disappeared: 0"));
    assert!(findings.contains("No security-significant finding change."));
    assert!(!findings.contains("Cause:"));
}
