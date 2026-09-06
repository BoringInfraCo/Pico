//! Sprint 026 CLI graph-memory fixtures (R1–R12).
//!
//! `pico diff` compares COMPLETE observation snapshots by canonical_key.

use std::fs;

use pico::application::{
    ComparedVia, DiffService, FindingDiff, FindingDiffResult, Freshness, GraphSubject, InitService,
    ScanService,
};
use pico::cli::render::render_finding_diff;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::github::{self, GitHubAuthorityResult};
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
const MIXED_CLAUDE: &str = include_str!("../fixtures/mixed/.claude/settings.json");
const GITHUB_PAT: &str = "ghp_TESTFAKE0000000000000000000000000000";

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

fn provider_named(
    workspace: &std::path::Path,
    home: &std::path::Path,
    token: &str,
    script_name: &str,
    resolution: AuthorityResolution,
    state: RelationshipState,
) -> ProviderResult {
    let environment = [("CLOUDFLARE_API_TOKEN", token)];
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
            state,
            resolution,
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
    scan_token(workspace, home, "synthetic-token", script_name)
}

fn scan_token(
    workspace: &std::path::Path,
    home: &std::path::Path,
    token: &str,
    script_name: &str,
) -> pico::application::ScanResult {
    scan_with_resolution(
        workspace,
        home,
        token,
        script_name,
        AuthorityResolution::Exact,
        RelationshipState::Derived,
    )
}

fn scan_with_resolution(
    workspace: &std::path::Path,
    home: &std::path::Path,
    token: &str,
    script_name: &str,
    resolution: AuthorityResolution,
    state: RelationshipState,
) -> pico::application::ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", token)];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider_named(
            workspace,
            home,
            token,
            script_name,
            resolution,
            state,
        )),
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

fn by_key<'a>(entries: &'a [GraphSubject], key: &str) -> &'a GraphSubject {
    entries
        .iter()
        .find(|entry| entry.canonical_key == key)
        .unwrap_or_else(|| panic!("missing {key}"))
}

fn contains_key(entries: &[GraphSubject], key: &str) -> bool {
    entries.iter().any(|entry| entry.canonical_key == key)
}

fn findings_section(rendered: &str) -> &str {
    let start = rendered
        .find("\nFindings\n")
        .expect("Findings section missing");
    let rest = &rendered[start..];
    rest.split("\nResources\n")
        .next()
        .expect("Resources section missing")
}

#[test]
fn unchanged_complete_scans_have_empty_graph_diff() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert!(comparison.graph.resources.first_seen.is_empty());
    assert!(comparison.graph.resources.reappeared.is_empty());
    assert!(comparison.graph.resources.changed.is_empty());
    assert!(comparison.graph.resources.disappeared.is_empty());
    assert!(comparison.graph.relationships.first_seen.is_empty());
    assert!(comparison.graph.relationships.reappeared.is_empty());
    assert!(comparison.graph.relationships.changed.is_empty());
    assert!(comparison.graph.relationships.disappeared.is_empty());
    assert!(!comparison.graph.resources.unchanged.is_empty());
    assert!(!comparison.graph.relationships.unchanged.is_empty());
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("No security-significant finding change."));
    assert!(!rendered.contains("This is not an all-clear."));
}

#[test]
fn bash_deny_changes_can_execute_not_disappearing_bash() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), DENY);
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    let key = "agent:opencode|can_execute|shell:bash";
    assert!(
        contains_key(&comparison.graph.relationships.changed, key),
        "expected {key} changed, got {:?}",
        comparison
            .graph
            .relationships
            .changed
            .iter()
            .map(|e| &e.canonical_key)
            .collect::<Vec<_>>()
    );
    assert!(!contains_key(
        &comparison.graph.resources.disappeared,
        "shell:bash"
    ));
    let changed = by_key(&comparison.graph.relationships.changed, key);
    assert!(changed
        .deltas
        .iter()
        .any(|delta| delta.field == "state" || delta.field == "effective_state"));
}

#[test]
fn worker_identity_churn_is_disappeared_and_first_seen() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "billing");
    let comparison = ready(diff_latest(workspace.path()));
    let checkout = "cloudflare:worker:account-1234567890123456:worker-tag-checkout";
    let billing = "cloudflare:worker:account-1234567890123456:worker-tag-billing";
    assert!(contains_key(
        &comparison.graph.resources.disappeared,
        checkout
    ));
    assert!(contains_key(
        &comparison.graph.resources.first_seen,
        billing
    ));
    assert!(!contains_key(&comparison.graph.resources.changed, checkout));
    assert!(!contains_key(&comparison.graph.resources.changed, billing));
}

#[test]
fn partial_attempt_does_not_fabricate_graph_disappearance() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), MALFORMED);
    let partial = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(partial.status, ScanStatus::Partial);
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.freshness, Freshness::NewerIncomplete);
    assert!(comparison.graph.resources.first_seen.is_empty());
    assert!(comparison.graph.resources.reappeared.is_empty());
    assert!(comparison.graph.resources.changed.is_empty());
    assert!(comparison.graph.resources.disappeared.is_empty());
    assert!(comparison.graph.relationships.first_seen.is_empty());
    assert!(comparison.graph.relationships.reappeared.is_empty());
    assert!(comparison.graph.relationships.changed.is_empty());
    assert!(comparison.graph.relationships.disappeared.is_empty());
}

#[test]
fn reappeared_requires_older_complete_history() {
    let (workspace, home) = setup();
    let first = scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), DENY);
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), ALLOW);
    let third = scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    let mcp = comparison
        .graph
        .resources
        .reappeared
        .iter()
        .find(|entry| entry.canonical_key.contains("mcp:github"))
        .expect("expected GitHub MCP resource to reappear");
    assert_eq!(mcp.first_seen_scan_id, first.scan_id);
    assert_eq!(mcp.last_seen_scan_id, third.scan_id);
}

#[test]
fn authority_tier_change_is_changed_same_key() {
    let (workspace, home) = setup();
    scan_with_resolution(
        workspace.path(),
        home.path(),
        "synthetic-token",
        "checkout",
        AuthorityResolution::Exact,
        RelationshipState::Derived,
    );
    scan_with_resolution(
        workspace.path(),
        home.path(),
        "synthetic-token",
        "checkout",
        AuthorityResolution::Unknown,
        RelationshipState::Unknown,
    );
    let comparison = ready(diff_latest(workspace.path()));
    let changed = comparison
        .graph
        .relationships
        .changed
        .iter()
        .find(|entry| entry.canonical_key.contains("can_mutate"))
        .expect("expected can_mutate relationship to change");
    assert!(changed
        .deltas
        .iter()
        .any(|delta| delta.field == "authority_resolution"
            && delta.from == "EXACT"
            && delta.to == "UNKNOWN"));
}

#[test]
fn github_kind_flip_is_not_changed() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW);
    InitService::run(workspace.path()).unwrap();
    let environment = [("GITHUB_TOKEN", GITHUB_PAT)];
    let fingerprint = github::fingerprint(GITHUB_PAT);
    let write = GitHubAuthorityResult {
        credential_fingerprint: fingerprint.clone(),
        credential_type: Some("classic_pat".to_string()),
        resolution: AuthorityResolution::Exact,
        state: RelationshipState::Derived,
        permission_state: "REPO_WRITE".to_string(),
        unknown_reasons: Vec::new(),
        source_locator: "github:scope_probe:/user".to_string(),
        problems: Vec::new(),
    };
    ScanService::run_with_home_and_environment_and_github(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(write),
    )
    .unwrap();
    ScanService::run_with_home_and_environment_and_github(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        None,
    )
    .unwrap();
    let comparison = ready(diff_latest(workspace.path()));
    let mutate = format!("credential:github:{fingerprint}|can_mutate|github:repository");
    let access = format!("credential:github:{fingerprint}|can_access|github:repository");
    assert!(contains_key(
        &comparison.graph.relationships.disappeared,
        &mutate
    ));
    assert!(contains_key(
        &comparison.graph.relationships.first_seen,
        &access
    ));
    assert!(!contains_key(
        &comparison.graph.relationships.changed,
        &mutate
    ));
    assert!(!contains_key(
        &comparison.graph.relationships.changed,
        &access
    ));
}

#[test]
fn mixed_agents_do_not_collapse_bash_edges() {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW);
    let claude_dir = workspace.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(claude_dir.join("settings.json"), MIXED_CLAUDE).unwrap();
    InitService::run(workspace.path()).unwrap();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    let opencode = "agent:opencode|can_execute|shell:bash";
    let claude = "agent:claude|can_execute|shell:bash";
    assert!(contains_key(
        &comparison.graph.relationships.unchanged,
        opencode
    ));
    assert!(contains_key(
        &comparison.graph.relationships.unchanged,
        claude
    ));
    assert_eq!(
        comparison
            .graph
            .resources
            .unchanged
            .iter()
            .filter(|entry| entry.canonical_key == "shell:bash")
            .count(),
        1
    );
}

#[test]
fn credential_fingerprint_rotation_is_identity_churn() {
    let (workspace, home) = setup();
    let first = scan_token(workspace.path(), home.path(), "synthetic-token", "checkout");
    let second = scan_token(
        workspace.path(),
        home.path(),
        "synthetic-token-rotated",
        "checkout",
    );
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(second.status, ScanStatus::Complete);
    let comparison = ready(diff_latest(workspace.path()));
    let disappeared = comparison
        .graph
        .resources
        .disappeared
        .iter()
        .filter(|entry| entry.canonical_key.starts_with("credential:cloudflare:"))
        .count();
    let first_seen = comparison
        .graph
        .resources
        .first_seen
        .iter()
        .filter(|entry| entry.canonical_key.starts_with("credential:cloudflare:"))
        .count();
    assert_eq!(disappeared, 1);
    assert_eq!(first_seen, 1);
    assert!(!comparison
        .graph
        .resources
        .changed
        .iter()
        .any(|entry| entry.canonical_key.starts_with("credential:cloudflare:")));
}

#[test]
fn graph_empty_states_are_scoped() {
    let workspace = tempdir().unwrap();
    InitService::run(workspace.path()).unwrap();
    let rendered = render_finding_diff(&diff_latest(workspace.path()));
    assert!(rendered.contains("No COMPLETE scan exists"));
    assert!(rendered.contains("This is not an all-clear."));
    assert!(!rendered.contains("Resources\n"));

    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW);
    scan_named(workspace.path(), home.path(), "checkout");
    let rendered = render_finding_diff(&diff_latest(workspace.path()));
    assert!(rendered.contains("A previous COMPLETE scan is required to compare."));
    assert!(rendered.contains("This is not an all-clear."));
    assert!(!rendered.contains("Resources\n"));
}

#[test]
fn secret_sweep_never_leaks_in_graph_diff() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "billing");
    let rendered = render_finding_diff(&diff_latest(workspace.path()));
    assert!(!rendered.contains(SECRET_SENTINEL));
    assert!(!rendered.contains("synthetic-token"));
    assert!(!rendered.contains("ghp_"));
}

#[test]
fn findings_section_byte_contract_from_s024_s025() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.compared_via, ComparedVia::LatestTwo);
    assert_eq!(comparison.unchanged.len(), 1);
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    let findings = findings_section(&rendered);
    assert!(findings.contains("Unchanged: 1"));
    assert!(findings.contains("Appeared:  0"));
    assert!(findings.contains("Not observed: 0"));
    assert!(findings.contains("No security-significant finding change."));
    assert!(!findings.contains("This is not an all-clear."));
    assert!(!findings.contains("Resources"));
    assert!(rendered.contains("Compared: LAST TWO COMPLETE SCANS"));
    assert!(rendered.contains("Freshness: LATEST COMPLETE"));
}
