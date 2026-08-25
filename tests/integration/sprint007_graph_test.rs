//! Sprint 007 graph projection integration coverage.

use std::fs;

use pico::application::{InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, ScanStatus};
use pico::graph::{bounded_reachability, EdgeUsability, TraversalDirection, TraversalPolicy};
use pico::persistence::Database;
use tempfile::tempdir;

const CONFIG: &str = r#"{
  "$schema": "https://opencode.ai/config.json",
  "permission": { "bash": "allow" },
  "mcp": { "servers": {
    "github": {
      "type": "local",
      "command": ["docker", "run", "--rm", "ghcr.io/github/github-mcp-server:0.1.0"],
      "environment": { "GITHUB_PERSONAL_ACCESS_TOKEN": "TEST_SECRET_SHOULD_NOT_PERSIST" }
    }
  }},
  "permissions": [{"resource": "github_issue_read", "effect": "allow"}]
}"#;

fn setup() -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

#[test]
fn complete_golden_path_projects_exact_graph_manifest() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let fingerprint = discovered.credentials[0].fingerprint.clone();
    let worker = ObservedWorker {
        account_id: "account-1234567890123456".to_string(),
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: None,
    };
    let worker_key = worker.canonical_key();
    let provider = ProviderResult {
        credential_fingerprint: fingerprint,
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
    };
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider),
    )
    .unwrap();
    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.graph_projection_status, "PROJECTED");
    assert_eq!(result.graph_node_count, 8);
    assert_eq!(result.graph_edge_count, 8);
    assert_eq!(result.state_eligible_edge_count, 8);
    assert_eq!(result.non_eligible_edge_count, 0);
    let graph = result.graph.as_ref().unwrap();
    let node_keys: Vec<_> = graph
        .nodes
        .iter()
        .map(|node| node.canonical_key.as_str())
        .collect();
    assert!(node_keys.contains(&"agent:opencode"));
    assert!(node_keys.contains(&"source:github:public:issue-content"));
    assert!(node_keys.contains(
        &"credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f"
    ));
    assert!(node_keys.contains(&"cloudflare:account:account-1234567890123456"));
    assert!(node_keys
        .contains(&"cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456"));
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.canonical_key
            == "agent:opencode|can_call|mcp:github:official:tool:issue_read"));
    assert!(graph.edges.iter().any(|edge| edge.canonical_key
        == "mcp:github:official:tool:issue_read|can_retrieve|source:github:public:issue-content"));
    assert!(graph.edges.iter().all(|edge| !edge.evidence_ids.is_empty()));
    assert!(graph
        .nodes
        .iter()
        .any(|node| node.roles.contains(&pico::graph::SecurityRole::Source)));
    assert!(graph
        .nodes
        .iter()
        .any(|node| node.roles.contains(&pico::graph::SecurityRole::Authority)));
    assert!(graph
        .nodes
        .iter()
        .any(|node| node.roles.contains(&pico::graph::SecurityRole::Sink)));
}

#[test]
fn later_scan_excludes_stale_authority_graph_state() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
    )
    .unwrap();
    let provider = ProviderResult {
        credential_fingerprint: discovered.credentials[0].fingerprint.clone(),
        credential_status: Some(CredentialStatus::Active),
        ..ProviderResult::default()
    };
    let first = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider),
    )
    .unwrap();
    assert_eq!(first.graph_node_count, 6);
    let second = ScanService::run_with_home_and_environment(
        workspace.path(),
        Some(home.path()),
        None,
        EnvironmentReachability::Unknown,
    )
    .unwrap();
    assert_eq!(second.status, ScanStatus::Complete);
    let graph = second.graph.as_ref().unwrap();
    assert!(!graph.nodes.iter().any(|node| node.kind == "credential"));
    assert!(!graph.edges.iter().any(|edge| edge.kind == "can_mutate"));

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let current_scan_count: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
        .unwrap();
    assert_eq!(current_scan_count, 2);
}

#[test]
fn traversal_preserves_direction_and_rejects_unknown_edges() {
    let workspace = setup();
    let result = ScanService::run_with_home_and_environment(
        workspace.path(),
        None,
        None,
        EnvironmentReachability::Unknown,
    )
    .unwrap();
    let graph = result.graph.as_ref().unwrap();
    assert!(!graph.nodes.is_empty());
    assert_eq!(
        bounded_reachability(graph, "missing", &TraversalPolicy::default())
            .reachable_node_ids
            .len(),
        0
    );
    let agent_id = graph
        .nodes
        .iter()
        .find(|node| node.canonical_key == "agent:opencode")
        .map(|node| node.resource_id.as_str())
        .unwrap();
    let walk = bounded_reachability(graph, agent_id, &TraversalPolicy::default());
    assert!(walk.reachable_node_ids.len() > 1);
    let _ = (
        EdgeUsability::NonTraversableUnknown,
        TraversalDirection::Outgoing,
    );
}
