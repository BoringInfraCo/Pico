//! Sprint 008 analysis prerequisites and bounded-graph fixtures.
//!
//! The analysis domain is intentionally not present in the Sprint 007
//! baseline. These tests exercise the public SecurityGraph contract that the
//! analysis layer must consume: exact golden-path membership, authored edge
//! direction, usability, alternate routes, cycle safety, deterministic
//! limits, and secret-safe graph inputs.

use std::collections::BTreeMap;
use std::fs;

use pico::application::{InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, Resource, ScanStatus};
use pico::graph::{
    bounded_reachability, EdgeUsability, GraphEdge, GraphEvidenceIndex, GraphNode, SecurityGraph,
    SecurityRole, TraversalCompletion, TraversalDirection, TraversalLimits, TraversalPolicy,
};
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
  "permissions": [{ "resource": "github_issue_read", "effect": "allow" }]
}"#;

fn setup() -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn complete_provider(workspace: &std::path::Path, home: &std::path::Path) -> ProviderResult {
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
        script_name: "checkout".to_string(),
        worker_tag: Some("worker-tag-1234567890123456".to_string()),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
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

#[test]
fn golden_graph_has_exact_nodes_and_edges_for_analysis_input() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(complete_provider(workspace.path(), home.path())),
    )
    .unwrap();

    assert_eq!(result.status, ScanStatus::Complete);
    assert_eq!(result.graph_node_count, 8);
    assert_eq!(result.graph_edge_count, 8);
    let graph = result.graph.as_ref().expect("graph projection");
    let credential = result
        .graph
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|node| node.kind == "credential")
        .unwrap()
        .canonical_key
        .clone();
    let expected_nodes = vec![
        "agent:opencode".to_string(),
        "cloudflare:account:account-1234567890123456".to_string(),
        "cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456".to_string(),
        credential,
        "mcp:github:official".to_string(),
        "mcp:github:official:tool:issue_read".to_string(),
        "shell:bash".to_string(),
        "source:github:public:issue-content".to_string(),
    ];
    let actual_nodes: Vec<_> = graph
        .nodes
        .iter()
        .map(|node| node.canonical_key.clone())
        .collect();
    assert_eq!(actual_nodes, expected_nodes);

    let expected_edges = vec![
        "agent:opencode|can_call|mcp:github:official:tool:issue_read",
        "agent:opencode|can_execute|shell:bash",
        "agent:opencode|configured_with|mcp:github:official",
        "credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f|can_mutate|cloudflare:worker:account-1234567890123456:worker-tag-1234567890123456",
        "credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f|scoped_to|cloudflare:account:account-1234567890123456",
        "mcp:github:official:tool:issue_read|can_retrieve|source:github:public:issue-content",
        "mcp:github:official|exposes|mcp:github:official:tool:issue_read",
        "shell:bash|can_access|credential:cloudflare:1b5b9a6cc0058f348c037e16b3353ff76ef5ade490bd078c1169e74f714d552f",
    ];
    let actual_edges: Vec<_> = graph
        .edges
        .iter()
        .map(|edge| edge.canonical_key.as_str())
        .collect();
    assert_eq!(actual_edges, expected_edges);
    assert!(graph.edges.iter().all(|edge| !edge.evidence_ids.is_empty()));
}

#[test]
fn active_analysis_persists_stable_path_and_scan_history() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let first = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(complete_provider(workspace.path(), home.path())),
    )
    .unwrap();
    assert_eq!(first.analysis_status, "COMPLETE");
    assert_eq!(first.analysis_disposition, "ACTIVE_PRESENT");
    assert_eq!(first.influence_path_count, 1);
    assert_eq!(first.authority_path_count, 1);
    assert_eq!(first.active_attack_path_count, 1);
    assert_eq!(first.blocked_attack_path_count, 0);
    assert_eq!(first.unresolved_candidate_count, 0);
    let first_fingerprint = first
        .analysis
        .as_ref()
        .unwrap()
        .attack_paths
        .first()
        .unwrap()
        .fingerprint
        .clone();

    let second = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(complete_provider(workspace.path(), home.path())),
    )
    .unwrap();
    let second_fingerprint = second
        .analysis
        .as_ref()
        .unwrap()
        .attack_paths
        .first()
        .unwrap()
        .fingerprint
        .clone();
    assert_eq!(first_fingerprint, second_fingerprint);

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let analysis_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM scan_analyses", [], |row| row.get(0))
        .unwrap();
    let path_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM attack_paths", [], |row| row.get(0))
        .unwrap();
    let edge_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM attack_path_edges", [], |row| {
            row.get(0)
        })
        .unwrap();
    let evidence_rows: i64 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM attack_path_evidence", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(analysis_rows, 2);
    assert_eq!(path_rows, 2);
    assert_eq!(edge_rows, 10);
    assert!(evidence_rows >= 5);
    let distinct_fingerprints: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(DISTINCT fingerprint) FROM attack_paths",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(distinct_fingerprints, 1);
}

#[test]
fn blocked_authority_is_reported_without_active_path() {
    let workspace = setup();
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let mut provider = complete_provider(workspace.path(), home.path());
    provider.authorities[0].state = RelationshipState::Blocked;
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace.path(),
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider),
    )
    .unwrap();
    assert_eq!(result.analysis_status, "COMPLETE");
    assert_eq!(result.analysis_disposition, "BLOCKED_ONLY");
    assert_eq!(result.active_attack_path_count, 0);
    assert_eq!(result.blocked_attack_path_count, 1);
    assert_eq!(result.unresolved_candidate_count, 0);

    let db = Database::open(&workspace.path().join(".pico/pico.db")).unwrap();
    let persisted_disposition: String = db
        .connection()
        .query_row("SELECT disposition FROM attack_paths", [], |row| row.get(0))
        .unwrap();
    assert_eq!(persisted_disposition, "BLOCKED");
}

fn synthetic_graph(edges: Vec<GraphEdge>, node_count: usize) -> SecurityGraph {
    let mut nodes = BTreeMap::new();
    let mut outgoing = BTreeMap::new();
    let mut incoming = BTreeMap::new();
    for edge in &edges {
        for id in [&edge.from_resource_id, &edge.to_resource_id] {
            nodes.entry(id.clone()).or_insert_with(|| GraphNode {
                resource_id: id.clone(),
                canonical_key: format!("fixture:{id}"),
                kind: "fixture".to_string(),
                provider: "fixture".to_string(),
                name: id.clone(),
                safe_metadata: None,
                roles: Vec::new(),
            });
        }
        outgoing
            .entry(edge.from_resource_id.clone())
            .or_insert_with(Vec::new)
            .push(edge.relationship_id.clone());
        incoming
            .entry(edge.to_resource_id.clone())
            .or_insert_with(Vec::new)
            .push(edge.relationship_id.clone());
    }
    assert_eq!(nodes.len(), node_count);
    SecurityGraph {
        scan_id: "scan-synthetic".to_string(),
        snapshot_version: 1,
        nodes: nodes.into_values().collect(),
        edges,
        outgoing_index: outgoing,
        incoming_index: incoming,
        evidence_index: GraphEvidenceIndex::default(),
    }
}

fn edge(id: &str, from: &str, to: &str, kind: &str, state: RelationshipState) -> GraphEdge {
    GraphEdge {
        relationship_id: id.to_string(),
        canonical_key: format!("fixture:{from}|{kind}|{to}"),
        from_resource_id: from.to_string(),
        to_resource_id: to.to_string(),
        kind: kind.to_string(),
        state,
        usability: EdgeUsability::from_state(state),
        safe_metadata: None,
        evidence_ids: vec![format!("ev-{id}")],
    }
}

#[test]
fn alternate_route_keeps_open_route_reachable_when_other_route_is_blocked() {
    let graph = synthetic_graph(
        vec![
            edge(
                "deny",
                "actor",
                "bash",
                "can_execute",
                RelationshipState::Blocked,
            ),
            edge(
                "open",
                "actor",
                "tool",
                "can_execute",
                RelationshipState::Derived,
            ),
            edge(
                "sink-a",
                "bash",
                "sink",
                "can_mutate",
                RelationshipState::Derived,
            ),
            edge(
                "sink-b",
                "tool",
                "sink",
                "can_mutate",
                RelationshipState::Derived,
            ),
        ],
        4,
    );
    let result = bounded_reachability(&graph, "actor", &TraversalPolicy::default());
    assert!(result.reachable_node_ids.contains(&"tool".to_string()));
    assert!(result.reachable_node_ids.contains(&"sink".to_string()));
    assert!(!result.reachable_node_ids.contains(&"bash".to_string()));
}

#[test]
fn cycle_and_depth_limits_are_explicit_and_deterministic() {
    let graph = synthetic_graph(
        vec![
            edge("ab", "a", "b", "can_call", RelationshipState::Derived),
            edge("bc", "b", "c", "can_call", RelationshipState::Derived),
            edge("ca", "c", "a", "can_call", RelationshipState::Derived),
        ],
        3,
    );
    let policy = TraversalPolicy {
        limits: TraversalLimits {
            maximum_depth: 1,
            maximum_edge_examinations: 10,
            maximum_frontier_nodes: 10,
            maximum_reachable_nodes: 10,
        },
        ..TraversalPolicy::default()
    };
    let first = bounded_reachability(&graph, "a", &policy);
    let second = bounded_reachability(&graph, "a", &policy);
    assert_eq!(first, second);
    assert_eq!(first.reachable_node_ids, vec!["a", "b"]);
    assert_eq!(first.completion, TraversalCompletion::DepthLimited);
}

#[test]
fn direction_and_usability_do_not_allow_reverse_or_unknown_edges() {
    let graph = synthetic_graph(
        vec![
            edge(
                "reverse",
                "target",
                "source",
                "can_call",
                RelationshipState::Derived,
            ),
            edge(
                "unknown",
                "source",
                "unknown",
                "can_call",
                RelationshipState::Unknown,
            ),
        ],
        3,
    );
    let outgoing = bounded_reachability(&graph, "source", &TraversalPolicy::default());
    assert_eq!(outgoing.reachable_node_ids, vec!["source"]);
    let incoming = TraversalPolicy {
        direction: TraversalDirection::Incoming,
        ..TraversalPolicy::default()
    };
    let reverse = bounded_reachability(&graph, "source", &incoming);
    assert!(reverse.reachable_node_ids.contains(&"target".to_string()));
    assert!(!reverse.reachable_node_ids.contains(&"unknown".to_string()));
}

#[test]
fn secret_sentinel_is_not_present_in_normalized_graph_fixture() {
    let mut resource =
        Resource::new("credential:fixture", "credential", "fixture", "Credential").unwrap();
    resource.metadata = Some(serde_json::json!({
        "fingerprint": "sha256:fixture",
        "secret_stored": false,
    }));
    let node = GraphNode::from_resource(&resource);
    let serialized = serde_json::to_string(&node).unwrap();
    assert!(!serialized.contains("TEST_SECRET_SHOULD_NOT_PERSIST"));
    assert!(node.roles.contains(&SecurityRole::Authority));
}
