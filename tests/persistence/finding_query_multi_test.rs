//! Sprint 010 grouped-path fixtures (SPRINT-010.md §20/§30 items 11-13).
//!
//! These extend a controlled golden scan with additional persisted AttackPath
//! records so the explanation service can be verified against one Finding that
//! groups multiple paths and multiple production Sinks, and against two paths
//! reaching the same Sink. Worker B is constructed from scan-scoped Observation
//! snapshots exactly like the provider-driven golden path.

use std::fs;

use pico::application::{FindingQueryService, InitService, ScanService};
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{
    relationship_snapshot_metadata, resource_snapshot_metadata, Observation, Relationship,
    RelationshipState, Resource,
};
use pico::persistence::{
    AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo, Database,
    FindingPathRecord, FindingRepo, ObservationRepo, RelationshipRepo, ResourceRepo,
};
use serde_json::json;
use tempfile::tempdir;

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

const WORKER_B_KEY: &str = "cloudflare:worker:account-1234567890123456:worker-tag-9999999999999999";

struct GoldenIds {
    scan_id: String,
    finding_id: String,
    path_a_id: String,
    source_id: String,
    actor_id: String,
    sink_a_id: String,
    credential_id: String,
}

fn setup() -> tempfile::TempDir {
    let workspace = tempdir().unwrap();
    fs::write(workspace.path().join("opencode.json"), CONFIG).unwrap();
    InitService::run(workspace.path()).unwrap();
    workspace
}

fn run_golden_scan(workspace: &std::path::Path) {
    let home = tempdir().unwrap();
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    let discovered = discover_with_environment(
        workspace,
        Some(home.path()),
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
    let result = ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home.path()),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(ProviderResult {
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
        }),
    )
    .unwrap();
    assert_eq!(result.finding_count, 1);
}

fn open_rw(workspace: &std::path::Path) -> Database {
    Database::open_existing(&workspace.join(".pico").join("pico.db")).unwrap()
}

fn golden_ids(workspace: &std::path::Path) -> GoldenIds {
    let db = open_rw(workspace);
    let scan_id: String = db
        .connection()
        .query_row(
            "SELECT id FROM scans WHERE status = 'COMPLETE' ORDER BY started_at DESC, id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let finding_id: String = db
        .connection()
        .query_row("SELECT id FROM findings LIMIT 1", [], |row| row.get(0))
        .unwrap();
    let (path_a_id, source_id, actor_id, sink_a_id): (String, String, String, String) = db
        .connection()
        .query_row(
            "SELECT id, source_resource_id, actor_resource_id, sink_resource_id
             FROM attack_paths LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0).unwrap(),
                    row.get(1).unwrap(),
                    row.get(2).unwrap(),
                    row.get(3).unwrap(),
                ))
            },
        )
        .unwrap();
    let credential_id: String = db
        .connection()
        .query_row(
            "SELECT from_resource_id FROM relationships WHERE kind = 'can_mutate' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(db);
    GoldenIds {
        scan_id,
        finding_id,
        path_a_id,
        source_id,
        actor_id,
        sink_a_id,
        credential_id,
    }
}

/// Copies path A's edges and evidence under a new path ID.
fn copy_path_topology(
    db: &Database,
    golden: &GoldenIds,
    new_path_id: &str,
    last_relationship_id: Option<String>,
) {
    let path_repo = AttackPathRepo::new(db.connection());
    let golden_edges = path_repo.list_edges(&golden.path_a_id).unwrap();
    let mut edges: Vec<AttackPathEdgeRecord> = golden_edges[..4]
        .iter()
        .map(|edge| AttackPathEdgeRecord {
            attack_path_id: new_path_id.to_string(),
            relationship_id: edge.relationship_id.clone(),
            position: edge.position,
            phase: edge.phase.clone(),
            traversal: edge.traversal.clone(),
        })
        .collect();
    let final_relationship = last_relationship_id
        .unwrap_or_else(|| golden_edges.last().unwrap().relationship_id.clone());
    edges.push(AttackPathEdgeRecord {
        attack_path_id: new_path_id.to_string(),
        relationship_id: final_relationship,
        position: 4,
        phase: "AUTHORITY".to_string(),
        traversal: "FORWARD".to_string(),
    });
    for edge in edges {
        path_repo.insert_edge(&edge).unwrap();
    }
    let golden_evidence = path_repo.list_evidence(&golden.path_a_id).unwrap();
    for item in golden_evidence {
        path_repo
            .insert_evidence(&AttackPathEvidenceRecord {
                attack_path_id: new_path_id.to_string(),
                evidence_id: item.evidence_id,
                position: item.position,
                support_role: item.support_role,
            })
            .unwrap();
    }
}

fn insert_path(
    workspace: &std::path::Path,
    golden: &GoldenIds,
    path_id: &str,
    fingerprint: &str,
    sink_id: &str,
    last_relationship_id: Option<String>,
) {
    let db = open_rw(workspace);
    let path_repo = AttackPathRepo::new(db.connection());
    let path = AttackPathRecord {
        id: path_id.to_string(),
        scan_id: golden.scan_id.clone(),
        fingerprint: fingerprint.to_string(),
        analysis_version: "1".to_string(),
        source_resource_id: golden.source_id.clone(),
        actor_resource_id: golden.actor_id.clone(),
        sink_resource_id: sink_id.to_string(),
        disposition: "ACTIVE".to_string(),
        source_trust: "PUBLIC_EXTERNAL".to_string(),
        influence_strength: "AGENT_RETRIEVABLE".to_string(),
        capability: "EXECUTE".to_string(),
        authority_resolution: "EXACT".to_string(),
        sink_impact: "PRODUCTION".to_string(),
        boundary_metadata: Some(json!([])),
        created_at: chrono::Utc::now(),
    };
    path_repo.insert(&path).unwrap();
    copy_path_topology(&db, golden, path_id, last_relationship_id);
    FindingRepo::new(db.connection())
        .insert_path(&FindingPathRecord {
            finding_id: golden.finding_id.clone(),
            attack_path_id: path_id.to_string(),
            position: 1,
        })
        .unwrap();
}

/// Adds worker B (resource + observation snapshot) and its `can_mutate`
/// relationship from the credential, returning the new relationship ID.
fn add_worker_b(workspace: &std::path::Path, golden: &GoldenIds) -> String {
    let db = open_rw(workspace);
    let resources = ResourceRepo::new(db.connection());
    let relationships = RelationshipRepo::new(db.connection());
    let observations = ObservationRepo::new(db.connection());

    let mut worker_b = Resource::new(WORKER_B_KEY, "worker", "cloudflare", "checkout2").unwrap();
    worker_b.metadata = Some(json!({
        "account_id": "account-1234567890123456",
        "worker_tag": "worker-tag-9999999999999999",
        "identity_precision": "IMMUTABLE_TAG",
        "environment": "PRODUCTION",
        "sink_impact": "PRODUCTION",
        "consequential_sink": true,
        "source": "cloudflare_api",
    }));
    resources.upsert(&worker_b).unwrap();

    let mut resource_observation = Observation::new(
        &golden.scan_id,
        "resource",
        &worker_b.id,
        "present",
        "cloudflare_provider",
    )
    .unwrap();
    resource_observation.metadata = Some(resource_snapshot_metadata(&worker_b));
    observations.insert(&resource_observation).unwrap();

    let credential_key: String = db
        .connection()
        .query_row(
            "SELECT canonical_key FROM resources WHERE id = ?1",
            [golden.credential_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let relationship_key = format!("{credential_key}|can_mutate|{WORKER_B_KEY}");
    let mut can_mutate = Relationship::new(
        &relationship_key,
        &golden.credential_id,
        &worker_b.id,
        "can_mutate",
        RelationshipState::Derived,
    )
    .unwrap();
    can_mutate.metadata = Some(json!({
        "capability": "WORKERS_SCRIPTS_WRITE",
        "authority_resolution": "EXACT",
        "credential_status": "ACTIVE",
        "permission_state": "WORKERS_SCRIPTS_WRITE",
        "account_scope_state": "IN_SCOPE",
        "target_observation_state": "OBSERVED",
        "sink_impact": "PRODUCTION",
        "unknown_reasons": [],
    }));
    relationships.upsert(&can_mutate).unwrap();

    let mut relationship_observation = Observation::new(
        &golden.scan_id,
        "relationship",
        &can_mutate.id,
        "present",
        "cloudflare_provider",
    )
    .unwrap();
    relationship_observation.metadata = Some(relationship_snapshot_metadata(&can_mutate));
    observations.insert(&relationship_observation).unwrap();

    // Reuse a same-scan evidence id so the new edge carries provenance.
    let evidence_id: String = db
        .connection()
        .query_row(
            "SELECT evidence_id FROM relationship_evidence LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    relationships
        .link_evidence(&can_mutate.id, &evidence_id)
        .unwrap();
    can_mutate.id
}

#[test]
fn one_finding_grouping_multiple_paths_and_sinks_shows_all() {
    let workspace = setup();
    run_golden_scan(workspace.path());
    let golden = golden_ids(workspace.path());
    let rel_b = add_worker_b(workspace.path(), &golden);
    insert_path(
        workspace.path(),
        &golden,
        &format!("attack_path_b_{}", golden.scan_id),
        "sha256:path-b-digest",
        &{
            let db = open_rw(workspace.path());
            let id: String = db
                .connection()
                .query_row(
                    "SELECT id FROM resources WHERE canonical_key = ?1",
                    [WORKER_B_KEY],
                    |row| row.get(0),
                )
                .unwrap();
            drop(db);
            id
        },
        Some(rel_b),
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    assert_eq!(list.findings.len(), 1);
    let summary = &list.findings[0];
    assert_eq!(summary.attack_path_count, 2);
    assert_eq!(summary.affected_sink_count, 2);

    let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();
    assert_eq!(detail.paths.len(), 2);
    let sink_names: Vec<&str> = detail
        .paths
        .iter()
        .map(|path| path.steps.last().unwrap().to_resource.name.as_str())
        .collect();
    assert!(sink_names.contains(&"checkout"), "worker A visible");
    assert!(sink_names.contains(&"checkout2"), "worker B visible");
    assert_eq!(
        detail.evidence.len(),
        golden_evidence_count(workspace.path())
    );
}

fn golden_evidence_count(workspace: &std::path::Path) -> usize {
    let db = open_rw(workspace);
    let count: u32 = db
        .connection()
        .query_row("SELECT COUNT(*) FROM finding_evidence", [], |row| {
            row.get(0)
        })
        .unwrap();
    drop(db);
    count as usize
}

#[test]
fn two_paths_reaching_the_same_sink_count_it_once() {
    let workspace = setup();
    run_golden_scan(workspace.path());
    let golden = golden_ids(workspace.path());
    insert_path(
        workspace.path(),
        &golden,
        &format!("attack_path_c_{}", golden.scan_id),
        "sha256:path-c-digest",
        &golden.sink_a_id,
        None,
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let summary = &list.findings[0];
    assert_eq!(summary.attack_path_count, 2);
    assert_eq!(summary.affected_sink_count, 1);

    let detail = FindingQueryService::get(workspace.path(), &summary.id).unwrap();
    assert_eq!(detail.paths.len(), 2);
    let sinks: Vec<&str> = detail
        .paths
        .iter()
        .map(|path| path.sink_resource_id.as_str())
        .collect();
    assert_eq!(sinks[0], golden.sink_a_id);
    assert_eq!(sinks[1], golden.sink_a_id);
    for path in &detail.paths {
        for pair in path.steps.windows(2) {
            assert_eq!(pair[0].to_resource.id, pair[1].from_resource.id);
        }
        assert_eq!(path.steps.len(), 5);
    }
}

#[test]
fn reverse_traversal_renders_a_connected_source_to_sink_chain() {
    let workspace = setup();
    run_golden_scan(workspace.path());
    let golden = golden_ids(workspace.path());
    let rel_b = add_worker_b(workspace.path(), &golden);
    insert_path(
        workspace.path(),
        &golden,
        &format!("attack_path_d_{}", golden.scan_id),
        "sha256:path-d-digest",
        &{
            let db = open_rw(workspace.path());
            let id: String = db
                .connection()
                .query_row(
                    "SELECT id FROM resources WHERE canonical_key = ?1",
                    [WORKER_B_KEY],
                    |row| row.get(0),
                )
                .unwrap();
            drop(db);
            id
        },
        Some(rel_b),
    );

    let list = FindingQueryService::list_latest(workspace.path()).unwrap();
    let detail = FindingQueryService::get(workspace.path(), &list.findings[0].id).unwrap();
    for path in &detail.paths {
        assert_eq!(
            path.steps[0].from_resource.id, path.source_resource_id,
            "chain starts at the declared source"
        );
        assert_eq!(
            path.steps.last().unwrap().to_resource.id,
            path.sink_resource_id,
            "chain ends at the declared sink"
        );
        let traversals: Vec<&str> = path
            .steps
            .iter()
            .map(|step| step.traversal.as_str())
            .collect();
        assert_eq!(traversals[..2], ["REVERSE", "REVERSE"]);
        assert_eq!(traversals[2..], ["FORWARD", "FORWARD", "FORWARD"]);
    }
}
