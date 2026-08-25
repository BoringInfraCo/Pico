//! Sprint 008 analysis-summary and AttackPath persistence contracts.

use chrono::Utc;
use pico::domain::{Evidence, EvidenceClass, Relationship, RelationshipState, Resource, Scan};
use pico::persistence::{
    AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo, Database,
    EvidenceRepo, RelationshipRepo, ResourceRepo, ScanAnalysisRecord, ScanAnalysisRepo, ScanRepo,
};
use pico::shared::PICO_VERSION;

fn test_db() -> Database {
    let dir = tempfile::tempdir().unwrap();
    // Keep the directory alive for the database connection's lifetime.
    let path = dir.keep().join("pico.db");
    let mut db = Database::open(&path).unwrap();
    db.migrate().unwrap();
    db
}

fn fixture(db: &Database) -> (String, String, String, String, String) {
    let scan = Scan::start(PICO_VERSION).unwrap();
    ScanRepo::new(db.connection()).insert(&scan).unwrap();
    let resources = ResourceRepo::new(db.connection());
    let source = Resource::new("source:fixture", "external_source", "fixture", "Source").unwrap();
    let actor = Resource::new("agent:fixture", "agent", "fixture", "Actor").unwrap();
    let sink = Resource::new("sink:fixture", "worker", "fixture", "Sink").unwrap();
    for resource in [&source, &actor, &sink] {
        resources.upsert(resource).unwrap();
    }
    let relationship = Relationship::new(
        "source:fixture|can_call|agent:fixture",
        &source.id,
        &actor.id,
        "can_call",
        RelationshipState::Derived,
    )
    .unwrap();
    RelationshipRepo::new(db.connection())
        .upsert(&relationship)
        .unwrap();
    let evidence = Evidence::new(
        &scan.id,
        EvidenceClass::Derived,
        "fixture",
        "fixture:source",
        &relationship.canonical_key,
        "fixture evidence",
        pico::domain::Sensitivity::Internal,
    )
    .unwrap();
    EvidenceRepo::new(db.connection())
        .insert(&evidence)
        .unwrap();
    (scan.id, source.id, actor.id, sink.id, relationship.id)
}

#[test]
fn analysis_summary_and_ordered_path_refs_round_trip() {
    let db = test_db();
    let (scan_id, source_id, actor_id, sink_id, relationship_id) = fixture(&db);
    let analysis = ScanAnalysisRecord {
        scan_id: scan_id.clone(),
        analysis_version: "analysis-v1".to_string(),
        status: "COMPLETE".to_string(),
        overall_disposition: Some("ACTIVE_PRESENT".to_string()),
        influence_path_count: 1,
        authority_path_count: 1,
        active_path_count: 1,
        blocked_path_count: 0,
        unresolved_candidate_count: 0,
        limit_reasons: None,
        diagnostics: Some(serde_json::json!({"reason_code": "FIXTURE"})),
        created_at: Utc::now(),
    };
    let summaries = ScanAnalysisRepo::new(db.connection());
    summaries.upsert(&analysis).unwrap();
    assert_eq!(summaries.get(&scan_id).unwrap().unwrap(), analysis);

    let path = AttackPathRecord {
        id: "path_fixture".to_string(),
        scan_id: scan_id.clone(),
        fingerprint: "fp_fixture".to_string(),
        analysis_version: "analysis-v1".to_string(),
        source_resource_id: source_id,
        actor_resource_id: actor_id,
        sink_resource_id: sink_id,
        disposition: "ACTIVE".to_string(),
        source_trust: "PUBLIC_EXTERNAL".to_string(),
        influence_strength: "AGENT_RETRIEVABLE".to_string(),
        capability: "CAN_EXECUTE".to_string(),
        authority_resolution: "EXACT".to_string(),
        sink_impact: "CONSEQUENTIAL".to_string(),
        boundary_metadata: Some(serde_json::json!({"boundary": "NONE"})),
        created_at: Utc::now(),
    };
    let paths = AttackPathRepo::new(db.connection());
    paths.insert(&path).unwrap();
    paths
        .insert_edge(&AttackPathEdgeRecord {
            attack_path_id: path.id.clone(),
            relationship_id,
            position: 0,
            phase: "INFLUENCE".to_string(),
            traversal: "FORWARD".to_string(),
        })
        .unwrap();
    paths
        .insert_evidence(&AttackPathEvidenceRecord {
            attack_path_id: path.id.clone(),
            evidence_id: EvidenceRepo::new(db.connection())
                .get_for_scan(&scan_id)
                .unwrap()
                .remove(0)
                .id,
            position: 0,
            support_role: "EDGE".to_string(),
        })
        .unwrap();

    assert_eq!(paths.get(&path.id).unwrap().unwrap(), path);
    assert_eq!(paths.list_for_scan(&scan_id).unwrap(), vec![path]);
    assert_eq!(paths.list_edges("path_fixture").unwrap().len(), 1);
    assert_eq!(paths.list_evidence("path_fixture").unwrap().len(), 1);
}

#[test]
fn invalid_path_disposition_and_missing_foreign_keys_fail_closed() {
    let db = test_db();
    let (scan_id, source_id, actor_id, sink_id, _) = fixture(&db);
    let mut path = AttackPathRecord {
        id: "invalid".to_string(),
        scan_id,
        fingerprint: "invalid".to_string(),
        analysis_version: "analysis-v1".to_string(),
        source_resource_id: source_id,
        actor_resource_id: actor_id,
        sink_resource_id: sink_id,
        disposition: "UNRESOLVED".to_string(),
        source_trust: "UNKNOWN".to_string(),
        influence_strength: "UNKNOWN".to_string(),
        capability: "UNKNOWN".to_string(),
        authority_resolution: "UNKNOWN".to_string(),
        sink_impact: "UNKNOWN".to_string(),
        boundary_metadata: None,
        created_at: Utc::now(),
    };
    assert!(AttackPathRepo::new(db.connection()).insert(&path).is_err());
    path.disposition = "BLOCKED".to_string();
    path.sink_resource_id = "missing-resource".to_string();
    assert!(AttackPathRepo::new(db.connection()).insert(&path).is_err());
}
