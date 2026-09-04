//! Sprint 009 Finding persistence: normalized rows, deterministic ordering,
//! same-scan links, and fail-closed validation.

use chrono::Utc;
use pico::domain::{
    Evidence, EvidenceClass, Relationship, RelationshipState, Resource, Scan, Sensitivity,
};
use pico::persistence::{
    AttackPathRecord, AttackPathRepo, Database, EvidenceRepo, FindingEvidenceRecord,
    FindingPathRecord, FindingReasonRecord, FindingRecord, FindingRemediationRecord, FindingRepo,
    RelationshipRepo, ResourceRepo, ScanRepo,
};
use pico::shared::PICO_VERSION;

fn test_db() -> Database {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.keep().join("pico.db");
    let mut db = Database::open(&path).unwrap();
    db.migrate().unwrap();
    db
}

struct Fixture {
    scan_id: String,
    other_scan_id: String,
    source_id: String,
    actor_id: String,
    path_id: String,
    evidence_id: String,
}

fn fixture(db: &Database) -> Fixture {
    let scan = Scan::start(PICO_VERSION).unwrap();
    let other_scan = Scan::start(PICO_VERSION).unwrap();
    ScanRepo::new(db.connection()).insert(&scan).unwrap();
    ScanRepo::new(db.connection()).insert(&other_scan).unwrap();

    let source = Resource::new("source:finding", "external_source", "fixture", "Source").unwrap();
    let actor = Resource::new("agent:finding", "agent", "fixture", "Actor").unwrap();
    let sink = Resource::new("sink:finding", "worker", "fixture", "Sink").unwrap();
    for resource in [&source, &actor, &sink] {
        ResourceRepo::new(db.connection()).upsert(resource).unwrap();
    }
    let relationship = Relationship::new(
        "source:finding|can_call|agent:finding",
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
        "fixture:finding",
        &relationship.canonical_key,
        "normalized finding evidence",
        Sensitivity::Internal,
    )
    .unwrap();
    EvidenceRepo::new(db.connection())
        .insert(&evidence)
        .unwrap();

    let path = AttackPathRecord {
        id: "attack_path_finding_fixture".to_string(),
        scan_id: scan.id.clone(),
        fingerprint: "attack-fingerprint".to_string(),
        analysis_version: "analysis-v1".to_string(),
        source_resource_id: source.id.clone(),
        actor_resource_id: actor.id.clone(),
        sink_resource_id: sink.id.clone(),
        disposition: "ACTIVE".to_string(),
        source_trust: "PUBLIC_EXTERNAL".to_string(),
        influence_strength: "AGENT_RETRIEVABLE".to_string(),
        capability: "EXECUTE".to_string(),
        authority_resolution: "EXACT".to_string(),
        sink_impact: "CONSEQUENTIAL".to_string(),
        boundary_metadata: None,
        created_at: Utc::now(),
    };
    AttackPathRepo::new(db.connection()).insert(&path).unwrap();

    Fixture {
        scan_id: scan.id,
        other_scan_id: other_scan.id,
        source_id: source.id,
        actor_id: actor.id,
        path_id: path.id,
        evidence_id: evidence.id,
    }
}

fn finding(fixture: &Fixture) -> FindingRecord {
    FindingRecord {
        id: format!("finding_{}:digest", fixture.scan_id),
        scan_id: fixture.scan_id.clone(),
        fingerprint: "finding-fingerprint".to_string(),
        family_fingerprint: "finding-family".to_string(),
        finding_version: "finding-v1".to_string(),
        finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
        title: "External content can reach production mutation authority".to_string(),
        summary: "Externally controlled content can reach an autonomous coding environment with authority capable of changing an explicitly classified production resource.".to_string(),
        severity: "CRITICAL".to_string(),
        confidence: "HIGH".to_string(),
        status: "OPEN".to_string(),
        metadata: Some(serde_json::json!({"source": "deterministic-engine"})),
        created_at: Utc::now(),
    }
}

#[test]
fn finding_and_ordered_links_round_trip() {
    let db = test_db();
    let fixture = fixture(&db);
    let record = finding(&fixture);
    let repo = FindingRepo::new(db.connection());
    repo.insert(&record).unwrap();
    repo.insert_path(&FindingPathRecord {
        finding_id: record.id.clone(),
        attack_path_id: fixture.path_id.clone(),
        position: 0,
    })
    .unwrap();
    repo.insert_evidence(&FindingEvidenceRecord {
        finding_id: record.id.clone(),
        evidence_id: fixture.evidence_id.clone(),
        position: 0,
        support_role: "ATTACK_PATH".to_string(),
    })
    .unwrap();
    repo.insert_reason(&FindingReasonRecord {
        finding_id: record.id.clone(),
        position: 0,
        reason_code: "EXTERNAL_INFLUENCE_SOURCE".to_string(),
        resource_ids: vec![fixture.source_id.clone(), fixture.actor_id.clone()],
        relationship_ids: vec![],
        attack_path_ids: vec![fixture.path_id.clone()],
        evidence_ids: vec![fixture.evidence_id.clone()],
    })
    .unwrap();
    repo.insert_remediation(&FindingRemediationRecord {
        finding_id: record.id.clone(),
        position: 0,
        rule_id: "RESTRICT_EXTERNAL_RETRIEVAL".to_string(),
        title: "Restrict external retrieval".to_string(),
        description: "Limit the exact retrieval capability.".to_string(),
        security_effect: "Breaks the influence edge.".to_string(),
        cut_phase: "INFLUENCE".to_string(),
        target_resource_ids: vec![fixture.source_id.clone(), fixture.actor_id.clone()],
        target_relationship_ids: vec![],
    })
    .unwrap();

    assert_eq!(repo.get(&record.id).unwrap().unwrap(), record);
    assert_eq!(
        repo.list_for_scan(&fixture.scan_id).unwrap(),
        vec![record.clone()]
    );
    assert_eq!(repo.list_paths(&record.id).unwrap().len(), 1);
    assert_eq!(repo.list_evidence(&record.id).unwrap().len(), 1);
    assert_eq!(
        repo.list_reasons(&record.id).unwrap()[0].reason_code,
        "EXTERNAL_INFLUENCE_SOURCE"
    );
    assert_eq!(
        repo.list_remediations(&record.id).unwrap()[0].rule_id,
        "RESTRICT_EXTERNAL_RETRIEVAL"
    );
}

#[test]
fn duplicate_scan_fingerprint_and_foreign_scan_links_fail_closed() {
    let db = test_db();
    let fixture = fixture(&db);
    let record = finding(&fixture);
    let repo = FindingRepo::new(db.connection());
    repo.insert(&record).unwrap();
    assert!(repo.insert(&record).is_err());

    let mut foreign = record.clone();
    foreign.id = "finding_foreign".to_string();
    foreign.scan_id = fixture.other_scan_id;
    repo.insert(&foreign).unwrap();
    assert!(repo
        .insert_path(&FindingPathRecord {
            finding_id: record.id,
            attack_path_id: fixture.path_id,
            position: 0,
        })
        .is_ok());

    // This evidence belongs to the first scan, so linking it from the second
    // scan must be rejected by the database trigger.
    assert!(repo
        .insert_evidence(&FindingEvidenceRecord {
            finding_id: foreign.id,
            evidence_id: fixture.evidence_id,
            position: 0,
            support_role: "SINK_CLASSIFICATION".to_string(),
        })
        .is_err());
}

#[test]
fn finding_validation_rejects_unsupported_values() {
    let db = test_db();
    let fixture = fixture(&db);
    let mut record = finding(&fixture);
    record.severity = "SEVERE".to_string();
    assert!(FindingRepo::new(db.connection()).insert(&record).is_err());
    record.severity = "CRITICAL".to_string();
    record.finding_class = "OTHER".to_string();
    assert!(FindingRepo::new(db.connection()).insert(&record).is_err());
}
