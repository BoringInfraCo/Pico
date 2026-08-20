//! Repository persistence for scans, resources, relationships,
//! evidence, and observations.

use pico::domain::{
    Evidence, EvidenceClass, Observation, Relationship, RelationshipState, Resource, Scan,
    ScanStatus, ScanTrigger, Sensitivity,
};
use pico::persistence::{
    Database, EvidenceRepo, ObservationRepo, RelationshipRepo, ResourceRepo, ScanRepo,
};
use pico::shared::PICO_VERSION;
use tempfile::tempdir;

fn test_db() -> (tempfile::TempDir, Database) {
    let dir = tempdir().unwrap();
    let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
    db.migrate().unwrap();
    (dir, db)
}

fn stored_scan(db: &Database) -> Scan {
    let scan = Scan::start(PICO_VERSION).unwrap();
    ScanRepo::new(db.connection()).insert(&scan).unwrap();
    scan
}

#[test]
fn scan_insert_count_and_get() {
    let (_dir, db) = test_db();
    let repo = ScanRepo::new(db.connection());
    assert_eq!(repo.count().unwrap(), 0);
    let scan = stored_scan(&db);
    assert_eq!(repo.count().unwrap(), 1);
    let loaded = repo.get(&scan.id).unwrap().unwrap();
    assert_eq!(loaded.id, scan.id);
    assert_eq!(loaded.status, ScanStatus::Running);
    assert_eq!(loaded.trigger, scan.trigger);
    assert_eq!(loaded.pico_version, PICO_VERSION);
    assert_eq!(loaded.completed_at, None);
    assert!(repo.get("scan_missing").unwrap().is_none());
}

#[test]
fn scan_completion_update() {
    let (_dir, db) = test_db();
    let repo = ScanRepo::new(db.connection());
    let running = stored_scan(&db);
    let completed = running.complete().unwrap();
    repo.update(&completed).unwrap();
    let loaded = repo.get(&completed.id).unwrap().unwrap();
    assert_eq!(loaded.status, ScanStatus::Complete);
    assert!(loaded.completed_at.is_some());
    assert_eq!(loaded.started_at, completed.started_at);
    assert_eq!(loaded.trigger, ScanTrigger::Manual);
}

#[test]
fn resource_upsert_preserves_first_and_refreshes_last_observation() {
    let (_dir, db) = test_db();
    let repo = ResourceRepo::new(db.connection());
    let first = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
    repo.upsert(&first).unwrap();
    let second = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
    repo.upsert(&second).unwrap();
    assert_eq!(repo.count().unwrap(), 1);
    let loaded = repo
        .get_by_canonical_key("agent:opencode:default")
        .unwrap()
        .unwrap();
    assert_eq!(loaded.id, first.id);
    assert_eq!(loaded.first_observed_at, first.first_observed_at);
    assert_eq!(loaded.last_observed_at, second.last_observed_at);
    assert!(loaded.last_observed_at >= first.last_observed_at);
}

#[test]
fn resource_get_by_id_and_missing_lookups() {
    let (_dir, db) = test_db();
    let repo = ResourceRepo::new(db.connection());
    let r = Resource::new("shell:bash", "shell", "local", "Bash").unwrap();
    repo.upsert(&r).unwrap();
    let loaded = repo.get(&r.id).unwrap().unwrap();
    assert_eq!(loaded.canonical_key, "shell:bash");
    assert_eq!(loaded.kind, "shell");
    assert_eq!(loaded.provider, "local");
    assert_eq!(loaded.name, "Bash");
    assert!(repo.get("res_missing").unwrap().is_none());
    assert!(repo.get_by_canonical_key("nope").unwrap().is_none());
}

#[test]
fn relationship_persistence() {
    let (_dir, db) = test_db();
    let resources = ResourceRepo::new(db.connection());
    let a = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
    let b = Resource::new("shell:bash", "shell", "local", "Bash").unwrap();
    resources.upsert(&a).unwrap();
    resources.upsert(&b).unwrap();
    let repo = RelationshipRepo::new(db.connection());
    let rel = Relationship::new(
        "agent:opencode:default|can_execute|shell:bash",
        &a.id,
        &b.id,
        "can_execute",
        RelationshipState::Confirmed,
    )
    .unwrap();
    repo.upsert(&rel).unwrap();
    assert_eq!(repo.count().unwrap(), 1);
    let loaded = repo.get(&rel.id).unwrap().unwrap();
    assert_eq!(loaded.canonical_key, rel.canonical_key);
    assert_eq!(loaded.from_resource_id, a.id);
    assert_eq!(loaded.to_resource_id, b.id);
    assert_eq!(loaded.kind, "can_execute");
    assert_eq!(loaded.state, RelationshipState::Confirmed);
    assert!(repo.get("rel_missing").unwrap().is_none());
}

#[test]
fn relationship_upsert_updates_state_by_canonical_key() {
    let (_dir, db) = test_db();
    let resources = ResourceRepo::new(db.connection());
    let a = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
    let b = Resource::new("shell:bash", "shell", "local", "Bash").unwrap();
    resources.upsert(&a).unwrap();
    resources.upsert(&b).unwrap();
    let repo = RelationshipRepo::new(db.connection());
    let rel = Relationship::new(
        "agent:opencode:default|can_execute|shell:bash",
        &a.id,
        &b.id,
        "can_execute",
        RelationshipState::Confirmed,
    )
    .unwrap();
    repo.upsert(&rel).unwrap();
    let updated = Relationship::new(
        "agent:opencode:default|can_execute|shell:bash",
        &a.id,
        &b.id,
        "can_execute",
        RelationshipState::Derived,
    )
    .unwrap();
    repo.upsert(&updated).unwrap();
    assert_eq!(repo.count().unwrap(), 1);
    let loaded = repo.get(&rel.id).unwrap().unwrap();
    assert_eq!(loaded.state, RelationshipState::Derived);
}

#[test]
fn evidence_persistence() {
    let (_dir, db) = test_db();
    let scan = stored_scan(&db);
    let repo = EvidenceRepo::new(db.connection());
    let ev = Evidence::new(
        &scan.id,
        EvidenceClass::Direct,
        "opencode_config",
        "~/.config/opencode/opencode.json",
        "permission.bash",
        "allow",
        Sensitivity::Internal,
    )
    .unwrap();
    repo.insert(&ev).unwrap();
    assert_eq!(repo.count().unwrap(), 1);
    let loaded = repo.get(&ev.id).unwrap().unwrap();
    assert_eq!(loaded.scan_id, scan.id);
    assert_eq!(loaded.class, EvidenceClass::Direct);
    assert_eq!(loaded.source_type, "opencode_config");
    assert_eq!(loaded.source_locator, "~/.config/opencode/opencode.json");
    assert_eq!(loaded.subject, "permission.bash");
    assert_eq!(loaded.observation, "allow");
    assert_eq!(loaded.sensitivity, Sensitivity::Internal);
    assert!(repo.get("ev_missing").unwrap().is_none());
}

#[test]
fn observation_persistence() {
    let (_dir, db) = test_db();
    let scan = stored_scan(&db);
    let repo = ObservationRepo::new(db.connection());
    let obs =
        Observation::new(&scan.id, "resource", "res_1", "present", "opencode_adapter").unwrap();
    repo.insert(&obs).unwrap();
    assert_eq!(repo.count().unwrap(), 1);
    let loaded = repo.get(&obs.id).unwrap().unwrap();
    assert_eq!(loaded.scan_id, scan.id);
    assert_eq!(loaded.subject_type, "resource");
    assert_eq!(loaded.subject_id, "res_1");
    assert_eq!(loaded.observation_type, "present");
    assert_eq!(loaded.source, "opencode_adapter");
    assert!(repo.get("obs_missing").unwrap().is_none());
}
