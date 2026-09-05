//! Sprint 030 retention, prune, and doctor service contracts.
//!
//! Exercises the public application API end to end: the retention plan,
//! `PruneService` (refusal, no-op, ordered deletion, idempotency), and the
//! read-only `DoctorService`. Engine-level deletion and rollback proofs live
//! in `src/application/retention.rs` (the engine is `pub(crate)`).

use chrono::{DateTime, TimeZone, Utc};
use pico::application::{
    plan_retention, DanglingRef, DoctorService, PruneService, RetentionWindow, UnitCounts,
    KEEP_COMPLETE_DEFAULT,
};
use pico::domain::{
    Evidence, EvidenceClass, Observation, Relationship, RelationshipState, Resource, Scan,
    ScanStatus, ScanTrigger, Sensitivity,
};
use pico::persistence::{
    AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo, Database,
    EvidenceRepo, FindingEvidenceRecord, FindingPathRecord, FindingReasonRecord, FindingRecord,
    FindingRemediationRecord, FindingRepo, ObservationRepo, RelationshipRepo, ResourceRepo,
    ScanAnalysisRecord, ScanAnalysisRepo, ScanDiagnosticsRepo, ScanRepo,
};
use pico::shared::{PicoError, PICO_VERSION};

fn ts(hours: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap() + chrono::Duration::hours(hours)
}

fn scan_with(
    id: &str,
    status: ScanStatus,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
) -> Scan {
    Scan {
        id: id.to_string(),
        started_at,
        completed_at,
        status,
        trigger: ScanTrigger::Manual,
        scope: None,
        pico_version: PICO_VERSION.to_string(),
        environment_fingerprint: None,
        metadata: None,
    }
}

fn workspace_db(workspace: &std::path::Path) -> Database {
    let dir = workspace.join(".pico");
    std::fs::create_dir_all(&dir).unwrap();
    let mut db = Database::open(&dir.join("pico.db")).unwrap();
    db.migrate().unwrap();
    db
}

const ALL_TABLES: [&str; 16] = [
    "scans",
    "resources",
    "relationships",
    "observations",
    "evidence",
    "relationship_evidence",
    "scan_analyses",
    "attack_paths",
    "attack_path_edges",
    "attack_path_evidence",
    "findings",
    "finding_paths",
    "finding_evidence",
    "finding_reasons",
    "finding_remediations",
    "scan_diagnostics",
];

fn count_rows(conn: &rusqlite::Connection, table: &str) -> u64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get::<_, i64>(0)
    })
    .unwrap() as u64
}

fn table_counts(conn: &rusqlite::Connection) -> Vec<u64> {
    ALL_TABLES
        .iter()
        .map(|table| count_rows(conn, table))
        .collect()
}

/// Seed one coherent whole scan unit with explicit timestamps. The scan
/// lifecycle row is inserted as RUNNING first (the analysis summary refuses
/// upserts after COMPLETE, S029) and finalized afterwards. Returns
/// `(scan, evidence_id, finding_id)`.
fn seed_unit(
    db: &Database,
    scan_id: &str,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    status: ScanStatus,
) -> (Scan, String, String) {
    let conn = db.connection();
    let scan_repo = ScanRepo::new(conn);
    scan_repo
        .insert(&scan_with(scan_id, ScanStatus::Running, started_at, None))
        .unwrap();

    ScanAnalysisRepo::new(conn)
        .upsert(&ScanAnalysisRecord {
            scan_id: scan_id.to_string(),
            analysis_version: "analysis-v1".to_string(),
            status: "COMPLETE".to_string(),
            overall_disposition: Some("ACTIVE_PRESENT".to_string()),
            influence_path_count: 1,
            authority_path_count: 1,
            active_path_count: 1,
            blocked_path_count: 0,
            unresolved_candidate_count: 0,
            limit_reasons: None,
            diagnostics: None,
            created_at: started_at,
        })
        .unwrap();
    ScanDiagnosticsRepo::new(conn)
        .upsert(scan_id, r#"{"reason_code":"FIXTURE"}"#)
        .unwrap();

    let resources = ResourceRepo::new(conn);
    for (id, key, kind, provider, name) in [
        (
            "res_src",
            "external_source:src",
            "external_source",
            "fixture",
            "Source",
        ),
        ("res_actor", "agent:actor", "agent", "fixture", "Actor"),
        ("res_sink", "worker:sink", "worker", "fixture", "Sink"),
    ] {
        resources
            .upsert(&Resource {
                id: id.to_string(),
                canonical_key: key.to_string(),
                kind: kind.to_string(),
                provider: provider.to_string(),
                name: name.to_string(),
                metadata: None,
                first_observed_at: started_at,
                last_observed_at: started_at,
            })
            .unwrap();
    }
    let relationship = Relationship {
        id: format!("rel_{scan_id}"),
        canonical_key: format!("external_source:src|can_call|agent:{scan_id}"),
        from_resource_id: "res_src".to_string(),
        to_resource_id: "res_actor".to_string(),
        kind: "can_call".to_string(),
        state: RelationshipState::Derived,
        metadata: None,
        first_observed_at: started_at,
        last_observed_at: started_at,
    };
    RelationshipRepo::new(conn).upsert(&relationship).unwrap();

    let evidence = Evidence {
        id: format!("ev_{scan_id}"),
        scan_id: scan_id.to_string(),
        class: EvidenceClass::Direct,
        source_type: "fixture".to_string(),
        source_locator: "fixture:source".to_string(),
        subject: format!("subject_{scan_id}"),
        observation: "fixture evidence".to_string(),
        captured_at: started_at,
        freshness: Some("FRESH".to_string()),
        sensitivity: Sensitivity::Internal,
        metadata: None,
    };
    EvidenceRepo::new(conn).insert(&evidence).unwrap();
    RelationshipRepo::new(conn)
        .link_evidence(&relationship.id, &evidence.id)
        .unwrap();

    let attack_path_id = format!("ap_{scan_id}");
    let paths = AttackPathRepo::new(conn);
    paths
        .insert(&AttackPathRecord {
            id: attack_path_id.clone(),
            scan_id: scan_id.to_string(),
            fingerprint: format!("sha256:path:{scan_id}"),
            analysis_version: "analysis-v1".to_string(),
            source_resource_id: "res_src".to_string(),
            actor_resource_id: "res_actor".to_string(),
            sink_resource_id: "res_sink".to_string(),
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_RETRIEVABLE".to_string(),
            capability: "CAN_EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "PRODUCTION".to_string(),
            boundary_metadata: None,
            created_at: started_at,
        })
        .unwrap();
    paths
        .insert_edge(&AttackPathEdgeRecord {
            attack_path_id: attack_path_id.clone(),
            relationship_id: relationship.id.clone(),
            position: 0,
            phase: "INFLUENCE".to_string(),
            traversal: "FORWARD".to_string(),
        })
        .unwrap();
    paths
        .insert_evidence(&AttackPathEvidenceRecord {
            attack_path_id: attack_path_id.clone(),
            evidence_id: evidence.id.clone(),
            position: 0,
            support_role: "EDGE".to_string(),
        })
        .unwrap();

    let finding_id = format!("finding_{scan_id}");
    let findings = FindingRepo::new(conn);
    findings
        .insert(&FindingRecord {
            id: finding_id.clone(),
            scan_id: scan_id.to_string(),
            fingerprint: format!("sha256:finding:{scan_id}"),
            family_fingerprint: format!("sha256:family:{scan_id}"),
            finding_version: "v1".to_string(),
            finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
            title: "Fixture finding".to_string(),
            summary: "Fixture finding summary".to_string(),
            severity: "CRITICAL".to_string(),
            confidence: "HIGH".to_string(),
            status: "OPEN".to_string(),
            metadata: None,
            created_at: started_at,
        })
        .unwrap();
    findings
        .insert_path(&FindingPathRecord {
            finding_id: finding_id.clone(),
            attack_path_id: attack_path_id.clone(),
            position: 0,
        })
        .unwrap();
    findings
        .insert_evidence(&FindingEvidenceRecord {
            finding_id: finding_id.clone(),
            evidence_id: evidence.id.clone(),
            position: 0,
            support_role: "EDGE".to_string(),
        })
        .unwrap();
    findings
        .insert_reason(&FindingReasonRecord {
            finding_id: finding_id.clone(),
            position: 0,
            reason_code: "PRODUCTION_SINK".to_string(),
            resource_ids: vec!["res_src".to_string()],
            relationship_ids: vec![relationship.id.clone()],
            attack_path_ids: vec![attack_path_id.clone()],
            evidence_ids: vec![evidence.id.clone()],
        })
        .unwrap();
    findings
        .insert_remediation(&FindingRemediationRecord {
            finding_id: finding_id.clone(),
            position: 0,
            rule_id: "ENFIX".to_string(),
            title: "Fixture remediation".to_string(),
            description: "Fixture remediation description".to_string(),
            security_effect: "Interrupts the fixture path".to_string(),
            cut_phase: "AUTHORITY".to_string(),
            target_resource_ids: vec!["res_actor".to_string()],
            target_relationship_ids: vec![relationship.id.clone()],
        })
        .unwrap();

    ObservationRepo::new(conn)
        .insert(&Observation {
            id: format!("obs_{scan_id}"),
            scan_id: scan_id.to_string(),
            subject_type: "resource".to_string(),
            subject_id: "res_sink".to_string(),
            observation_type: "present".to_string(),
            observed_at: started_at,
            source: "fixture".to_string(),
            metadata: None,
        })
        .unwrap();

    let scan = scan_with(
        scan_id,
        status,
        started_at,
        completed_at.or(Some(started_at)),
    );
    scan_repo.update(&scan).unwrap();
    (scan, evidence.id, finding_id)
}

const FULL_UNIT_COUNTS: UnitCounts = UnitCounts {
    observations: 1,
    evidence: 1,
    findings: 1,
    attack_paths: 1,
    scan_analyses: 1,
    scan_diagnostics: 1,
    relationship_evidence: 1,
};

#[test]
fn retention_policy_is_reachable_through_public_api() {
    let scans = vec![
        scan_with("scan_old", ScanStatus::Complete, ts(1), Some(ts(1))),
        scan_with("scan_new", ScanStatus::Complete, ts(2), Some(ts(2))),
        scan_with("scan_partial", ScanStatus::Partial, ts(3), Some(ts(3))),
    ];
    let plan = plan_retention(
        RetentionWindow {
            keep: KEEP_COMPLETE_DEFAULT,
        },
        &scans,
    );
    assert_eq!(
        plan.keep_ids,
        ["scan_old", "scan_new"].map(String::from).to_vec()
    );
    assert!(plan.prune_complete.is_empty());
    assert!(plan.prune_incomplete.is_empty());
}

#[test]
fn keep_window_validation_happens_before_any_database_work() {
    // The workspace has no `.pico` directory at all: only the flag
    // validation runs before any database access, so the keep error must
    // win over the missing-state error.
    let workspace = tempfile::tempdir().unwrap();
    for keep in [Some(0), Some(1)] {
        let error = PruneService::run(workspace.path(), keep).unwrap_err();
        assert!(
            matches!(error, PicoError::Usage(ref msg) if msg == "--keep must be an integer of at least 2"),
            "expected the frozen usage error, got {error:?}"
        );
    }
    assert!(!workspace.path().join(".pico").exists());
}

#[test]
fn prune_service_refuses_running_scan_and_changes_nothing() {
    let workspace = tempfile::tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_keep", ts(1), Some(ts(1)), ScanStatus::Complete);
    // Two RUNNING attempts: the newest (started_at, id) tuple must be named.
    ScanRepo::new(db.connection())
        .insert(&scan_with(
            "scan_running_old",
            ScanStatus::Running,
            ts(2),
            None,
        ))
        .unwrap();
    ScanRepo::new(db.connection())
        .insert(&scan_with(
            "scan_running_new",
            ScanStatus::Running,
            ts(6),
            None,
        ))
        .unwrap();

    let conn = db.connection();
    let before = table_counts(conn);
    let error = PruneService::run(workspace.path(), None).unwrap_err();
    assert!(
        matches!(error, PicoError::Usage(ref msg) if msg == "cannot prune while scan scan_running_new is RUNNING"),
        "expected the frozen refusal naming the newest RUNNING scan, got {error:?}"
    );
    assert_eq!(table_counts(conn), before, "refusal must change nothing");
}

#[test]
fn prune_service_no_op_below_window() {
    let workspace = tempfile::tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(
        &db,
        "scan_keep_old",
        ts(1),
        Some(ts(1)),
        ScanStatus::Complete,
    );
    seed_unit(
        &db,
        "scan_keep_new",
        ts(2),
        Some(ts(2)),
        ScanStatus::Complete,
    );
    let conn = db.connection();
    let before = table_counts(conn);

    let report = PruneService::run(workspace.path(), None).unwrap();
    assert!(report.nothing_pruned);
    assert!(report.pruned.is_empty());
    assert_eq!(
        report.totals,
        pico::application::PruneTotals(UnitCounts::default())
    );
    assert_eq!(
        report.retained.complete, 2,
        "both COMPLETE scans stay below the default window"
    );
    assert_eq!(report.retained.partial, 0);
    assert_eq!(report.retained.failed, 0);
    assert_eq!(report.retained.running, 0);
    assert!(report.pre_health_ok);
    assert!(report.post_health_ok);
    assert_eq!(report.keep, KEEP_COMPLETE_DEFAULT);
    assert_eq!(table_counts(conn), before, "no-op must write nothing");
}

#[test]
fn prune_service_prunes_oldest_units_in_order_and_is_idempotent() {
    let workspace = tempfile::tempdir().unwrap();
    let db = workspace_db(workspace.path());
    for i in 1..=4 {
        seed_unit(
            &db,
            &format!("scan_{i:02}"),
            ts(i),
            Some(ts(i)),
            ScanStatus::Complete,
        );
    }
    let conn = db.connection();
    let globals_before = (
        count_rows(conn, "resources"),
        count_rows(conn, "relationships"),
    );

    let report = PruneService::run(workspace.path(), Some(2)).unwrap();
    assert_eq!(report.keep, 2);
    assert!(!report.nothing_pruned);
    assert!(report.pre_health_ok);
    assert!(report.post_health_ok);
    let pruned_ids: Vec<&str> = report
        .pruned
        .iter()
        .map(|unit| unit.scan_id.as_str())
        .collect();
    assert_eq!(pruned_ids, ["scan_01", "scan_02"], "prune oldest-first");
    for unit in &report.pruned {
        assert_eq!(unit.status, "COMPLETE");
        assert_eq!(unit.counts, FULL_UNIT_COUNTS);
    }
    assert_eq!(
        report.totals.0,
        UnitCounts {
            observations: 2,
            evidence: 2,
            findings: 2,
            attack_paths: 2,
            scan_analyses: 2,
            scan_diagnostics: 2,
            relationship_evidence: 2,
        }
    );
    assert_eq!(report.retained.complete, 2);
    assert_eq!(report.retained.partial, 0);
    assert_eq!(report.retained.failed, 0);
    assert_eq!(report.retained.running, 0);

    // Whole units are gone; retained units and global surfaces stay.
    let remaining: Vec<String> = ScanRepo::new(conn)
        .list()
        .unwrap()
        .into_iter()
        .map(|scan| scan.id)
        .collect();
    assert_eq!(remaining, ["scan_03", "scan_04"].map(String::from).to_vec());
    assert_eq!(count_rows(conn, "findings"), 2);
    assert_eq!(count_rows(conn, "evidence"), 2);
    assert_eq!(count_rows(conn, "finding_reasons"), 2);
    assert_eq!(count_rows(conn, "attack_paths"), 2);
    assert_eq!(count_rows(conn, "observations"), 2);
    assert_eq!(count_rows(conn, "resources"), globals_before.0);
    assert_eq!(count_rows(conn, "relationships"), globals_before.1);
    assert_eq!(count_rows(conn, "relationship_evidence"), 2);

    // Re-running prune below the new window is a no-op.
    let again = PruneService::run(workspace.path(), Some(2)).unwrap();
    assert!(again.nothing_pruned);
    assert!(again.pruned.is_empty());
}

#[test]
fn prune_service_prunes_stale_incomplete_attempts() {
    let workspace = tempfile::tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(
        &db,
        "scan_partial_1",
        ts(1),
        Some(ts(1)),
        ScanStatus::Partial,
    );
    seed_unit(&db, "scan_failed_1", ts(2), Some(ts(2)), ScanStatus::Failed);
    seed_unit(
        &db,
        "scan_complete",
        ts(5),
        Some(ts(5)),
        ScanStatus::Complete,
    );
    seed_unit(
        &db,
        "scan_partial_new",
        ts(7),
        Some(ts(7)),
        ScanStatus::Partial,
    );

    let report = PruneService::run(workspace.path(), None).unwrap();
    assert!(!report.nothing_pruned);
    let pruned: Vec<(&str, &str)> = report
        .pruned
        .iter()
        .map(|unit| (unit.scan_id.as_str(), unit.status.as_str()))
        .collect();
    assert_eq!(
        pruned,
        [("scan_partial_1", "PARTIAL"), ("scan_failed_1", "FAILED")],
        "incomplete attempts strictly older than the newest COMPLETE, oldest-first"
    );
    for unit in &report.pruned {
        assert_eq!(unit.counts, FULL_UNIT_COUNTS);
    }
    assert_eq!(report.retained.complete, 1);
    assert_eq!(report.retained.partial, 1, "the newer attempt is kept");
    assert_eq!(report.retained.failed, 0);

    let remaining: Vec<String> = ScanRepo::new(db.connection())
        .list()
        .unwrap()
        .into_iter()
        .map(|scan| scan.id)
        .collect();
    assert_eq!(
        remaining,
        ["scan_complete", "scan_partial_new"]
            .map(String::from)
            .to_vec()
    );
}

#[test]
fn doctor_service_reports_ok_and_writes_nothing() {
    let workspace = tempfile::tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(
        &db,
        "scan_keep_old",
        ts(1),
        Some(ts(1)),
        ScanStatus::Complete,
    );
    seed_unit(
        &db,
        "scan_keep_new",
        ts(2),
        Some(ts(2)),
        ScanStatus::Complete,
    );
    seed_unit(
        &db,
        "scan_partial_new",
        ts(3),
        Some(ts(3)),
        ScanStatus::Partial,
    );
    let conn = db.connection();
    let before = table_counts(conn);

    let report = DoctorService::run(workspace.path()).unwrap();
    assert!(report.ok, "expected a healthy report, got {report:?}");
    assert!(report.schema_ok);
    assert!(report.integrity_ok);
    assert!(report.foreign_keys_ok);
    assert_eq!(report.schema_version, 6);
    assert!(report.dangling_json_refs.is_empty());
    assert_eq!(report.orphan_scan_rows, 0);
    assert_eq!(report.summary_rows, 0);
    assert_eq!(report.counts.complete, 2);
    assert_eq!(report.counts.partial, 1);
    assert_eq!(report.window_keep, KEEP_COMPLETE_DEFAULT);
    assert_eq!(
        report.oldest_retained_complete.as_deref(),
        Some("scan_keep_old")
    );
    assert_eq!(report.newest_complete.as_deref(), Some("scan_keep_new"));
    assert_eq!(table_counts(conn), before, "doctor must never write");
}

#[test]
fn doctor_service_reports_injected_dangling_reference() {
    let workspace = tempfile::tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_one", ts(1), Some(ts(1)), ScanStatus::Complete);
    FindingRepo::new(db.connection())
        .insert_reason(&FindingReasonRecord {
            finding_id: "finding_scan_one".to_string(),
            position: 1,
            reason_code: "DANGLING".to_string(),
            resource_ids: vec![],
            relationship_ids: vec![],
            attack_path_ids: vec![],
            evidence_ids: vec!["evidence_nonexistent".to_string()],
        })
        .unwrap();

    let report = DoctorService::run(workspace.path()).unwrap();
    assert!(!report.ok, "an injected inconsistency must fail closed");
    assert_eq!(report.dangling_json_refs.len(), 1);
    assert_eq!(report.dangling_more, 0);
    // SPRINT-031 §5.2 shape: redacted diagnostics carry the stable reason
    // code, the referenced table, and a bounded structural location with the
    // per-cell unresolved count — never the unresolved id itself.
    assert_eq!(
        report.dangling_json_refs[0],
        DanglingRef {
            table: "finding_reasons".to_string(),
            column: "evidence_ids".to_string(),
            referenced_table: "evidence".to_string(),
            category: "unresolved".to_string(),
            finding_id: "finding_scan_one".to_string(),
            position: 1,
            unresolved_count: 1,
        }
    );
}
