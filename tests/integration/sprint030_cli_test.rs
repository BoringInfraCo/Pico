//! Sprint 030 `pico prune` CLI fixtures (SPRINT-030.md §4 R1–R5, R8).
//!
//! Each fixture drives `PruneService` through the real renderer. Zero-write
//! proofs reuse the S029 whole-database `content_digest` pattern; the
//! retained-row digest restricts the same canonical serialization to the
//! scan units the window keeps (plus the never-pruned global identity
//! surfaces), so byte-identity proves every retained row survives a prune
//! untouched.

use std::fs;
use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use pico::application::{
    DiffService, DoctorService, FindingDiffResult, HistoryService, PruneService, PruneTotals,
    RetentionCounts, UnitCounts, CURRENT_COMPARISON_CONTRACT,
};
use pico::cli::render::{render_doctor_report, render_finding_diff, render_prune_report};
use pico::domain::{
    resource_snapshot_metadata, Evidence, EvidenceClass, Observation, Relationship,
    RelationshipState, Resource, Scan, ScanStatus, ScanTrigger, Sensitivity,
};
use pico::persistence::{
    AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo, Database,
    EvidenceRepo, FindingEvidenceRecord, FindingPathRecord, FindingReasonRecord, FindingRecord,
    FindingRemediationRecord, FindingRepo, ObservationRepo, RelationshipRepo, ResourceRepo,
    ScanAnalysisRecord, ScanAnalysisRepo, ScanDiagnosticsRepo, ScanRepo,
};
use pico::shared::{PicoError, PICO_VERSION};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn workspace_db(workspace: &Path) -> Database {
    let dir = workspace.join(".pico");
    fs::create_dir_all(&dir).unwrap();
    let mut db = Database::open(&dir.join("pico.db")).unwrap();
    db.migrate().unwrap();
    db
}

/// Deterministic clock base: every fixture scan gets an explicit timestamp so
/// retention windowing never depends on wall-clock races. Larger arguments
/// are newer.
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

/// Declared comparison-contract Scan metadata (SPRINT-029): `analysis_version`
/// is intentionally absent (the scan_analyses summary is authoritative).
fn metadata() -> serde_json::Value {
    serde_json::json!({
        "comparison_contract_version": 1,
        "graph_snapshot_version": 1,
        "finding_version": 1,
    })
}

/// Row counts of one fully seeded unit (every counted table carries exactly
/// one row).
const FULL_UNIT_COUNTS: UnitCounts = UnitCounts {
    observations: 1,
    evidence: 1,
    findings: 1,
    attack_paths: 1,
    scan_analyses: 1,
    scan_diagnostics: 1,
    relationship_evidence: 1,
};

/// Seed one coherent whole scan unit with explicit timestamps and a valid
/// S029 comparison contract: the declared tuple `c1-g1-f1`, the canonical
/// analysis version "1" on the summary and every attack path, `finding_version`
/// "1" on every Finding row, and one resource observation snapshot at the
/// declared graph version. The scan lifecycle row is inserted as RUNNING
/// first (the analysis summary refuses upserts after COMPLETE, S029) and
/// finalized with its declared metadata afterwards.
fn seed_unit(db: &Database, scan_id: &str, started_at: DateTime<Utc>, status: ScanStatus) {
    let conn = db.connection();
    let scan_repo = ScanRepo::new(conn);
    scan_repo
        .insert(&scan_with(scan_id, ScanStatus::Running, started_at, None))
        .unwrap();

    ScanAnalysisRepo::new(conn)
        .upsert(&ScanAnalysisRecord {
            scan_id: scan_id.to_string(),
            analysis_version: "1".to_string(),
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

    // Global identity surfaces: fixed ids re-upserted by every unit, so the
    // canonical-key upsert keeps the original rows stable across units.
    let resources = ResourceRepo::new(conn);
    let source = Resource {
        id: "res_src".to_string(),
        canonical_key: "external_source:src".to_string(),
        kind: "external_source".to_string(),
        provider: "fixture".to_string(),
        name: "Source".to_string(),
        metadata: None,
        first_observed_at: started_at,
        last_observed_at: started_at,
    };
    let actor = Resource {
        id: "res_actor".to_string(),
        canonical_key: "agent:actor".to_string(),
        kind: "agent".to_string(),
        provider: "fixture".to_string(),
        name: "Actor".to_string(),
        metadata: None,
        first_observed_at: started_at,
        last_observed_at: started_at,
    };
    let sink = Resource {
        id: "res_sink".to_string(),
        canonical_key: "worker:sink".to_string(),
        kind: "worker".to_string(),
        provider: "fixture".to_string(),
        name: "Sink".to_string(),
        metadata: None,
        first_observed_at: started_at,
        last_observed_at: started_at,
    };
    for resource in [&source, &actor, &sink] {
        resources.upsert(resource).unwrap();
    }

    let relationship = Relationship {
        id: format!("rel_{scan_id}"),
        canonical_key: format!("external_source:src|can_call|agent:{scan_id}"),
        from_resource_id: source.id.clone(),
        to_resource_id: actor.id.clone(),
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
            analysis_version: "1".to_string(),
            source_resource_id: source.id.clone(),
            actor_resource_id: actor.id.clone(),
            sink_resource_id: sink.id.clone(),
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
            finding_version: "1".to_string(),
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
            resource_ids: vec![source.id.clone()],
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
            target_resource_ids: vec![actor.id.clone()],
            target_relationship_ids: vec![relationship.id.clone()],
        })
        .unwrap();

    // The scan-scoped graph snapshot: a resource observation whose metadata
    // carries the declared graph_snapshot_version plus the full snapshot
    // payload, exactly as the scan service persists it.
    ObservationRepo::new(conn)
        .insert(&Observation {
            id: format!("obs_{scan_id}"),
            scan_id: scan_id.to_string(),
            subject_type: "resource".to_string(),
            subject_id: sink.id.clone(),
            observation_type: "present".to_string(),
            observed_at: started_at,
            source: "fixture".to_string(),
            metadata: Some(resource_snapshot_metadata(&sink)),
        })
        .unwrap();

    let completed_at = match status {
        ScanStatus::Running => None,
        _ => Some(started_at),
    };
    let mut scan = scan_with(scan_id, status, started_at, completed_at);
    scan.metadata = Some(metadata());
    scan_repo.update(&scan).unwrap();
}

// ---------------------------------------------------------------------------
// Digest helpers
// ---------------------------------------------------------------------------

fn open_read_only(workspace: &Path) -> Connection {
    Connection::open_with_flags(
        workspace.join(".pico").join("pico.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap()
}

/// Canonical row serialization for one table: all columns via `quote()`, rows
/// in rowid order, optionally restricted by a WHERE filter.
fn table_rows(conn: &Connection, table: &str, filter: Option<&str>) -> String {
    let column_names: Vec<String> = {
        let mut columns = conn
            .prepare(&format!(
                "SELECT name FROM pragma_table_info('{table}') ORDER BY cid"
            ))
            .unwrap();
        columns
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    };
    let mut out = format!("table {table} [{}]\n", column_names.join(","));
    let projection = column_names
        .iter()
        .map(|column| format!("quote({column})"))
        .collect::<Vec<_>>()
        .join(", ");
    let where_clause = filter.map(|f| format!(" WHERE {f}")).unwrap_or_default();
    let mut rows = conn
        .prepare(&format!(
            "SELECT {projection} FROM \"{table}\"{where_clause} ORDER BY rowid"
        ))
        .unwrap();
    let column_count = column_names.len();
    for row in rows
        .query_map([], |row| {
            let mut values = Vec::with_capacity(column_count);
            for index in 0..column_count {
                values.push(row.get::<_, String>(index)?);
            }
            Ok(values.join("\u{1}"))
        })
        .unwrap()
    {
        out.push_str(&row.unwrap());
        out.push('\n');
    }
    out
}

fn sha256_hex(digest: String) -> String {
    let mut hasher = Sha256::new();
    hasher.update(digest.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Whole-database content digest (SPRINT-029 §4 pattern): SHA-256 over a
/// canonical serialization of `PRAGMA user_version`, every `sqlite_master`
/// row, and every user table's full row content (all columns, rows in rowid
/// order, tables in name order). Equal digests before and after a call prove
/// the database content is byte-identical, not just row counts.
fn content_digest(workspace: &Path) -> String {
    let conn = open_read_only(workspace);
    let mut digest = String::new();
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    digest.push_str(&format!("user_version {user_version}\n"));
    let mut objects = conn
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '(null)')
             FROM sqlite_master ORDER BY type, name, tbl_name",
        )
        .unwrap();
    for object in objects
        .query_map([], |row| {
            Ok(format!(
                "schema {} {} {} {}\n",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap()
    {
        digest.push_str(&object.unwrap());
    }
    let table_names: Vec<String> = {
        let mut tables = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .unwrap();
        tables
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect()
    };
    for table in table_names {
        digest.push_str(&table_rows(&conn, &table, None));
    }
    sha256_hex(digest)
}

/// Digest over only the retained scan units' rows: every scan-scoped table is
/// filtered to the retained scan ids (link tables through their parent
/// subquery, `relationship_evidence` through the unit's evidence), while the
/// global identity surfaces (`resources`, `relationships`) enter unfiltered.
/// Equal digests before and after a prune prove every retained row is
/// byte-identical — no retained row gains or loses rows or fields.
fn retained_digest(workspace: &Path, retained: &[&str]) -> String {
    let conn = open_read_only(workspace);
    let set = format!(
        "({})",
        retained
            .iter()
            .map(|id| format!("'{id}'"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut digest = String::new();
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    digest.push_str(&format!("user_version {user_version}\n"));
    let scoped_tables: [(&str, Option<String>); 16] = [
        ("scans", Some(format!("id IN {set}"))),
        ("resources", None),
        ("relationships", None),
        ("observations", Some(format!("scan_id IN {set}"))),
        ("evidence", Some(format!("scan_id IN {set}"))),
        (
            "relationship_evidence",
            Some(format!(
                "evidence_id IN (SELECT id FROM evidence WHERE scan_id IN {set})"
            )),
        ),
        ("scan_analyses", Some(format!("scan_id IN {set}"))),
        ("attack_paths", Some(format!("scan_id IN {set}"))),
        (
            "attack_path_edges",
            Some(format!(
                "attack_path_id IN (SELECT id FROM attack_paths WHERE scan_id IN {set})"
            )),
        ),
        (
            "attack_path_evidence",
            Some(format!(
                "attack_path_id IN (SELECT id FROM attack_paths WHERE scan_id IN {set})"
            )),
        ),
        ("findings", Some(format!("scan_id IN {set}"))),
        (
            "finding_paths",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        (
            "finding_evidence",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        (
            "finding_reasons",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        (
            "finding_remediations",
            Some(format!(
                "finding_id IN (SELECT id FROM findings WHERE scan_id IN {set})"
            )),
        ),
        ("scan_diagnostics", Some(format!("scan_id IN {set}"))),
    ];
    for (table, filter) in scoped_tables {
        digest.push_str(&table_rows(&conn, table, filter.as_deref()));
    }
    sha256_hex(digest)
}

/// Every scan-scoped row of one pruned unit must be gone: the six directly
/// keyed tables plus the `scans` row, every link-table row through its parent
/// subquery, and the unit's `relationship_evidence` links.
fn assert_unit_fully_removed(conn: &Connection, scan_id: &str) {
    for sql in [
        "SELECT COUNT(*) FROM observations WHERE scan_id = ?1",
        "SELECT COUNT(*) FROM evidence WHERE scan_id = ?1",
        "SELECT COUNT(*) FROM findings WHERE scan_id = ?1",
        "SELECT COUNT(*) FROM attack_paths WHERE scan_id = ?1",
        "SELECT COUNT(*) FROM scan_analyses WHERE scan_id = ?1",
        "SELECT COUNT(*) FROM scan_diagnostics WHERE scan_id = ?1",
        "SELECT COUNT(*) FROM scans WHERE id = ?1",
        "SELECT COUNT(*) FROM finding_paths
         WHERE finding_id IN (SELECT id FROM findings WHERE scan_id = ?1)",
        "SELECT COUNT(*) FROM finding_evidence
         WHERE finding_id IN (SELECT id FROM findings WHERE scan_id = ?1)",
        "SELECT COUNT(*) FROM finding_reasons
         WHERE finding_id IN (SELECT id FROM findings WHERE scan_id = ?1)",
        "SELECT COUNT(*) FROM finding_remediations
         WHERE finding_id IN (SELECT id FROM findings WHERE scan_id = ?1)",
        "SELECT COUNT(*) FROM attack_path_edges
         WHERE attack_path_id IN (SELECT id FROM attack_paths WHERE scan_id = ?1)",
        "SELECT COUNT(*) FROM attack_path_evidence
         WHERE attack_path_id IN (SELECT id FROM attack_paths WHERE scan_id = ?1)",
        "SELECT COUNT(*) FROM relationship_evidence
         WHERE evidence_id IN (SELECT id FROM evidence WHERE scan_id = ?1)",
    ] {
        let count: i64 = conn.query_row(sql, [scan_id], |row| row.get(0)).unwrap();
        assert_eq!(count, 0, "no residual rows may remain for {scan_id}: {sql}");
    }
}

// ---------------------------------------------------------------------------
// R1: below-window prune is a byte-identical no-op
// ---------------------------------------------------------------------------

#[test]
fn below_window_prune_is_a_no_op() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    for i in 1..=3 {
        seed_unit(&db, &format!("scan_{i:02}"), ts(i), ScanStatus::Complete);
    }
    let before = content_digest(workspace.path());

    let report = PruneService::run(workspace.path(), None).unwrap();
    assert!(report.nothing_pruned);
    assert!(report.pruned.is_empty());
    assert_eq!(report.totals, PruneTotals(UnitCounts::default()));
    assert_eq!(report.retained.complete, 3);
    assert_eq!(report.retained.partial, 0);
    assert_eq!(report.retained.failed, 0);
    assert_eq!(report.retained.running, 0);
    assert_eq!(report.keep, 10);

    // The frozen no-op copy, byte for byte.
    let rendered = render_prune_report(&report);
    assert_eq!(
        rendered,
        "Pico prune\n\n\
         Policy: keep 10 COMPLETE scans\n\
         Nothing pruned: history is within the window.\n\
         Retained: 3 COMPLETE, 0 PARTIAL, 0 FAILED, 0 RUNNING\n\
         Health: ok\n"
    );

    assert_eq!(
        content_digest(workspace.path()),
        before,
        "the no-op must leave the database content byte-identical"
    );
}

// ---------------------------------------------------------------------------
// R2: window exceeded — the oldest units go, retained rows are untouched
// ---------------------------------------------------------------------------

#[test]
fn window_exceeded_prunes_oldest_units_idempotently() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    for i in 1..=12 {
        seed_unit(&db, &format!("scan_{i:02}"), ts(i), ScanStatus::Complete);
    }
    let retained: Vec<String> = (3..=12).map(|i| format!("scan_{i:02}")).collect();
    let retained_refs: Vec<&str> = retained.iter().map(String::as_str).collect();
    let before_retained = retained_digest(workspace.path(), &retained_refs);

    let report = PruneService::run(workspace.path(), Some(10)).unwrap();
    assert_eq!(report.keep, 10);
    assert!(!report.nothing_pruned);
    assert!(report.pre_health_ok);
    assert!(report.post_health_ok);
    let pruned_ids: Vec<&str> = report.pruned.iter().map(|u| u.scan_id.as_str()).collect();
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
    assert_eq!(report.retained.complete, 10);
    assert_eq!(report.retained.partial, 0);
    assert_eq!(report.retained.failed, 0);
    assert_eq!(report.retained.running, 0);

    assert_eq!(
        retained_digest(workspace.path(), &retained_refs),
        before_retained,
        "every retained row must be byte-identical after the prune"
    );

    // The frozen report copy, byte for byte.
    let rendered = render_prune_report(&report);
    assert_eq!(
        rendered,
        "Pico prune\n\n\
         Policy: keep 10 COMPLETE scans\n\
         Pruned: 2 scans\n\
         \x20\x20scan_01 (COMPLETE): 1 observations, 1 evidence, 1 findings, 1 attack paths, 1 analyses, 1 diagnostics, 1 relationship evidence links\n\
         \x20\x20scan_02 (COMPLETE): 1 observations, 1 evidence, 1 findings, 1 attack paths, 1 analyses, 1 diagnostics, 1 relationship evidence links\n\
         Totals: 2 observations, 2 evidence, 2 findings, 2 attack paths, 2 analyses, 2 diagnostics, 2 relationship evidence links\n\
         Retained: 10 COMPLETE, 0 PARTIAL, 0 FAILED, 0 RUNNING\n\
         Health after prune: ok\n"
    );

    // Re-running below the new window is an explicit no-op success.
    let after_first = content_digest(workspace.path());
    let again = PruneService::run(workspace.path(), Some(10)).unwrap();
    assert!(again.nothing_pruned);
    assert!(again.pruned.is_empty());
    assert_eq!(
        render_prune_report(&again),
        "Pico prune\n\n\
         Policy: keep 10 COMPLETE scans\n\
         Nothing pruned: history is within the window.\n\
         Retained: 10 COMPLETE, 0 PARTIAL, 0 FAILED, 0 RUNNING\n\
         Health: ok\n"
    );
    assert_eq!(
        content_digest(workspace.path()),
        after_first,
        "the idempotent re-run must leave the database content byte-identical"
    );

    // The default window (no flag) behaves exactly as --keep 10.
    let default_workspace = tempdir().unwrap();
    let default_db = workspace_db(default_workspace.path());
    for i in 1..=12 {
        seed_unit(
            &default_db,
            &format!("scan_{i:02}"),
            ts(i),
            ScanStatus::Complete,
        );
    }
    let default_report = PruneService::run(default_workspace.path(), None).unwrap();
    assert_eq!(default_report.keep, 10);
    let default_pruned: Vec<&str> = default_report
        .pruned
        .iter()
        .map(|unit| unit.scan_id.as_str())
        .collect();
    assert_eq!(default_pruned, ["scan_01", "scan_02"]);
}

// ---------------------------------------------------------------------------
// R3: any RUNNING scan blocks the prune entirely
// ---------------------------------------------------------------------------

#[test]
fn running_scan_blocks_prune() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_keep_old", ts(1), ScanStatus::Complete);
    seed_unit(&db, "scan_keep_new", ts(2), ScanStatus::Complete);
    seed_unit(&db, "scan_partial_stale", ts(-1), ScanStatus::Partial);
    seed_unit(&db, "scan_running", ts(9), ScanStatus::Running);
    let before = content_digest(workspace.path());

    let error = PruneService::run(workspace.path(), None).unwrap_err();
    assert!(
        matches!(error, PicoError::Usage(ref msg) if msg == "cannot prune while scan scan_running is RUNNING"),
        "expected the frozen RUNNING refusal, got {error:?}"
    );
    assert_eq!(
        content_digest(workspace.path()),
        before,
        "the refusal must leave the database content byte-identical"
    );
}

// ---------------------------------------------------------------------------
// R4: pruned units leave zero residual rows; retained rows are untouched
// ---------------------------------------------------------------------------

#[test]
fn pruned_units_leave_no_residual_rows() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    for i in 1..=12 {
        seed_unit(&db, &format!("scan_{i:02}"), ts(i), ScanStatus::Complete);
    }
    seed_unit(&db, "scan_partial_stale", ts(-2), ScanStatus::Partial);
    seed_unit(&db, "scan_failed_stale", ts(-1), ScanStatus::Failed);
    seed_unit(&db, "scan_partial_new", ts(30), ScanStatus::Partial);

    let retained: Vec<String> = (3..=12)
        .map(|i| format!("scan_{i:02}"))
        .chain(std::iter::once("scan_partial_new".to_string()))
        .collect();
    let retained_refs: Vec<&str> = retained.iter().map(String::as_str).collect();
    let before_retained = retained_digest(workspace.path(), &retained_refs);

    let report = PruneService::run(workspace.path(), None).unwrap();
    assert!(!report.nothing_pruned);
    let pruned_ids: Vec<&str> = report.pruned.iter().map(|u| u.scan_id.as_str()).collect();
    assert_eq!(
        pruned_ids,
        [
            "scan_01",
            "scan_02",
            "scan_partial_stale",
            "scan_failed_stale"
        ],
        "COMPLETE units oldest-first, then stale incomplete attempts oldest-first"
    );
    for unit in &report.pruned {
        assert_eq!(unit.counts, FULL_UNIT_COUNTS);
    }

    let conn = db.connection();
    for scan_id in [
        "scan_01",
        "scan_02",
        "scan_partial_stale",
        "scan_failed_stale",
    ] {
        assert_unit_fully_removed(conn, scan_id);
    }

    // Retained scans' rows are byte-identical, and the global identity
    // surfaces keep every row.
    assert_eq!(
        retained_digest(workspace.path(), &retained_refs),
        before_retained,
        "retained rows must be byte-identical after the prune"
    );
    let remaining: Vec<String> = ScanRepo::new(conn)
        .list()
        .unwrap()
        .into_iter()
        .map(|scan| scan.id)
        .collect();
    assert_eq!(remaining, retained);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM resources", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM relationships", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        15
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM relationship_evidence", [], |row| row
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        11,
        "only the retained units' evidence links survive"
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM findings", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        11
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM evidence", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        11
    );
}

// ---------------------------------------------------------------------------
// R5: pruned history stays explicit — never fabricated
// ---------------------------------------------------------------------------

#[test]
fn pruned_history_is_explicit_not_fabricated() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_partial_stale", ts(-1), ScanStatus::Partial);
    seed_unit(&db, "scan_old", ts(1), ScanStatus::Complete);
    seed_unit(&db, "scan_new", ts(2), ScanStatus::Complete);

    let report = PruneService::run(workspace.path(), None).unwrap();
    let pruned_ids: Vec<&str> = report.pruned.iter().map(|u| u.scan_id.as_str()).collect();
    assert_eq!(pruned_ids, ["scan_partial_stale"]);

    // History lists only the retained scans, chronologically, still COMPLETE.
    let history = HistoryService::list(workspace.path()).unwrap();
    let history_ids: Vec<&str> = history.scans.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(history_ids, ["scan_old", "scan_new"]);
    assert!(history.scans.iter().all(|s| s.status == "COMPLETE"));

    // A diff referencing a pruned scan fails with the existing explicit
    // "not found" usage error, in both directions.
    for (from, to) in [
        ("scan_partial_stale", "scan_new"),
        ("scan_new", "scan_partial_stale"),
    ] {
        let error = DiffService::compare(workspace.path(), from, to).unwrap_err();
        assert!(
            matches!(error, PicoError::Usage(ref msg) if msg == "scan scan_partial_stale not found"),
            "expected the frozen not-found usage error, got {error:?}"
        );
    }

    // The latest diff over the retained pair is Ready with intact S029
    // provenance: contracts equal on both sides and equal to the current
    // contract, and the frozen SUPPORTED MATCH line renders.
    let latest = match DiffService::latest(workspace.path()).unwrap() {
        FindingDiffResult::Ready(diff) => diff,
        other => panic!("expected a Ready diff, got {other:?}"),
    };
    assert_eq!(
        latest.provenance.from.contract,
        Some(CURRENT_COMPARISON_CONTRACT)
    );
    assert_eq!(
        latest.provenance.to.contract,
        Some(CURRENT_COMPARISON_CONTRACT)
    );
    assert_eq!(latest.provenance.from.pico_version, PICO_VERSION);
    assert_eq!(latest.provenance.to.pico_version, PICO_VERSION);
    let diff_rendered = render_finding_diff(&FindingDiffResult::Ready(latest));
    assert!(diff_rendered
        .contains("Comparison contracts: c1-g1-a1-f1 → c1-g1-a1-f1 (SUPPORTED MATCH)\n"));

    // The prune report never fabricates environment semantics.
    let report_rendered = render_prune_report(&report);
    for banned in ["disappeared", "remediated", "environment changed"] {
        assert!(
            !report_rendered.contains(banned),
            "prune report must not contain {banned:?}:\n{report_rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// R8: --keep validation precedes any database access
// ---------------------------------------------------------------------------

#[test]
fn keep_flag_is_validated_before_any_deletion() {
    // The workspace has no `.pico` state at all: only the flag validation
    // runs before any database access, so the keep error must win over the
    // missing-state error and no database may be created.
    let workspace = tempdir().unwrap();
    for keep in [Some(0), Some(1)] {
        let error = PruneService::run(workspace.path(), keep).unwrap_err();
        assert!(
            matches!(error, PicoError::Usage(ref msg) if msg == "--keep must be an integer of at least 2"),
            "expected the frozen keep error, got {error:?}"
        );
    }
    assert!(
        !workspace.path().join(".pico").exists(),
        "no database state may be created by a rejected flag"
    );
}

// ---------------------------------------------------------------------------
// R6–R9: pico doctor, injected inconsistency, and the extended secret sweep
// ---------------------------------------------------------------------------

/// R9 sentinel: an alphanumeric marker that can only reach the database
/// through the deliberate fixture injections below.
const SECRET_SENTINEL: &str = "PICO_R9_SECRET_SENTINEL_SHOULD_NOT_SURVIVE_PRUNE";

/// R9 sweep helper (SPRINT-030.md §5.5): count, per persisted table, the rows
/// containing `needle` in ANY text column — ALL 16 tables, including the
/// migrations-3–6 surfaces the sprint006 helper predates (extended locally in
/// this file, not in place). Columns are discovered from `pragma_table_info`
/// so the sweep cannot drift from the schema; values are CAST to TEXT before
/// the LIKE comparison and text-declared columns only, so integer columns
/// (counts, positions) can never produce a false match.
fn persisted_occurrences_by_table(conn: &Connection, needle: &str) -> Vec<(&'static str, i64)> {
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
    ALL_TABLES
        .iter()
        .map(|table| {
            let text_columns: Vec<String> = {
                let mut columns = conn
                    .prepare(&format!(
                        "SELECT name FROM pragma_table_info('{table}')
                         WHERE type = 'TEXT' ORDER BY cid"
                    ))
                    .unwrap();
                columns
                    .query_map([], |row| row.get::<_, String>(0))
                    .unwrap()
                    .map(|row| row.unwrap())
                    .collect()
            };
            assert!(
                !text_columns.is_empty(),
                "{table} must declare text columns for the sweep"
            );
            let predicate = text_columns
                .iter()
                .map(|column| format!("CAST({column} AS TEXT) LIKE '%' || ?1 || '%'"))
                .collect::<Vec<_>>()
                .join(" OR ");
            let count: i64 = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM \"{table}\" WHERE {predicate}"),
                    [needle],
                    |row| row.get(0),
                )
                .unwrap();
            (*table, count)
        })
        .collect()
}

/// Every rendered line must be terminal-safe: no byte below 0x20 anywhere
/// except the `\n` line terminators (SPRINT-030.md §5.4).
fn assert_terminal_safe(rendered: &str) {
    for line in rendered.split('\n') {
        for byte in line.as_bytes() {
            assert!(
                *byte >= 0x20,
                "control byte 0x{byte:02X} in rendered line {line:?}"
            );
        }
    }
}

/// R6: a healthy workspace reports ok on every check with the frozen copy,
/// and doctor performs no writes at all.
#[test]
fn doctor_reports_ok_without_writing() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    for i in 1..=8 {
        seed_unit(&db, &format!("scan_{i:02}"), ts(i), ScanStatus::Complete);
    }
    seed_unit(&db, "scan_partial_new", ts(9), ScanStatus::Partial);
    let before = content_digest(workspace.path());

    let report = DoctorService::run(workspace.path()).unwrap();
    assert!(report.ok, "expected a healthy report, got {report:?}");
    assert_eq!(report.schema_version, 6);
    assert!(report.integrity_ok);
    assert!(report.foreign_keys_ok);
    assert!(report.dangling_json_refs.is_empty());
    assert_eq!(
        report.counts,
        RetentionCounts {
            complete: 8,
            partial: 1,
            failed: 0,
            running: 0,
        }
    );
    assert_eq!(report.window_keep, 10);
    assert_eq!(report.oldest_retained_complete.as_deref(), Some("scan_01"));
    assert_eq!(report.newest_complete.as_deref(), Some("scan_08"));

    // The frozen healthy copy, byte for byte (re-pinned to the SPRINT-031
    // §5.3 window line, which separates the policy window from the scans
    // actually present).
    let rendered = render_doctor_report(&report);
    assert_eq!(
        rendered,
        "Pico doctor\n\n\
         Schema version: 6 (supported)\n\
         Integrity: ok\n\
         Foreign keys: ok\n\
         Dangling references: none\n\
         Orphan scan rows: 0\n\
         Summary rows: 0\n\
         Scans: 8 COMPLETE, 1 PARTIAL, 0 FAILED, 0 RUNNING\n\
         Retention window: policy keep 10 COMPLETE scans; workspace has 8 COMPLETE scans; oldest retained scan_01; newest scan_08\n\
         Result: ok\n"
    );
    assert_terminal_safe(&rendered);

    assert_eq!(
        content_digest(workspace.path()),
        before,
        "doctor must never write: the database content must be byte-identical"
    );
}

/// R7: injected inconsistencies fail closed — reported deterministically,
/// never silently ignored, and never auto-repaired.
#[test]
fn doctor_reports_injected_inconsistency_fail_closed() {
    // (a) Dangling JSON reference: a finding_reasons row whose evidence_ids
    //     array names an evidence row that does not exist (JSON id columns
    //     carry no foreign keys, so no pragma toggling is needed).
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_01", ts(1), ScanStatus::Complete);
    FindingRepo::new(db.connection())
        .insert_reason(&FindingReasonRecord {
            finding_id: "finding_scan_01".to_string(),
            position: 1,
            reason_code: "EXTRA".to_string(),
            resource_ids: vec![],
            relationship_ids: vec![],
            attack_path_ids: vec![],
            evidence_ids: vec!["evidence_nonexistent".to_string()],
        })
        .unwrap();
    let before = content_digest(workspace.path());

    let report = DoctorService::run(workspace.path()).unwrap();
    assert!(!report.ok);
    assert!(report.integrity_ok);
    assert!(report.foreign_keys_ok);
    assert_eq!(report.dangling_json_refs.len(), 1);
    assert_eq!(report.dangling_json_refs[0].table, "finding_reasons");
    assert_eq!(report.dangling_json_refs[0].column, "evidence_ids");
    assert_eq!(report.dangling_json_refs[0].category, "unresolved");
    assert_eq!(report.dangling_json_refs[0].referenced_table, "evidence");
    assert_eq!(report.dangling_json_refs[0].finding_id, "finding_scan_01");
    assert_eq!(report.dangling_json_refs[0].position, 1);
    assert_eq!(report.dangling_json_refs[0].unresolved_count, 1);

    // The frozen redacted copy, byte for byte (re-pinned to the SPRINT-031
    // §5.2 shape: the unresolved id contents are counted, never echoed).
    let rendered = render_doctor_report(&report);
    assert_eq!(
        rendered,
        "Pico doctor\n\n\
         Schema version: 6 (supported)\n\
         Integrity: ok\n\
         Foreign keys: ok\n\
         Dangling references: 1\n\
         \x20\x20finding_reasons/evidence_ids: 1 unresolved evidence id(s) at finding_id=finding_scan_01 position=1\n\
         Orphan scan rows: 0\n\
         Summary rows: 0\n\
         Scans: 1 COMPLETE, 0 PARTIAL, 0 FAILED, 0 RUNNING\n\
         Retention window: policy keep 10 COMPLETE scans; workspace has 1 COMPLETE scans; oldest retained scan_01; newest scan_01\n\
         Result: FAIL\n"
    );
    assert_terminal_safe(&rendered);
    assert!(
        !rendered.contains("evidence_nonexistent"),
        "the unresolved id must never render (redacted diagnostics)"
    );

    assert_eq!(
        content_digest(workspace.path()),
        before,
        "doctor must never repair: the database content must be byte-identical"
    );

    // (b) Foreign-key-invalid row: a relationship_evidence row referencing a
    //     nonexistent relationship, seeded with foreign keys disabled and the
    //     pragma restored afterwards. The referenced evidence is real, so the
    //     violation is exactly the missing relationship.
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_01", ts(1), ScanStatus::Complete);
    let conn = db.connection();
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    conn.execute(
        "INSERT INTO relationship_evidence (relationship_id, evidence_id)
         VALUES ('rel_nonexistent', 'ev_scan_01')",
        [],
    )
    .unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    let before = content_digest(workspace.path());

    let report = DoctorService::run(workspace.path()).unwrap();
    assert!(!report.ok);
    assert!(report.integrity_ok);
    assert!(!report.foreign_keys_ok);
    assert!(report.dangling_json_refs.is_empty());

    // The frozen redacted copy, byte for byte (FK case: the FAILED marker is
    // unchanged; only the §5.3 window line moved).
    let rendered = render_doctor_report(&report);
    assert_eq!(
        rendered,
        "Pico doctor\n\n\
         Schema version: 6 (supported)\n\
         Integrity: ok\n\
         Foreign keys: FAILED\n\
         Dangling references: none\n\
         Orphan scan rows: 0\n\
         Summary rows: 0\n\
         Scans: 1 COMPLETE, 0 PARTIAL, 0 FAILED, 0 RUNNING\n\
         Retention window: policy keep 10 COMPLETE scans; workspace has 1 COMPLETE scans; oldest retained scan_01; newest scan_01\n\
         Result: FAIL\n"
    );
    assert_terminal_safe(&rendered);

    assert_eq!(
        content_digest(workspace.path()),
        before,
        "doctor must never repair: the database content must be byte-identical"
    );
}

/// R9: prune removes every seeded sentinel occurrence from the pruned unit
/// while retention keeps the retained unit's sentinel-bearing metadata, and
/// both the prune and doctor renders stay sentinel-free and control-byte-free.
#[test]
fn pruning_removes_secrets_and_reports_stay_clean() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_secret", ts(1), ScanStatus::Complete);
    seed_unit(&db, "scan_retained", ts(2), ScanStatus::Complete);
    seed_unit(&db, "scan_other", ts(3), ScanStatus::Complete);
    let conn = db.connection();

    // Inject the sentinel into the pruned scan's evidence observation, scan
    // metadata, diagnostics detail, and Finding metadata — and into the
    // retained scan's metadata (which retention must keep).
    let with_sentinel = |note: &str| {
        serde_json::json!({
            "comparison_contract_version": 1,
            "graph_snapshot_version": 1,
            "finding_version": 1,
            "note": note,
        })
        .to_string()
    };
    conn.execute(
        "UPDATE scans SET metadata = ?1 WHERE id = 'scan_secret'",
        [with_sentinel(SECRET_SENTINEL)],
    )
    .unwrap();
    conn.execute(
        "UPDATE scans SET metadata = ?1 WHERE id = 'scan_retained'",
        [with_sentinel(SECRET_SENTINEL)],
    )
    .unwrap();
    conn.execute(
        "UPDATE evidence SET observation = ?1 WHERE id = 'ev_scan_secret'",
        [format!("fixture evidence {SECRET_SENTINEL}")],
    )
    .unwrap();
    conn.execute(
        "UPDATE scan_diagnostics SET detail = ?1 WHERE scan_id = 'scan_secret'",
        [format!(
            r#"{{"reason_code":"FIXTURE","detail":"{SECRET_SENTINEL}"}}"#
        )],
    )
    .unwrap();
    conn.execute(
        "UPDATE findings SET metadata = ?1 WHERE id = 'finding_scan_secret'",
        [format!(r#"{{"note":"{SECRET_SENTINEL}"}}"#)],
    )
    .unwrap();

    // The injections are visible before the prune: two rows in scans (both
    // metadata), one each in evidence, findings, and scan_diagnostics.
    for (table, expected) in [
        ("scans", 2),
        ("evidence", 1),
        ("findings", 1),
        ("scan_diagnostics", 1),
    ] {
        let count = persisted_occurrences_by_table(conn, SECRET_SENTINEL)
            .into_iter()
            .find(|(name, _)| *name == table)
            .map(|(_, count)| count)
            .unwrap();
        assert_eq!(count, expected, "sentinel must be seeded in {table}");
    }

    // keep 2 of three COMPLETE scans: exactly the oldest, sentinel-bearing
    // scan unit is pruned.
    let report = PruneService::run(workspace.path(), Some(2)).unwrap();
    let pruned_ids: Vec<&str> = report.pruned.iter().map(|u| u.scan_id.as_str()).collect();
    assert_eq!(pruned_ids, ["scan_secret"]);
    assert!(report.post_health_ok);

    // Whole-unit removal of the pruned content...
    assert_unit_fully_removed(conn, "scan_secret");
    // ...and the extended sweep reports zero sentinel occurrences everywhere
    // except the retained scan's metadata row, which retention must keep
    // (pruning only removes pruned units; it never rewrites retained rows).
    let occurrences = persisted_occurrences_by_table(conn, SECRET_SENTINEL);
    for (table, count) in &occurrences {
        if *table == "scans" {
            assert_eq!(
                *count, 1,
                "exactly the retained scan's metadata keeps the sentinel"
            );
        } else {
            assert_eq!(*count, 0, "sentinel must be gone from {table}");
        }
    }
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM scans WHERE id = 'scan_secret'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM scans
             WHERE id = 'scan_retained'
               AND CAST(metadata AS TEXT) LIKE '%' || ?1 || '%'",
            [SECRET_SENTINEL],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        1,
        "the retained scan's sentinel-bearing metadata must remain"
    );

    // The prune report lists the pruned scan id but never the sentinel.
    let prune_rendered = render_prune_report(&report);
    assert!(prune_rendered.contains("scan_secret"), "{prune_rendered}");
    assert!(
        !prune_rendered.contains(SECRET_SENTINEL),
        "the prune render must never echo the sentinel:\n{prune_rendered}"
    );
    assert_terminal_safe(&prune_rendered);

    // A doctor render over the same post-prune workspace: sentinel-free,
    // control-byte-free, and healthy.
    let doctor_report = DoctorService::run(workspace.path()).unwrap();
    assert!(
        doctor_report.ok,
        "expected a healthy report, got {doctor_report:?}"
    );
    assert_eq!(doctor_report.counts.complete, 2);
    let doctor_rendered = render_doctor_report(&doctor_report);
    assert!(
        !doctor_rendered.contains(SECRET_SENTINEL),
        "the doctor render must never echo the sentinel:\n{doctor_rendered}"
    );
    assert_terminal_safe(&doctor_rendered);
}

/// Doctor on a workspace with no `.pico` state fails with the existing
/// missing-state error and creates nothing.
#[test]
fn doctor_requires_initialized_state() {
    let workspace = tempdir().unwrap();
    let error = DoctorService::run(workspace.path()).unwrap_err();
    assert!(
        matches!(error, PicoError::Scan(ref msg) if msg == "no Pico state in this workspace (run `pico init` first)"),
        "expected the frozen missing-state error, got {error:?}"
    );
    assert!(
        !workspace.path().join(".pico").exists(),
        "doctor must never create state"
    );
}
