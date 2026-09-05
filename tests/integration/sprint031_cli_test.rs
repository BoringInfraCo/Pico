//! Sprint 031 Stage A corrective fixtures (SPRINT-031.md §4 R1–R7).
//!
//! STAGE A ONLY: no production change. These fixtures pin the safe
//! contracts the corrective sprint must deliver — one immediate write
//! transaction whose failed health gates roll back and delete nothing
//! (§5.1), redacted diagnostics that never echo raw JSON text or
//! unresolved id contents (§5.2), and fail-closed schema rejection
//! without migrating — and prove that R1–R4 fail on the `4c0c49f`
//! baseline:
//!
//! - R1 (`post_health_failure_rolls_back_and_deletes_nothing`) fails on
//!   the baseline at the whole-database digest, the retained-unit row
//!   counts, and the post-prune doctor state: the baseline commits the
//!   deletion before the post-health check, so the oldest unit is gone
//!   and doctor then reports the dangling cross-scan reference. The test
//!   pins the post-fix contract (state byte-identical, doctor still
//!   reports the pre-prune healthy window), which the baseline
//!   contradicts.
//! - R2 (`doctor_redacts_malformed_json_sentinel`) and
//!   R3 (`doctor_redacts_unresolved_id_contents`) fail on the baseline
//!   because `render_doctor_report` echoes the raw stored cell text and
//!   each unresolved id; they pin the §5.2 bounded-location shape.
//! - R4 (`prune_rejects_unsupported_schema_without_migrating`) fails on
//!   the baseline because `PruneService::run` migrates a schema-v5
//!   database to v6 before any refusal or no-op path; the test pins the
//!   `require_schema_version` remedy with zero writes.
//! - R5 (`immediate_transaction_excludes_concurrent_writer`) passes on
//!   the baseline: it pins the exclusion mechanism and the RUNNING
//!   refusal contract the fix must preserve.
//! - R6 (`prune_noop_and_refusal_stay_zero_write`,
//!   `prune_repeat_stays_idempotent`) pass on the baseline and re-pin
//!   the zero-write and idempotence semantics the fix must preserve.
//! - R7 (`prune_and_doctor_output_stay_secret_safe`) passes on the
//!   baseline and re-pins the terminal-safe secret sweep.

use std::fs;
use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use pico::application::{
    DoctorService, PruneService, PruneTotals, UnitCounts, KEEP_COMPLETE_DEFAULT,
};
use pico::cli::render::{render_doctor_report, render_prune_report};
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
/// S029 comparison contract, and return the unit's evidence and finding ids
/// so fixtures can reference them across scans (R1's cross-scan JSON
/// reference). The scan lifecycle row is inserted as RUNNING first (the
/// analysis summary refuses upserts after COMPLETE, S029) and finalized with
/// its declared metadata afterwards.
fn seed_unit(
    db: &Database,
    scan_id: &str,
    started_at: DateTime<Utc>,
    status: ScanStatus,
) -> (String, String) {
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
    (evidence.id, finding_id)
}

// ---------------------------------------------------------------------------
// Digest helpers (SPRINT-029 §4 whole-database pattern, S030 retained rows)
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

/// Whole-database content digest: SHA-256 over a canonical serialization of
/// `PRAGMA user_version`, every `sqlite_master` row, and every user table's
/// full row content (all columns, rows in rowid order, tables in name order).
/// Equal digests before and after a call prove the database content is
/// byte-identical, not just row counts.
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

/// Digest over only the retained scan units' rows (S030 pattern): every
/// scan-scoped table is filtered to the retained scan ids (link tables
/// through their parent subquery, `relationship_evidence` through the unit's
/// evidence), while the global identity surfaces (`resources`,
/// `relationships`) enter unfiltered. Equal digests before and after a prune
/// prove every retained row is byte-identical.
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

/// Every scan-scoped row of one pruned unit must be gone: the directly keyed
/// tables plus the `scans` row, every link-table row through its parent
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
// Secret-sweep helpers (S030 R9 pattern, kept independent in this file)
// ---------------------------------------------------------------------------

/// Sentinel marker: an alphanumeric token that can only reach the database
/// through the deliberate fixture injections below. It must never appear in
/// any rendered output line.
const SECRET_SENTINEL: &str = "PICO_S031_SENTINEL_SECRET_MUST_NEVER_RENDER";

/// Count, per persisted table, the rows containing `needle` in ANY text
/// column — all 16 tables. Columns are discovered from `pragma_table_info`
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

/// Count the doctor render's dangling-location lines for one table/column
/// cell (`{table}/{column}: ...`).
fn dangling_location_line_count(rendered: &str, table: &str, column: &str) -> usize {
    let prefix = format!("{table}/{column}:");
    rendered
        .lines()
        .filter(|line| line.contains(&prefix))
        .count()
}

// ---------------------------------------------------------------------------
// R1: a failed post-health gate must roll back and delete nothing
//     (SPRINT-031.md §4 R1; fails on the 4c0c49f baseline)
// ---------------------------------------------------------------------------

/// Three COMPLETE units with `--keep 2`: only the oldest unit is pruned. The
/// RETAINED (newest) finding's `finding_reasons.evidence_ids` JSON is
/// rewritten (raw SQL; JSON id columns carry no foreign keys and no
/// same-scan trigger) to reference the OLDEST unit's existing evidence id, so
/// the pre-health gate passes — the reference resolves while the oldest unit
/// exists. The post-health gate must fail (its evidence is deleted inside the
/// same transaction) and the whole prune must roll back.
#[test]
fn post_health_failure_rolls_back_and_deletes_nothing() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    let (old_evidence, _old_finding) = seed_unit(&db, "scan_01", ts(1), ScanStatus::Complete);
    seed_unit(&db, "scan_02", ts(2), ScanStatus::Complete);
    let (_retained_evidence, retained_finding) =
        seed_unit(&db, "scan_03", ts(3), ScanStatus::Complete);

    // The cross-scan JSON reference: the retained finding now names the
    // oldest unit's evidence id. No FK and no same-scan trigger guard this
    // column, so a plain UPDATE is enough.
    db.connection()
        .execute(
            "UPDATE finding_reasons SET evidence_ids = ?1
             WHERE finding_id = ?2 AND position = 0",
            params![
                serde_json::to_string(&vec![old_evidence.clone()]).unwrap(),
                retained_finding,
            ],
        )
        .unwrap();

    // Pin the pre-state: the cross-scan reference resolves while the oldest
    // unit exists, so the pre-health gate passes ("doctor initially
    // passes").
    let pre = DoctorService::run(workspace.path()).unwrap();
    assert!(
        pre.ok,
        "the cross-scan reference must resolve pre-prune, got {pre:?}"
    );
    assert!(pre.dangling_json_refs.is_empty());

    let before = content_digest(workspace.path());

    // keep 2 of 3: exactly scan_01 is planned for deletion. The post-health
    // gate must fail (the deleted evidence is referenced by the retained
    // finding) and the whole operation must roll back with the frozen
    // message.
    let error = PruneService::run(workspace.path(), Some(2)).unwrap_err();
    assert!(
        matches!(error, PicoError::Database(ref msg) if msg == "database health check failed after prune"),
        "expected the frozen post-health failure, got {error:?}"
    );

    // The failure must have changed NOTHING: whole-database byte identity.
    assert_eq!(
        content_digest(workspace.path()),
        before,
        "a failed post-health gate must roll back: the database content must be \
         byte-identical (the baseline commits the deletion first, so this fails)"
    );

    // The oldest pruned unit must still exist with all of its rows.
    let conn = open_read_only(workspace.path());
    for (table, expected) in [
        ("scans", 3),
        ("observations", 3),
        ("evidence", 3),
        ("findings", 3),
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            count, expected,
            "no unit may be deleted by a failed prune ({table})"
        );
    }
    let old_evidence_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE id = ?1",
            [&old_evidence],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        old_evidence_rows, 1,
        "the oldest unit's evidence row referenced by the retained finding must survive"
    );

    // Doctor on the rolled-back state must still see the pre-prune healthy
    // window: nothing was deleted, so the cross-scan reference still
    // resolves. (The baseline contradicts this: doctor reports the dangling
    // finding_reasons/evidence_ids reference to the deleted oldest unit's
    // evidence.)
    let post = DoctorService::run(workspace.path()).unwrap();
    assert!(
        post.ok,
        "after the rolled-back prune doctor must still report ok (nothing was \
         deleted); baseline deletes the unit and reports the dangling \
         reference instead, got {post:?}"
    );
    assert!(
        post.dangling_json_refs.is_empty(),
        "no dangling reference may exist after the rollback: {:?}",
        post.dangling_json_refs
    );
    assert_eq!(
        post.counts.complete, 3,
        "all three COMPLETE scans must still be present after the rollback"
    );
}

// ---------------------------------------------------------------------------
// R2: malformed JSON cells render a bounded location, never their contents
//     (SPRINT-031.md §4 R2; fails on the 4c0c49f baseline)
// ---------------------------------------------------------------------------

/// A sentinel placed inside a malformed `finding_reasons.evidence_ids` cell
/// must never reach the doctor render: the report names the table, column,
/// the unparseable category, and a bounded structural location (finding_id +
/// position) — never the raw stored text.
#[test]
fn doctor_redacts_malformed_json_sentinel() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    let (_evidence_id, finding_id) = seed_unit(&db, "scan_01", ts(1), ScanStatus::Complete);

    // Malformed JSON text with the sentinel: not parseable as an array of
    // string ids.
    db.connection()
        .execute(
            "INSERT INTO finding_reasons
             (finding_id, position, reason_code, resource_ids, relationship_ids,
              attack_path_ids, evidence_ids)
             VALUES (?1, 1, 'BROKEN', '[]', '[]', '[]', ?2)",
            params![finding_id, format!("[{SECRET_SENTINEL} -- not json")],
        )
        .unwrap();

    let before = content_digest(workspace.path());
    let report = DoctorService::run(workspace.path()).unwrap();
    assert!(!report.ok, "an unparseable cell must fail closed");
    assert_eq!(
        report.dangling_json_refs.len(),
        1,
        "one diagnostic item per problem cell"
    );
    assert_eq!(report.dangling_more, 0);

    let rendered = render_doctor_report(&report);
    // The structural identity is reported...
    assert!(rendered.contains("finding_reasons"), "{rendered}");
    assert!(rendered.contains("evidence_ids"), "{rendered}");
    assert!(rendered.contains("unparseable"), "{rendered}");
    // ...but never the sentinel...
    assert!(
        !rendered.contains(SECRET_SENTINEL),
        "the doctor render must never echo the sentinel:\n{rendered}"
    );
    // ...and never any raw JSON-shaped text.
    assert!(
        !rendered.contains('[') && !rendered.contains('{'),
        "the doctor render must never echo raw JSON text shapes:\n{rendered}"
    );
    // The frozen §5.2 shape carries the bounded structural location.
    assert!(
        rendered.contains("finding_reasons/evidence_ids: unparseable JSON at finding_id="),
        "expected the frozen unparseable-location line shape:\n{rendered}"
    );
    assert_eq!(
        dangling_location_line_count(&rendered, "finding_reasons", "evidence_ids"),
        1,
        "exactly one location line for the malformed cell:\n{rendered}"
    );
    assert_terminal_safe(&rendered);

    assert_eq!(
        content_digest(workspace.path()),
        before,
        "doctor must never write"
    );
}

// ---------------------------------------------------------------------------
// R3: unresolved ids are counted, never echoed
//     (SPRINT-031.md §4 R3; fails on the 4c0c49f baseline)
// ---------------------------------------------------------------------------

/// Valid JSON ids that resolve to nothing render as one bounded location with
/// the per-cell unresolved count — never any id content (sentinel or
/// otherwise).
#[test]
fn doctor_redacts_unresolved_id_contents() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    let (_evidence_id, finding_id) = seed_unit(&db, "scan_01", ts(1), ScanStatus::Complete);

    // Two DISTINCT unresolved ids in one cell (the sentinel twice): the
    // per-cell unresolved count is 2, and neither id may render.
    let ids = vec![
        "evidence_ok".to_string(),
        SECRET_SENTINEL.to_string(),
        SECRET_SENTINEL.to_string(),
    ];
    db.connection()
        .execute(
            "UPDATE finding_reasons SET evidence_ids = ?1
             WHERE finding_id = ?2 AND position = 0",
            params![serde_json::to_string(&ids).unwrap(), finding_id],
        )
        .unwrap();

    let before = content_digest(workspace.path());
    let report = DoctorService::run(workspace.path()).unwrap();
    assert!(!report.ok, "unresolved ids must fail closed");
    assert_eq!(
        report.dangling_json_refs.len(),
        1,
        "one diagnostic item per problem cell (ids are counted, not listed)"
    );
    assert_eq!(report.dangling_more, 0);

    let rendered = render_doctor_report(&report);
    assert!(rendered.contains("finding_reasons"), "{rendered}");
    assert!(rendered.contains("evidence_ids"), "{rendered}");
    assert!(
        !rendered.contains(SECRET_SENTINEL),
        "the doctor render must never echo unresolved id contents:\n{rendered}"
    );
    assert!(
        !rendered.contains("evidence_ok"),
        "the doctor render must never echo unresolved id contents:\n{rendered}"
    );
    // The frozen §5.2 shape: per-cell unresolved count at the structural
    // location (2 distinct unresolved ids in this cell).
    assert!(
        rendered.contains("finding_reasons/evidence_ids: 2 unresolved evidence id(s)"),
        "expected the frozen unresolved-count line shape:\n{rendered}"
    );
    assert_eq!(
        dangling_location_line_count(&rendered, "finding_reasons", "evidence_ids"),
        1,
        "exactly one location line for the cell, whatever the id count:\n{rendered}"
    );
    assert!(
        !rendered.contains('[') && !rendered.contains('{'),
        "the doctor render must never echo raw JSON text shapes:\n{rendered}"
    );
    assert_terminal_safe(&rendered);

    assert_eq!(
        content_digest(workspace.path()),
        before,
        "doctor must never write"
    );
}

// ---------------------------------------------------------------------------
// R4: an unsupported schema fails closed in prune, without migrating
//     (SPRINT-031.md §4 R4; fails on the 4c0c49f baseline)
// ---------------------------------------------------------------------------

/// Build a genuine schema-v5 workspace (S029 rewind pattern): create the v6
/// shape, rewind migration 6 (drop its objects and the family column so
/// `findings` matches the v5 DDL shape), and set `user_version` to 5. The
/// caller reopens WITHOUT migrating.
fn build_v5_prune_workspace() -> (tempfile::TempDir, Database) {
    let workspace = tempdir().unwrap();
    let dir = workspace.path().join(".pico");
    fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("pico.db");
    {
        let mut db = Database::open(&db_path).unwrap();
        db.migrate().unwrap();
        let conn = db.connection();
        conn.execute("DROP TRIGGER IF EXISTS findings_family_nonempty_insert", [])
            .unwrap();
        conn.execute("DROP INDEX IF EXISTS idx_findings_scan_family", [])
            .unwrap();
        conn.execute("ALTER TABLE findings DROP COLUMN family_fingerprint", [])
            .unwrap();
        conn.pragma_update(None, "user_version", 5).unwrap();
    }
    let db = Database::open(&db_path).unwrap();
    assert_eq!(db.schema_version().unwrap(), 5);
    let family_columns: i64 = db
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('findings')
             WHERE name = 'family_fingerprint'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        family_columns, 0,
        "rewound findings table must be v5-shaped"
    );
    (workspace, db)
}

/// Prune on a schema-v5 database must fail closed with the
/// `require_schema_version` remedy — without migrating (the baseline's
/// `db.migrate()` upgrades the database to v6 and proceeds) and without any
/// write. Doctor on the same state reports the same rejection without
/// writing.
#[test]
fn prune_rejects_unsupported_schema_without_migrating() {
    let (workspace, db) = build_v5_prune_workspace();

    // A minimal COMPLETE scan row in v5 shape (the `scans` table is
    // unchanged by migration 6), so "no rows change" is a meaningful proof.
    ScanRepo::new(db.connection())
        .insert(&scan_with(
            "scan_v5",
            ScanStatus::Complete,
            ts(1),
            Some(ts(1)),
        ))
        .unwrap();
    drop(db);

    let before = content_digest(workspace.path());

    // The frozen require_schema_version remedy, exact.
    match PruneService::run(workspace.path(), Some(2)) {
        Err(PicoError::Migration(msg)) => assert_eq!(
            msg,
            "unsupported schema version 5; this build requires schema \
             version 6 (run `pico init` to upgrade)",
            "expected the frozen require_schema_version remedy, got: {msg}"
        ),
        Ok(report) => panic!(
            "prune must reject the unsupported schema without migrating or \
             deleting, got {report:?}"
        ),
        Err(error) => panic!("expected the schema-version migration error, got {error:?}"),
    }

    // Zero writes: the schema stays at v5 and every byte is unchanged.
    let user_version: i64 = open_read_only(workspace.path())
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        user_version, 5,
        "prune must never migrate an unsupported schema (baseline migrates to 6)"
    );
    assert_eq!(
        content_digest(workspace.path()),
        before,
        "the rejected prune must leave the database content byte-identical"
    );
    let conn = open_read_only(workspace.path());
    for (table, expected) in [
        ("scans", 1),
        ("observations", 0),
        ("evidence", 0),
        ("findings", 0),
        ("attack_paths", 0),
        ("scan_analyses", 0),
        ("scan_diagnostics", 0),
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected, "no rows may change in {table}");
    }

    // Doctor on the same state: the same frozen rejection, also without
    // writing.
    match DoctorService::run(workspace.path()) {
        Err(PicoError::Migration(msg)) => assert_eq!(
            msg,
            "unsupported schema version 5; this build requires schema \
             version 6 (run `pico init` to upgrade)",
            "expected the frozen require_schema_version remedy, got: {msg}"
        ),
        Ok(report) => panic!("doctor must reject the unsupported schema, got {report:?}"),
        Err(error) => panic!("expected the schema-version migration error, got {error:?}"),
    }
    let user_version: i64 = open_read_only(workspace.path())
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        user_version, 5,
        "doctor must never migrate an unsupported schema"
    );
    assert_eq!(
        content_digest(workspace.path()),
        before,
        "the rejected doctor must leave the database content byte-identical"
    );
}

// ---------------------------------------------------------------------------
// R5: the immediate write transaction excludes concurrent writers; the
//     RUNNING refusal contract (SPRINT-031.md §4 R5; passes on baseline)
// ---------------------------------------------------------------------------

/// Two connections to one database: connection A holds the immediate write
/// transaction the prune service uses (a probe write inside it); connection
/// B with `busy_timeout(0)` cannot write until A commits, and succeeds right
/// after. Deterministic — no sleeps, no polling.
///
/// Service-level contract pin: a RUNNING scan that commits before prune
/// starts is refused with the frozen message and nothing is deleted (this
/// half passes on the baseline; the fix must preserve it).
#[test]
fn immediate_transaction_excludes_concurrent_writer() {
    // --- Mechanism: BEGIN IMMEDIATE excludes a concurrent writer. ---
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("pico.db");
    {
        let mut db = Database::open(&db_path).unwrap();
        db.migrate().unwrap();
    }
    let mut conn_a = Connection::open(&db_path).unwrap();
    let conn_b = Connection::open(&db_path).unwrap();
    conn_b.busy_timeout(std::time::Duration::ZERO).unwrap();

    let tx = conn_a
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute(
        "INSERT INTO scans
         (id, started_at, completed_at, status, trigger, scope, pico_version,
          environment_fingerprint, metadata)
         VALUES ('scan_probe_a', '2026-08-01T12:00:00+00:00', NULL, 'RUNNING',
                 'manual', NULL, 'test', NULL, NULL)",
        [],
    )
    .unwrap();

    // B cannot write while A holds the immediate transaction...
    let blocked = conn_b.execute(
        "INSERT INTO scans
         (id, started_at, completed_at, status, trigger, scope, pico_version,
          environment_fingerprint, metadata)
         VALUES ('scan_probe_b', '2026-08-01T12:01:00+00:00', NULL, 'RUNNING',
                 'manual', NULL, 'test', NULL, NULL)",
        [],
    );
    let error = blocked.unwrap_err();
    assert!(
        matches!(
            error,
            rusqlite::Error::SqliteFailure(e, _) if e.code == rusqlite::ErrorCode::DatabaseBusy
        ),
        "connection B must be excluded with SQLITE_BUSY, got {error:?}"
    );
    // ...and sees no uncommitted rows from A.
    let visible_to_b: i64 = conn_b
        .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
        .unwrap();
    assert_eq!(visible_to_b, 0, "B must not see A's uncommitted probe row");

    // After A commits, B's write succeeds.
    tx.commit().unwrap();
    conn_b
        .execute(
            "INSERT INTO scans
         (id, started_at, completed_at, status, trigger, scope, pico_version,
          environment_fingerprint, metadata)
         VALUES ('scan_probe_b', '2026-08-01T12:01:00+00:00', NULL, 'RUNNING',
                 'manual', NULL, 'test', NULL, NULL)",
            [],
        )
        .unwrap();
    let total: i64 = conn_b
        .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
        .unwrap();
    assert_eq!(total, 2, "both probe rows must exist after A commits");

    // --- Contract pin: a committed RUNNING scan is refused, zero-write. ---
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_old", ts(1), ScanStatus::Complete);
    seed_unit(&db, "scan_new", ts(2), ScanStatus::Complete);
    ScanRepo::new(db.connection())
        .insert(&scan_with("scan_running", ScanStatus::Running, ts(9), None))
        .unwrap();
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
// R6: zero-write no-op/refusal and idempotent repeat pruning stay green
//     (SPRINT-031.md §4 R6; regression re-pins, passes on baseline)
// ---------------------------------------------------------------------------

/// Below-window no-op success and the RUNNING refusal change nothing
/// (whole-database digest), preserving S030's zero-write semantics under the
/// corrected sequence.
#[test]
fn prune_noop_and_refusal_stay_zero_write() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_old", ts(1), ScanStatus::Complete);
    seed_unit(&db, "scan_new", ts(2), ScanStatus::Complete);
    let before = content_digest(workspace.path());

    // Below the default window: an explicit no-op success that writes
    // nothing.
    let report = PruneService::run(workspace.path(), None).unwrap();
    assert!(report.nothing_pruned);
    assert!(report.pruned.is_empty());
    assert_eq!(report.totals, PruneTotals(UnitCounts::default()));
    assert_eq!(report.retained.complete, 2);
    assert_eq!(report.retained.running, 0);
    assert_eq!(report.keep, KEEP_COMPLETE_DEFAULT);
    assert_eq!(
        content_digest(workspace.path()),
        before,
        "the no-op must leave the database content byte-identical"
    );

    // A committed RUNNING scan is refused; still nothing written.
    ScanRepo::new(db.connection())
        .insert(&scan_with("scan_running", ScanStatus::Running, ts(9), None))
        .unwrap();
    let refusal_before = content_digest(workspace.path());
    let error = PruneService::run(workspace.path(), None).unwrap_err();
    assert!(
        matches!(error, PicoError::Usage(ref msg) if msg == "cannot prune while scan scan_running is RUNNING"),
        "expected the frozen RUNNING refusal, got {error:?}"
    );
    assert_eq!(
        content_digest(workspace.path()),
        refusal_before,
        "the refusal must leave the database content byte-identical"
    );
}

/// Repeated pruning stays idempotent: the first prune removes exactly the
/// units outside the window with every retained row byte-identical, and the
/// re-run below the new window is a no-op with a byte-identical database.
#[test]
fn prune_repeat_stays_idempotent() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    for i in 1..=4 {
        seed_unit(&db, &format!("scan_{i:02}"), ts(i), ScanStatus::Complete);
    }
    let retained_refs = ["scan_03", "scan_04"];
    let before_retained = retained_digest(workspace.path(), &retained_refs);

    let report = PruneService::run(workspace.path(), Some(2)).unwrap();
    assert_eq!(report.keep, 2);
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
    assert_eq!(report.retained.complete, 2);
    assert_eq!(
        retained_digest(workspace.path(), &retained_refs),
        before_retained,
        "every retained row must be byte-identical after the prune"
    );

    // The re-run below the new window is a no-op with an unchanged database.
    let after_first = content_digest(workspace.path());
    let again = PruneService::run(workspace.path(), Some(2)).unwrap();
    assert!(again.nothing_pruned);
    assert!(again.pruned.is_empty());
    assert_eq!(
        content_digest(workspace.path()),
        after_first,
        "the idempotent re-run must leave the database content byte-identical"
    );
}

// ---------------------------------------------------------------------------
// R7: prune and doctor output stay secret-safe
//     (SPRINT-031.md §4 R7; passes on baseline, kept independent)
// ---------------------------------------------------------------------------

/// A sentinel seeded into a pruned unit's rows (evidence observation, scan
/// metadata, diagnostics detail, finding metadata) plus the retained unit's
/// metadata must never surface in the prune or doctor renders; every output
/// byte is terminal-safe.
#[test]
fn prune_and_doctor_output_stay_secret_safe() {
    let workspace = tempdir().unwrap();
    let db = workspace_db(workspace.path());
    seed_unit(&db, "scan_secret", ts(1), ScanStatus::Complete);
    seed_unit(&db, "scan_retained", ts(2), ScanStatus::Complete);
    seed_unit(&db, "scan_other", ts(3), ScanStatus::Complete);
    let conn = db.connection();

    // Inject the sentinel into the pruned scan's rows and the retained
    // scan's metadata (which retention must keep).
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
    assert_unit_fully_removed(conn, "scan_secret");

    // The prune report names the pruned scan but never the sentinel.
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

    // The persisted sentinel survives only in the retained scan's metadata
    // (pruning removes whole units; it never rewrites retained rows).
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
}
