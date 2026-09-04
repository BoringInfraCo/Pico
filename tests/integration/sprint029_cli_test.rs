//! Sprint 029 comparison-contract guard fixtures (SPRINT-029.md §4 R1–R9).
//!
//! Each fixture drives `DiffService` through the real renderer. The
//! non-comparable render implements the frozen contract (SPRINT-029.md §5.5):
//! a comparison-skipped explanation with exact fail-closed copy, no
//! Finding/graph sections or change counts, and terminal-safe persisted
//! values throughout.

use std::fs;
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OpenFlags};
use sha2::{Digest, Sha256};

use pico::application::{
    ComparedVia, ComparisonContractField, ComparisonContractVersions, ComparisonProvenanceGap,
    DiffNotComparable, DiffNotComparableReason, DiffService, DiffSide, FindingDiff,
    FindingDiffResult, Freshness, CURRENT_COMPARISON_CONTRACT,
};
use pico::cli::render::render_finding_diff;
use pico::domain::{Observation, Resource, Scan};
use pico::persistence::{
    codec, AttackPathRecord, AttackPathRepo, Database, FindingRecord, FindingRepo, ObservationRepo,
    ResourceRepo, ScanRepo,
};
use pico::shared::{PicoError, PICO_VERSION};
use tempfile::tempdir;

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const SYNTHETIC_GITHUB_PAT: &str = "ghp_TESTFAKE0000000000000000000000000000";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn setup_db() -> (tempfile::TempDir, Database) {
    let workspace = tempdir().unwrap();
    let dir = workspace.path().join(".pico");
    fs::create_dir_all(&dir).unwrap();
    let mut db = Database::open(&dir.join("pico.db")).unwrap();
    db.migrate().unwrap();
    (workspace, db)
}

/// Deterministic clock base: every fixture scan gets an explicit timestamp so
/// COMPLETE-history ordering never depends on wall-clock races. Larger
/// arguments are older (`at(10)` precedes `at(5)`), matching the `from` →
/// `to` direction of the fixtures.
fn at(minutes_before_base: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
        - Duration::minutes(minutes_before_base)
}

/// Declared comparison-contract Scan metadata: `analysis_version` is
/// intentionally absent (the scan_analyses summary is authoritative).
fn metadata(envelope: i64, graph: i64, finding: i64) -> serde_json::Value {
    serde_json::json!({
        "comparison_contract_version": envelope,
        "graph_snapshot_version": graph,
        "finding_version": finding,
    })
}

/// Scan metadata with fixture-only sentinel material in fields the guard and
/// renderer never copy. A leak of these values into rendered output or error
/// strings fails the secret sweep.
fn metadata_with_sentinels(envelope: i64, graph: i64, finding: i64) -> serde_json::Value {
    let mut value = metadata(envelope, graph, finding);
    let object = value.as_object_mut().unwrap();
    object.insert(
        "fixture_note".to_string(),
        serde_json::Value::String(SECRET_SENTINEL.to_string()),
    );
    object.insert(
        "fixture_token".to_string(),
        serde_json::Value::String("synthetic-token".to_string()),
    );
    object.insert(
        "fixture_pat".to_string(),
        serde_json::Value::String(SYNTHETIC_GITHUB_PAT.to_string()),
    );
    value
}

/// A COMPLETE fixture scan with explicit timestamps and contract metadata.
/// Seeding the summary and rows is left to the caller so each fixture decides
/// exactly which contract components to make consistent or contradictory.
fn insert_complete_scan(
    db: &Database,
    pico_version: &str,
    completed_at: DateTime<Utc>,
    metadata: Option<serde_json::Value>,
) -> Scan {
    let mut scan = Scan::start(pico_version).unwrap();
    scan.started_at = completed_at - Duration::seconds(60);
    scan.metadata = metadata;
    let mut scan = scan.complete().unwrap();
    scan.completed_at = Some(completed_at);
    ScanRepo::new(db.connection()).insert(&scan).unwrap();
    scan
}

/// Seed the analysis summary with raw SQL: the summary is immutable once its
/// parent scan is COMPLETE, so the repository boundary (which enforces that)
/// cannot seed a finished scan.
fn seed_analysis_summary(conn: &Connection, scan_id: &str, version: &str, status: &str) {
    conn.execute(
        "INSERT INTO scan_analyses
         (scan_id, analysis_version, status, overall_disposition,
          influence_path_count, authority_path_count, active_path_count,
          blocked_path_count, unresolved_candidate_count, created_at)
         VALUES (?1, ?2, ?3, 'NONE', 0, 0, 0, 0, 0, ?4)",
        params![scan_id, version, status, codec::ts_to_text(Utc::now())],
    )
    .unwrap();
}

fn insert_finding(
    db: &Database,
    scan_id: &str,
    fingerprint: &str,
    family: &str,
    version: &str,
    severity: &str,
    confidence: &str,
) {
    FindingRepo::new(db.connection())
        .insert(&FindingRecord {
            id: format!("finding-{fingerprint}"),
            scan_id: scan_id.to_string(),
            fingerprint: fingerprint.to_string(),
            family_fingerprint: family.to_string(),
            finding_version: version.to_string(),
            finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
            title: format!("Finding {fingerprint}"),
            summary: format!("Summary of {fingerprint}"),
            severity: severity.to_string(),
            confidence: confidence.to_string(),
            status: "OPEN".to_string(),
            metadata: None,
            created_at: Utc::now(),
        })
        .unwrap();
}

/// A fully consistent current-contract COMPLETE scan, optionally carrying one
/// Finding at the declared version.
fn insert_current_scan(
    db: &Database,
    completed_at: DateTime<Utc>,
    pico_version: &str,
    finding: Option<(&str, &str, &str, &str)>, // (fingerprint, family, severity, confidence)
) -> Scan {
    let scan = insert_complete_scan(db, pico_version, completed_at, Some(metadata(1, 1, 1)));
    seed_analysis_summary(db.connection(), &scan.id, "1", "COMPLETE");
    if let Some((fingerprint, family, severity, confidence)) = finding {
        insert_finding(db, &scan.id, fingerprint, family, "1", severity, confidence);
    }
    scan
}

fn seed_observation(db: &Database, scan_id: &str, snapshot_metadata: &str) {
    let mut observation =
        Observation::new(scan_id, "resource", "res_fixture", "present", "fixture").unwrap();
    observation.metadata = Some(serde_json::from_str(snapshot_metadata).unwrap());
    ObservationRepo::new(db.connection())
        .insert(&observation)
        .unwrap();
}

/// One internally consistent AttackPath at the given analysis version.
fn seed_attack_path(db: &Database, scan_id: &str, version: &str) {
    let conn = db.connection();
    let resources = ResourceRepo::new(conn);
    let source = Resource::new(
        &format!("external_source:{scan_id}"),
        "external_source",
        "t",
        "S",
    )
    .unwrap();
    let actor = Resource::new(&format!("agent:{scan_id}"), "agent", "t", "A").unwrap();
    let sink = Resource::new(&format!("sink:{scan_id}"), "worker", "t", "K").unwrap();
    for resource in [&source, &actor, &sink] {
        resources.upsert(resource).unwrap();
    }
    AttackPathRepo::new(conn)
        .insert(&AttackPathRecord {
            id: format!("path-{scan_id}"),
            scan_id: scan_id.to_string(),
            fingerprint: format!("sha256:path-{scan_id}"),
            analysis_version: version.to_string(),
            source_resource_id: source.id,
            actor_resource_id: actor.id,
            sink_resource_id: sink.id,
            disposition: "ACTIVE".to_string(),
            source_trust: "PUBLIC_EXTERNAL".to_string(),
            influence_strength: "AGENT_RETRIEVABLE".to_string(),
            capability: "CAN_EXECUTE".to_string(),
            authority_resolution: "EXACT".to_string(),
            sink_impact: "CONSEQUENTIAL".to_string(),
            boundary_metadata: Some(serde_json::json!({"boundary": "NONE"})),
            created_at: Utc::now(),
        })
        .unwrap();
}

fn tuple(envelope: u32, graph: u64, analysis: u32, finding: u32) -> ComparisonContractVersions {
    ComparisonContractVersions {
        comparison_contract_version: envelope,
        graph_snapshot_version: graph,
        analysis_version: analysis,
        finding_version: finding,
    }
}

fn ready(result: FindingDiffResult) -> FindingDiff {
    match result {
        FindingDiffResult::Ready(value) => value,
        other => panic!("expected Ready diff, got {other:?}"),
    }
}

fn not_comparable(result: FindingDiffResult) -> DiffNotComparable {
    match result {
        FindingDiffResult::NotComparable(value) => value,
        other => panic!("expected NotComparable, got {other:?}"),
    }
}

fn gap(side: DiffSide, field: ComparisonContractField) -> ComparisonProvenanceGap {
    ComparisonProvenanceGap { side, field }
}

/// The frozen non-comparable render must never carry comparison claims
/// (SPRINT-029.md §5.5): no Findings/Resources/Relationships headings, no
/// zero-valued change counts, no S024 no-change sentence, and no Cause line.
fn assert_no_comparison_claims(rendered: &str) {
    for banned in [
        "\nFindings\n",
        "\nResources\n",
        "\nRelationships\n",
        "No security-significant finding change.",
        "Cause: ",
        "  Unchanged:",
        "  Appeared:",
        "  Disappeared:",
        "  Weakened:",
        "  Strengthened:",
        "  Uncertain:",
    ] {
        assert!(
            !rendered.contains(banned),
            "non-comparable render must not contain {banned:?}:\n{rendered}"
        );
    }
}

/// Sentinel material must never surface in rendered output or error strings.
fn assert_no_secret_material(text: &str, context: &str) {
    for sentinel in [
        SECRET_SENTINEL,
        "synthetic-token",
        SYNTHETIC_GITHUB_PAT,
        "ghp_",
    ] {
        assert!(
            !text.contains(sentinel),
            "{context} must never contain {sentinel:?}:\n{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// R1: equal current tuple is comparable and preserves S024–S028 semantics
// ---------------------------------------------------------------------------

#[test]
fn current_contract_pair_is_comparable() {
    let (workspace, db) = setup_db();
    let from = insert_current_scan(
        &db,
        at(10),
        PICO_VERSION,
        Some(("sha256:old", "sha256:family", "CRITICAL", "HIGH")),
    );
    let to = insert_current_scan(
        &db,
        at(5),
        PICO_VERSION,
        Some(("sha256:new", "sha256:family", "HIGH", "HIGH")),
    );

    let latest = ready(DiffService::latest(workspace.path()).unwrap());
    let explicit = ready(DiffService::compare(workspace.path(), &from.id, &to.id).unwrap());

    for comparison in [&latest, &explicit] {
        // All four contract components are named, equal on both sides, and
        // equal to the current contract.
        assert_eq!(
            comparison.provenance.from.contract,
            Some(CURRENT_COMPARISON_CONTRACT)
        );
        assert_eq!(
            comparison.provenance.to.contract,
            Some(CURRENT_COMPARISON_CONTRACT)
        );
        let contract = comparison.provenance.from.contract.unwrap();
        assert_eq!(contract, tuple(1, 1, 1, 1));
        assert_eq!(contract.comparison_contract_version, 1);
        assert_eq!(contract.graph_snapshot_version, 1);
        assert_eq!(contract.analysis_version, 1);
        assert_eq!(contract.finding_version, 1);
    }

    // S024–S028 semantics intact on the supported-match branch: the same
    // family with a severity drop is weakened, and every row participates
    // exactly once (conservation).
    assert_eq!(latest.weakened.len(), 1);
    assert!(latest.unchanged.is_empty());
    assert!(latest.appeared.is_empty());
    assert!(latest.disappeared.is_empty());
    assert!(latest.strengthened.is_empty());
    assert!(latest.uncertain.is_empty());
    let change = &latest.weakened[0];
    assert_eq!(change.from.fingerprint, "sha256:old");
    assert_eq!(change.to.fingerprint, "sha256:new");
    let from_count = FindingRepo::new(db.connection())
        .count_for_scan(&from.id)
        .unwrap() as usize;
    let to_count = FindingRepo::new(db.connection())
        .count_for_scan(&to.id)
        .unwrap() as usize;
    let lifecycle = latest.weakened.len();
    assert_eq!(
        from_count,
        latest.unchanged.len() + latest.disappeared.len() + lifecycle
    );
    assert_eq!(
        to_count,
        latest.unchanged.len() + latest.appeared.len() + lifecycle
    );

    // Frozen provenance lines (SPRINT-029 §5.5) sit exactly between the
    // existing Compared/Freshness block and the unchanged Findings section,
    // with the S024 two-space `Appeared:  ` counts row intact.
    let rendered = render_finding_diff(&FindingDiffResult::Ready(latest));
    assert!(rendered.contains(&format!(
        "Compared: LAST TWO COMPLETE SCANS\n\
         Freshness: LATEST COMPLETE\n\
         Comparison contracts: c1-g1-a1-f1 → c1-g1-a1-f1 (SUPPORTED MATCH)\n\
         Pico versions: {pv} → {pv}\n\
         \nFindings\n\
         \x20 Unchanged: 0\n\
         \x20 Appeared:  0\n\
         \x20 Disappeared: 0\n\
         \x20 Weakened: 1\n\
         \x20 Strengthened: 0\n\
         \x20 Uncertain: 0\n",
        pv = PICO_VERSION
    )));
    assert!(rendered.contains("\nWeakened\n"));
    assert!(!rendered.contains("No security-significant finding change."));
    assert_no_secret_material(&rendered, "latest Ready render");

    let explicit_rendered = render_finding_diff(&FindingDiffResult::Ready(explicit));
    assert!(explicit_rendered.contains("Compared: EXPLICIT PAIR\n"));
    assert!(explicit_rendered.contains(&format!(
        "Comparison contracts: c1-g1-a1-f1 → c1-g1-a1-f1 (SUPPORTED MATCH)\nPico versions: {pv} → {pv}\n",
        pv = PICO_VERSION
    )));
}

// ---------------------------------------------------------------------------
// R2: package-version drift alone is not the guard key
// ---------------------------------------------------------------------------

#[test]
fn pico_version_change_alone_does_not_block() {
    let (workspace, db) = setup_db();
    // FROM at package version 0.4.0, TO at 0.4.1.
    insert_current_scan(
        &db,
        at(10),
        "0.4.0",
        Some(("sha256:old", "sha256:family", "CRITICAL", "HIGH")),
    );
    insert_current_scan(
        &db,
        at(5),
        "0.4.1",
        Some(("sha256:new", "sha256:family", "HIGH", "HIGH")),
    );

    let comparison = ready(DiffService::latest(workspace.path()).unwrap());
    assert_eq!(comparison.provenance.from.pico_version, "0.4.0");
    assert_eq!(comparison.provenance.to.pico_version, "0.4.1");
    assert_eq!(
        comparison.provenance.from.contract,
        Some(CURRENT_COMPARISON_CONTRACT)
    );
    assert_eq!(
        comparison.provenance.to.contract,
        Some(CURRENT_COMPARISON_CONTRACT)
    );
    assert_eq!(comparison.weakened.len(), 1);
    assert!(comparison.unchanged.is_empty());
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());

    // Package-version drift never blocks: the frozen provenance lines name
    // both persisted package versions while the contract tuple matches.
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains(
        "Freshness: LATEST COMPLETE\nComparison contracts: c1-g1-a1-f1 → c1-g1-a1-f1 (SUPPORTED MATCH)\nPico versions: 0.4.0 → 0.4.1\n\nFindings\n",
    ));
    assert!(rendered.contains("Compared: LAST TWO COMPLETE SCANS\n"));
    assert!(rendered.contains("Weakened: 1"));
}

// ---------------------------------------------------------------------------
// R3: one drifted component blocks comparison (ContractChanged, no inputs)
// ---------------------------------------------------------------------------

#[test]
fn changed_contract_component_blocks_comparison() {
    // (a) Analysis component: TO summary and every AttackPath row at "2".
    {
        let (workspace, db) = setup_db();
        let from = insert_current_scan(
            &db,
            at(10),
            PICO_VERSION,
            Some(("sha256:old", "sha256:family", "HIGH", "HIGH")),
        );
        let to = insert_complete_scan(&db, PICO_VERSION, at(5), Some(metadata(1, 1, 1)));
        seed_analysis_summary(db.connection(), &to.id, "2", "COMPLETE");
        seed_attack_path(&db, &to.id, "2");
        let nc = not_comparable(DiffService::latest(workspace.path()).unwrap());
        assert_eq!(nc.reason, DiffNotComparableReason::ContractChanged);
        assert!(nc.gaps.is_empty());
        assert_eq!(
            nc.provenance.from.contract,
            Some(CURRENT_COMPARISON_CONTRACT)
        );
        assert_eq!(nc.provenance.to.contract, Some(tuple(1, 1, 2, 1)));
        // The whole non-comparable render is the frozen contract, byte for
        // byte (SPRINT-029 §5.5).
        let from_id = from.id.as_str();
        let to_id = to.id.as_str();
        let rendered = render_finding_diff(&FindingDiffResult::NotComparable(nc));
        assert_eq!(
            rendered,
            format!(
                "Pico diff\n\n\
                 From: {from_id} (COMPLETE)\n\
                 To:   {to_id} (COMPLETE)\n\
                 Compared: LAST TWO COMPLETE SCANS\n\
                 Freshness: LATEST COMPLETE\n\
                 \nComparison contracts: c1-g1-a1-f1 → c1-g1-a2-f1 (MISMATCH)\n\
                 Pico versions: {pv} → {pv}\n\
                 \nSecurity change comparison was skipped because the persisted comparison contracts differ.\n\
                 No Finding, graph, lifecycle, or Cause claim was computed for this pair.\n\
                 This is not an all-clear.\n",
                pv = PICO_VERSION
            )
        );
        assert_no_comparison_claims(&rendered);
    }

    // (b) Finding component: TO declaration and every Finding row at "2".
    {
        let (workspace, db) = setup_db();
        insert_current_scan(
            &db,
            at(10),
            PICO_VERSION,
            Some(("sha256:old", "sha256:family", "HIGH", "HIGH")),
        );
        let to = insert_complete_scan(&db, PICO_VERSION, at(5), Some(metadata(1, 1, 2)));
        seed_analysis_summary(db.connection(), &to.id, "1", "COMPLETE");
        insert_finding(
            &db,
            &to.id,
            "sha256:new",
            "sha256:family",
            "2",
            "HIGH",
            "HIGH",
        );
        let nc = not_comparable(DiffService::latest(workspace.path()).unwrap());
        assert_eq!(nc.reason, DiffNotComparableReason::ContractChanged);
        assert!(nc.gaps.is_empty());
        assert_eq!(nc.provenance.to.contract, Some(tuple(1, 1, 1, 2)));
        let rendered = render_finding_diff(&FindingDiffResult::NotComparable(nc));
        assert!(rendered.contains("Comparison contracts: c1-g1-a1-f1 → c1-g1-a1-f2 (MISMATCH)\n",));
        assert!(rendered.contains(&format!("Pico versions: {pv} → {pv}\n", pv = PICO_VERSION)));
        assert!(rendered.contains(
            "Security change comparison was skipped because the persisted comparison contracts differ.\n",
        ));
        assert!(rendered.contains(
            "No Finding, graph, lifecycle, or Cause claim was computed for this pair.\n",
        ));
        assert!(rendered.contains("This is not an all-clear.\n"));
        assert_no_comparison_claims(&rendered);
    }

    // (c) Graph component: TO declaration and every observation snapshot at 2.
    {
        let (workspace, db) = setup_db();
        insert_current_scan(
            &db,
            at(10),
            PICO_VERSION,
            Some(("sha256:old", "sha256:family", "HIGH", "HIGH")),
        );
        let to = insert_complete_scan(&db, PICO_VERSION, at(5), Some(metadata(1, 2, 1)));
        seed_analysis_summary(db.connection(), &to.id, "1", "COMPLETE");
        seed_observation(&db, &to.id, r#"{"graph_snapshot_version":2}"#);
        let nc = not_comparable(DiffService::latest(workspace.path()).unwrap());
        assert_eq!(nc.reason, DiffNotComparableReason::ContractChanged);
        assert!(nc.gaps.is_empty());
        assert_eq!(nc.provenance.to.contract, Some(tuple(1, 2, 1, 1)));
        let rendered = render_finding_diff(&FindingDiffResult::NotComparable(nc));
        assert!(rendered.contains("Comparison contracts: c1-g1-a1-f1 → c1-g2-a1-f1 (MISMATCH)\n",));
        assert!(rendered.contains("This is not an all-clear.\n"));
        assert_no_comparison_claims(&rendered);
    }
}

// ---------------------------------------------------------------------------
// R4: equal but unsupported tuple is never comparable
// ---------------------------------------------------------------------------

#[test]
fn equal_unsupported_contract_is_not_comparable() {
    let (workspace, db) = setup_db();
    for (offset, fingerprint) in [(10, "sha256:old"), (5, "sha256:new")] {
        let scan = insert_complete_scan(&db, PICO_VERSION, at(offset), Some(metadata(2, 2, 2)));
        seed_analysis_summary(db.connection(), &scan.id, "2", "COMPLETE");
        seed_attack_path(&db, &scan.id, "2");
        seed_observation(&db, &scan.id, r#"{"graph_snapshot_version":2}"#);
        insert_finding(
            &db,
            &scan.id,
            fingerprint,
            "sha256:family",
            "2",
            "HIGH",
            "HIGH",
        );
    }
    let scans = ScanRepo::new(db.connection()).list().unwrap();
    let from = &scans[0];
    let to = &scans[1];

    let nc = not_comparable(DiffService::compare(workspace.path(), &from.id, &to.id).unwrap());
    assert_eq!(nc.reason, DiffNotComparableReason::ContractUnsupported);
    assert!(nc.gaps.is_empty());
    assert_eq!(nc.provenance.from.contract, Some(tuple(2, 2, 2, 2)));
    assert_eq!(nc.provenance.to.contract, Some(tuple(2, 2, 2, 2)));

    // Never Ready: the latest-two path reaches the same verdict.
    let latest = not_comparable(DiffService::latest(workspace.path()).unwrap());
    assert_eq!(latest.reason, DiffNotComparableReason::ContractUnsupported);
    assert!(latest.gaps.is_empty());

    let from_id = from.id.as_str();
    let to_id = to.id.as_str();
    let rendered = render_finding_diff(&FindingDiffResult::NotComparable(nc));
    assert_eq!(
        rendered,
        format!(
            "Pico diff\n\n\
             From: {from_id} (COMPLETE)\n\
             To:   {to_id} (COMPLETE)\n\
             Compared: EXPLICIT PAIR\n\
             \nComparison contracts: c2-g2-a2-f2 → c2-g2-a2-f2 (UNSUPPORTED)\n\
             Pico versions: {pv} → {pv}\n\
             \nSecurity change comparison was skipped because this Pico build does not support the persisted comparison contract.\n\
             No Finding, graph, lifecycle, or Cause claim was computed for this pair.\n\
             This is not an all-clear.\n",
            pv = PICO_VERSION
        )
    );
    assert_no_comparison_claims(&rendered);
}

// ---------------------------------------------------------------------------
// R5: missing legacy provenance is an explicit non-comparable result
// ---------------------------------------------------------------------------

/// Build a genuine schema-v5 workspace: create the v6 shape, rewind migration
/// 6 (drop its objects and the family column so `findings` matches the v5 DDL
/// shape used by the migration-6 fixtures in src/persistence/db.rs), and set
/// `user_version` to 5. The caller then reopens and migrates forward.
fn build_v5_workspace() -> (tempfile::TempDir, Database) {
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
        assert_eq!(db.schema_version().unwrap(), 5);
        let family_columns: i64 = conn
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
    }
    let mut db = Database::open(&db_path).unwrap();
    db.migrate().unwrap();
    assert_eq!(db.schema_version().unwrap(), 6);
    (workspace, db)
}

#[test]
fn legacy_missing_provenance_is_explicit() {
    let (workspace, db) = build_v5_workspace();
    // Pre-S008 COMPLETE scan: valid timestamps, package version "0.1.0",
    // metadata NULL, no analysis summary, no Findings.
    let from = insert_complete_scan(&db, "0.1.0", at(10), None);
    let to = insert_current_scan(
        &db,
        at(5),
        PICO_VERSION,
        Some(("sha256:new", "sha256:family", "HIGH", "HIGH")),
    );

    let nc = not_comparable(DiffService::latest(workspace.path()).unwrap());
    assert_eq!(nc.reason, DiffNotComparableReason::ProvenanceUnavailable);
    // Gaps name the FROM side's missing components in tuple-field order; the
    // current TO side is fully derivable.
    assert_eq!(
        nc.gaps,
        vec![
            gap(
                DiffSide::From,
                ComparisonContractField::GraphSnapshotVersion
            ),
            gap(DiffSide::From, ComparisonContractField::AnalysisVersion),
            gap(DiffSide::From, ComparisonContractField::FindingVersion),
        ]
    );
    // An unavailable side reports its validated package version with no
    // contract; the result is explicit, not corruption and not an empty diff.
    assert_eq!(nc.provenance.from.contract, None);
    assert_eq!(nc.provenance.from.pico_version, "0.1.0");
    assert_eq!(nc.provenance.to.pico_version, PICO_VERSION);
    assert_eq!(nc.provenance.to.contract, Some(CURRENT_COMPARISON_CONTRACT));

    let from_id = from.id.as_str();
    let to_id = to.id.as_str();
    let rendered = render_finding_diff(&FindingDiffResult::NotComparable(nc));
    assert_eq!(
        rendered,
        format!(
            "Pico diff\n\n\
             From: {from_id} (COMPLETE)\n\
             To:   {to_id} (COMPLETE)\n\
             Compared: LAST TWO COMPLETE SCANS\n\
             Freshness: LATEST COMPLETE\n\
             \nComparison contracts: (PROVENANCE UNAVAILABLE)\n\
             Missing: FROM graph_snapshot_version\n\
             Missing: FROM analysis_version\n\
             Missing: FROM finding_version\n\
             Pico versions: 0.1.0 → {pv}\n\
             \nSecurity change comparison was skipped because required historical provenance is unavailable.\n\
             No Finding, graph, lifecycle, or Cause claim was computed for this pair.\n\
             This is not an all-clear.\n",
            pv = PICO_VERSION
        )
    );
    assert_no_comparison_claims(&rendered);
}

// ---------------------------------------------------------------------------
// R6: contradictory provenance fails closed as an integrity error
// ---------------------------------------------------------------------------

#[test]
fn contradictory_provenance_fails_closed() {
    // (a) Declared finding_version vs Finding rows disagree.
    {
        let (workspace, db) = setup_db();
        insert_current_scan(
            &db,
            at(10),
            PICO_VERSION,
            Some(("sha256:old", "sha256:family", "HIGH", "HIGH")),
        );
        let to = insert_current_scan(
            &db,
            at(5),
            PICO_VERSION,
            Some(("sha256:new", "sha256:family", "HIGH", "HIGH")),
        );
        db.connection()
            .execute(
                "UPDATE findings SET finding_version = '2' WHERE scan_id = ?1",
                [&to.id],
            )
            .unwrap();
        let error = DiffService::latest(workspace.path()).unwrap_err();
        assert!(matches!(error, PicoError::Database(_)), "got {error}");
        assert!(error.to_string().contains("finding_version"));
    }

    // (b) Declared graph version vs observation snapshots disagree.
    {
        let (workspace, db) = setup_db();
        insert_current_scan(&db, at(10), PICO_VERSION, None);
        let to = insert_current_scan(&db, at(5), PICO_VERSION, None);
        seed_observation(&db, &to.id, r#"{"graph_snapshot_version":2}"#);
        let error = DiffService::latest(workspace.path()).unwrap_err();
        assert!(matches!(error, PicoError::Database(_)), "got {error}");
        assert!(error.to_string().contains("graph_snapshot_version"));
    }

    // (c) Analysis summary vs AttackPath rows disagree.
    {
        let (workspace, db) = setup_db();
        insert_current_scan(&db, at(10), PICO_VERSION, None);
        let to = insert_current_scan(&db, at(5), PICO_VERSION, None);
        seed_attack_path(&db, &to.id, "2");
        let error = DiffService::latest(workspace.path()).unwrap_err();
        assert!(matches!(error, PicoError::Database(_)), "got {error}");
        assert!(error.to_string().contains("attack_paths analysis_version"));
    }

    // (d) A non-COMPLETE summary on a COMPLETE scan.
    {
        let (workspace, db) = setup_db();
        insert_current_scan(&db, at(10), PICO_VERSION, None);
        let to = insert_current_scan(&db, at(5), PICO_VERSION, None);
        // Replace the seeded COMPLETE summary with a LIMITED one.
        db.connection()
            .execute(
                "UPDATE scan_analyses SET status = 'LIMITED' WHERE scan_id = ?1",
                [&to.id],
            )
            .unwrap();
        let error = DiffService::latest(workspace.path()).unwrap_err();
        assert!(matches!(error, PicoError::Database(_)), "got {error}");
        assert!(error.to_string().contains("not COMPLETE"));
    }

    // (e) The summary is immutable once its parent scan is COMPLETE.
    {
        let (_workspace, db) = setup_db();
        let to = insert_current_scan(&db, at(5), PICO_VERSION, None);
        let error = pico::persistence::ScanAnalysisRepo::new(db.connection())
            .upsert(&pico::persistence::ScanAnalysisRecord {
                scan_id: to.id.clone(),
                analysis_version: "2".to_string(),
                status: "COMPLETE".to_string(),
                overall_disposition: Some("NONE".to_string()),
                influence_path_count: 0,
                authority_path_count: 0,
                active_path_count: 0,
                blocked_path_count: 0,
                unresolved_candidate_count: 0,
                limit_reasons: None,
                diagnostics: None,
                created_at: Utc::now(),
            })
            .unwrap_err();
        assert!(matches!(error, PicoError::Database(_)), "got {error}");
        assert!(error
            .to_string()
            .contains("scan analysis summary is immutable once its scan is COMPLETE"));
    }
}

// ---------------------------------------------------------------------------
// R7: latest and explicit paths agree on pair, provenance, and decision
// ---------------------------------------------------------------------------

#[test]
fn latest_and_explicit_guard_decisions_agree() {
    let (workspace, db) = setup_db();
    // S1: COMPLETE, current tuple, older.
    let s1 = insert_current_scan(&db, at(20), PICO_VERSION, None);
    // S2: COMPLETE, changed tuple (analysis component), newer.
    let s2 = insert_complete_scan(&db, PICO_VERSION, at(10), Some(metadata(1, 1, 1)));
    seed_analysis_summary(db.connection(), &s2.id, "2", "COMPLETE");
    // S3: newer incomplete RUNNING attempt with valid metadata; never a side.
    let mut attempt = Scan::start(PICO_VERSION).unwrap();
    attempt.started_at = at(5);
    attempt.metadata = Some(metadata(1, 1, 1));
    ScanRepo::new(db.connection()).insert(&attempt).unwrap();

    let latest = not_comparable(DiffService::latest(workspace.path()).unwrap());
    let explicit = not_comparable(DiffService::compare(workspace.path(), &s1.id, &s2.id).unwrap());

    // Same pair, same guard decision, same provenance, same gaps.
    assert_eq!(latest.from.id, s1.id);
    assert_eq!(latest.to.id, s2.id);
    assert_eq!(explicit.from.id, s1.id);
    assert_eq!(explicit.to.id, s2.id);
    assert_eq!(latest.reason, DiffNotComparableReason::ContractChanged);
    assert_eq!(explicit.reason, DiffNotComparableReason::ContractChanged);
    assert!(latest.gaps.is_empty() && explicit.gaps.is_empty());
    assert_eq!(latest.provenance, explicit.provenance);
    assert_eq!(latest.provenance.from.contract, Some(tuple(1, 1, 1, 1)));
    assert_eq!(latest.provenance.to.contract, Some(tuple(1, 1, 2, 1)));

    // Intentional context differences only.
    assert_eq!(latest.compared_via, ComparedVia::LatestTwo);
    assert_eq!(explicit.compared_via, ComparedVia::ExplicitPair);
    assert_eq!(latest.freshness, Freshness::NewerIncomplete);
    let warning = latest.freshness_warning.as_deref().unwrap();
    assert!(warning.contains(&attempt.id));
    assert!(warning.contains("RUNNING"));
    assert_eq!(explicit.freshness, Freshness::LatestComplete);
    assert_eq!(explicit.freshness_warning, None);
    assert_eq!(explicit.newest_attempt, None);

    // The newer incomplete attempt is reported but never selected as a side.
    let reported = latest.newest_attempt.as_ref().unwrap();
    assert_eq!(reported.id, attempt.id);
    assert_eq!(reported.status, "RUNNING");

    // A reversed explicit pair is still a chronology error even though the
    // contract tuples differ.
    let error = DiffService::compare(workspace.path(), &s2.id, &s1.id).unwrap_err();
    assert!(
        error.to_string().contains("not at or before"),
        "expected temporal guard error, got {error}"
    );
}

// ---------------------------------------------------------------------------
// R8: the guard precedes comparison loading (structural early return)
// ---------------------------------------------------------------------------

#[test]
fn contract_guard_precedes_comparison_loading() {
    let (workspace, db) = setup_db();
    let from = insert_current_scan(
        &db,
        at(10),
        PICO_VERSION,
        Some(("sha256:old", "sha256:family", "HIGH", "HIGH")),
    );
    let to = insert_complete_scan(&db, PICO_VERSION, at(5), Some(metadata(1, 1, 1)));
    seed_analysis_summary(db.connection(), &to.id, "2", "COMPLETE");
    // This observation is well-formed for the guard (snapshot version 1
    // matches the declaration) but would fail graph projection if it were
    // loaded: the metadata carries no `resource` payload. A ContractChanged
    // result proves the guard returned before any projection ran.
    seed_observation(&db, &to.id, r#"{"graph_snapshot_version":1}"#);

    let first = not_comparable(DiffService::compare(workspace.path(), &from.id, &to.id).unwrap());
    assert_eq!(first.reason, DiffNotComparableReason::ContractChanged);
    assert!(first.gaps.is_empty());
    assert_eq!(
        first.provenance.from.contract,
        Some(CURRENT_COMPARISON_CONTRACT)
    );
    assert_eq!(first.provenance.to.contract, Some(tuple(1, 1, 2, 1)));

    // Repeated calls are byte-deterministic through the real renderer.
    let second = not_comparable(DiffService::compare(workspace.path(), &from.id, &to.id).unwrap());
    let first_rendered = render_finding_diff(&FindingDiffResult::NotComparable(first));
    let second_rendered = render_finding_diff(&FindingDiffResult::NotComparable(second));
    assert_eq!(first_rendered, second_rendered);

    // The frozen render names the mismatched tuples and the skip sentence.
    assert!(first_rendered.contains("Compared: EXPLICIT PAIR\n"));
    assert!(
        first_rendered.contains("Comparison contracts: c1-g1-a1-f1 → c1-g1-a2-f1 (MISMATCH)\n",)
    );
    assert!(first_rendered.contains(
        "Security change comparison was skipped because the persisted comparison contracts differ.\n",
    ));
    assert!(first_rendered.contains("This is not an all-clear.\n"));
    assert_no_comparison_claims(&first_rendered);

    // Every rendered token is terminal-safe: no control bytes beyond the
    // layout newlines and no synthetic secret material.
    assert!(
        first_rendered.chars().all(|c| c == '\n' || !c.is_control()),
        "rendered output must be terminal-safe"
    );
    assert_no_secret_material(&first_rendered, "R8 render");
}

// ---------------------------------------------------------------------------
// R9: every service+render call is read-only and secret-safe
// ---------------------------------------------------------------------------

/// Deterministic full-database content digest (SPRINT-029.md §4 R9): SHA-256
/// over a canonical serialization of every `sqlite_master` row, `PRAGMA
/// user_version`, and every user table's full row content (all columns, rows
/// in rowid order, tables in name order). Equal digests before and after a
/// call prove the database content is byte-identical, not just row counts.
fn content_digest(workspace: &Path) -> String {
    let db_path = workspace.join(".pico").join("pico.db");
    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
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
        digest.push_str(&format!("table {table} [{}]\n", column_names.join(",")));
        let column_count = column_names.len();
        let projection = column_names
            .iter()
            .map(|column| format!("quote({column})"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut rows = conn
            .prepare(&format!(
                "SELECT {projection} FROM \"{table}\" ORDER BY rowid"
            ))
            .unwrap();
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
            digest.push_str(&row.unwrap());
            digest.push('\n');
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(digest.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Runs one service call plus its render bracketed by the full-database
/// content digest: the digest must be identical before and after, whether the
/// call produced a rendered result or an error string.
fn guarded_service_and_render(
    workspace: &Path,
    call: impl FnOnce() -> Result<FindingDiffResult, PicoError>,
) -> String {
    let before = content_digest(workspace);
    let rendered_or_error = match call() {
        Ok(result) => render_finding_diff(&result),
        Err(error) => error.to_string(),
    };
    assert_eq!(
        before,
        content_digest(workspace),
        "service+render call must leave the database content byte-identical"
    );
    rendered_or_error
}

#[test]
fn contract_guard_is_read_only_and_secret_safe() {
    let (workspace, db) = setup_db();

    // FROM-side legacy: no metadata, no summary, no rows → ProvenanceUnavailable.
    let legacy = insert_complete_scan(&db, "0.1.0", at(50), None);
    // Contract-changed pair (analysis component drift on the TO side).
    let changed_from = insert_current_scan(
        &db,
        at(40),
        PICO_VERSION,
        Some((
            "sha256:changed-old",
            "sha256:family-changed",
            "HIGH",
            "HIGH",
        )),
    );
    let changed_to = insert_complete_scan(&db, PICO_VERSION, at(30), Some(metadata(1, 1, 1)));
    seed_analysis_summary(db.connection(), &changed_to.id, "2", "COMPLETE");
    seed_attack_path(&db, &changed_to.id, "2");
    // Current, comparable pair (the newest two COMPLETE scans).
    let current_from = insert_current_scan(
        &db,
        at(20),
        PICO_VERSION,
        Some(("sha256:old", "sha256:family-current", "CRITICAL", "HIGH")),
    );
    let current_to = insert_current_scan(
        &db,
        at(10),
        PICO_VERSION,
        Some(("sha256:new", "sha256:family-current", "HIGH", "HIGH")),
    );

    // Sentinel material is seeded in metadata fields the guard and renderer
    // never copy (scan metadata notes and Finding metadata), so any leak into
    // rendered output or error strings would surface in the sweep.
    for scan_id in [
        &changed_from.id,
        &changed_to.id,
        &current_from.id,
        &current_to.id,
    ] {
        db.connection()
            .execute(
                "UPDATE scans SET metadata = ?1 WHERE id = ?2",
                params![metadata_with_sentinels(1, 1, 1).to_string(), scan_id],
            )
            .unwrap();
    }
    let finding_sentinels = serde_json::json!({
        "fixture_note": SECRET_SENTINEL,
        "fixture_token": "synthetic-token",
        "fixture_pat": SYNTHETIC_GITHUB_PAT,
    });
    db.connection()
        .execute(
            "UPDATE findings SET metadata = ?1",
            params![finding_sentinels.to_string()],
        )
        .unwrap();

    // Latest path: the current pair is comparable and renders Ready.
    let latest_ready =
        guarded_service_and_render(workspace.path(), || DiffService::latest(workspace.path()));
    // Explicit path on the same pair: same Ready contract.
    let explicit_ready = guarded_service_and_render(workspace.path(), || {
        DiffService::compare(workspace.path(), &current_from.id, &current_to.id)
    });
    // Explicit path on the contract-changed pair: NotComparable.
    let explicit_changed = guarded_service_and_render(workspace.path(), || {
        DiffService::compare(workspace.path(), &changed_from.id, &changed_to.id)
    });
    // Explicit path onto the legacy side: NotComparable with gap lines.
    let explicit_legacy = guarded_service_and_render(workspace.path(), || {
        DiffService::compare(workspace.path(), &legacy.id, &current_from.id)
    });

    // Both paths really executed: Ready on the current pair, and the two
    // distinct non-comparable explanations on the guarded pairs.
    assert!(latest_ready
        .contains("Comparison contracts: c1-g1-a1-f1 → c1-g1-a1-f1 (SUPPORTED MATCH)\n",));
    assert!(latest_ready.contains("Weakened: 1"));
    assert!(explicit_ready
        .contains("Comparison contracts: c1-g1-a1-f1 → c1-g1-a1-f1 (SUPPORTED MATCH)\n",));
    assert!(explicit_ready.contains("Compared: EXPLICIT PAIR\n"));
    assert!(
        explicit_changed.contains("Comparison contracts: c1-g1-a1-f1 → c1-g1-a2-f1 (MISMATCH)\n",)
    );
    assert!(explicit_changed.contains(
        "Security change comparison was skipped because the persisted comparison contracts differ.\n",
    ));
    assert!(explicit_legacy.contains("Comparison contracts: (PROVENANCE UNAVAILABLE)\n",));
    assert!(explicit_legacy.contains("Missing: FROM graph_snapshot_version\n"));
    assert!(explicit_legacy.contains("Missing: FROM analysis_version\n"));
    assert!(explicit_legacy.contains("Missing: FROM finding_version\n"));
    assert!(explicit_legacy.contains(
        "Security change comparison was skipped because required historical provenance is unavailable.\n",
    ));

    // Secret sweep: no sentinel material surfaces in any rendered output.
    for (context, text) in [
        ("latest Ready render", &latest_ready),
        ("explicit Ready render", &explicit_ready),
        ("ContractChanged render", &explicit_changed),
        ("ProvenanceUnavailable render", &explicit_legacy),
    ] {
        assert_no_secret_material(text, context);
    }

    // R6-style integrity sub-case: a contradictory Finding version fails
    // closed. The failed call is still read-only (digest untouched) and the
    // error string carries no sentinel material. The fixture mutation itself
    // is a seeded write, so the digest baseline is taken after it.
    let before_mutation = content_digest(workspace.path());
    db.connection()
        .execute(
            "UPDATE findings SET finding_version = '2' WHERE scan_id = ?1",
            [&current_to.id],
        )
        .unwrap();
    let after_mutation = content_digest(workspace.path());
    assert_ne!(before_mutation, after_mutation);
    let integrity_error = DiffService::latest(workspace.path()).unwrap_err();
    assert_eq!(
        after_mutation,
        content_digest(workspace.path()),
        "failed service call must leave the database content byte-identical"
    );
    assert!(
        matches!(integrity_error, PicoError::Database(_)),
        "got {integrity_error}"
    );
    assert!(integrity_error.to_string().contains("finding_version"));
    assert_no_secret_material(&integrity_error.to_string(), "integrity error");
}
