//! Sprint 028 CLI finding-lifecycle fixtures (R1–R9).
//!
//! Production findings are fixed at HIGH confidence. The confidence-only
//! and mixed-direction lifecycle cases are proven here with persistence
//! fixtures: crafted Finding rows sharing `family_fingerprint` with
//! differing `fingerprint`/severity/confidence. Engine-generated continuity
//! is proven in src/findings/engine.rs.

use std::fs;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use rusqlite::{params, Connection};

use pico::application::{
    ComparedVia, DiffService, FindingDiff, FindingDiffResult, Freshness, InitService, ScanService,
};
use pico::cli::render::render_finding_diff;
use pico::discovery::cloudflare::{
    AuthorityObservation, AuthorityResolution, CredentialStatus, ObservedAccount, ObservedWorker,
    ProviderResult, ScopeState,
};
use pico::discovery::{discover_with_environment, EnvironmentReachability};
use pico::domain::{RelationshipState, Scan, ScanStatus};
use pico::persistence::{
    codec, require_schema_version, Database, FindingRecord, FindingRepo, ScanRepo,
    SUPPORTED_SCHEMA_VERSION,
};
use pico::shared::PICO_VERSION;
use tempfile::tempdir;

const SECRET_SENTINEL: &str = "TEST_SECRET_SHOULD_NOT_PERSIST";
const ALLOW: &str = r#"{
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
const DENY: &str = include_str!("../fixtures/opencode/deny/opencode.json");
const MALFORMED: &str = include_str!("../fixtures/opencode/malformed/opencode.json");

fn write_opencode(workspace: &std::path::Path, contents: &str) {
    fs::write(workspace.join("opencode.json"), contents).unwrap();
}

fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
    let workspace = tempdir().unwrap();
    let home = tempdir().unwrap();
    write_opencode(workspace.path(), ALLOW);
    InitService::run(workspace.path()).unwrap();
    (workspace, home)
}

fn provider(
    workspace: &std::path::Path,
    home: &std::path::Path,
    script_name: &str,
) -> ProviderResult {
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
        script_name: script_name.to_string(),
        worker_tag: Some(format!("worker-tag-{script_name}")),
        source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        sink_impact: Some("PRODUCTION".to_string()),
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
            granted_permissions: Vec::new(),
            zone_scoped: false,
            source_locator: "/accounts/account-1234567890123456/workers/scripts".to_string(),
        }],
        ..ProviderResult::default()
    }
}

fn scan_named(
    workspace: &std::path::Path,
    home: &std::path::Path,
    script_name: &str,
) -> pico::application::ScanResult {
    let environment = [("CLOUDFLARE_API_TOKEN", "synthetic-token")];
    ScanService::run_with_home_and_environment_and_provider(
        workspace,
        Some(home),
        Some(&environment),
        EnvironmentReachability::Proven,
        Some(provider(workspace, home, script_name)),
    )
    .unwrap()
}

fn diff_latest(workspace: &std::path::Path) -> FindingDiffResult {
    DiffService::latest(workspace).unwrap()
}

fn ready(result: FindingDiffResult) -> FindingDiff {
    match result {
        FindingDiffResult::Ready(value) => value,
        other => panic!("expected Ready diff, got {other:?}"),
    }
}

fn compare_ready(workspace: &std::path::Path, from_id: &str, to_id: &str) -> FindingDiff {
    ready(DiffService::compare(workspace, from_id, to_id).unwrap())
}

fn findings_section(rendered: &str) -> &str {
    let start = rendered
        .find("\nFindings\n")
        .expect("Findings section missing");
    rendered[start..]
        .split("\nResources\n")
        .next()
        .expect("Resources section missing")
}

/// Rendered text of one lifecycle bucket heading up to the next heading.
fn lifecycle_section<'a>(rendered: &'a str, heading: &str) -> &'a str {
    let marker = format!("\n{heading}\n");
    let start = rendered
        .find(&marker)
        .unwrap_or_else(|| panic!("{heading} section missing in:\n{rendered}"));
    let rest = &rendered[start..];
    let end = [
        "\nAppeared\n",
        "\nNot observed\n",
        "\nWeakened\n",
        "\nStrengthened\n",
        "\nUncertain\n",
        "\nResources\n",
    ]
    .iter()
    .filter(|next| **next != marker)
    .filter_map(|next| rest.find(*next))
    .min()
    .unwrap_or(rest.len());
    &rest[..end]
}

// ---------------------------------------------------------------------------
// Persistence fixtures
// ---------------------------------------------------------------------------

fn setup_db() -> (tempfile::TempDir, Database) {
    let workspace = tempdir().unwrap();
    let dir = workspace.path().join(".pico");
    fs::create_dir_all(&dir).unwrap();
    let mut db = Database::open(&dir.join("pico.db")).unwrap();
    db.migrate().unwrap();
    (workspace, db)
}

fn insert_complete_scan(db: &Database) -> String {
    let mut scan = Scan::start(PICO_VERSION).unwrap();
    // Every fixture scan declares the full comparison contract (SPRINT-029).
    scan.metadata = Some(serde_json::json!({
        "comparison_contract_version": 1,
        "graph_snapshot_version": 1,
        "finding_version": 1,
    }));
    let scan = scan.complete().unwrap();
    ScanRepo::new(db.connection()).insert(&scan).unwrap();
    seed_complete_analysis(db.connection(), &scan.id);
    scan.id
}

/// Seed the COMPLETE analysis summary for a fixture scan with raw SQL: the
/// summary is immutable once its parent scan is COMPLETE, so the repository
/// boundary (which enforces that) cannot seed a finished scan.
fn seed_complete_analysis(conn: &Connection, scan_id: &str) {
    conn.execute(
        "INSERT INTO scan_analyses
         (scan_id, analysis_version, status, overall_disposition,
          influence_path_count, authority_path_count, active_path_count,
          blocked_path_count, unresolved_candidate_count, created_at)
         VALUES (?1, '1', 'COMPLETE', 'NONE', 0, 0, 0, 0, 0, ?2)",
        params![scan_id, codec::ts_to_text(Utc::now())],
    )
    .unwrap();
}

fn finding_record(
    scan_id: &str,
    fingerprint: &str,
    family: &str,
    severity: &str,
    confidence: &str,
) -> FindingRecord {
    FindingRecord {
        id: format!("finding-{fingerprint}"),
        scan_id: scan_id.to_string(),
        fingerprint: fingerprint.to_string(),
        family_fingerprint: family.to_string(),
        finding_version: "1".to_string(),
        finding_class: "UNTRUSTED_TO_PRODUCTION".to_string(),
        title: format!("Finding {fingerprint}"),
        summary: format!("Summary of {fingerprint}"),
        severity: severity.to_string(),
        confidence: confidence.to_string(),
        status: "OPEN".to_string(),
        metadata: None,
        created_at: Utc::now(),
    }
}

fn insert_finding(
    db: &Database,
    scan_id: &str,
    fingerprint: &str,
    family: &str,
    severity: &str,
    confidence: &str,
) -> FindingRecord {
    let record = finding_record(scan_id, fingerprint, family, severity, confidence);
    FindingRepo::new(db.connection()).insert(&record).unwrap();
    record
}

/// Simulate a migrated v5 row: write with a placeholder family, then set
/// `family_fingerprint = ''` via raw SQL (the insert-only trigger blocks
/// empty-family inserts post-migration, and `FindingRepo::insert` rejects
/// them too).
fn insert_legacy_finding(
    db: &Database,
    scan_id: &str,
    fingerprint: &str,
    severity: &str,
    confidence: &str,
) {
    let conn = db.connection();
    let placeholder = format!("sha256:placeholder-{fingerprint}");
    conn.execute(
        "INSERT INTO findings
         (id, scan_id, fingerprint, family_fingerprint, finding_version, finding_class, title,
          summary, severity, confidence, status, metadata, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            format!("finding-{fingerprint}"),
            scan_id,
            fingerprint,
            placeholder,
            "1",
            "UNTRUSTED_TO_PRODUCTION",
            format!("Finding {fingerprint}"),
            format!("Summary of {fingerprint}"),
            severity,
            confidence,
            "OPEN",
            Option::<String>::None,
            codec::ts_to_text(Utc::now()),
        ],
    )
    .unwrap();
    conn.execute(
        "UPDATE findings SET family_fingerprint = '' WHERE fingerprint = ?1",
        [fingerprint],
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// A. Live-scan CLI tests
// ---------------------------------------------------------------------------

/// R1: an identical COMPLETE pair never reports lifecycle movement.
#[test]
fn unchanged_pair_has_no_lifecycle_movement() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert!(comparison.weakened.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert!(comparison.uncertain.is_empty());
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    let findings = findings_section(&rendered);
    assert!(findings.contains("No security-significant finding change."));
    assert!(findings.contains("Weakened: 0"));
    assert!(findings.contains("Strengthened: 0"));
    assert!(findings.contains("Uncertain: 0"));
}

/// R2: ALLOW → DENY is disappearance, never weakening (different families).
#[test]
fn bash_deny_is_disappeared_not_weakened() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), DENY);
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.disappeared.len(), 1);
    assert!(comparison.appeared.is_empty());
    assert!(comparison.weakened.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert!(comparison.uncertain.is_empty());
}

/// R3: worker churn keeps different families (sink identity) — appeared +
/// disappeared, not weakened.
#[test]
fn worker_churn_is_not_weakened() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "billing");
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.appeared.len(), 1);
    assert_eq!(comparison.disappeared.len(), 1);
    assert!(comparison.weakened.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert!(comparison.uncertain.is_empty());
}

/// R6: a newer PARTIAL attempt never fabricates lifecycle movement; it only
/// sets freshness context.
#[test]
fn partial_does_not_fabricate_lifecycle() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    write_opencode(workspace.path(), MALFORMED);
    let partial = ScanService::run_with_home(workspace.path(), Some(home.path())).unwrap();
    assert_eq!(partial.status, ScanStatus::Partial);
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.freshness, Freshness::NewerIncomplete);
    assert_eq!(comparison.unchanged.len(), 1);
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    assert!(comparison.weakened.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert!(comparison.uncertain.is_empty());
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("No security-significant finding change."));
}

/// R7: no token material leaks through the new lifecycle headings/cause lines.
#[test]
fn secret_sweep_never_leaks_in_lifecycle() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "billing");
    let rendered = render_finding_diff(&diff_latest(workspace.path()));
    assert!(!rendered.contains(SECRET_SENTINEL));
    assert!(!rendered.contains("synthetic-token"));
    assert!(!rendered.contains("ghp_"));
}

/// Header byte-contract: `Appeared:  N` keeps two spaces; the new lifecycle
/// rows use a single space (S024 byte-compat).
#[test]
fn counts_contract() {
    let (workspace, home) = setup();
    scan_named(workspace.path(), home.path(), "checkout");
    scan_named(workspace.path(), home.path(), "checkout");
    let comparison = ready(diff_latest(workspace.path()));
    assert_eq!(comparison.compared_via, ComparedVia::LatestTwo);
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    let findings = findings_section(&rendered);
    assert!(findings.contains("Unchanged: 1"));
    assert!(findings.contains("Appeared:  0"));
    assert!(findings.contains("Not observed: 0"));
    assert!(findings.contains("Weakened: 0"));
    assert!(findings.contains("Strengthened: 0"));
    assert!(findings.contains("Uncertain: 0"));
}

// ---------------------------------------------------------------------------
// B. Persistence fixture tests — lifecycle directions
// ---------------------------------------------------------------------------

/// R5: same family, severity down with equal confidence → weakened with the
/// severity delta rendered in the Weakened section.
#[test]
fn severity_down_is_weakened() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    insert_finding(
        &db,
        &from_id,
        "sha256:old",
        "sha256:fam-1",
        "CRITICAL",
        "HIGH",
    );
    insert_finding(&db, &to_id, "sha256:new", "sha256:fam-1", "HIGH", "HIGH");
    let comparison = compare_ready(workspace.path(), &from_id, &to_id);
    assert!(comparison.unchanged.is_empty());
    assert!(comparison.appeared.is_empty());
    assert!(comparison.disappeared.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert!(comparison.uncertain.is_empty());
    assert_eq!(comparison.weakened.len(), 1);
    let change = &comparison.weakened[0];
    assert_eq!(change.from.fingerprint, "sha256:old");
    assert_eq!(change.to.fingerprint, "sha256:new");
    assert_eq!(
        change.deltas,
        vec![pico::application::FindingRatingDelta {
            field: "severity".to_string(),
            from_value: "CRITICAL".to_string(),
            to_value: "HIGH".to_string(),
        }]
    );
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    let section = lifecycle_section(&rendered, "Weakened");
    assert!(section.contains("Cause: Severity CRITICAL → HIGH"));
}

/// R5: same family, confidence up with equal severity → strengthened.
#[test]
fn strengthened_direction() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    insert_finding(
        &db,
        &from_id,
        "sha256:old",
        "sha256:fam-1",
        "HIGH",
        "MEDIUM",
    );
    insert_finding(&db, &to_id, "sha256:new", "sha256:fam-1", "HIGH", "HIGH");
    let comparison = compare_ready(workspace.path(), &from_id, &to_id);
    assert!(comparison.weakened.is_empty());
    assert!(comparison.uncertain.is_empty());
    assert_eq!(comparison.strengthened.len(), 1);
    let change = &comparison.strengthened[0];
    assert_eq!(change.from.fingerprint, "sha256:old");
    assert_eq!(change.to.fingerprint, "sha256:new");
    assert_eq!(
        change.deltas,
        vec![pico::application::FindingRatingDelta {
            field: "confidence".to_string(),
            from_value: "MEDIUM".to_string(),
            to_value: "HIGH".to_string(),
        }]
    );
}

/// R5: opposing severity/confidence directions are uncertain, exactly once.
#[test]
fn mixed_direction_is_uncertain() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    insert_finding(
        &db,
        &from_id,
        "sha256:old",
        "sha256:fam-1",
        "HIGH",
        "MEDIUM",
    );
    insert_finding(&db, &to_id, "sha256:new", "sha256:fam-1", "MEDIUM", "HIGH");
    let comparison = compare_ready(workspace.path(), &from_id, &to_id);
    assert!(comparison.weakened.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert_eq!(comparison.uncertain.len(), 1);
    assert_eq!(comparison.uncertain[0].deltas.len(), 2);
    let rendered = render_finding_diff(&FindingDiffResult::Ready(comparison));
    assert!(rendered.contains("Cause: Severity HIGH → MEDIUM; Confidence MEDIUM → HIGH"));
}

/// Direction is a comparison fact: the same family pair classified rising is
/// strengthened, falling is weakened. The reverse chronological pair
/// (newer → older) is rejected by the temporal guard, so the swap is proven
/// with two chronological comparisons over three scans.
#[test]
fn reverse_pair_swaps_weakened_strengthened() {
    let (workspace, db) = setup_db();
    let first_id = insert_complete_scan(&db);
    let second_id = insert_complete_scan(&db);
    let third_id = insert_complete_scan(&db);
    insert_finding(
        &db,
        &first_id,
        "sha256:old",
        "sha256:fam-1",
        "CRITICAL",
        "HIGH",
    );
    insert_finding(
        &db,
        &second_id,
        "sha256:new",
        "sha256:fam-1",
        "HIGH",
        "HIGH",
    );
    insert_finding(
        &db,
        &third_id,
        "sha256:old-again",
        "sha256:fam-1",
        "CRITICAL",
        "HIGH",
    );
    let falling = compare_ready(workspace.path(), &first_id, &second_id);
    assert_eq!(falling.weakened.len(), 1);
    assert!(falling.strengthened.is_empty());
    let rising = compare_ready(workspace.path(), &second_id, &third_id);
    assert_eq!(rising.strengthened.len(), 1);
    assert!(rising.weakened.is_empty());
    // The temporal guard refuses the out-of-order pair explicitly.
    let error = DiffService::compare(workspace.path(), &second_id, &first_id).unwrap_err();
    assert!(
        error.to_string().contains("not at or before"),
        "expected temporal guard error, got {error}"
    );
}

/// Collision (2 old × 1 new in one family) never pairs: lifecycle 0, all rows
/// stay appeared/disappeared. The partial unique index forbids a same-family
/// duplicate within one scan in production; this fixture drops it to simulate
/// the defensive compare path (e.g., a writer bug bypassing the index), so
/// compare is proven to never fabricate 1:N lifecycle pairs.
#[test]
fn collision_is_conservative() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    db.connection()
        .execute("DROP INDEX idx_findings_scan_family", [])
        .unwrap();
    insert_finding(
        &db,
        &from_id,
        "sha256:old-1",
        "sha256:fam-1",
        "CRITICAL",
        "HIGH",
    );
    insert_finding(&db, &from_id, "sha256:old-2", "sha256:fam-1", "LOW", "LOW");
    insert_finding(&db, &to_id, "sha256:new", "sha256:fam-1", "HIGH", "HIGH");
    let comparison = compare_ready(workspace.path(), &from_id, &to_id);
    assert!(comparison.weakened.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert!(comparison.uncertain.is_empty());
    assert_eq!(comparison.disappeared.len(), 2);
    assert_eq!(comparison.appeared.len(), 1);
}

/// Legacy `''` families never family-match across fingerprints: effective
/// family falls back to the full fingerprint.
#[test]
fn legacy_empty_family_never_joins() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    insert_legacy_finding(&db, &from_id, "sha256:old-x", "CRITICAL", "HIGH");
    insert_legacy_finding(&db, &to_id, "sha256:new-y", "HIGH", "HIGH");
    let comparison = compare_ready(workspace.path(), &from_id, &to_id);
    assert!(comparison.weakened.is_empty());
    assert!(comparison.strengthened.is_empty());
    assert!(comparison.uncertain.is_empty());
    assert_eq!(comparison.disappeared.len(), 1);
    assert_eq!(comparison.appeared.len(), 1);
    let loaded = FindingRepo::new(db.connection())
        .get("finding-sha256:old-x")
        .unwrap()
        .unwrap();
    assert_eq!(loaded.family_fingerprint, "");
}

/// Conservation: each from-row participates exactly once, each to-row
/// participates exactly once (`F = U + D + L`, `T = U + A + L`).
#[test]
fn conservation_invariant() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    insert_finding(
        &db,
        &from_id,
        "sha256:old",
        "sha256:fam-1",
        "CRITICAL",
        "HIGH",
    );
    insert_finding(&db, &to_id, "sha256:new", "sha256:fam-1", "HIGH", "HIGH");
    let comparison = compare_ready(workspace.path(), &from_id, &to_id);
    let from_count = FindingRepo::new(db.connection())
        .count_for_scan(&from_id)
        .unwrap();
    let to_count = FindingRepo::new(db.connection())
        .count_for_scan(&to_id)
        .unwrap();
    let lifecycle =
        comparison.weakened.len() + comparison.strengthened.len() + comparison.uncertain.len();
    assert_eq!(
        from_count as usize,
        comparison.unchanged.len() + comparison.disappeared.len() + lifecycle
    );
    assert_eq!(
        to_count as usize,
        comparison.unchanged.len() + comparison.appeared.len() + lifecycle
    );
}

/// Comparison is deterministic: the same pair renders byte-identically twice.
#[test]
fn comparison_is_byte_identical() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    insert_finding(
        &db,
        &from_id,
        "sha256:old",
        "sha256:fam-1",
        "CRITICAL",
        "HIGH",
    );
    insert_finding(&db, &to_id, "sha256:new", "sha256:fam-1", "HIGH", "HIGH");
    let first =
        render_finding_diff(&DiffService::compare(workspace.path(), &from_id, &to_id).unwrap());
    let second =
        render_finding_diff(&DiffService::compare(workspace.path(), &from_id, &to_id).unwrap());
    assert_eq!(first, second);
}

/// Only COMPLETE scans participate as comparison sides.
#[test]
fn explicit_partial_operand_fails() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    let partial = Scan::start(PICO_VERSION).unwrap().partial().unwrap();
    ScanRepo::new(db.connection()).insert(&partial).unwrap();
    let error = DiffService::compare(workspace.path(), &from_id, &partial.id).unwrap_err();
    assert!(
        error.to_string().contains("COMPLETE"),
        "expected COMPLETE error, got {error}"
    );
    let error = DiffService::compare(workspace.path(), &partial.id, &to_id).unwrap_err();
    assert!(
        error.to_string().contains("COMPLETE"),
        "expected COMPLETE error, got {error}"
    );
}

/// `DiffService::latest` is a read snapshot: schema version and row counts
/// before and after are identical.
#[test]
fn read_only_diff_performs_zero_writes() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    let to_id = insert_complete_scan(&db);
    insert_finding(
        &db,
        &from_id,
        "sha256:old",
        "sha256:fam-1",
        "CRITICAL",
        "HIGH",
    );
    insert_finding(&db, &to_id, "sha256:new", "sha256:fam-1", "HIGH", "HIGH");
    let conn = db.connection();
    let snapshot = || -> (i64, i64, i64) {
        (
            pico::persistence::db::schema_version(conn).unwrap(),
            conn.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
                .unwrap(),
            conn.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
                .unwrap(),
        )
    };
    let before = snapshot();
    let comparison = ready(DiffService::latest(workspace.path()).unwrap());
    assert_eq!(comparison.compared_via, ComparedVia::LatestTwo);
    assert_eq!(comparison.weakened.len(), 1);
    let after = snapshot();
    assert_eq!(before, after);
}

// ---------------------------------------------------------------------------
// C. Migration / integrity tests
// ---------------------------------------------------------------------------

/// Fresh databases initialize at schema v6 (SUPPORTED_SCHEMA_VERSION).
#[test]
fn fresh_db_initializes_at_schema_v6() {
    let (workspace, db) = setup_db();
    assert_eq!(SUPPORTED_SCHEMA_VERSION, 6);
    assert_eq!(db.schema_version().unwrap(), 6);
    drop(workspace);
}

/// Migration 6 objects exist; the partial unique index and the non-empty
/// family trigger reject violating raw-SQL writes.
#[test]
fn migration6_integrity_objects() {
    let (workspace, db) = setup_db();
    let scan_id = insert_complete_scan(&db);
    insert_finding(&db, &scan_id, "sha256:a", "sha256:fam-1", "HIGH", "HIGH");
    let conn = db.connection();
    for object in [
        "idx_findings_scan_family",
        "findings_family_nonempty_insert",
    ] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                [object],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "missing {object}");
    }
    // Duplicate (scan_id, family) with a distinct fingerprint fails on the
    // partial unique index (the legacy UNIQUE(scan_id, fingerprint) passes).
    let duplicate = conn.execute(
        "INSERT INTO findings
         (id, scan_id, fingerprint, family_fingerprint, finding_version, finding_class, title,
          summary, severity, confidence, status, metadata, created_at)
         VALUES ('finding-dup', ?1, 'sha256:dup', 'sha256:fam-1', '1',
                 'UNTRUSTED_TO_PRODUCTION', 'Finding dup', 'Summary of dup',
                 'LOW', 'LOW', 'OPEN', NULL, '2026-01-01T00:00:00Z')",
        [&scan_id],
    );
    assert!(duplicate.is_err(), "duplicate family must fail");
    // Raw insert with an empty family fails on the trigger.
    let empty_family = conn.execute(
        "INSERT INTO findings
         (id, scan_id, fingerprint, family_fingerprint, finding_version, finding_class, title,
          summary, severity, confidence, status, metadata, created_at)
         VALUES ('finding-empty', ?1, 'sha256:empty', '', '1',
                 'UNTRUSTED_TO_PRODUCTION', 'Finding empty', 'Summary of empty',
                 'LOW', 'LOW', 'OPEN', NULL, '2026-01-01T00:00:00Z')",
        [&scan_id],
    );
    assert!(empty_family.is_err(), "empty family must fail");
    // The repository boundary rejects empty families as well.
    let mut record = finding_record(&scan_id, "sha256:legacy", "", "LOW", "LOW");
    record.id = "finding-repo-legacy".to_string();
    let error = FindingRepo::new(conn).insert(&record).unwrap_err();
    assert!(error.to_string().contains("family_fingerprint"));
    drop(workspace);
}

/// A future schema version fails closed before any write: `migrate()` and
/// `require_schema_version` reject, `user_version` stays, content unchanged.
#[test]
fn future_schema_version_fails_before_writes() {
    let (workspace, mut db) = setup_db();
    let scan_id = insert_complete_scan(&db);
    let record = insert_finding(
        &db,
        &scan_id,
        "sha256:keep",
        "sha256:fam-keep",
        "HIGH",
        "HIGH",
    );
    db.connection()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    assert_eq!(db.schema_version().unwrap(), 99);
    assert!(require_schema_version(db.connection()).is_err());
    assert!(db.migrate().is_err());
    assert_eq!(db.schema_version().unwrap(), 99);
    let repo = FindingRepo::new(db.connection());
    let loaded = repo.get(&record.id).unwrap().unwrap();
    assert_eq!(loaded.fingerprint, record.fingerprint);
    assert_eq!(loaded.family_fingerprint, record.family_fingerprint);
    assert_eq!(loaded.severity, record.severity);
    assert_eq!(loaded.confidence, record.confidence);
    assert_eq!(loaded.status, record.status);
    assert_eq!(repo.count_for_scan(&scan_id).unwrap(), 1);
    drop(workspace);
}

/// P2: a NULL `family_fingerprint` is corruption (schema v6 declares the
/// column NOT NULL) and must fail closed, never masquerade as the legacy `''`
/// behavior. Simulated hermetically: `UPDATE ... SET family_fingerprint =
/// NULL` is rejected by the NOT NULL constraint, so the fixture drops and
/// recreates the `findings` table with the identical column list minus the
/// NOT NULL on `family_fingerprint` (recreating the v6 index and trigger),
/// then inserts a raw NULL-family row. The diff query must return an integrity
/// error and leave `user_version` untouched.
#[test]
fn null_family_fails_closed() {
    let (workspace, db) = setup_db();
    let from_id = insert_complete_scan(&db);
    thread::sleep(Duration::from_millis(2));
    let to_id = insert_complete_scan(&db);
    let conn = db.connection();

    // Rebuild `findings` with a nullable family column.
    let (create_sql, index_sql, trigger_sql): (String, Option<String>, Option<String>) = {
        let sql_for = |name: &str| -> Option<String> {
            conn.query_row(
                "SELECT sql FROM sqlite_master WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .ok()
        };
        (
            sql_for("findings").expect("findings table must exist"),
            sql_for("idx_findings_scan_family"),
            sql_for("findings_family_nonempty_insert"),
        )
    };
    assert!(
        create_sql.contains("family_fingerprint TEXT NOT NULL"),
        "fixture assumes the v6 NOT NULL family column, got: {create_sql}"
    );
    let nullable_sql = create_sql.replace(
        "family_fingerprint TEXT NOT NULL",
        "family_fingerprint TEXT",
    );
    conn.pragma_update(None, "foreign_keys", false).unwrap();
    conn.execute("DROP TABLE findings", []).unwrap();
    conn.execute(&nullable_sql, []).unwrap();
    if let Some(index_sql) = index_sql {
        conn.execute(&index_sql, []).unwrap();
    }
    if let Some(trigger_sql) = trigger_sql {
        conn.execute(&trigger_sql, []).unwrap();
    }
    conn.pragma_update(None, "foreign_keys", true).unwrap();

    // The pre-fix COALESCE behavior would treat NULL as legacy ''; the fixed
    // reader must reject it instead.
    let from_error = FindingRepo::new(conn)
        .insert(&finding_record(
            &from_id,
            "sha256:old",
            "sha256:fam-1",
            "CRITICAL",
            "HIGH",
        ))
        .err();
    assert!(
        from_error.is_none(),
        "recreated table must accept non-empty families"
    );
    conn.execute(
        "INSERT INTO findings
         (id, scan_id, fingerprint, family_fingerprint, finding_version, finding_class,
          title, summary, severity, confidence, status, metadata, created_at)
         VALUES ('finding-null', ?1, 'sha256:new', NULL, '1',
                 'UNTRUSTED_TO_PRODUCTION', 'Finding null', 'Summary of null',
                 'HIGH', 'HIGH', 'OPEN', NULL, ?2)",
        params![to_id, codec::ts_to_text(Utc::now())],
    )
    .unwrap();

    let error = DiffService::latest(workspace.path()).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("family_fingerprint") && message.contains("integrity"),
        "expected NULL-family integrity error, got {error}"
    );
    // The diff read failed closed without touching the schema version.
    assert_eq!(db.schema_version().unwrap(), 6);
    drop(workspace);
}
