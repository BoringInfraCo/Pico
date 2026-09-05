//! Retention policy, whole-unit pruning, and database health
//! (SPRINT-030.md §5.1–§5.3).
//!
//! The retention policy is a pure function over loaded scans. Pruning is
//! transactional: the caller owns the transaction, and the frozen deletion
//! order keeps every step foreign-key-safe with `foreign_keys = true`. The
//! health check is read-only (`PRAGMA`s and `SELECT`s only) and is shared by
//! `pico prune` (before and after deletion) and `pico doctor` (which never
//! mutates state).
//!
//! Contract frozen by SPRINT-030.md:
//! - keep the newest N COMPLETE scans (default N = 10, N >= 2) plus every
//!   incomplete attempt newer than the newest COMPLETE scan;
//! - prune COMPLETE scans outside the window and PARTIAL/FAILED attempts
//!   strictly older than the newest COMPLETE scan, oldest-first;
//! - never prune RUNNING scans (prune refuses instead of racing a live
//!   scan);
//! - delete whole units only, in the frozen table order, inside one
//!   transaction; global identity surfaces (`resources`, `relationships`,
//!   and `relationship_evidence` rows of retained evidence) are never
//!   pruned.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::domain::{Scan, ScanStatus};
use crate::persistence::db::schema_version;
use crate::persistence::{require_schema_version, Database, ScanRepo, SUPPORTED_SCHEMA_VERSION};
use crate::shared::PicoError;

fn db_err(error: rusqlite::Error) -> PicoError {
    PicoError::Database(error.to_string())
}

/// Default number of COMPLETE scans retained (SPRINT-030.md §5.1).
pub const KEEP_COMPLETE_DEFAULT: usize = 10;

/// Smallest accepted `--keep` value; keeps the latest-two diff contract
/// (S024) meaningful under any accepted flag value.
pub const MIN_KEEP_COMPLETE: usize = 2;

/// Cap on individually STORED dangling JSON-reference diagnostics
/// (SPRINT-031.md §5.2): the scan stops storing at the cap but keeps
/// scanning and counting problem locations; the remainder beyond the cap is
/// summarized by `HealthReport::dangling_more`.
const DANGLING_REPORT_CAP: usize = 20;

/// The retention window: how many COMPLETE scans stay behind a prune.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionWindow {
    pub keep: usize,
}

impl RetentionWindow {
    /// Resolve the `--keep` flag. `None` selects the frozen default; values
    /// below the floor are a usage error before any database work.
    pub fn resolve(keep: Option<usize>) -> Result<Self, PicoError> {
        match keep {
            Some(n) if n < MIN_KEEP_COMPLETE => {
                Err(PicoError::usage("--keep must be an integer of at least 2"))
            }
            Some(n) => Ok(RetentionWindow { keep: n }),
            None => Ok(RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            }),
        }
    }
}

/// The retention plan over one snapshot of all scans (SPRINT-030.md §5.1).
///
/// Pure policy output: `keep_ids` are the retained COMPLETE scans
/// oldest-first; `prune_complete` is the COMPLETE units to prune
/// oldest-first; `prune_incomplete` is the PARTIAL/FAILED attempts to prune
/// oldest-first by `(started_at, id)`. RUNNING scans never appear anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPlan {
    /// Retained COMPLETE scan ids, ascending (oldest-first).
    pub keep_ids: Vec<String>,
    /// COMPLETE units to prune, oldest-first.
    pub prune_complete: Vec<String>,
    /// PARTIAL/FAILED units to prune, oldest-first by `(started_at, id)`.
    pub prune_incomplete: Vec<String>,
}

/// Compute the retention plan over `all_scans` (SPRINT-030.md §5.1).
///
/// The keep set is the newest `window.keep` COMPLETE scans in the
/// `list_complete` ordering (`completed_at DESC, started_at DESC, id DESC`),
/// presented ascending. COMPLETE scans outside the keep set are pruned
/// oldest-first. A PARTIAL/FAILED attempt is pruned only when its
/// `(started_at, id)` tuple is strictly older than the tuple of the newest
/// COMPLETE scan (the first element of the `list_complete` ordering); when
/// no COMPLETE scan exists, nothing is pruned, so every incomplete attempt
/// newer than the newest COMPLETE is kept. RUNNING scans never appear in
/// any set.
pub fn plan_retention(window: RetentionWindow, all_scans: &[Scan]) -> RetentionPlan {
    let mut completes: Vec<&Scan> = all_scans
        .iter()
        .filter(|scan| scan.status == ScanStatus::Complete)
        .collect();
    completes.sort_by(|a, b| {
        b.completed_at
            .cmp(&a.completed_at)
            .then_with(|| b.started_at.cmp(&a.started_at))
            .then_with(|| b.id.cmp(&a.id))
    });

    let keep_ids: Vec<String> = completes
        .iter()
        .take(window.keep)
        .rev()
        .map(|scan| scan.id.clone())
        .collect();
    let prune_complete: Vec<String> = completes
        .iter()
        .skip(window.keep)
        .rev()
        .map(|scan| scan.id.clone())
        .collect();

    let mut prune_incomplete = Vec::new();
    if let Some(newest) = completes.first() {
        let mut attempts: Vec<&Scan> = all_scans
            .iter()
            .filter(|scan| matches!(scan.status, ScanStatus::Partial | ScanStatus::Failed))
            .filter(|scan| {
                (scan.started_at, scan.id.as_str()) < (newest.started_at, newest.id.as_str())
            })
            .collect();
        attempts.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        prune_incomplete = attempts.into_iter().map(|scan| scan.id.clone()).collect();
    }

    RetentionPlan {
        keep_ids,
        prune_complete,
        prune_incomplete,
    }
}

/// Row counts deleted for one scan unit (SPRINT-031.md §5.4). Counts are
/// taken at deletion time and cover exactly the seven directly deleted
/// tables — observations, evidence, findings, attack_paths, scan_analyses,
/// scan_diagnostics, relationship_evidence. Rows removed only by cascade
/// (the six link tables) and the `scans` row itself are neither counted nor
/// claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct UnitCounts {
    pub observations: u64,
    pub evidence: u64,
    pub findings: u64,
    pub attack_paths: u64,
    pub scan_analyses: u64,
    pub scan_diagnostics: u64,
    pub relationship_evidence: u64,
}

/// What was deleted for one scan unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrunedUnitReport {
    pub scan_id: String,
    pub status: String,
    pub counts: UnitCounts,
}

/// Deletes the given scan units in the frozen order (SPRINT-030.md §5.2).
///
/// The caller owns the transaction: run this inside a transaction and roll
/// back on error so a failed prune leaves the database exactly as it was.
/// Units are processed in the given order (COMPLETE units oldest-first, then
/// incomplete attempts oldest-first). Each unit is deleted in the frozen
/// table order, foreign-key-safe with `foreign_keys = true`:
/// `scan_diagnostics` → `scan_analyses` → `findings` (four link tables
/// cascade) → `attack_paths` (two link tables cascade) → `observations` →
/// `relationship_evidence` rows targeting the unit's evidence ids → the
/// unit's `evidence` rows → the `scans` row. The `relationship_evidence`
/// cleanup must precede the `evidence` delete because those rows reference
/// `evidence(id)` without cascades.
///
/// Per-table counts are taken from rusqlite's `execute()` return value,
/// which reflects SQLite's `changes()` for exactly that statement. This
/// choice is applied consistently to every counted table: each count is
/// bound to the statement that produced it, never stale, and never a
/// separate read. Counts cover exactly the seven directly deleted tables;
/// cascade-deleted link-table rows and the `scans` row itself are not
/// counted and not claimed (SPRINT-031.md §5.4).
///
/// Global identity surfaces are never touched beyond the unit-scoped
/// `relationship_evidence` membership delete: `resources` and
/// `relationships` are never deleted, and link rows whose evidence belongs
/// to a retained unit stay. No cascade from `scans(id)` is relied on (none
/// exists).
pub(crate) fn delete_scan_units(
    conn: &Connection,
    scans: &[Scan],
) -> Result<Vec<PrunedUnitReport>, PicoError> {
    let mut reports = Vec::with_capacity(scans.len());
    for scan in scans {
        let scan_diagnostics = conn.execute(
            "DELETE FROM scan_diagnostics WHERE scan_id = ?1",
            params![scan.id],
        )? as u64;
        let scan_analyses = conn.execute(
            "DELETE FROM scan_analyses WHERE scan_id = ?1",
            params![scan.id],
        )? as u64;
        let findings =
            conn.execute("DELETE FROM findings WHERE scan_id = ?1", params![scan.id])? as u64;
        let attack_paths = conn.execute(
            "DELETE FROM attack_paths WHERE scan_id = ?1",
            params![scan.id],
        )? as u64;
        let observations = conn.execute(
            "DELETE FROM observations WHERE scan_id = ?1",
            params![scan.id],
        )? as u64;
        let relationship_evidence = conn.execute(
            "DELETE FROM relationship_evidence
                 WHERE evidence_id IN (SELECT id FROM evidence WHERE scan_id = ?1)",
            params![scan.id],
        )? as u64;
        let evidence =
            conn.execute("DELETE FROM evidence WHERE scan_id = ?1", params![scan.id])? as u64;
        conn.execute("DELETE FROM scans WHERE id = ?1", params![scan.id])?;
        reports.push(PrunedUnitReport {
            scan_id: scan.id.clone(),
            status: scan.status.as_str().to_string(),
            counts: UnitCounts {
                observations,
                evidence,
                findings,
                attack_paths,
                scan_analyses,
                scan_diagnostics,
                relationship_evidence,
            },
        });
    }
    Ok(reports)
}

/// One unresolvable JSON id reference CELL (SPRINT-031.md §5.2). The DTO
/// carries structural locations and stable reason codes only: no raw JSON
/// text and no unresolved id contents ever travel in it, so no renderer can
/// echo them. One item per problem (row, column) cell, never per id.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DanglingRef {
    /// `finding_reasons` or `finding_remediations`.
    pub table: String,
    /// The JSON id column, in schema order within its table.
    pub column: String,
    /// The referenced target table; `-` when the cell text is unparseable.
    pub referenced_table: String,
    /// Stable reason code: `unresolved` or `unparseable`.
    pub category: String,
    /// Structural row location; the only persisted value a renderer echoes
    /// (through `terminal_safe`).
    pub finding_id: String,
    /// Structural row position within the finding.
    pub position: u32,
    /// Distinct unresolved ids in this cell; 0 when unparseable.
    pub unresolved_count: u64,
}

/// Retention counts over all scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct RetentionCounts {
    pub complete: u64,
    pub partial: u64,
    pub failed: u64,
    pub running: u64,
}

/// Read-only database health report (SPRINT-030.md §5.3), shared by
/// `pico doctor` and the `pico prune` pre/post checks.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HealthReport {
    pub schema_version: i64,
    pub schema_ok: bool,
    pub integrity_ok: bool,
    pub foreign_keys_ok: bool,
    /// Deterministic: `finding_reasons` before `finding_remediations`,
    /// rows by `(finding_id, position)`, columns in schema order; the first
    /// at most [`DANGLING_REPORT_CAP`] problem locations.
    pub dangling_json_refs: Vec<DanglingRef>,
    /// Total problem locations, uncapped: collection keeps counting after
    /// the stored list is full (SPRINT-031.md §5.2).
    pub dangling_total: u64,
    /// Problem locations beyond the reported cap (`dangling_total` minus
    /// the stored count).
    pub dangling_more: u64,
    /// Scan-scoped rows whose `scan_id` has no `scans` row (six tables).
    pub orphan_scan_rows: u64,
    /// Scans with more than one `scan_analyses` or more than one
    /// `scan_diagnostics` row (primary keys make zero expected).
    pub summary_rows: u64,
    pub counts: RetentionCounts,
    pub window_keep: usize,
    pub oldest_retained_complete: Option<String>,
    pub newest_complete: Option<String>,
    /// All checks pass.
    pub ok: bool,
}

/// (column, referenced table) pairs for `finding_reasons`, in schema column
/// order (SPRINT-030.md §5.3 determinism contract).
const REASON_JSON_COLUMNS: &[(&str, &str)] = &[
    ("resource_ids", "resources"),
    ("relationship_ids", "relationships"),
    ("attack_path_ids", "attack_paths"),
    ("evidence_ids", "evidence"),
];

/// (column, referenced table) pairs for `finding_remediations`, in schema
/// column order.
const REMEDIATION_JSON_COLUMNS: &[(&str, &str)] = &[
    ("target_resource_ids", "resources"),
    ("target_relationship_ids", "relationships"),
];

/// Stable reason codes (SPRINT-031.md §5.2): a parseable array with ids
/// missing from the target set is `unresolved`; text that does not parse as
/// a JSON array of string ids is `unparseable`.
const CATEGORY_UNRESOLVED: &str = "unresolved";
const CATEGORY_UNPARSEABLE: &str = "unparseable";

/// `referenced_table` reported for a cell whose text cannot be parsed as an
/// array of string ids: the target is unknown and the raw text is never
/// carried.
const NO_REFERENCED_TABLE: &str = "-";

/// Total count of scan-scoped rows whose `scan_id` has no `scans` row,
/// summed across the six scan-scoped tables.
const ORPHAN_SCAN_ROWS_SQL: &str = "
SELECT
  (SELECT COUNT(*) FROM observations AS o
     LEFT JOIN scans AS s ON o.scan_id = s.id WHERE s.id IS NULL) +
  (SELECT COUNT(*) FROM evidence AS e
     LEFT JOIN scans AS s ON e.scan_id = s.id WHERE s.id IS NULL) +
  (SELECT COUNT(*) FROM findings AS f
     LEFT JOIN scans AS s ON f.scan_id = s.id WHERE s.id IS NULL) +
  (SELECT COUNT(*) FROM attack_paths AS p
     LEFT JOIN scans AS s ON p.scan_id = s.id WHERE s.id IS NULL) +
  (SELECT COUNT(*) FROM scan_analyses AS a
     LEFT JOIN scans AS s ON a.scan_id = s.id WHERE s.id IS NULL) +
  (SELECT COUNT(*) FROM scan_diagnostics AS d
     LEFT JOIN scans AS s ON d.scan_id = s.id WHERE s.id IS NULL)";

/// Scans carrying more than one analysis summary or more than one
/// diagnostics row. Both tables are keyed by `scan_id`, so any positive
/// count indicates corruption of the primary-key contract.
const SUMMARY_ROWS_SQL: &str = "
SELECT COUNT(*) FROM (
  SELECT scan_id FROM scan_analyses GROUP BY scan_id HAVING COUNT(*) > 1
  UNION
  SELECT scan_id FROM scan_diagnostics GROUP BY scan_id HAVING COUNT(*) > 1
)";

/// Run the read-only health check (SPRINT-030.md §5.3): schema version,
/// `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, dangling JSON id
/// references over `finding_reasons`/`finding_remediations`, orphan scan
/// rows, unit-coherence summaries, and the retention state for `window`.
/// Only `PRAGMA`s and `SELECT`s run, so this is safe on a read-only
/// connection.
pub(crate) fn check_health(
    conn: &Connection,
    window: RetentionWindow,
) -> Result<HealthReport, PicoError> {
    let schema_version = schema_version(conn)?;
    let schema_ok = schema_version == SUPPORTED_SCHEMA_VERSION;

    // First row of integrity_check is "ok" exactly when nothing is wrong.
    let integrity_ok = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map(|first_row| first_row == "ok")
        .map_err(db_err)?;

    let mut foreign_keys_ok = true;
    {
        let mut violations = conn.prepare("PRAGMA foreign_key_check").map_err(db_err)?;
        let mut rows = violations.query([]).map_err(db_err)?;
        while let Some(_violation) = rows.next().map_err(db_err)? {
            foreign_keys_ok = false;
        }
    }

    let (dangling_json_refs, dangling_total) = detect_dangling_json_refs(conn)?;
    let dangling_more = dangling_total.saturating_sub(dangling_json_refs.len() as u64);

    let orphan_scan_rows: i64 = conn
        .query_row(ORPHAN_SCAN_ROWS_SQL, [], |row| row.get(0))
        .map_err(db_err)?;
    let summary_rows: i64 = conn
        .query_row(SUMMARY_ROWS_SQL, [], |row| row.get(0))
        .map_err(db_err)?;

    let scans = ScanRepo::new(conn).list()?;
    let mut counts = RetentionCounts::default();
    for scan in &scans {
        match scan.status {
            ScanStatus::Complete => counts.complete += 1,
            ScanStatus::Partial => counts.partial += 1,
            ScanStatus::Failed => counts.failed += 1,
            ScanStatus::Running => counts.running += 1,
        }
    }

    let plan = plan_retention(window, &scans);
    let oldest_retained_complete = plan.keep_ids.first().cloned();
    let newest_complete = plan.keep_ids.last().cloned();

    let ok = schema_ok
        && integrity_ok
        && foreign_keys_ok
        && dangling_total == 0
        && orphan_scan_rows == 0
        && summary_rows == 0;

    Ok(HealthReport {
        schema_version,
        schema_ok,
        integrity_ok,
        foreign_keys_ok,
        dangling_json_refs,
        dangling_total,
        dangling_more,
        orphan_scan_rows: orphan_scan_rows as u64,
        summary_rows: summary_rows as u64,
        counts,
        window_keep: window.keep,
        oldest_retained_complete,
        newest_complete,
        ok,
    })
}

/// Detect unresolvable ids in the frozen JSON id columns (SPRINT-031.md
/// §5.2). Rows are scanned `finding_reasons` first, then
/// `finding_remediations`, each ordered by `(finding_id, position)`; columns
/// are checked in schema order. One diagnostic item is produced per problem
/// CELL, never per id: a cell whose text does not parse as a JSON array of
/// strings yields one `unparseable` item; a parseable array with ids missing
/// from the target set yields one `unresolved` item carrying the per-cell
/// distinct-unresolved-id count. Never a crash, never a silent skip.
///
/// Returns the at-most-cap stored diagnostics plus the uncapped total
/// problem-location count. Storage stops at [`DANGLING_REPORT_CAP`] while
/// counting continues, so the report stays exact beyond the cap.
///
/// Note: the reference-target id sets still load in full — this bounds the
/// diagnostic SHAPE, not total database memory use.
fn detect_dangling_json_refs(conn: &Connection) -> Result<(Vec<DanglingRef>, u64), PicoError> {
    let mut existence: HashMap<&'static str, HashSet<String>> = HashMap::new();
    for table in ["resources", "relationships", "attack_paths", "evidence"] {
        existence.insert(table, load_id_set(conn, table)?);
    }
    let mut dangling = Vec::new();
    let mut total: u64 = 0;
    scan_table_json_refs(
        conn,
        "finding_reasons",
        REASON_JSON_COLUMNS,
        &existence,
        &mut dangling,
        &mut total,
    )?;
    scan_table_json_refs(
        conn,
        "finding_remediations",
        REMEDIATION_JSON_COLUMNS,
        &existence,
        &mut dangling,
        &mut total,
    )?;
    Ok((dangling, total))
}

/// Scan one table's JSON id columns against the referenced id sets, storing
/// at most [`DANGLING_REPORT_CAP`] problem cells and counting every one.
fn scan_table_json_refs(
    conn: &Connection,
    table: &'static str,
    columns: &'static [(&'static str, &'static str)],
    existence: &HashMap<&'static str, HashSet<String>>,
    dangling: &mut Vec<DanglingRef>,
    total: &mut u64,
) -> Result<(), PicoError> {
    let column_list = columns
        .iter()
        .map(|(column, _)| *column)
        .collect::<Vec<_>>()
        .join(", ");
    let mut stmt = conn
        .prepare(&format!(
            "SELECT finding_id, position, {column_list} FROM {table}
             ORDER BY finding_id, position"
        ))
        .map_err(db_err)?;
    let mut rows = stmt.query([]).map_err(db_err)?;
    while let Some(row) = rows.next().map_err(db_err)? {
        let finding_id: String = row.get(0).map_err(db_err)?;
        let position: u32 = row.get(1).map_err(db_err)?;
        for (index, (column, referenced)) in columns.iter().enumerate() {
            let text: String = row.get(index + 2).map_err(db_err)?;
            let (category, referenced_table, unresolved_count) =
                match serde_json::from_str::<Vec<String>>(&text) {
                    Ok(ids) => {
                        let known = &existence[*referenced];
                        let unresolved_count = ids
                            .iter()
                            .filter(|id| !known.contains(id.as_str()))
                            .map(|id| id.as_str())
                            .collect::<HashSet<&str>>()
                            .len() as u64;
                        if unresolved_count == 0 {
                            continue;
                        }
                        (
                            CATEGORY_UNRESOLVED.to_string(),
                            (*referenced).to_string(),
                            unresolved_count,
                        )
                    }
                    Err(_) => (
                        CATEGORY_UNPARSEABLE.to_string(),
                        NO_REFERENCED_TABLE.to_string(),
                        0,
                    ),
                };
            *total += 1;
            if dangling.len() < DANGLING_REPORT_CAP {
                dangling.push(DanglingRef {
                    table: table.to_string(),
                    column: (*column).to_string(),
                    referenced_table,
                    category,
                    finding_id: finding_id.clone(),
                    position,
                    unresolved_count,
                });
            }
        }
    }
    Ok(())
}

/// Load the id set of one of the four frozen reference targets. The table
/// name comes only from the frozen column constants, never user input.
fn load_id_set(conn: &Connection, table: &str) -> Result<HashSet<String>, PicoError> {
    let mut stmt = conn
        .prepare(&format!("SELECT id FROM {table}"))
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(db_err)?;
    rows.collect::<Result<HashSet<_>, _>>().map_err(db_err)
}

/// Totals across every pruned unit of one prune run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct PruneTotals(pub UnitCounts);

/// Deterministic prune report (SPRINT-030.md §5.4). Rendering is a later
/// CLI task; this shape is the application-layer contract.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PruneReport {
    pub keep: usize,
    /// Deleted units in deletion order (COMPLETE oldest-first, then
    /// incomplete attempts oldest-first).
    pub pruned: Vec<PrunedUnitReport>,
    pub totals: PruneTotals,
    /// Retention state after the prune: the kept COMPLETE scans plus every
    /// kept incomplete attempt.
    pub retained: RetentionCounts,
    pub pre_health_ok: bool,
    pub post_health_ok: bool,
    /// True exactly when the workspace was below the window and nothing was
    /// deleted (a no-op is a success, never an error).
    pub nothing_pruned: bool,
}

/// `pico prune` application service (SPRINT-030.md §5.4, corrected by
/// SPRINT-031.md §5.1). CLI wiring and rendering are later tasks.
pub struct PruneService;

impl PruneService {
    /// Apply the retention policy inside ONE immediate write transaction
    /// (SPRINT-031.md §5.1): validate the window, open the existing state
    /// without migrating (an unsupported schema fails closed), then inside a
    /// single `BEGIN IMMEDIATE` snapshot — load the scans, refuse while any
    /// scan is RUNNING, plan the retention window, gate on a pre-deletion
    /// health check, delete whole scan units beyond the window in the frozen
    /// order, and re-verify database health BEFORE committing. Any failure
    /// rolls back and changes nothing. Unit counts cover exactly the seven
    /// directly deleted tables; cascade-deleted link rows and the `scans`
    /// row are not counted or claimed. The report is built entirely from the
    /// transaction's snapshot.
    pub fn run(workspace: &Path, keep: Option<usize>) -> Result<PruneReport, PicoError> {
        // 1. Validate the window before ANY database work.
        let window = RetentionWindow::resolve(keep)?;

        // 2. Open the existing state with the scan-command pattern. Prune
        //    never migrates: an unsupported schema fails closed below.
        let db = Database::open_existing(&workspace.join(".pico").join("pico.db"))?;
        let conn = db.connection();

        // 3. Fail closed on an unsupported schema, without migrating (the
        //    remedy stays "run `pico init` to upgrade").
        require_schema_version(conn)?;

        // 4. One immediate write transaction covers the entire decision and
        //    mutation: BEGIN IMMEDIATE excludes concurrent writers for the
        //    whole operation, so the RUNNING refusal, the plan, the health
        //    gates, and the deletion all see one snapshot and no scan can
        //    start in between. (`Transaction::new_unchecked` is rusqlite's
        //    `&Connection` constructor for exactly the transaction
        //    `transaction_with_behavior` builds; the database handle only
        //    yields a shared connection, and no transaction is open yet.)
        let tx =
            Transaction::new_unchecked(conn, TransactionBehavior::Immediate).map_err(db_err)?;

        // 5a. Load all scans inside the transaction snapshot.
        let scans = ScanRepo::new(&tx).list()?;

        // 5b. Fail closed while any scan is RUNNING: a live scan may still
        //     write, so prune refuses instead of racing it. Nothing deleted,
        //     and the refusal happens before any health check.
        if let Some(running) = scans
            .iter()
            .filter(|scan| scan.status == ScanStatus::Running)
            .max_by(|a, b| {
                a.started_at
                    .cmp(&b.started_at)
                    .then_with(|| a.id.cmp(&b.id))
            })
        {
            let id = running.id.clone();
            let _ = tx.rollback();
            return Err(PicoError::usage(format!(
                "cannot prune while scan {id} is RUNNING"
            )));
        }

        // 5c. Plan the retention window over the snapshot.
        let plan = plan_retention(window, &scans);

        // 5d. Pre-health gate: any failing check aborts before any deletion.
        let pre_health = check_health(&tx, window)?;
        if !pre_health.ok {
            let _ = tx.rollback();
            return Err(PicoError::database(
                "refusing to prune: database health check failed",
            ));
        }

        // 5e. Below-window workspace: a no-op is a success, never an error.
        //     The transaction performed only reads, so it rolls back.
        if plan.prune_complete.is_empty() && plan.prune_incomplete.is_empty() {
            let _ = tx.rollback();
            return Ok(PruneReport {
                keep: window.keep,
                pruned: Vec::new(),
                totals: PruneTotals::default(),
                retained: retained_counts(&scans, &plan),
                pre_health_ok: true,
                post_health_ok: true,
                nothing_pruned: true,
            });
        }

        // 5f. Delete the planned units in the frozen order, all-or-nothing.
        let by_id: HashMap<&str, &Scan> =
            scans.iter().map(|scan| (scan.id.as_str(), scan)).collect();
        let prune_order: Vec<Scan> = plan
            .prune_complete
            .iter()
            .chain(&plan.prune_incomplete)
            .map(|id| {
                by_id
                    .get(id.as_str())
                    .copied()
                    .expect("planned prune id must exist in loaded scans")
                    .clone()
            })
            .collect();

        let pruned = match delete_scan_units(&tx, &prune_order) {
            Ok(reports) => reports,
            Err(error) => {
                let _ = tx.rollback();
                return Err(error);
            }
        };

        // 5g. THE FIX (SPRINT-031 §1 P1): validate health on the
        //     transaction's post-deletion state BEFORE committing; a failing
        //     gate rolls back and deletes nothing.
        let post_health = check_health(&tx, window)?;
        if !post_health.ok {
            let _ = tx.rollback();
            return Err(PicoError::database(
                "database health check failed after prune",
            ));
        }

        tx.commit().map_err(db_err)?;

        // 6. Report, built from the same snapshot the transaction read.
        let mut totals = UnitCounts::default();
        for report in &pruned {
            totals.observations += report.counts.observations;
            totals.evidence += report.counts.evidence;
            totals.findings += report.counts.findings;
            totals.attack_paths += report.counts.attack_paths;
            totals.scan_analyses += report.counts.scan_analyses;
            totals.scan_diagnostics += report.counts.scan_diagnostics;
            totals.relationship_evidence += report.counts.relationship_evidence;
        }
        Ok(PruneReport {
            keep: window.keep,
            pruned,
            totals: PruneTotals(totals),
            retained: retained_counts(&scans, &plan),
            pre_health_ok: true,
            post_health_ok: true,
            nothing_pruned: false,
        })
    }
}

/// Retention state after a prune: the kept COMPLETE scans plus every kept
/// incomplete attempt (RUNNING attempts always stay).
fn retained_counts(scans: &[Scan], plan: &RetentionPlan) -> RetentionCounts {
    let pruned: HashSet<&str> = plan
        .prune_complete
        .iter()
        .chain(&plan.prune_incomplete)
        .map(String::as_str)
        .collect();
    let mut counts = RetentionCounts {
        complete: plan.keep_ids.len() as u64,
        ..RetentionCounts::default()
    };
    for scan in scans {
        if pruned.contains(scan.id.as_str()) {
            continue;
        }
        match scan.status {
            ScanStatus::Partial => counts.partial += 1,
            ScanStatus::Failed => counts.failed += 1,
            ScanStatus::Running => counts.running += 1,
            ScanStatus::Complete => {}
        }
    }
    counts
}

/// `pico doctor` application service: read-only health report
/// (SPRINT-030.md §5.4). Never mutates state; CLI rendering is a later task.
pub struct DoctorService;

impl DoctorService {
    /// Open the persisted state strictly read-only, require the supported
    /// schema version, and run the shared health check over the frozen
    /// default window inside a snapshot transaction.
    pub fn run(workspace: &Path) -> Result<HealthReport, PicoError> {
        let db = Database::open_read_only(&workspace.join(".pico").join("pico.db"))?;
        require_schema_version(db.connection())?;
        let tx = db
            .connection()
            .unchecked_transaction()
            .map_err(|e| PicoError::database(e.to_string()))?;
        let report = check_health(
            &tx,
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
        );
        match report {
            Ok(report) => {
                tx.commit()
                    .map_err(|e| PicoError::database(e.to_string()))?;
                Ok(report)
            }
            Err(error) => {
                let _ = tx.rollback();
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Evidence, EvidenceClass, Observation, Relationship, RelationshipState, Resource,
        ScanTrigger, Sensitivity,
    };
    use crate::persistence::{
        AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo,
        EvidenceRepo, FindingEvidenceRecord, FindingPathRecord, FindingReasonRecord, FindingRecord,
        FindingRemediationRecord, FindingRepo, ObservationRepo, RelationshipRepo, ResourceRepo,
        ScanAnalysisRecord, ScanAnalysisRepo, ScanDiagnosticsRepo,
    };
    use crate::shared::PICO_VERSION;
    use chrono::{DateTime, TimeZone, Utc};

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

    // --- Retention window validation ---

    #[test]
    fn resolve_rejects_keep_below_floor_with_frozen_message() {
        for keep in [Some(0), Some(1)] {
            let error = RetentionWindow::resolve(keep).unwrap_err();
            assert!(
                matches!(error, PicoError::Usage(ref msg) if msg == "--keep must be an integer of at least 2"),
                "expected the frozen usage error, got {error:?}"
            );
        }
    }

    #[test]
    fn resolve_defaults_and_accepts_floor_and_above() {
        assert_eq!(
            RetentionWindow::resolve(None).unwrap(),
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT
            }
        );
        assert_eq!(
            RetentionWindow::resolve(Some(2)).unwrap(),
            RetentionWindow { keep: 2 }
        );
        assert_eq!(
            RetentionWindow::resolve(Some(11)).unwrap(),
            RetentionWindow { keep: 11 }
        );
    }

    // --- Retention policy (pure) ---

    #[test]
    fn keep_ten_of_twelve_prunes_exactly_the_two_oldest_complete() {
        let scans: Vec<Scan> = (1..=12)
            .map(|i| {
                scan_with(
                    &format!("scan_{i:02}"),
                    ScanStatus::Complete,
                    ts(i),
                    Some(ts(i)),
                )
            })
            .collect();
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        assert_eq!(
            plan.keep_ids,
            (3..=12).map(|i| format!("scan_{i:02}")).collect::<Vec<_>>()
        );
        assert_eq!(
            plan.prune_complete,
            ["scan_01", "scan_02"].map(String::from).to_vec()
        );
        assert!(plan.prune_incomplete.is_empty());
    }

    #[test]
    fn completed_at_ties_break_by_started_at_then_id() {
        // All twelve COMPLETE scans share one completed_at; the list_complete
        // ordering must fall through to started_at, then id.
        let scans: Vec<Scan> = (1..=12)
            .map(|i| {
                scan_with(
                    &format!("scan_{i:02}"),
                    ScanStatus::Complete,
                    ts(i),
                    Some(ts(20)),
                )
            })
            .collect();
        let plan = plan_retention(RetentionWindow { keep: 10 }, &scans);
        assert_eq!(
            plan.keep_ids,
            (3..=12).map(|i| format!("scan_{i:02}")).collect::<Vec<_>>()
        );
        assert_eq!(
            plan.prune_complete,
            ["scan_01", "scan_02"].map(String::from).to_vec()
        );
    }

    #[test]
    fn identical_timestamps_break_by_id_descending() {
        let scans = vec![
            scan_with("scan_tie_a", ScanStatus::Complete, ts(1), Some(ts(1))),
            scan_with("scan_tie_b", ScanStatus::Complete, ts(1), Some(ts(1))),
        ];
        let plan = plan_retention(RetentionWindow { keep: 1 }, &scans);
        assert_eq!(plan.keep_ids, ["scan_tie_b"].map(String::from).to_vec());
        assert_eq!(
            plan.prune_complete,
            ["scan_tie_a"].map(String::from).to_vec()
        );
    }

    #[test]
    fn keep_floor_two_prunes_ten_of_twelve() {
        let scans: Vec<Scan> = (1..=12)
            .map(|i| {
                scan_with(
                    &format!("scan_{i:02}"),
                    ScanStatus::Complete,
                    ts(i),
                    Some(ts(i)),
                )
            })
            .collect();
        let plan = plan_retention(RetentionWindow { keep: 2 }, &scans);
        assert_eq!(
            plan.keep_ids,
            ["scan_11", "scan_12"].map(String::from).to_vec()
        );
        assert_eq!(
            plan.prune_complete,
            (1..=10).map(|i| format!("scan_{i:02}")).collect::<Vec<_>>()
        );
    }

    #[test]
    fn complete_scans_below_window_prune_nothing() {
        let scans: Vec<Scan> = (1..=8)
            .map(|i| {
                scan_with(
                    &format!("scan_{i:02}"),
                    ScanStatus::Complete,
                    ts(i),
                    Some(ts(i)),
                )
            })
            .collect();
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        assert_eq!(plan.keep_ids.len(), 8);
        assert!(plan.prune_complete.is_empty());
        assert!(plan.prune_incomplete.is_empty());
    }

    #[test]
    fn stale_incomplete_attempts_prune_oldest_first() {
        let scans = vec![
            scan_with("scan_partial_1", ScanStatus::Partial, ts(1), Some(ts(1))),
            scan_with("scan_partial_2", ScanStatus::Partial, ts(2), Some(ts(2))),
            scan_with("scan_failed_1", ScanStatus::Failed, ts(3), Some(ts(3))),
            scan_with("scan_complete", ScanStatus::Complete, ts(5), Some(ts(5))),
        ];
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        assert_eq!(plan.keep_ids, ["scan_complete"].map(String::from).to_vec());
        assert!(plan.prune_complete.is_empty());
        assert_eq!(
            plan.prune_incomplete,
            ["scan_partial_1", "scan_partial_2", "scan_failed_1"]
                .map(String::from)
                .to_vec()
        );
    }

    #[test]
    fn incomplete_newer_than_newest_complete_is_kept() {
        let scans = vec![
            scan_with("scan_complete", ScanStatus::Complete, ts(5), Some(ts(5))),
            scan_with("scan_partial_new", ScanStatus::Partial, ts(7), Some(ts(7))),
        ];
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        assert!(plan.prune_complete.is_empty());
        assert!(plan.prune_incomplete.is_empty());
        assert_eq!(plan.keep_ids, ["scan_complete"].map(String::from).to_vec());
    }

    #[test]
    fn multiple_newer_incomplete_attempts_are_all_kept() {
        let scans = vec![
            scan_with("scan_complete", ScanStatus::Complete, ts(5), Some(ts(5))),
            scan_with("scan_partial_a", ScanStatus::Partial, ts(6), Some(ts(6))),
            scan_with("scan_failed_b", ScanStatus::Failed, ts(7), Some(ts(7))),
        ];
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        assert!(plan.prune_incomplete.is_empty());
        assert!(plan.prune_complete.is_empty());
    }

    #[test]
    fn incomplete_at_the_newest_complete_tuple_is_kept() {
        // Strictly older is required: an attempt whose (started_at, id)
        // tuple equals or exceeds the newest COMPLETE's tuple stays. A
        // same-timestamp attempt with a lexicographically greater id is
        // newer and kept; a smaller id is strictly older and pruned.
        let scans = vec![
            scan_with("scan_a", ScanStatus::Partial, ts(5), Some(ts(5))),
            scan_with("scan_complete", ScanStatus::Complete, ts(5), Some(ts(5))),
            scan_with("scan_z", ScanStatus::Partial, ts(5), Some(ts(5))),
        ];
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        assert_eq!(plan.prune_incomplete, ["scan_a"].map(String::from).to_vec());
    }

    #[test]
    fn no_complete_scan_prunes_nothing() {
        let scans = vec![
            scan_with("scan_partial", ScanStatus::Partial, ts(1), Some(ts(1))),
            scan_with("scan_failed", ScanStatus::Failed, ts(2), Some(ts(2))),
        ];
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        assert!(plan.keep_ids.is_empty());
        assert!(plan.prune_complete.is_empty());
        assert!(plan.prune_incomplete.is_empty());
    }

    #[test]
    fn running_scans_never_appear_in_any_set() {
        let scans = vec![
            scan_with("scan_running_old", ScanStatus::Running, ts(0), None),
            scan_with("scan_complete", ScanStatus::Complete, ts(5), Some(ts(5))),
            scan_with("scan_partial_old", ScanStatus::Partial, ts(1), Some(ts(1))),
            scan_with("scan_running_new", ScanStatus::Running, ts(20), None),
        ];
        let plan = plan_retention(
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
            &scans,
        );
        for list in [&plan.keep_ids, &plan.prune_complete, &plan.prune_incomplete] {
            assert!(!list.iter().any(|id| id.starts_with("scan_running")));
        }
        assert_eq!(
            plan.prune_incomplete,
            ["scan_partial_old"].map(String::from).to_vec()
        );
    }

    // --- Deletion engine and health check (crate-internal surface) ---

    fn test_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
        db.migrate().unwrap();
        (dir, db)
    }

    const UNIT_TABLES: [&str; 14] = [
        "scans",
        "observations",
        "evidence",
        "findings",
        "finding_paths",
        "finding_evidence",
        "finding_reasons",
        "finding_remediations",
        "attack_paths",
        "attack_path_edges",
        "attack_path_evidence",
        "scan_analyses",
        "scan_diagnostics",
        "relationship_evidence",
    ];

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

    fn count_rows(conn: &Connection, table: &str) -> u64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap() as u64
    }

    fn table_counts(conn: &Connection) -> Vec<u64> {
        ALL_TABLES
            .iter()
            .map(|table| count_rows(conn, table))
            .collect()
    }

    /// Seed global identity surfaces shared by every unit. Re-upserts keep
    /// the original resource ids (the canonical-key upsert never rewrites
    /// ids), so global surfaces stay stable across units.
    fn seed_global_surfaces(conn: &Connection, observed_at: DateTime<Utc>) {
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
                    first_observed_at: observed_at,
                    last_observed_at: observed_at,
                })
                .unwrap();
        }
    }

    /// Seed one coherent whole scan unit with explicit timestamps. The scan
    /// lifecycle row is inserted as RUNNING first (the analysis summary
    /// refuses upserts after COMPLETE, S029) and finalized afterwards.
    /// Returns `(scan, evidence_id, finding_id)`.
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

        seed_global_surfaces(conn, started_at);
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

    #[test]
    fn deletion_removes_whole_unit_and_keeps_global_surfaces() {
        let (_dir, db) = test_db();
        let conn = db.connection();
        let (scan, _evidence_id, _finding_id) =
            seed_unit(&db, "scan_one", ts(1), Some(ts(1)), ScanStatus::Complete);
        let global_resources = count_rows(conn, "resources");
        let global_relationships = count_rows(conn, "relationships");

        let reports = delete_scan_units(conn, &[scan]).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].scan_id, "scan_one");
        assert_eq!(reports[0].status, "COMPLETE");
        assert_eq!(
            reports[0].counts,
            UnitCounts {
                observations: 1,
                evidence: 1,
                findings: 1,
                attack_paths: 1,
                scan_analyses: 1,
                scan_diagnostics: 1,
                relationship_evidence: 1,
            }
        );

        for table in UNIT_TABLES {
            assert_eq!(count_rows(conn, table), 0, "{table} must be empty");
        }
        assert_eq!(count_rows(conn, "resources"), global_resources);
        assert_eq!(count_rows(conn, "relationships"), global_relationships);
    }

    #[test]
    fn deletion_fails_closed_and_rolls_back_on_cross_scan_evidence_link() {
        let (_dir, db) = test_db();
        let conn = db.connection();
        let (pruned_scan, _pruned_evidence, _pruned_finding) =
            seed_unit(&db, "scan_old", ts(1), Some(ts(1)), ScanStatus::Complete);
        let (_retained_scan, _retained_evidence, retained_finding) =
            seed_unit(&db, "scan_new", ts(9), Some(ts(9)), ScanStatus::Complete);

        // Fixture-only trigger bypass (same approach as the S028 legacy
        // fixtures): a cross-scan finding_evidence row linking the retained
        // finding to the pruned unit's evidence (position 1: the retained
        // finding's own unit link occupies position 0).
        conn.execute("DROP TRIGGER finding_evidence_same_scan_insert", [])
            .unwrap();
        conn.execute(
            "INSERT INTO finding_evidence (finding_id, evidence_id, position, support_role)
             VALUES (?1, 'ev_scan_old', 1, 'EDGE')",
            [&retained_finding],
        )
        .unwrap();

        let before = table_counts(conn);
        let tx = conn.unchecked_transaction().unwrap();
        let error = delete_scan_units(&tx, &[pruned_scan]).unwrap_err();
        assert!(
            matches!(error, PicoError::Database(_)),
            "the engine must fail closed at the evidence delete, got {error:?}"
        );
        tx.rollback().unwrap();
        assert_eq!(
            table_counts(conn),
            before,
            "rollback must restore every table count exactly"
        );
    }

    #[test]
    fn health_reports_ok_on_coherent_units() {
        let (_dir, db) = test_db();
        seed_unit(
            &db,
            "scan_keep_old",
            ts(5),
            Some(ts(5)),
            ScanStatus::Complete,
        );
        seed_unit(
            &db,
            "scan_keep_new",
            ts(9),
            Some(ts(9)),
            ScanStatus::Complete,
        );
        seed_unit(
            &db,
            "scan_partial_new",
            ts(10),
            Some(ts(10)),
            ScanStatus::Partial,
        );

        let report = check_health(
            db.connection(),
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
        )
        .unwrap();
        assert!(report.ok, "expected a healthy report, got {report:?}");
        assert!(report.schema_ok);
        assert!(report.integrity_ok);
        assert!(report.foreign_keys_ok);
        assert_eq!(report.schema_version, SUPPORTED_SCHEMA_VERSION);
        assert!(report.dangling_json_refs.is_empty());
        assert_eq!(report.dangling_more, 0);
        assert_eq!(report.orphan_scan_rows, 0);
        assert_eq!(report.summary_rows, 0);
        assert_eq!(
            report.counts,
            RetentionCounts {
                complete: 2,
                partial: 1,
                failed: 0,
                running: 0,
            }
        );
        assert_eq!(report.window_keep, KEEP_COMPLETE_DEFAULT);
        assert_eq!(
            report.oldest_retained_complete.as_deref(),
            Some("scan_keep_old")
        );
        assert_eq!(report.newest_complete.as_deref(), Some("scan_keep_new"));
    }

    #[test]
    fn health_reports_dangling_reason_evidence_id() {
        let (_dir, db) = test_db();
        seed_unit(&db, "scan_one", ts(1), Some(ts(1)), ScanStatus::Complete);
        FindingRepo::new(db.connection())
            .insert_reason(&FindingReasonRecord {
                finding_id: "finding_scan_one".to_string(),
                position: 1,
                reason_code: "EXTRA".to_string(),
                resource_ids: vec![],
                relationship_ids: vec![],
                attack_path_ids: vec![],
                evidence_ids: vec!["evidence_nonexistent".to_string()],
            })
            .unwrap();

        let report = check_health(
            db.connection(),
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
        )
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.dangling_more, 0);
        assert_eq!(report.dangling_total, 1);
        assert_eq!(
            report.dangling_json_refs,
            vec![DanglingRef {
                table: "finding_reasons".to_string(),
                column: "evidence_ids".to_string(),
                referenced_table: "evidence".to_string(),
                category: CATEGORY_UNRESOLVED.to_string(),
                finding_id: "finding_scan_one".to_string(),
                position: 1,
                unresolved_count: 1,
            }]
        );
    }

    #[test]
    fn health_reports_unparseable_json_without_contents() {
        let (_dir, db) = test_db();
        seed_unit(&db, "scan_one", ts(1), Some(ts(1)), ScanStatus::Complete);
        db.connection()
            .execute(
                "INSERT INTO finding_reasons
                 (finding_id, position, reason_code, resource_ids, relationship_ids,
                  attack_path_ids, evidence_ids)
                 VALUES ('finding_scan_one', 2, 'BROKEN', '[]', '[]', '[]', 'not json')",
                [],
            )
            .unwrap();

        let report = check_health(
            db.connection(),
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
        )
        .unwrap();
        assert!(!report.ok);
        // The unparseable cell reports one bounded location with the
        // `unparseable` reason code — never the raw stored text.
        assert_eq!(
            report.dangling_json_refs,
            vec![DanglingRef {
                table: "finding_reasons".to_string(),
                column: "evidence_ids".to_string(),
                referenced_table: NO_REFERENCED_TABLE.to_string(),
                category: CATEGORY_UNPARSEABLE.to_string(),
                finding_id: "finding_scan_one".to_string(),
                position: 2,
                unresolved_count: 0,
            }]
        );
        assert_eq!(report.dangling_total, 1);
        assert_eq!(report.dangling_more, 0);
    }

    #[test]
    fn health_caps_dangling_refs_and_counts_remainder() {
        let (_dir, db) = test_db();
        seed_unit(&db, "scan_one", ts(1), Some(ts(1)), ScanStatus::Complete);
        let findings = FindingRepo::new(db.connection());
        for position in 1..=25u32 {
            findings
                .insert_reason(&FindingReasonRecord {
                    finding_id: "finding_scan_one".to_string(),
                    position,
                    reason_code: format!("DANGLING_{position:02}"),
                    resource_ids: vec![],
                    relationship_ids: vec![],
                    attack_path_ids: vec![],
                    evidence_ids: vec![format!("evidence_missing_{position:02}")],
                })
                .unwrap();
        }

        let report = check_health(
            db.connection(),
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
        )
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.dangling_json_refs.len(), DANGLING_REPORT_CAP);
        assert_eq!(report.dangling_total, 25);
        assert_eq!(report.dangling_more, 5);
        assert_eq!(
            report.dangling_json_refs[0],
            DanglingRef {
                table: "finding_reasons".to_string(),
                column: "evidence_ids".to_string(),
                referenced_table: "evidence".to_string(),
                category: CATEGORY_UNRESOLVED.to_string(),
                finding_id: "finding_scan_one".to_string(),
                position: 1,
                unresolved_count: 1,
            }
        );
        assert_eq!(report.dangling_json_refs[19].position, 20);
    }

    #[test]
    fn health_counts_orphan_scan_rows_and_fk_violations() {
        let (_dir, db) = test_db();
        seed_unit(&db, "scan_one", ts(1), Some(ts(1)), ScanStatus::Complete);
        let conn = db.connection();

        // Fixture: an orphan observation seeded with foreign keys disabled,
        // then re-enabled (corruption-fixture pattern from S028).
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute(
            "INSERT INTO observations
             (id, scan_id, subject_type, subject_id, observation_type, observed_at,
              source, metadata)
             VALUES ('obs_orphan', 'scan_missing', 'resource', 'res_x', 'present',
                     '2026-08-01T12:02:00+00:00', 'fixture', NULL)",
            [],
        )
        .unwrap();
        conn.pragma_update(None, "foreign_keys", true).unwrap();

        let report = check_health(
            conn,
            RetentionWindow {
                keep: KEEP_COMPLETE_DEFAULT,
            },
        )
        .unwrap();
        assert_eq!(report.orphan_scan_rows, 1);
        assert!(!report.foreign_keys_ok);
        assert!(!report.ok);
    }
}
