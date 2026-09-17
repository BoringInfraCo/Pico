//! Read-only, content-free ingestion of the OpenCode session store
//! (SPRINT-040 §1.2–§1.5).
//!
//! This module answers one narrow question for an opt-in `pico scan --runtime`:
//! *which tool invocations did the OpenCode agent attempt in this workspace
//! within the retained window?* It is deliberately the smallest reader that can
//! answer that honestly:
//!
//! - **Safe-read (§1.2):** the store is opened read-only and immutable
//!   (`file:<abs>?mode=ro&immutable=1` with `SQLITE_OPEN_READ_ONLY |
//!   SQLITE_OPEN_URI | SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_NOFOLLOW`, plus
//!   `PRAGMA query_only=ON` and a short busy timeout). No `-wal`/`-shm`, temp
//!   file, copy, or write is ever created. `immutable=1` ignores the WAL, so the
//!   result is a possibly-stale snapshot — disclosed by the caller, never
//!   presented as real-time truth.
//! - **Content-free (§1.3):** only [`SELECT_EXPRESSIONS`] are selected, all of
//!   them `json_extract` on the four frozen paths or safe identity columns. Raw
//!   `part.data`, `$.state.input|output|text|metadata`, `message.data`,
//!   `session_input.prompt`, `session.title`, credential/account/share tables,
//!   and every other content or secret column are never named by the reader.
//! - **Workspace-scoped (§1.4):** a row is kept only when `session.directory`
//!   canonically equals the scanned workspace. Rows that resolve to another
//!   workspace, or whose directory cannot be resolved, are excluded and counted
//!   by [`RuntimeIngestSummary`] — never attributed to this workspace.
//! - **Fail-closed schema gate (§1.5):** the migration version must fall inside
//!   the frozen supported range and all required table/column presence must be
//!   proven. Unknown, missing, out-of-range, or missing-required-column states
//!   return [`RuntimeReadOutcome::Unsupported`] *without reading any row data*.
//! - **Bounded (§1.2/§1.2):** keyset pagination on `part.id` (no `OFFSET`, no
//!   bare `COUNT(*)` on the large tables), a `max_rows` cap, a required indexed
//!   `time_created` window, and a wall-clock budget enforced by an
//!   interrupt-handle watchdog. The store connection's `get_interrupt_handle()`
//!   is always available (unlike `progress_handler`, which needs a feature flag);
//!   one watchdog thread polls a short bounded interval to the deadline, flips
//!   the shared truncation flag, and calls `interrupt()` so a statement already
//!   in flight still aborts. The polling interval bounds interrupt granularity;
//!   a page-boundary deadline check keeps truncation deterministic.
//!
//! Nothing here constructs a finding, promotes an edge, classifies freshness, or
//! invents a timestamp. It returns observed invocations and nothing more; the
//! application and analysis layers own every security conclusion.

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rusqlite::types::Value;
use rusqlite::{params, Connection, OpenFlags};

use crate::shared::PicoError;

/// Lowest migration version whose schema this reader understands. Frozen with
/// [`SUPPORTED_MIGRATION_MAX`] (SPRINT-040 §1.5); bump only with a new reader.
pub const SUPPORTED_MIGRATION_MIN: u64 = 38;
/// Highest migration version whose schema this reader understands.
pub const SUPPORTED_MIGRATION_MAX: u64 = 38;

/// Default retained window: seven days.
pub const DEFAULT_WINDOW_SECS: i64 = 7 * 24 * 60 * 60;
/// Default maximum number of `part` rows scanned.
pub const DEFAULT_MAX_ROWS: usize = 10_000;
/// Default wall-clock budget for the whole read, in milliseconds.
pub const DEFAULT_WALL_CLOCK_MS: u64 = 3_000;

/// Short busy timeout; the store is immutable and read-only, so waits are rare.
const BUSY_TIMEOUT_MS: u64 = 250;
/// Bounded retry for `SQLITE_BUSY`/`SQLITE_CORRUPT` races (support note §6).
const MAX_OPEN_ATTEMPTS: u32 = 3;
const RETRY_BACKOFF: Duration = Duration::from_millis(10);
/// Rows fetched per keyset page.
const PAGE_SIZE: usize = 512;
/// How often the budget watchdog rechecks the deadline. Bounds how promptly an
/// in-flight statement is interrupted without busy-waiting.
const WATCHDOG_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// The complete content-free selection allowlist. The reader builds its `SELECT`
/// from exactly this list, so a forbidden column cannot be introduced casually;
/// [`tests::select_is_built_only_from_the_content_free_allowlist`] enforces it.
const SELECT_EXPRESSIONS: [&str; 7] = [
    "part.id",
    "json_extract(part.data, '$.tool')",
    "json_extract(part.data, '$.callID')",
    "json_extract(part.data, '$.state.status')",
    "part.time_created",
    "part.session_id",
    "session.directory",
];

/// Columns the reader cannot operate without. Absence fails closed rather than
/// triggering a full scan of an unknown schema (SPRINT-040 §1.5).
const REQUIRED_PART_COLUMNS: [&str; 4] = ["id", "data", "time_created", "session_id"];
const REQUIRED_SESSION_COLUMNS: [&str; 2] = ["id", "directory"];

const REASON_STORE_ABSENT: &str = "store path does not exist";
const REASON_STORE_SYMLINK: &str = "store path is a symlink";
const REASON_STORE_NOT_FILE: &str = "store path is not a regular file";
const REASON_STORE_BUSY: &str = "store is locked by another writer";
const REASON_STORE_CORRUPT: &str = "store is corrupt or being rewritten";
const REASON_STORE_NOT_DATABASE: &str = "store is not a SQLite database";
const REASON_STORE_UNREADABLE: &str = "store cannot be opened read-only";
const REASON_STORE_IO: &str = "store read failed";
const REASON_INTERRUPTED: &str = "store read was interrupted";
const REASON_WORKSPACE_UNRESOLVED: &str = "workspace root cannot be resolved";

/// Inputs for one opt-in runtime read. The store is optional so a default scan
/// can report [`RuntimeReadOutcome::NotAttempted`] without touching the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeIngestConfig {
    pub store: Option<PathBuf>,
    pub workspace: PathBuf,
    pub window_secs: i64,
    pub max_rows: usize,
    pub wall_clock_ms: u64,
}

impl Default for RuntimeIngestConfig {
    fn default() -> Self {
        Self {
            store: None,
            workspace: PathBuf::new(),
            window_secs: DEFAULT_WINDOW_SECS,
            max_rows: DEFAULT_MAX_ROWS,
            wall_clock_ms: DEFAULT_WALL_CLOCK_MS,
        }
    }
}

/// Lifecycle status of an observed tool call, normalized from
/// `part.data.$.state.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolStatus {
    Pending,
    Running,
    Completed,
    Error,
}

impl ToolStatus {
    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// One observed tool invocation. Contains only identity, status, scope, and the
/// time the fact was true — never arguments, output, prompts, or credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInvocation {
    pub tool: String,
    pub status: ToolStatus,
    pub call_id: String,
    pub session_id: String,
    pub observed_at: DateTime<Utc>,
}

/// Result of one read. `Unsupported`/`Unavailable` never carry row data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeReadOutcome {
    Ingested {
        invocations: Vec<ToolInvocation>,
        truncated: bool,
    },
    NotAttempted,
    Unsupported {
        migrations: Option<u64>,
    },
    Unavailable {
        reason: &'static str,
    },
}

/// Deterministic read accounting, including the workspace exclusions required by
/// SPRINT-040 §1.4. This is a companion to the frozen [`RuntimeReadOutcome`],
/// which cannot carry a summary without changing its signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeIngestSummary {
    /// `part` rows returned by the bounded scan (all satisfied the tool filter).
    pub rows_scanned: u64,
    /// Invocations returned after workspace scoping and classification.
    pub invocations_kept: u64,
    /// Rows whose `session.directory` resolved to a different workspace.
    pub excluded_other_workspace: u64,
    /// Rows whose `session.directory` could not be resolved or matched.
    pub excluded_unresolved_workspace: u64,
    /// Rows with no usable tool name.
    pub excluded_missing_tool: u64,
    /// Rows with an unrecognized `$.state.status`.
    pub excluded_unknown_status: u64,
    /// Rows with a missing or unparseable `part.time_created`.
    pub excluded_missing_timestamp: u64,
    /// True when the row cap or the wall-clock budget stopped the scan early.
    pub truncated: bool,
}

/// Read the OpenCode store and return observed tool invocations for the scanned
/// workspace. Never mutates the store; expected failures are reported as
/// [`RuntimeReadOutcome::Unavailable`], not errors.
pub fn ingest(cfg: &RuntimeIngestConfig) -> Result<RuntimeReadOutcome, PicoError> {
    Ok(ingest_with_summary(cfg)?.0)
}

/// [`ingest`] plus the deterministic [`RuntimeIngestSummary`] needed to report
/// excluded counts. The frozen [`ingest`] signature is unchanged.
pub fn ingest_with_summary(
    cfg: &RuntimeIngestConfig,
) -> Result<(RuntimeReadOutcome, RuntimeIngestSummary), PicoError> {
    let mut summary = RuntimeIngestSummary::default();
    let Some(store) = cfg.store.as_deref() else {
        return Ok((RuntimeReadOutcome::NotAttempted, summary));
    };

    let conn = match open_store(store) {
        Ok(conn) => conn,
        Err(reason) => return Ok((RuntimeReadOutcome::Unavailable { reason }, summary)),
    };

    let migrations = match detect_migration_version(&conn) {
        Ok(MigrationVersion::Known(version)) => version,
        Ok(MigrationVersion::Unknown) => {
            return Ok((
                RuntimeReadOutcome::Unsupported { migrations: None },
                summary,
            ));
        }
        Err(reason) => return Ok((RuntimeReadOutcome::Unavailable { reason }, summary)),
    };

    if migrations < SUPPORTED_MIGRATION_MIN || migrations > SUPPORTED_MIGRATION_MAX {
        return Ok((
            RuntimeReadOutcome::Unsupported {
                migrations: Some(migrations),
            },
            summary,
        ));
    }

    match data_schema_ready(&conn) {
        Ok(true) => {}
        Ok(false) => {
            return Ok((
                RuntimeReadOutcome::Unsupported {
                    migrations: Some(migrations),
                },
                summary,
            ));
        }
        Err(reason) => return Ok((RuntimeReadOutcome::Unavailable { reason }, summary)),
    }

    let workspace = match path_identity(&cfg.workspace) {
        Some(identity) => identity,
        None => {
            return Ok((
                RuntimeReadOutcome::Unavailable {
                    reason: REASON_WORKSPACE_UNRESOLVED,
                },
                summary,
            ));
        }
    };

    let invocations = match scan_invocations(&conn, cfg, &workspace, &mut summary) {
        Ok(invocations) => invocations,
        Err(reason) => return Ok((RuntimeReadOutcome::Unavailable { reason }, summary)),
    };

    Ok((
        RuntimeReadOutcome::Ingested {
            invocations,
            truncated: summary.truncated,
        },
        summary,
    ))
}

/// Open the store read-only, immutable, and without following symlinks. Expected
/// failures (absent, busy, corrupt, not a database) map to a static reason so the
/// caller can report [`RuntimeReadOutcome::Unavailable`] without a panic.
fn open_store(store: &Path) -> Result<Connection, &'static str> {
    let metadata = std::fs::symlink_metadata(store).map_err(|_| REASON_STORE_ABSENT)?;
    if metadata.file_type().is_symlink() {
        return Err(REASON_STORE_SYMLINK);
    }
    if !metadata.is_file() {
        return Err(REASON_STORE_NOT_FILE);
    }
    let uri = read_only_uri(store).ok_or(REASON_STORE_UNREADABLE)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;

    let mut last = REASON_STORE_UNREADABLE;
    for attempt in 0..MAX_OPEN_ATTEMPTS {
        match probe_open(&uri, flags) {
            Ok(conn) => return Ok(conn),
            Err((reason, retryable)) => {
                last = reason;
                if !retryable || attempt + 1 >= MAX_OPEN_ATTEMPTS {
                    break;
                }
                std::thread::sleep(RETRY_BACKOFF);
            }
        }
    }
    Err(last)
}

/// One open attempt plus a schema probe. The probe forces SQLite to validate the
/// file header and schema, which surfaces `SQLITE_NOTADB`/`SQLITE_CORRUPT` that a
/// lazy open defers.
fn probe_open(uri: &str, flags: OpenFlags) -> Result<Connection, (&'static str, bool)> {
    let conn = Connection::open_with_flags(uri, flags).map_err(classify_sqlite_error)?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
        .map_err(classify_sqlite_error)?;
    conn.pragma_update(None, "query_only", true)
        .map_err(classify_sqlite_error)?;
    {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master LIMIT 1")
            .map_err(classify_sqlite_error)?;
        let mut rows = stmt.query([]).map_err(classify_sqlite_error)?;
        let _ = rows.next().map_err(classify_sqlite_error)?;
    }
    Ok(conn)
}

/// Build the immutable read-only URI, percent-encoding the characters that would
/// otherwise change URI parsing. The store path originates from Pico's own home
/// resolution, so non-UTF-8 paths are out of scope.
fn read_only_uri(path: &Path) -> Option<String> {
    // Resolve parent-directory symlinks (e.g. macOS `/var` -> `/private/var`)
    // so `SQLITE_OPEN_NOFOLLOW` only judges the store file itself, which
    // `open_store` has already proven is not a symlink.
    let absolute = std::fs::canonicalize(path)
        .or_else(|_| std::path::absolute(path))
        .ok()?;
    let text = absolute.to_string_lossy();
    let mut encoded = String::with_capacity(text.len() + 24);
    for character in text.chars() {
        match character {
            '%' => encoded.push_str("%25"),
            '?' => encoded.push_str("%3F"),
            '#' => encoded.push_str("%23"),
            ' ' => encoded.push_str("%20"),
            _ => encoded.push(character),
        }
    }
    Some(format!("file:{encoded}?mode=ro&immutable=1"))
}

/// Classify a SQLite failure into a static reason plus whether a bounded retry
/// may help (support note §6: treat a racing checkpoint as retryable corrupt).
fn classify_sqlite_error(err: rusqlite::Error) -> (&'static str, bool) {
    use rusqlite::ErrorCode;
    match err.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy) | Some(ErrorCode::DatabaseLocked) => {
            (REASON_STORE_BUSY, true)
        }
        Some(ErrorCode::DatabaseCorrupt) => (REASON_STORE_CORRUPT, true),
        Some(ErrorCode::SystemIoFailure) => (REASON_STORE_IO, true),
        Some(ErrorCode::NotADatabase) => (REASON_STORE_NOT_DATABASE, false),
        Some(ErrorCode::CannotOpen)
        | Some(ErrorCode::PermissionDenied)
        | Some(ErrorCode::ReadOnly) => (REASON_STORE_UNREADABLE, false),
        Some(ErrorCode::OperationInterrupted) => (REASON_INTERRUPTED, false),
        _ => (REASON_STORE_UNREADABLE, false),
    }
}

fn sqlite_reason(err: rusqlite::Error) -> &'static str {
    classify_sqlite_error(err).0
}

/// Resolve a path to a comparison identity: the canonical path when it exists,
/// otherwise a lexically normalized absolute path (SPRINT-040 §1.4).
fn path_identity(path: &Path) -> Option<PathBuf> {
    match std::fs::canonicalize(path) {
        Ok(canonical) => Some(canonical),
        Err(_) => normalize_lexically(path),
    }
}

/// Resolve `.`/`..` and trailing separators without touching the filesystem.
fn normalize_lexically(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Some(normalized)
}

/// The migration version observed in the store.
enum MigrationVersion {
    Known(u64),
    Unknown,
}

/// Detect the schema version by reading the `migration` table (falling back to
/// the legacy `__drizzle_migrations`). `Unknown` means the version could not be
/// established, which must fail closed.
fn detect_migration_version(conn: &Connection) -> Result<MigrationVersion, &'static str> {
    if table_exists(conn, "migration")? {
        if !column_exists(conn, "migration", "id")? {
            return Ok(MigrationVersion::Unknown);
        }
        let ids = text_column(conn, "SELECT id FROM migration")?;
        return Ok(MigrationVersion::Known(migration_version_from_ids(&ids)));
    }
    if table_exists(conn, "__drizzle_migrations")? {
        let count = row_count(conn, "__drizzle_migrations")?;
        return Ok(MigrationVersion::Known(count));
    }
    Ok(MigrationVersion::Unknown)
}

/// Interpret the `migration.id` values as a version. OpenCode's real ids are
/// timestamp strings, so the honest version is the number of applied migrations;
/// a store whose ids are uniformly numeric is read as its numeric maximum. Both
/// interpretations are deterministic for a given store.
fn migration_version_from_ids(ids: &[String]) -> u64 {
    if ids.is_empty() {
        return 0;
    }
    let numeric: Option<Vec<u64>> = ids.iter().map(|id| id.trim().parse::<u64>().ok()).collect();
    match numeric {
        Some(values) => values.into_iter().max().unwrap_or(0),
        None => ids.len() as u64,
    }
}

/// True when the tables and columns the reader needs are all present.
fn data_schema_ready(conn: &Connection) -> Result<bool, &'static str> {
    if !table_exists(conn, "part")? || !table_exists(conn, "session")? {
        return Ok(false);
    }
    for column in REQUIRED_PART_COLUMNS {
        if !column_exists(conn, "part", column)? {
            return Ok(false);
        }
    }
    for column in REQUIRED_SESSION_COLUMNS {
        if !column_exists(conn, "session", column)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool, &'static str> {
    let mut stmt = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1")
        .map_err(sqlite_reason)?;
    let mut rows = stmt.query([table]).map_err(sqlite_reason)?;
    Ok(rows.next().map_err(sqlite_reason)?.is_some())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool, &'static str> {
    let mut stmt = conn
        .prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2 LIMIT 1")
        .map_err(sqlite_reason)?;
    let mut rows = stmt.query(params![table, column]).map_err(sqlite_reason)?;
    Ok(rows.next().map_err(sqlite_reason)?.is_some())
}

fn text_column(conn: &Connection, sql: &str) -> Result<Vec<String>, &'static str> {
    let mut stmt = conn.prepare(sql).map_err(sqlite_reason)?;
    let mut rows = stmt.query([]).map_err(sqlite_reason)?;
    let mut values = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_reason)? {
        let value = row.get::<_, Value>(0).map_err(sqlite_reason)?;
        if let Some(text) = value_text(value) {
            values.push(text);
        }
    }
    Ok(values)
}

/// `COUNT(*)` is acceptable here only because this fallback table is tiny; the
/// large `part`/`session` tables are never counted.
fn row_count(conn: &Connection, table: &str) -> Result<u64, &'static str> {
    let sql = format!("SELECT COUNT(*) FROM \"{table}\"");
    let count: i64 = conn
        .query_row(&sql, [], |row| row.get(0))
        .map_err(sqlite_reason)?;
    Ok(count.max(0) as u64)
}

/// The only `SELECT` the reader issues, assembled from [`SELECT_EXPRESSIONS`].
/// The `json_valid` guard keeps a malformed row from aborting the whole scan.
fn select_sql() -> String {
    format!(
        "SELECT {columns} FROM part JOIN session ON session.id = part.session_id \
         WHERE (CASE WHEN json_valid(part.data) THEN json_extract(part.data, '$.type') END) = 'tool' \
         AND part.time_created >= ?1 AND part.id > ?2 ORDER BY part.id LIMIT ?3",
        columns = SELECT_EXPRESSIONS.join(", ")
    )
}

/// One raw scanned row before workspace scoping and classification.
struct RawRow {
    id: String,
    tool: Option<String>,
    call_id: Option<String>,
    status: Option<String>,
    created: Value,
    session_id: Option<String>,
    directory: Option<String>,
}

/// Bounded keyset scan over tool parts. Returned invocations are ordered by
/// `observed_at` then `call_id`; the `max_rows` cap and wall-clock budget stop
/// early and set `summary.truncated`.
fn scan_invocations(
    conn: &Connection,
    cfg: &RuntimeIngestConfig,
    workspace: &Path,
    summary: &mut RuntimeIngestSummary,
) -> Result<Vec<ToolInvocation>, &'static str> {
    if cfg.max_rows == 0 {
        return Ok(Vec::new());
    }

    let timed_out = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now().checked_add(Duration::from_millis(cfg.wall_clock_ms));
    let watchdog = {
        let interrupt = conn.get_interrupt_handle();
        let flag = Arc::clone(&timed_out);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let Some(deadline) = deadline else {
                return;
            };
            while !done.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    flag.store(true, Ordering::SeqCst);
                    interrupt.interrupt();
                    return;
                }
                std::thread::sleep(WATCHDOG_POLL_INTERVAL);
            }
        })
    };

    let interrupted = || timed_out.load(Ordering::SeqCst);
    let cutoff = time_window_cutoff_ms(cfg.window_secs);
    let cap_plus_one = cfg.max_rows.saturating_add(1);
    let sql = select_sql();

    let mut invocations = Vec::new();
    let mut cursor: Option<String> = None;
    let mut scanned: usize = 0;
    let mut failure: Option<&'static str> = None;

    'scan: loop {
        // Cooperative deadline check between pages; the watchdog separately
        // aborts any single statement that overruns the deadline on its own.
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            summary.truncated = true;
            break;
        }
        let remaining = cap_plus_one.saturating_sub(scanned);
        if remaining == 0 {
            break;
        }
        let page = remaining.min(PAGE_SIZE);
        let mut stmt = match conn.prepare_cached(&sql) {
            Ok(stmt) => stmt,
            Err(err) => {
                if interrupted() {
                    summary.truncated = true;
                    break 'scan;
                }
                failure = Some(sqlite_reason(err));
                break 'scan;
            }
        };
        let rows = match stmt.query_map(
            params![cutoff, cursor.as_deref().unwrap_or(""), page as i64],
            |row| {
                Ok(RawRow {
                    id: value_text(row.get::<_, Value>(0)?).unwrap_or_default(),
                    tool: value_text(row.get::<_, Value>(1)?),
                    call_id: value_text(row.get::<_, Value>(2)?),
                    status: value_text(row.get::<_, Value>(3)?),
                    created: row.get::<_, Value>(4)?,
                    session_id: value_text(row.get::<_, Value>(5)?),
                    directory: value_text(row.get::<_, Value>(6)?),
                })
            },
        ) {
            Ok(rows) => rows,
            Err(err) => {
                if interrupted() {
                    summary.truncated = true;
                    break 'scan;
                }
                failure = Some(sqlite_reason(err));
                break 'scan;
            }
        };

        let mut page_count = 0usize;
        for item in rows {
            let raw = match item {
                Ok(raw) => raw,
                Err(err) => {
                    if interrupted() {
                        summary.truncated = true;
                        break 'scan;
                    }
                    failure = Some(sqlite_reason(err));
                    break 'scan;
                }
            };
            page_count += 1;
            scanned += 1;
            summary.rows_scanned += 1;
            cursor = Some(raw.id.clone());
            if let Some(invocation) = classify_row(&raw, workspace, summary) {
                invocations.push(invocation);
            }
            if scanned >= cap_plus_one {
                summary.truncated = true;
                break 'scan;
            }
        }

        if page_count < page {
            break;
        }
    }

    done.store(true, Ordering::SeqCst);
    let _ = watchdog.join();

    if let Some(reason) = failure {
        return Err(reason);
    }
    if summary.truncated && invocations.len() > cfg.max_rows {
        invocations.truncate(cfg.max_rows);
    }
    summary.invocations_kept = invocations.len() as u64;
    invocations.sort_by(|left, right| {
        left.observed_at
            .cmp(&right.observed_at)
            .then_with(|| left.call_id.cmp(&right.call_id))
    });
    Ok(invocations)
}

/// Apply workspace scoping and tool/status classification to one row, updating
/// the deterministic exclusion counters.
fn classify_row(
    raw: &RawRow,
    workspace: &Path,
    summary: &mut RuntimeIngestSummary,
) -> Option<ToolInvocation> {
    match scope_verdict(raw.directory.as_deref(), workspace) {
        ScopeVerdict::OtherWorkspace => {
            summary.excluded_other_workspace += 1;
            return None;
        }
        ScopeVerdict::Unresolved => {
            summary.excluded_unresolved_workspace += 1;
            return None;
        }
        ScopeVerdict::InScope => {}
    }

    let Some(tool) = raw.tool.as_deref().filter(|tool| !tool.is_empty()) else {
        summary.excluded_missing_tool += 1;
        return None;
    };
    let Some(status) = raw.status.as_deref().and_then(ToolStatus::from_wire) else {
        summary.excluded_unknown_status += 1;
        return None;
    };
    let Some(observed_at) = parse_observed_at(&raw.created) else {
        summary.excluded_missing_timestamp += 1;
        return None;
    };

    Some(ToolInvocation {
        tool: tool.to_string(),
        status,
        call_id: raw.call_id.clone().unwrap_or_default(),
        session_id: raw.session_id.clone().unwrap_or_default(),
        observed_at,
    })
}

enum ScopeVerdict {
    InScope,
    OtherWorkspace,
    Unresolved,
}

/// Keep a row only when its `session.directory` canonically equals the workspace.
/// Canonicalization handles trailing slashes and symlinks; when it fails, a
/// lexical comparison is used and any mismatch is counted rather than guessed.
fn scope_verdict(directory: Option<&str>, workspace: &Path) -> ScopeVerdict {
    let Some(directory) = directory.filter(|value| !value.is_empty()) else {
        return ScopeVerdict::Unresolved;
    };
    let path = Path::new(directory);
    match std::fs::canonicalize(path) {
        Ok(canonical) => {
            if canonical == workspace {
                ScopeVerdict::InScope
            } else {
                ScopeVerdict::OtherWorkspace
            }
        }
        Err(_) => match normalize_lexically(path) {
            Some(normalized) if normalized == workspace => ScopeVerdict::InScope,
            _ => ScopeVerdict::Unresolved,
        },
    }
}

/// Lower-bound for the `part.time_created` filter, in epoch milliseconds
/// (OpenCode stores `Date.now()` integers). A non-positive window means no bound.
fn time_window_cutoff_ms(window_secs: i64) -> i64 {
    if window_secs <= 0 {
        return i64::MIN;
    }
    let cutoff = Utc::now() - chrono::Duration::seconds(window_secs);
    cutoff.timestamp_millis()
}

fn value_text(value: Value) -> Option<String> {
    match value {
        Value::Text(text) => Some(text),
        Value::Integer(number) => Some(number.to_string()),
        Value::Real(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Parse `part.time_created` without inventing a value: integer/real values are
/// epoch milliseconds (seconds accepted by magnitude), text is integer or
/// RFC 3339. Unparseable input excludes the row rather than defaulting it.
fn parse_observed_at(value: &Value) -> Option<DateTime<Utc>> {
    match value {
        Value::Integer(number) => epoch_millis_to_datetime(*number),
        Value::Real(number) => epoch_millis_to_datetime(*number as i64),
        Value::Text(text) => {
            let trimmed = text.trim();
            if let Ok(number) = trimmed.parse::<i64>() {
                epoch_millis_to_datetime(number)
            } else {
                DateTime::parse_from_rfc3339(trimmed)
                    .ok()
                    .map(|parsed| parsed.with_timezone(&Utc))
            }
        }
        _ => None,
    }
}

fn epoch_millis_to_datetime(raw: i64) -> Option<DateTime<Utc>> {
    let millis = if raw.abs() >= 100_000_000_000 {
        raw
    } else {
        raw.saturating_mul(1_000)
    };
    DateTime::from_timestamp_millis(millis)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::symlink;

    use rusqlite::params;
    use serde_json::{json, Value as JsonValue};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;

    const SENTINEL: &str = "SENTINEL_FORBIDDEN_CONTENT_9f3a";

    /// Forbidden content or secret tokens that must never be named by the reader.
    const FORBIDDEN_SELECT_TOKENS: [&str; 15] = [
        "$.state.input",
        "$.state.output",
        "$.state.text",
        "$.state.metadata",
        "message.data",
        "session_input",
        "session.title",
        "summary_diffs",
        "summary_",
        "session.revert",
        "todo.content",
        "project.commands",
        "event.data",
        "credential",
        "session_share",
    ];

    fn new_store(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT, title TEXT);
             CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, time_created INTEGER, data TEXT);
             CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT);
             CREATE TABLE migration (id TEXT PRIMARY KEY, time_completed INTEGER);
             CREATE TABLE session_input (id TEXT PRIMARY KEY, session_id TEXT, prompt TEXT);",
        )
        .unwrap();
        conn
    }

    fn seed_migrations(conn: &Connection, count: usize) {
        for index in 0..count {
            conn.execute(
                "INSERT INTO migration (id, time_completed) VALUES (?1, ?2)",
                params![format!("migration_{index:04}"), 0i64],
            )
            .unwrap();
        }
    }

    fn seed_numeric_migrations(conn: &Connection, count: usize) {
        for index in 1..=count {
            conn.execute(
                "INSERT INTO migration (id, time_completed) VALUES (?1, ?2)",
                params![format!("{index:04}"), 0i64],
            )
            .unwrap();
        }
    }

    fn seed_session(conn: &Connection, id: &str, directory: &str) {
        conn.execute(
            "INSERT INTO session (id, directory, title) VALUES (?1, ?2, ?3)",
            params![id, directory, SENTINEL],
        )
        .unwrap();
    }

    fn tool_data(tool: &str, status: &str, call_id: &str) -> JsonValue {
        json!({
            "type": "tool",
            "tool": tool,
            "callID": call_id,
            "state": {
                "status": status,
                "input": { "note": SENTINEL },
                "output": SENTINEL,
                "text": SENTINEL,
                "metadata": { "note": SENTINEL },
            }
        })
    }

    fn seed_part(conn: &Connection, id: &str, session_id: &str, data: &JsonValue, created_ms: i64) {
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, "msg_1", session_id, created_ms, data.to_string()],
        )
        .unwrap();
    }

    fn config(store: &Path, workspace: &Path) -> RuntimeIngestConfig {
        RuntimeIngestConfig {
            store: Some(store.to_path_buf()),
            workspace: workspace.to_path_buf(),
            ..RuntimeIngestConfig::default()
        }
    }

    fn now_ms() -> i64 {
        Utc::now().timestamp_millis()
    }

    fn directory(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn invocations(outcome: RuntimeReadOutcome) -> (Vec<ToolInvocation>, bool) {
        match outcome {
            RuntimeReadOutcome::Ingested {
                invocations,
                truncated,
            } => (invocations, truncated),
            other => panic!("expected Ingested, got {other:?}"),
        }
    }

    fn snapshot(dir: &Path) -> BTreeMap<String, (u64, String)> {
        let mut entries = BTreeMap::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = std::fs::read(entry.path()).unwrap();
            let digest = format!("{:x}", Sha256::digest(&bytes));
            entries.insert(name, (bytes.len() as u64, digest));
        }
        entries
    }

    #[test]
    fn store_none_is_not_attempted_without_touching_disk() {
        let cfg = RuntimeIngestConfig {
            store: None,
            workspace: PathBuf::from("/nonexistent/workspace"),
            ..RuntimeIngestConfig::default()
        };
        let (outcome, summary) = ingest_with_summary(&cfg).unwrap();
        assert_eq!(outcome, RuntimeReadOutcome::NotAttempted);
        assert_eq!(summary, RuntimeIngestSummary::default());
    }

    #[test]
    fn absent_store_is_unavailable() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.db");
        let cfg = config(&missing, dir.path());
        let outcome = ingest(&cfg).unwrap();
        assert!(matches!(
            outcome,
            RuntimeReadOutcome::Unavailable {
                reason: REASON_STORE_ABSENT
            }
        ));
    }

    #[test]
    fn happy_path_maps_tool_statuses_and_orders_deterministically() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            let base = now_ms();
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                base - 1_000,
            );
            seed_part(
                &conn,
                "p2",
                "ses_1",
                &tool_data("bash", "running", "c2"),
                base - 2_000,
            );
            seed_part(
                &conn,
                "p3",
                "ses_1",
                &tool_data("bash", "error", "c3"),
                base - 3_000,
            );
            seed_part(
                &conn,
                "p4",
                "ses_1",
                &tool_data("bash", "pending", "c4"),
                base - 4_000,
            );
        }

        let (found, truncated) = invocations(ingest(&config(&db, workspace.path())).unwrap());
        assert!(!truncated);
        assert_eq!(found.len(), 4);
        let statuses: Vec<ToolStatus> = found.iter().map(|item| item.status).collect();
        assert_eq!(
            statuses,
            vec![
                ToolStatus::Pending,
                ToolStatus::Error,
                ToolStatus::Running,
                ToolStatus::Completed
            ]
        );
        let call_ids: Vec<&str> = found.iter().map(|item| item.call_id.as_str()).collect();
        assert_eq!(call_ids, vec!["c4", "c3", "c2", "c1"]);
        assert!(found.iter().all(|item| item.tool == "bash"));
        assert!(found.iter().all(|item| item.session_id == "ses_1"));
    }

    #[test]
    fn numeric_migration_ids_are_read_as_a_version() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_numeric_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                now_ms(),
            );
        }
        let (found, _) = invocations(ingest(&config(&db, workspace.path())).unwrap());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn tool_filter_keeps_named_tools_and_drops_non_tool_parts() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            let base = now_ms();
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &json!({ "type": "text", "text": SENTINEL }),
                base,
            );
            seed_part(
                &conn,
                "p2",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                base,
            );
            seed_part(
                &conn,
                "p3",
                "ses_1",
                &tool_data("write", "completed", "c2"),
                base,
            );
        }
        let (found, _) = invocations(ingest(&config(&db, workspace.path())).unwrap());
        assert_eq!(found.len(), 2);
        let mut tools: Vec<&str> = found.iter().map(|item| item.tool.as_str()).collect();
        tools.sort_unstable();
        assert_eq!(tools, vec!["bash", "write"]);
    }

    #[test]
    fn workspace_scoping_excludes_other_directories_and_counts_them() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let other = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_here", &directory(workspace.path()));
            seed_session(&conn, "ses_other", &directory(other.path()));
            let base = now_ms();
            seed_part(
                &conn,
                "p1",
                "ses_here",
                &tool_data("bash", "completed", "c1"),
                base - 1_000,
            );
            seed_part(
                &conn,
                "p2",
                "ses_other",
                &tool_data("bash", "completed", "c2"),
                base,
            );
        }
        let (outcome, summary) = ingest_with_summary(&config(&db, workspace.path())).unwrap();
        let (found, _) = invocations(outcome);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].call_id, "c1");
        assert_eq!(summary.excluded_other_workspace, 1);
        assert_eq!(summary.excluded_unresolved_workspace, 0);
    }

    #[test]
    fn workspace_scoping_handles_trailing_slash_and_symlink_variants() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let link_dir = tempdir().unwrap();
        let link = link_dir.path().join("workspace-link");
        symlink(workspace.path(), &link).unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            let trailing = format!("{}/", directory(workspace.path()));
            seed_session(&conn, "ses_trailing", &trailing);
            seed_session(&conn, "ses_symlink", &directory(&link));
            let base = now_ms();
            seed_part(
                &conn,
                "p1",
                "ses_trailing",
                &tool_data("bash", "completed", "c1"),
                base - 1_000,
            );
            seed_part(
                &conn,
                "p2",
                "ses_symlink",
                &tool_data("bash", "completed", "c2"),
                base,
            );
        }
        let (found, _) = invocations(ingest(&config(&db, workspace.path())).unwrap());
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn workspace_scoping_falls_back_to_lexical_comparison_when_unresolvable() {
        let store_dir = tempdir().unwrap();
        let base = tempdir().unwrap();
        let ghost_workspace = base.path().join("ghost").join("ws");
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            let trailing = format!("{}/", directory(&ghost_workspace));
            seed_session(&conn, "ses_ghost", &trailing);
            seed_part(
                &conn,
                "p1",
                "ses_ghost",
                &tool_data("bash", "completed", "c1"),
                now_ms(),
            );
        }
        let cfg = RuntimeIngestConfig {
            store: Some(db),
            workspace: ghost_workspace,
            ..RuntimeIngestConfig::default()
        };
        let (found, _) = invocations(ingest(&cfg).unwrap());
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn version_gate_rejects_out_of_range_counts() {
        for count in [37usize, 39] {
            let store_dir = tempdir().unwrap();
            let workspace = tempdir().unwrap();
            let db = store_dir.path().join("opencode.db");
            {
                let conn = new_store(&db);
                seed_migrations(&conn, count);
                seed_session(&conn, "ses_1", &directory(workspace.path()));
                seed_part(
                    &conn,
                    "p1",
                    "ses_1",
                    &tool_data("bash", "completed", "c1"),
                    now_ms(),
                );
            }
            let outcome = ingest(&config(&db, workspace.path())).unwrap();
            assert_eq!(
                outcome,
                RuntimeReadOutcome::Unsupported {
                    migrations: Some(count as u64)
                },
                "count {count} must fail closed"
            );
        }
    }

    #[test]
    fn version_gate_rejects_missing_table_without_reading_rows() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            conn.execute_batch("DROP TABLE migration").unwrap();
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                now_ms(),
            );
        }
        let outcome = ingest(&config(&db, workspace.path())).unwrap();
        assert_eq!(
            outcome,
            RuntimeReadOutcome::Unsupported { migrations: None }
        );
    }

    #[test]
    fn version_gate_rejects_missing_required_column() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            conn.execute_batch(
                "DROP TABLE migration; CREATE TABLE migration (time_completed INTEGER)",
            )
            .unwrap();
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                now_ms(),
            );
        }
        let outcome = ingest(&config(&db, workspace.path())).unwrap();
        assert_eq!(
            outcome,
            RuntimeReadOutcome::Unsupported { migrations: None }
        );
    }

    #[test]
    fn version_gate_rejects_missing_time_column() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            conn.execute_batch(
                "DROP TABLE part; CREATE TABLE part (id TEXT, data TEXT, session_id TEXT)",
            )
            .unwrap();
            seed_session(&conn, "ses_1", &directory(workspace.path()));
        }
        let outcome = ingest(&config(&db, workspace.path())).unwrap();
        assert_eq!(
            outcome,
            RuntimeReadOutcome::Unsupported {
                migrations: Some(38)
            }
        );
    }

    #[test]
    fn max_rows_cap_truncates_and_reports() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            let base = now_ms();
            for index in 0..5 {
                seed_part(
                    &conn,
                    &format!("p{index}"),
                    "ses_1",
                    &tool_data("bash", "completed", &format!("c{index}")),
                    base - (index as i64),
                );
            }
        }
        let cfg = RuntimeIngestConfig {
            max_rows: 2,
            ..config(&db, workspace.path())
        };
        let (outcome, summary) = ingest_with_summary(&cfg).unwrap();
        let (found, truncated) = invocations(outcome);
        assert!(truncated);
        assert!(summary.truncated);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn tiny_wall_clock_budget_terminates_without_panic() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            let base = now_ms();
            for index in 0..3_000 {
                seed_part(
                    &conn,
                    &format!("p{index}"),
                    "ses_1",
                    &tool_data("bash", "completed", &format!("c{index}")),
                    base - (index as i64),
                );
            }
        }
        let cfg = RuntimeIngestConfig {
            wall_clock_ms: 0,
            ..config(&db, workspace.path())
        };
        let (outcome, summary) = ingest_with_summary(&cfg).unwrap();
        let (found, truncated) = invocations(outcome);
        assert!(truncated, "a zero budget must mark the read truncated");
        assert!(summary.truncated);
        assert!(found.len() <= cfg.max_rows);
    }

    #[test]
    fn forbidden_content_never_appears_in_the_reader_output() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            let base = now_ms();
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                base - 1_000,
            );
            seed_part(
                &conn,
                "p2",
                "ses_1",
                &tool_data("write", "running", "c2"),
                base,
            );
            conn.execute(
                "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
                params![
                    "m1",
                    "ses_1",
                    format!("{{\"role\":\"user\",\"text\":\"{SENTINEL}\"}}")
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO session_input (id, session_id, prompt) VALUES (?1, ?2, ?3)",
                params!["si1", "ses_1", SENTINEL],
            )
            .unwrap();
        }

        let (outcome, summary) = ingest_with_summary(&config(&db, workspace.path())).unwrap();
        let debug = format!("{outcome:?}");
        assert!(
            !debug.contains(SENTINEL),
            "outcome leaked sentinel: {debug}"
        );
        assert!(!format!("{summary:?}").contains(SENTINEL));
        let (found, _) = invocations(outcome);
        for item in &found {
            assert!(!item.tool.contains(SENTINEL));
            assert!(!item.call_id.contains(SENTINEL));
            assert!(!item.session_id.contains(SENTINEL));
            assert!(!format!("{item:?}").contains(SENTINEL));
        }
    }

    #[test]
    fn select_is_built_only_from_the_content_free_allowlist() {
        let sql = select_sql();
        for token in FORBIDDEN_SELECT_TOKENS {
            assert!(
                !sql.contains(token),
                "SELECT names forbidden token {token}: {sql}"
            );
            assert!(
                !SELECT_EXPRESSIONS.iter().any(|expr| expr.contains(token)),
                "allowlist contains forbidden token {token}"
            );
        }
        assert!(sql.starts_with(&format!("SELECT {}", SELECT_EXPRESSIONS.join(", "))));
        assert_eq!(
            SELECT_EXPRESSIONS,
            [
                "part.id",
                "json_extract(part.data, '$.tool')",
                "json_extract(part.data, '$.callID')",
                "json_extract(part.data, '$.state.status')",
                "part.time_created",
                "part.session_id",
                "session.directory",
            ]
        );
    }

    #[test]
    fn read_is_byte_identical_and_creates_no_sidecars() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                now_ms(),
            );
        }
        let before = snapshot(store_dir.path());
        assert!(!before.contains_key("opencode.db-wal"));
        assert!(!before.contains_key("opencode.db-shm"));

        let _ = ingest(&config(&db, workspace.path())).unwrap();

        let after = snapshot(store_dir.path());
        assert_eq!(before, after, "runtime read mutated the store directory");
        assert_eq!(before.len(), 1);
    }

    #[test]
    fn corrupt_store_is_unavailable_without_panic() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        let garbage: Vec<u8> = (0..4_096u32).map(|index| (index % 251) as u8).collect();
        std::fs::write(&db, garbage).unwrap();

        let outcome = ingest(&config(&db, workspace.path())).unwrap();
        match outcome {
            RuntimeReadOutcome::Unavailable { reason } => {
                assert!(
                    reason == REASON_STORE_NOT_DATABASE || reason == REASON_STORE_CORRUPT,
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn two_reads_return_identical_vectors() {
        let store_dir = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let db = store_dir.path().join("opencode.db");
        {
            let conn = new_store(&db);
            seed_migrations(&conn, 38);
            seed_session(&conn, "ses_1", &directory(workspace.path()));
            let base = now_ms();
            seed_part(
                &conn,
                "p1",
                "ses_1",
                &tool_data("bash", "completed", "c1"),
                base - 2_000,
            );
            seed_part(
                &conn,
                "p2",
                "ses_1",
                &tool_data("bash", "pending", "c2"),
                base - 1_000,
            );
            seed_part(
                &conn,
                "p3",
                "ses_1",
                &tool_data("bash", "error", "c3"),
                base,
            );
        }
        let cfg = config(&db, workspace.path());
        let first = ingest_with_summary(&cfg).unwrap();
        let second = ingest_with_summary(&cfg).unwrap();
        assert_eq!(first, second);
    }
}
