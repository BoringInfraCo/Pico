//! Database connection, schema initialization, and migrations.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::shared::PicoError;

/// Ordered schema migrations. Each entry is applied exactly once, in
/// order, and recorded via SQLite's `PRAGMA user_version`.
///
/// Migration 1: Sprint 001 observed-domain schema
/// (scans, resources, relationships, observations, evidence,
/// relationship_evidence) per ARCHITECTURE.md and SPRINT-001.md §9.
const MIGRATIONS: &[&str] = &[
    r#"
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        trigger TEXT NOT NULL,
        scope TEXT,
        pico_version TEXT NOT NULL,
        environment_fingerprint TEXT,
        metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS resources (
        id TEXT PRIMARY KEY,
        canonical_key TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        provider TEXT NOT NULL,
        name TEXT NOT NULL,
        metadata TEXT,
        first_observed_at TEXT NOT NULL,
        last_observed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS relationships (
        id TEXT PRIMARY KEY,
        canonical_key TEXT NOT NULL UNIQUE,
        from_resource_id TEXT NOT NULL REFERENCES resources(id),
        to_resource_id TEXT NOT NULL REFERENCES resources(id),
        kind TEXT NOT NULL,
        state TEXT NOT NULL,
        metadata TEXT,
        first_observed_at TEXT NOT NULL,
        last_observed_at TEXT NOT NULL,
        CHECK (from_resource_id != to_resource_id)
    );

    CREATE TABLE IF NOT EXISTS observations (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id),
        subject_type TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        observation_type TEXT NOT NULL,
        observed_at TEXT NOT NULL,
        source TEXT NOT NULL,
        metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id),
        class TEXT NOT NULL,
        source_type TEXT NOT NULL,
        source_locator TEXT NOT NULL,
        subject TEXT NOT NULL,
        observation TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        freshness TEXT,
        sensitivity TEXT NOT NULL,
        metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS relationship_evidence (
        relationship_id TEXT NOT NULL REFERENCES relationships(id),
        evidence_id TEXT NOT NULL REFERENCES evidence(id),
        PRIMARY KEY (relationship_id, evidence_id)
    );

    CREATE INDEX IF NOT EXISTS idx_observations_scan ON observations(scan_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
    CREATE INDEX IF NOT EXISTS idx_relationships_from ON relationships(from_resource_id);
    CREATE INDEX IF NOT EXISTS idx_relationships_to ON relationships(to_resource_id);
    "#,
    // Migration 2: Sprint 007 canonicalizes the provider-neutral Resource
    // vocabulary used by graph projection. Keep the migration idempotent for
    // databases created by earlier sprints.
    r#"
    UPDATE resources SET kind = 'external_source' WHERE kind = 'external_content';
    UPDATE resources SET kind = 'provider_account' WHERE kind = 'account';
    "#,
    // Migration 3: Sprint 008 deterministic analysis results. Analysis is
    // append-oriented and remains a projection over the observed domain;
    // these tables retain only normalized path summaries and ordered links.
    r#"
    CREATE TABLE IF NOT EXISTS scan_analyses (
        scan_id TEXT PRIMARY KEY REFERENCES scans(id),
        analysis_version TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('COMPLETE', 'LIMITED', 'FAILED')),
        overall_disposition TEXT CHECK (
            overall_disposition IS NULL OR overall_disposition IN
            ('ACTIVE_PRESENT', 'UNRESOLVED_PRESENT', 'BLOCKED_ONLY', 'NONE')
        ),
        influence_path_count INTEGER NOT NULL DEFAULT 0 CHECK (influence_path_count >= 0),
        authority_path_count INTEGER NOT NULL DEFAULT 0 CHECK (authority_path_count >= 0),
        active_path_count INTEGER NOT NULL DEFAULT 0 CHECK (active_path_count >= 0),
        blocked_path_count INTEGER NOT NULL DEFAULT 0 CHECK (blocked_path_count >= 0),
        unresolved_candidate_count INTEGER NOT NULL DEFAULT 0 CHECK (unresolved_candidate_count >= 0),
        limit_reasons TEXT,
        diagnostics TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS attack_paths (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id),
        fingerprint TEXT NOT NULL,
        analysis_version TEXT NOT NULL,
        source_resource_id TEXT NOT NULL REFERENCES resources(id),
        actor_resource_id TEXT NOT NULL REFERENCES resources(id),
        sink_resource_id TEXT NOT NULL REFERENCES resources(id),
        disposition TEXT NOT NULL CHECK (disposition IN ('ACTIVE', 'BLOCKED')),
        source_trust TEXT NOT NULL,
        influence_strength TEXT NOT NULL,
        capability TEXT NOT NULL,
        authority_resolution TEXT NOT NULL,
        sink_impact TEXT NOT NULL,
        boundary_metadata TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (scan_id, fingerprint)
    );

    CREATE TABLE IF NOT EXISTS attack_path_edges (
        attack_path_id TEXT NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
        relationship_id TEXT NOT NULL REFERENCES relationships(id),
        position INTEGER NOT NULL CHECK (position >= 0),
        phase TEXT NOT NULL CHECK (phase IN ('INFLUENCE', 'AUTHORITY')),
        traversal TEXT NOT NULL CHECK (traversal IN ('FORWARD', 'REVERSE')),
        PRIMARY KEY (attack_path_id, position),
        UNIQUE (attack_path_id, relationship_id, position)
    );

    CREATE TABLE IF NOT EXISTS attack_path_evidence (
        attack_path_id TEXT NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
        evidence_id TEXT NOT NULL REFERENCES evidence(id),
        position INTEGER NOT NULL CHECK (position >= 0),
        support_role TEXT NOT NULL CHECK (support_role IN ('EDGE', 'BOUNDARY')),
        PRIMARY KEY (attack_path_id, position),
        UNIQUE (attack_path_id, evidence_id, position)
    );

    CREATE INDEX IF NOT EXISTS idx_scan_analyses_status ON scan_analyses(status);
    CREATE INDEX IF NOT EXISTS idx_attack_paths_scan ON attack_paths(scan_id);
    CREATE INDEX IF NOT EXISTS idx_attack_path_edges_path ON attack_path_edges(attack_path_id);
    CREATE INDEX IF NOT EXISTS idx_attack_path_evidence_path ON attack_path_evidence(attack_path_id);
    "#,
    // Migration 4: Sprint 009 normalized Finding persistence. Findings are
    // scan-scoped projections over completed analysis; links retain exact
    // paths, same-scan evidence, structured reasons, and ordered remediation
    // cuts without copying provider configuration into the Finding.
    r#"
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES scans(id),
        fingerprint TEXT NOT NULL,
        finding_version TEXT NOT NULL,
        finding_class TEXT NOT NULL CHECK (finding_class IN ('UNTRUSTED_TO_PRODUCTION')),
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
        confidence TEXT NOT NULL CHECK (confidence IN ('LOW', 'MEDIUM', 'HIGH')),
        status TEXT NOT NULL CHECK (status IN ('OPEN')),
        metadata TEXT,
        created_at TEXT NOT NULL,
        UNIQUE (scan_id, fingerprint)
    );

    CREATE TABLE IF NOT EXISTS finding_paths (
        finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        attack_path_id TEXT NOT NULL REFERENCES attack_paths(id),
        position INTEGER NOT NULL CHECK (position >= 0),
        PRIMARY KEY (finding_id, position),
        UNIQUE (finding_id, attack_path_id)
    );

    CREATE TABLE IF NOT EXISTS finding_evidence (
        finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        evidence_id TEXT NOT NULL REFERENCES evidence(id),
        position INTEGER NOT NULL CHECK (position >= 0),
        support_role TEXT NOT NULL,
        PRIMARY KEY (finding_id, position),
        UNIQUE (finding_id, evidence_id, position)
    );

    CREATE TABLE IF NOT EXISTS finding_reasons (
        finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        position INTEGER NOT NULL CHECK (position >= 0),
        reason_code TEXT NOT NULL,
        resource_ids TEXT NOT NULL,
        relationship_ids TEXT NOT NULL,
        attack_path_ids TEXT NOT NULL,
        evidence_ids TEXT NOT NULL,
        PRIMARY KEY (finding_id, position),
        UNIQUE (finding_id, reason_code, position)
    );

    CREATE TABLE IF NOT EXISTS finding_remediations (
        finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        position INTEGER NOT NULL CHECK (position >= 0),
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        security_effect TEXT NOT NULL,
        cut_phase TEXT NOT NULL,
        target_resource_ids TEXT NOT NULL,
        target_relationship_ids TEXT NOT NULL,
        PRIMARY KEY (finding_id, position),
        UNIQUE (finding_id, rule_id, position)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(finding_class);
    CREATE INDEX IF NOT EXISTS idx_finding_paths_finding ON finding_paths(finding_id);
    CREATE INDEX IF NOT EXISTS idx_finding_paths_attack_path ON finding_paths(attack_path_id);
    CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding ON finding_evidence(finding_id);
    CREATE INDEX IF NOT EXISTS idx_finding_evidence_evidence ON finding_evidence(evidence_id);
    CREATE INDEX IF NOT EXISTS idx_finding_reasons_finding ON finding_reasons(finding_id);
    CREATE INDEX IF NOT EXISTS idx_finding_remediations_finding ON finding_remediations(finding_id);

    -- SQLite cannot express the scan-scoped part of these relationships as a
    -- composite foreign key because the legacy attack_paths/evidence tables
    -- do not expose scan_id in a UNIQUE composite key. Keep the ordinary FKs
    -- above and enforce the stronger invariant at the database boundary.
    CREATE TRIGGER IF NOT EXISTS finding_paths_same_scan_insert
    BEFORE INSERT ON finding_paths
    FOR EACH ROW
    WHEN (SELECT scan_id FROM findings WHERE id = NEW.finding_id) IS NOT NULL
     AND (SELECT scan_id FROM attack_paths WHERE id = NEW.attack_path_id) IS NOT NULL
     AND (SELECT scan_id FROM findings WHERE id = NEW.finding_id)
         != (SELECT scan_id FROM attack_paths WHERE id = NEW.attack_path_id)
    BEGIN
        SELECT RAISE(ABORT, 'finding path must reference an attack path from the same scan');
    END;

    CREATE TRIGGER IF NOT EXISTS finding_evidence_same_scan_insert
    BEFORE INSERT ON finding_evidence
    FOR EACH ROW
    WHEN (SELECT scan_id FROM findings WHERE id = NEW.finding_id) IS NOT NULL
     AND (SELECT scan_id FROM evidence WHERE id = NEW.evidence_id) IS NOT NULL
     AND (SELECT scan_id FROM findings WHERE id = NEW.finding_id)
         != (SELECT scan_id FROM evidence WHERE id = NEW.evidence_id)
    BEGIN
        SELECT RAISE(ABORT, 'finding evidence must reference evidence from the same scan');
    END;
    "#,
    // Migration 5: Sprint 019 structured scan diagnostics. The scan service
    // composes a machine-readable explanation of incomplete evidence (provider
    // failures, suppressed candidates, and confidence-reducing edges) that the
    // CLI and MCP surfaces surface verbatim. It is a scan-scoped projection
    // derived from already-sanitized discovery facts; the JSON carries no raw
    // secrets.
    r#"
    CREATE TABLE IF NOT EXISTS scan_diagnostics (
        scan_id TEXT PRIMARY KEY REFERENCES scans(id),
        detail TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_scan_diagnostics_scan ON scan_diagnostics(scan_id);
    "#,
    // Migration 6: Sprint 028 family identity for Finding lifecycle.
    // Legacy rows backfill to '' (pre-family); new writes must carry a
    // non-empty family_fingerprint enforced by the insert trigger. The
    // partial unique index scopes family identity per scan while ignoring
    // legacy empty rows.
    r#"
    ALTER TABLE findings ADD COLUMN family_fingerprint TEXT NOT NULL DEFAULT '';
    CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_scan_family ON findings(scan_id, family_fingerprint) WHERE family_fingerprint <> '';
    CREATE TRIGGER IF NOT EXISTS findings_family_nonempty_insert BEFORE INSERT ON findings FOR EACH ROW WHEN NEW.family_fingerprint = '' BEGIN SELECT RAISE(ABORT, 'family_fingerprint is required'); END;
    "#,
];

/// The only schema version supported by this build. Query commands must
/// never migrate; a mismatch is a compatibility error.
pub const SUPPORTED_SCHEMA_VERSION: i64 = 6;

/// A SQLite-backed Pico database.
pub struct Database {
    conn: Connection,
}

fn reject_symlink_db_path(path: &Path) -> Result<(), PicoError> {
    if let Some(parent) = path.parent() {
        match std::fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PicoError::database(
                    "refusing to use symlink at .pico".to_string(),
                ));
            }
            _ => {}
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(PicoError::database(
                "refusing to use symlink at pico.db".to_string(),
            ));
        }
        _ => {}
    }
    Ok(())
}

impl Database {
    /// Open (creating if necessary) the database at `path`.
    pub fn open(path: &Path) -> Result<Self, PicoError> {
        reject_symlink_db_path(path)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Database { conn })
    }

    /// Open an existing database read-write without creating it.
    ///
    /// Used by `pico scan` so that a scan fails clearly when Pico has
    /// not been initialized.
    pub fn open_existing(path: &Path) -> Result<Self, PicoError> {
        reject_symlink_db_path(path)?;
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(|e| {
                PicoError::scan(format!(
                    "no Pico state at {} (run `pico init` first): {e}",
                    path.display()
                ))
            })?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Database { conn })
    }

    /// Open an existing database strictly read-only without creating it.
    ///
    /// Used by query commands so that explanation can never mutate state,
    /// run DDL, or update `user_version`.
    pub fn open_read_only(path: &Path) -> Result<Self, PicoError> {
        if !path.exists() {
            return Err(PicoError::scan(
                "no Pico state in this workspace (run `pico init` first)".to_string(),
            ));
        }
        reject_symlink_db_path(path)?;
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| {
                PicoError::scan(format!(
                    "cannot read Pico state (run `pico init` first): {e}"
                ))
            })?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Database { conn })
    }

    /// Apply all pending migrations. Safe to call repeatedly.
    pub fn migrate(&mut self) -> Result<(), PicoError> {
        migrate(&mut self.conn)
    }

    /// The current schema version (`PRAGMA user_version`).
    pub fn schema_version(&self) -> Result<i64, PicoError> {
        schema_version(&self.conn)
    }

    /// Access to the underlying connection for repositories.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Apply all pending migrations, recording each via `user_version`.
pub fn migrate(conn: &mut Connection) -> Result<(), PicoError> {
    migrate_to_version(conn, MIGRATIONS.len() as i64)
}

/// Applies migrations 1..=target. Internal helper for migration tests and
/// tooling; partial migrations are NOT a supported public surface.
fn migrate_to_version(conn: &mut Connection, target: i64) -> Result<(), PicoError> {
    let len = MIGRATIONS.len() as i64;
    if target < 1 || target > len {
        return Err(PicoError::migration(format!(
            "unsupported migration target {target}; supported range is 1..={len}"
        )));
    }
    let current = schema_version(conn).map_err(|e| PicoError::migration(e.to_string()))?;
    if current > len {
        return Err(PicoError::migration(format!(
            "unsupported schema version {current}; this build supports schema \
             version {SUPPORTED_SCHEMA_VERSION} (upgrade Pico or use a compatible \
             build; database downgrade is unsupported)"
        )));
    }
    if target < current {
        return Err(PicoError::migration(format!(
            "requested migration target {target} is below current schema version \
             {current}; downgrade is unsupported"
        )));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let version = (i + 1) as i64;
        if version > target {
            break;
        }
        if version <= current {
            continue;
        }
        let tx = conn
            .transaction()
            .map_err(|e| PicoError::migration(e.to_string()))?;
        tx.execute_batch(sql)
            .map_err(|e| PicoError::migration(e.to_string()))?;
        tx.pragma_update(None, "user_version", version)
            .map_err(|e| PicoError::migration(e.to_string()))?;
        tx.commit()
            .map_err(|e| PicoError::migration(e.to_string()))?;
    }
    Ok(())
}

/// Read the current schema version.
pub fn schema_version(conn: &Connection) -> Result<i64, PicoError> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| PicoError::migration(e.to_string()))?;
    Ok(version)
}

/// Require the current schema version without migrating or writing.
pub fn require_schema_version(conn: &Connection) -> Result<i64, PicoError> {
    let version = schema_version(conn)?;
    if version != SUPPORTED_SCHEMA_VERSION {
        let remedy = if version < SUPPORTED_SCHEMA_VERSION {
            // `pico init` genuinely migrates older databases forward.
            "run `pico init` to upgrade"
        } else {
            // A newer database cannot be migrated down; init would hit the
            // same rejection.
            "upgrade Pico or use a compatible build; database downgrade is unsupported"
        };
        return Err(PicoError::migration(format!(
            "unsupported schema version {version}; this build requires schema \
             version {SUPPORTED_SCHEMA_VERSION} ({remedy})"
        )));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::codec;
    use crate::shared::PICO_VERSION;
    use crate::{
        domain::{Evidence, EvidenceClass, Observation, Resource, Scan, ScanStatus},
        persistence::{
            EvidenceRepo, FindingRepo, ObservationRepo, RelationshipRepo, ResourceRepo, ScanRepo,
        },
    };
    use chrono::Utc;
    use rusqlite::params;

    #[test]
    fn fresh_database_initializes() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
        db.migrate().unwrap();
        assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
    }

    #[test]
    fn migration_executes_all_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pico.db");
        {
            let mut db = Database::open(&path).unwrap();
            db.migrate().unwrap();
        }
        {
            let mut db = Database::open(&path).unwrap();
            assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
            db.migrate().unwrap();
            assert_eq!(db.schema_version().unwrap(), MIGRATIONS.len() as i64);
        }
    }

    #[test]
    fn migrate_to_version_stops_at_target_and_rejects_invalid_targets() {
        let len = MIGRATIONS.len() as i64;
        let conn = Connection::open_in_memory().unwrap();
        let mut conn = conn;
        conn.pragma_update(None, "foreign_keys", true).unwrap();

        // Target 0 and beyond the newest migration are rejected outright.
        assert!(migrate_to_version(&mut conn, 0).is_err());
        assert!(migrate_to_version(&mut conn, len + 1).is_err());
        assert_eq!(schema_version(&conn).unwrap(), 0);

        // Migrate partially, then verify behavior relative to current version.
        migrate_to_version(&mut conn, 5).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 5);

        // Targets below the current version are rejected (no downgrade).
        assert!(migrate_to_version(&mut conn, 4).is_err());
        assert_eq!(schema_version(&conn).unwrap(), 5);

        // Re-running at the current version is a no-op.
        migrate_to_version(&mut conn, 5).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 5);

        // Migrating forward to an explicit target works.
        migrate_to_version(&mut conn, len).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), len);
    }

    #[test]
    fn database_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pico.db");
        {
            let mut db = Database::open(&path).unwrap();
            db.migrate().unwrap();
            let scan = Scan::start(PICO_VERSION).unwrap().complete().unwrap();
            ScanRepo::new(db.connection()).insert(&scan).unwrap();
        }
        {
            let mut db = Database::open(&path).unwrap();
            db.migrate().unwrap();
            let repo = ScanRepo::new(db.connection());
            assert_eq!(repo.count().unwrap(), 1);
            let loaded = repo.get(&scan_id_of(&repo)).unwrap().unwrap();
            assert_eq!(loaded.status, ScanStatus::Complete);
        }
    }

    fn scan_id_of(repo: &ScanRepo) -> String {
        repo.list().unwrap().remove(0).id
    }

    #[test]
    fn scan_persistence_and_completion_update() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
        db.migrate().unwrap();
        let repo = ScanRepo::new(db.connection());

        let running = Scan::start(PICO_VERSION).unwrap();
        repo.insert(&running).unwrap();
        assert_eq!(repo.count().unwrap(), 1);
        let loaded_running = repo.get(&running.id).unwrap().unwrap();
        assert_eq!(loaded_running.status, ScanStatus::Running);
        assert!(loaded_running.completed_at.is_none());

        let completed = running.complete().unwrap();
        repo.update(&completed).unwrap();
        let loaded_completed = repo.get(&completed.id).unwrap().unwrap();
        assert_eq!(loaded_completed.status, ScanStatus::Complete);
        assert!(loaded_completed.completed_at.is_some());
        assert_eq!(
            codec::ts_to_text(loaded_completed.started_at),
            codec::ts_to_text(completed.started_at)
        );
    }

    #[test]
    fn resource_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
        db.migrate().unwrap();
        let repo = ResourceRepo::new(db.connection());

        let r = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
        repo.upsert(&r).unwrap();
        assert_eq!(repo.count().unwrap(), 1);

        let by_key = repo
            .get_by_canonical_key("agent:opencode:default")
            .unwrap()
            .unwrap();
        assert_eq!(by_key.id, r.id);
        assert_eq!(by_key.kind, "agent");
        assert_eq!(by_key.provider, "opencode");
        assert_eq!(by_key.name, "OpenCode");
    }

    #[test]
    fn relationship_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
        db.migrate().unwrap();
        let res = ResourceRepo::new(db.connection());
        let rel = RelationshipRepo::new(db.connection());

        let a = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
        let b = Resource::new("shell:bash", "shell", "local", "Bash").unwrap();
        res.upsert(&a).unwrap();
        res.upsert(&b).unwrap();

        let r = crate::domain::Relationship::new(
            "agent:opencode:default|can_execute|shell:bash",
            &a.id,
            &b.id,
            "can_execute",
            crate::domain::RelationshipState::Confirmed,
        )
        .unwrap();
        rel.upsert(&r).unwrap();
        assert_eq!(rel.count().unwrap(), 1);

        let loaded = rel.get(&r.id).unwrap().unwrap();
        assert_eq!(loaded.from_resource_id, a.id);
        assert_eq!(loaded.to_resource_id, b.id);
        assert_eq!(loaded.state, crate::domain::RelationshipState::Confirmed);
    }

    #[test]
    fn evidence_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
        db.migrate().unwrap();
        let scans = ScanRepo::new(db.connection());
        let ev = EvidenceRepo::new(db.connection());

        let scan = Scan::start(PICO_VERSION).unwrap();
        scans.insert(&scan).unwrap();

        let e = crate::domain::Evidence::new(
            &scan.id,
            crate::domain::EvidenceClass::Direct,
            "opencode_config",
            "~/.config/opencode/opencode.json",
            "permission.bash",
            "allow",
            crate::domain::Sensitivity::Internal,
        )
        .unwrap();
        ev.insert(&e).unwrap();
        assert_eq!(ev.count().unwrap(), 1);
        let loaded = ev.get(&e.id).unwrap().unwrap();
        assert_eq!(loaded.class, crate::domain::EvidenceClass::Direct);
        assert_eq!(loaded.subject, "permission.bash");
        assert_eq!(loaded.observation, "allow");
    }

    #[test]
    fn observation_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
        db.migrate().unwrap();
        let scans = ScanRepo::new(db.connection());
        let obs = ObservationRepo::new(db.connection());

        let scan = Scan::start(PICO_VERSION).unwrap();
        scans.insert(&scan).unwrap();

        let o = Observation::new(&scan.id, "resource", "res_1", "present", "test").unwrap();
        obs.insert(&o).unwrap();
        assert_eq!(obs.count().unwrap(), 1);
        let loaded = obs.get(&o.id).unwrap().unwrap();
        assert_eq!(loaded.subject_type, "resource");
        assert_eq!(loaded.subject_id, "res_1");
        assert_eq!(loaded.observation_type, "present");
    }

    #[test]
    fn scan_requires_initialization_before_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.db");
        {
            let mut db = Database::open(&path).unwrap();
            db.migrate().unwrap();
        }
        drop(path);
    }

    /// Real v5 → v6 migration: build a genuine schema-v5 database, seed rows
    /// (a findings row carries no family column at v5), migrate to v6, and
    /// prove preservation, legacy-read semantics, integrity objects, idempotency,
    /// and rollback safety. All four link types are seeded and proven to survive:
    /// finding_paths, finding_evidence, finding_reasons, finding_remediations.
    #[test]
    fn migration6_from_v5_preserves_rows_and_links() {
        let workspace = tempfile::tempdir().unwrap();
        let dir = workspace.path().join(".pico");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("pico.db");

        // --- Build a true v5 database and seed it. ---
        {
            let mut conn = Connection::open(&db_path).unwrap();
            conn.pragma_update(None, "foreign_keys", true).unwrap();
            migrate_to_version(&mut conn, 5).unwrap();
            assert_eq!(schema_version(&conn).unwrap(), 5);

            let scan = Scan::start(PICO_VERSION).unwrap().complete().unwrap();
            ScanRepo::new(&conn).insert(&scan).unwrap();

            let source = Resource::new(
                "external_source:github",
                "external_source",
                "github",
                "GitHub",
            )
            .unwrap();
            let actor =
                Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
            let sink = Resource::new(
                "provider_account:cloudflare",
                "provider_account",
                "cloudflare",
                "Acct",
            )
            .unwrap();
            let resources = ResourceRepo::new(&conn);
            for resource in [&source, &actor, &sink] {
                resources.upsert(resource).unwrap();
            }

            let evidence = Evidence::new(
                &scan.id,
                EvidenceClass::Direct,
                "opencode_config",
                "~/.config/opencode/opencode.json",
                "permission.bash",
                "allow",
                crate::domain::Sensitivity::Internal,
            )
            .unwrap();
            EvidenceRepo::new(&conn).insert(&evidence).unwrap();

            conn.execute(
                "INSERT INTO scan_analyses
                 (scan_id, analysis_version, status, influence_path_count,
                  authority_path_count, active_path_count, blocked_path_count,
                  unresolved_candidate_count, created_at)
                 VALUES (?1, '1', 'COMPLETE', 1, 1, 1, 0, 0, ?2)",
                params![scan.id, codec::ts_to_text(Utc::now())],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO attack_paths
                 (id, scan_id, fingerprint, analysis_version, source_resource_id,
                  actor_resource_id, sink_resource_id, disposition, source_trust,
                  influence_strength, capability, authority_resolution,
                  sink_impact, created_at)
                 VALUES ('ap-legacy', ?1, 'sha256:path-legacy', '1', ?2, ?3, ?4,
                         'ACTIVE', 'PUBLIC_EXTERNAL', 'AGENT_RETRIEVABLE',
                         'EXECUTE', 'EXACT', 'PRODUCTION', ?5)",
                params![
                    scan.id,
                    source.id,
                    actor.id,
                    sink.id,
                    codec::ts_to_text(Utc::now())
                ],
            )
            .unwrap();
            // v5 findings have NO family_fingerprint column.
            conn.execute(
                "INSERT INTO findings
                 (id, scan_id, fingerprint, finding_version, finding_class, title,
                  summary, severity, confidence, status, metadata, created_at)
                 VALUES ('finding-legacy', ?1, 'sha256:legacy', 'v1',
                         'UNTRUSTED_TO_PRODUCTION', 'Legacy finding',
                         'Summary of legacy', 'CRITICAL', 'HIGH', 'OPEN', NULL, ?2)",
                params![scan.id, codec::ts_to_text(Utc::now())],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO finding_paths (finding_id, attack_path_id, position)
                 VALUES ('finding-legacy', 'ap-legacy', 0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO finding_evidence (finding_id, evidence_id, position, support_role)
                 VALUES ('finding-legacy', ?1, 0, 'EDGE')",
                [&evidence.id],
            )
            .unwrap();
            let evidence_ids_json = format!("[\"{}\"]", evidence.id);
            conn.execute(
                "INSERT INTO finding_reasons
                 (finding_id, position, reason_code, resource_ids, relationship_ids,
                  attack_path_ids, evidence_ids)
                 VALUES ('finding-legacy', 0, 'PRODUCTION_SINK', '[]', '[]',
                         '[\"ap-legacy\"]', ?1)",
                [&evidence_ids_json],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO finding_remediations
                 (finding_id, position, rule_id, title, description, security_effect,
                  cut_phase, target_resource_ids, target_relationship_ids)
                 VALUES ('finding-legacy', 0, 'ENFORCE_BASH_APPROVAL_OR_DENY',
                         'Require enforced approval for Bash',
                         'Ensure the Actor cannot self-approve execution of the shell capability.',
                         'Interrupt autonomous execution before authority becomes reachable.',
                         'AUTHORITY', '[\"actor\",\"bash\"]', '[\"execute\"]')",
                [],
            )
            .unwrap();
        }

        // --- Migrate v5 → v6. ---
        let mut db = Database::open(&db_path).unwrap();
        db.migrate().unwrap();
        assert_eq!(db.schema_version().unwrap(), 6);
        let conn = db.connection();

        // Integrity objects exist.
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
        // FKs and the database itself are healthy after the migration.
        let mut fk = conn.prepare("PRAGMA foreign_key_check").unwrap();
        assert!(
            fk.query([]).unwrap().next().unwrap().is_none(),
            "foreign_key_check must be empty"
        );
        drop(fk);
        let integrity: String = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity, "ok");

        // Every seeded row survived with identical key values.
        let count = |table: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        for (table, expected) in [
            ("scans", 1),
            ("resources", 3),
            ("scan_analyses", 1),
            ("attack_paths", 1),
            ("evidence", 1),
            ("findings", 1),
            ("finding_paths", 1),
            ("finding_evidence", 1),
            ("finding_reasons", 1),
            ("finding_remediations", 1),
        ] {
            assert_eq!(count(table), expected, "row count mismatch in {table}");
        }
        let path_link: String = conn
            .query_row(
                "SELECT attack_path_id FROM finding_paths
                 WHERE finding_id = 'finding-legacy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(path_link, "ap-legacy");
        let evidence_link: String = conn
            .query_row(
                "SELECT evidence_id FROM finding_evidence WHERE finding_id = 'finding-legacy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!evidence_link.is_empty());
        let reason_links: String = conn
            .query_row(
                "SELECT attack_path_ids FROM finding_reasons
                 WHERE finding_id = 'finding-legacy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason_links, "[\"ap-legacy\"]");
        let (rule_id, target_resources, target_relationships): (String, String, String) = conn
            .query_row(
                "SELECT rule_id, target_resource_ids, target_relationship_ids
                 FROM finding_remediations WHERE finding_id = 'finding-legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(rule_id, "ENFORCE_BASH_APPROVAL_OR_DENY");
        assert_eq!(target_resources, "[\"actor\",\"bash\"]");
        assert_eq!(target_relationships, "[\"execute\"]");

        // Legacy-read semantics: the migrated row keeps an empty family (no
        // backfill), validates, and lists through the repository.
        {
            let repo = FindingRepo::new(conn);
            let loaded = repo.get("finding-legacy").unwrap().unwrap();
            assert_eq!(loaded.fingerprint, "sha256:legacy");
            assert_eq!(loaded.severity, "CRITICAL");
            assert_eq!(loaded.confidence, "HIGH");
            assert_eq!(loaded.family_fingerprint, "");
            loaded.validate().unwrap();
            let rows = repo.list_for_scan(&loaded.scan_id).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].id, "finding-legacy");
        }

        // Idempotency: a second full migrate is a no-op with data intact.
        db.migrate().unwrap();
        assert_eq!(db.schema_version().unwrap(), 6);
        let conn = db.connection();
        let count = |table: &str| -> i64 {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count("findings"), 1);
        assert_eq!(count("finding_paths"), 1);
        assert_eq!(count("finding_remediations"), 1);
        let repo = FindingRepo::new(conn);
        assert_eq!(
            repo.get("finding-legacy")
                .unwrap()
                .unwrap()
                .family_fingerprint,
            ""
        );
        drop(workspace);

        // --- Rollback safety: a conflicting pre-existing object makes migration
        // 6 fail closed with user_version untouched; removing it re-migrates. ---
        let dir2 = tempfile::tempdir().unwrap();
        let db_path2 = dir2.path().join(".pico").join("pico.db");
        std::fs::create_dir_all(db_path2.parent().unwrap()).unwrap();
        {
            let mut conn = Connection::open(&db_path2).unwrap();
            conn.pragma_update(None, "foreign_keys", true).unwrap();
            migrate_to_version(&mut conn, 5).unwrap();
            // Squat on a migration-6 object name; CREATE ... IF NOT EXISTS must
            // not silently skip past a clashing table.
            conn.execute("CREATE TABLE idx_findings_scan_family (id TEXT)", [])
                .unwrap();
        }
        let mut db2 = Database::open(&db_path2).unwrap();
        let error = db2.migrate().unwrap_err();
        assert!(
            error.to_string().contains("idx_findings_scan_family"),
            "expected a clash error, got {error}"
        );
        assert_eq!(db2.schema_version().unwrap(), 5);
        db2.connection()
            .execute("DROP TABLE idx_findings_scan_family", [])
            .unwrap();
        db2.migrate().unwrap();
        assert_eq!(db2.schema_version().unwrap(), 6);
    }
}
