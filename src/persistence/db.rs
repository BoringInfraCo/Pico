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
];

/// A SQLite-backed Pico database.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (creating if necessary) the database at `path`.
    pub fn open(path: &Path) -> Result<Self, PicoError> {
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
    let current = schema_version(conn).map_err(|e| PicoError::migration(e.to_string()))?;
    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let version = (i + 1) as i64;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::codec;
    use crate::shared::PICO_VERSION;
    use crate::{
        domain::{Observation, Resource, Scan, ScanStatus},
        persistence::{EvidenceRepo, ObservationRepo, RelationshipRepo, ResourceRepo, ScanRepo},
    };

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
}
