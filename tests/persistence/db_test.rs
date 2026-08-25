//! Database lifecycle: fresh initialization, migration idempotency,
//! reopen, and schema tables.

use pico::domain::Scan;
use pico::persistence::{Database, ScanRepo};
use pico::shared::{PicoError, PICO_VERSION};
use tempfile::tempdir;

#[test]
fn fresh_database_initializes_to_schema_version_2() {
    let dir = tempdir().unwrap();
    let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
    db.migrate().unwrap();
    assert_eq!(db.schema_version().unwrap(), 2);
}

#[test]
fn migration_is_idempotent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pico.db");
    let mut db = Database::open(&path).unwrap();
    db.migrate().unwrap();
    assert_eq!(db.schema_version().unwrap(), 2);
    db.migrate().unwrap();
    assert_eq!(db.schema_version().unwrap(), 2);
}

#[test]
fn database_reopens_and_scan_survives() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pico.db");
    {
        let mut db = Database::open(&path).unwrap();
        db.migrate().unwrap();
        let scan = Scan::start(PICO_VERSION).unwrap();
        ScanRepo::new(db.connection()).insert(&scan).unwrap();
        assert_eq!(ScanRepo::new(db.connection()).count().unwrap(), 1);
    }
    {
        let mut db = Database::open(&path).unwrap();
        db.migrate().unwrap();
        let repo = ScanRepo::new(db.connection());
        assert_eq!(repo.count().unwrap(), 1);
        let loaded = repo.list().unwrap().remove(0);
        assert_eq!(loaded.status, pico::domain::ScanStatus::Running);
    }
}

#[test]
fn schema_tables_exist() {
    let dir = tempdir().unwrap();
    let mut db = Database::open(&dir.path().join("pico.db")).unwrap();
    db.migrate().unwrap();
    for table in [
        "scans",
        "resources",
        "relationships",
        "observations",
        "evidence",
        "relationship_evidence",
    ] {
        let name: String = db
            .connection()
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, table);
    }
}

#[test]
fn open_existing_fails_when_database_missing() {
    let dir = tempdir().unwrap();
    let err = Database::open_existing(&dir.path().join("pico.db"))
        .err()
        .unwrap();
    assert!(matches!(err, PicoError::Scan(_)));
}
