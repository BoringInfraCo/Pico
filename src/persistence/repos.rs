//! Repositories for the observed-domain types.

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::domain::{Evidence, Observation, Relationship, Resource, Scan};
use crate::persistence::codec;
use std::str::FromStr;

use crate::shared::PicoError;

/// Map a repository row error to a database failure.
fn db_err(e: rusqlite::Error) -> PicoError {
    PicoError::Database(e.to_string())
}

/// Repository for `Scan` records.
pub struct ScanRepo<'a> {
    conn: &'a Connection,
}

impl<'a> ScanRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        ScanRepo { conn }
    }

    /// Persist a scan (insert).
    pub fn insert(&self, scan: &Scan) -> Result<(), PicoError> {
        self.conn
            .execute(
                "INSERT INTO scans
                 (id, started_at, completed_at, status, trigger, scope,
                  pico_version, environment_fingerprint, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    scan.id,
                    codec::ts_to_text(scan.started_at),
                    scan.completed_at.map(codec::ts_to_text),
                    scan.status.as_str(),
                    scan.trigger.as_str(),
                    codec::opt_json_to_text(&scan.scope),
                    scan.pico_version,
                    scan.environment_fingerprint,
                    codec::opt_json_to_text(&scan.metadata),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Update a scan's mutable completion state.
    pub fn update(&self, scan: &Scan) -> Result<(), PicoError> {
        let changed = self
            .conn
            .execute(
                "UPDATE scans
                 SET completed_at = ?1, status = ?2, scope = ?3,
                     environment_fingerprint = ?4, metadata = ?5
                 WHERE id = ?6",
                params![
                    scan.completed_at.map(codec::ts_to_text),
                    scan.status.as_str(),
                    codec::opt_json_to_text(&scan.scope),
                    scan.environment_fingerprint,
                    codec::opt_json_to_text(&scan.metadata),
                    scan.id,
                ],
            )
            .map_err(db_err)?;
        if changed == 0 {
            return Err(PicoError::Database(format!(
                "scan {} does not exist",
                scan.id
            )));
        }
        Ok(())
    }

    /// Load a scan by id.
    pub fn get(&self, id: &str) -> Result<Option<Scan>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, started_at, completed_at, status, trigger, scope,
                        pico_version, environment_fingerprint, metadata
                 FROM scans WHERE id = ?1",
                [id],
                row_to_scan,
            )
            .optional()
            .map_err(db_err)
    }

    /// List all scans ordered by start time.
    pub fn list(&self) -> Result<Vec<Scan>, PicoError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, started_at, completed_at, status, trigger, scope,
                        pico_version, environment_fingerprint, metadata
                 FROM scans ORDER BY started_at",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], row_to_scan)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }

    /// Count all scans.
    pub fn count(&self) -> Result<u64, PicoError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }
}

fn row_to_scan(row: &Row<'_>) -> rusqlite::Result<Scan> {
    let completed_at: Option<String> = row.get(2)?;
    let scope: Option<String> = row.get(5)?;
    let env_fp: Option<String> = row.get(7)?;
    let metadata: Option<String> = row.get(8)?;
    Ok(Scan {
        id: row.get(0)?,
        started_at: codec::text_to_ts(&row.get::<_, String>(1)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        completed_at: completed_at
            .map(|t| codec::text_to_ts(&t))
            .transpose()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        status: crate::domain::ScanStatus::from_str(&row.get::<_, String>(3)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        trigger: crate::domain::ScanTrigger::from_str(&row.get::<_, String>(4)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        scope: codec::text_to_opt_json(scope),
        pico_version: row.get(6)?,
        environment_fingerprint: env_fp,
        metadata: codec::text_to_opt_json(metadata),
    })
}

/// Repository for `Resource` records.
pub struct ResourceRepo<'a> {
    conn: &'a Connection,
}

impl<'a> ResourceRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        ResourceRepo { conn }
    }

    /// Insert or update a resource by canonical key. The first
    /// observation time is preserved; the last is refreshed.
    pub fn upsert(&self, r: &Resource) -> Result<(), PicoError> {
        self.conn
            .execute(
                "INSERT INTO resources
                 (id, canonical_key, kind, provider, name, metadata,
                  first_observed_at, last_observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(canonical_key) DO UPDATE SET
                   kind = excluded.kind,
                   provider = excluded.provider,
                   name = excluded.name,
                   metadata = excluded.metadata,
                   last_observed_at = excluded.last_observed_at",
                params![
                    r.id,
                    r.canonical_key,
                    r.kind,
                    r.provider,
                    r.name,
                    codec::opt_json_to_text(&r.metadata),
                    codec::ts_to_text(r.first_observed_at),
                    codec::ts_to_text(r.last_observed_at),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Load a resource by id.
    pub fn get(&self, id: &str) -> Result<Option<Resource>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, canonical_key, kind, provider, name, metadata,
                        first_observed_at, last_observed_at
                 FROM resources WHERE id = ?1",
                [id],
                row_to_resource,
            )
            .optional()
            .map_err(db_err)
    }

    /// Load a resource by canonical key.
    pub fn get_by_canonical_key(&self, key: &str) -> Result<Option<Resource>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, canonical_key, kind, provider, name, metadata,
                        first_observed_at, last_observed_at
                 FROM resources WHERE canonical_key = ?1",
                [key],
                row_to_resource,
            )
            .optional()
            .map_err(db_err)
    }

    /// Count all resources.
    pub fn count(&self) -> Result<u64, PicoError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM resources", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }
}

fn row_to_resource(row: &Row<'_>) -> rusqlite::Result<Resource> {
    Ok(Resource {
        id: row.get(0)?,
        canonical_key: row.get(1)?,
        kind: row.get(2)?,
        provider: row.get(3)?,
        name: row.get(4)?,
        metadata: codec::text_to_opt_json(row.get(5)?),
        first_observed_at: codec::text_to_ts(&row.get::<_, String>(6)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        last_observed_at: codec::text_to_ts(&row.get::<_, String>(7)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
    })
}

/// Repository for `Relationship` records.
pub struct RelationshipRepo<'a> {
    conn: &'a Connection,
}

impl<'a> RelationshipRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        RelationshipRepo { conn }
    }

    /// Insert or update a relationship by canonical key, preserving
    /// first observation time.
    pub fn upsert(&self, r: &Relationship) -> Result<(), PicoError> {
        self.conn
            .execute(
                "INSERT INTO relationships
                 (id, canonical_key, from_resource_id, to_resource_id, kind,
                  state, metadata, first_observed_at, last_observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(canonical_key) DO UPDATE SET
                   from_resource_id = excluded.from_resource_id,
                   to_resource_id = excluded.to_resource_id,
                   kind = excluded.kind,
                   state = excluded.state,
                   metadata = excluded.metadata,
                   last_observed_at = excluded.last_observed_at",
                params![
                    r.id,
                    r.canonical_key,
                    r.from_resource_id,
                    r.to_resource_id,
                    r.kind,
                    r.state.as_str(),
                    codec::opt_json_to_text(&r.metadata),
                    codec::ts_to_text(r.first_observed_at),
                    codec::ts_to_text(r.last_observed_at),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Load a relationship by id.
    pub fn get(&self, id: &str) -> Result<Option<Relationship>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, canonical_key, from_resource_id, to_resource_id,
                        kind, state, metadata, first_observed_at, last_observed_at
                 FROM relationships WHERE id = ?1",
                [id],
                row_to_relationship,
            )
            .optional()
            .map_err(db_err)
    }

    /// Count all relationships.
    pub fn count(&self) -> Result<u64, PicoError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }
}

fn row_to_relationship(row: &Row<'_>) -> rusqlite::Result<Relationship> {
    Ok(Relationship {
        id: row.get(0)?,
        canonical_key: row.get(1)?,
        from_resource_id: row.get(2)?,
        to_resource_id: row.get(3)?,
        kind: row.get(4)?,
        state: crate::domain::RelationshipState::from_str(&row.get::<_, String>(5)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        metadata: codec::text_to_opt_json(row.get(6)?),
        first_observed_at: codec::text_to_ts(&row.get::<_, String>(7)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        last_observed_at: codec::text_to_ts(&row.get::<_, String>(8)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
    })
}

/// Repository for `Evidence` records.
pub struct EvidenceRepo<'a> {
    conn: &'a Connection,
}

impl<'a> EvidenceRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        EvidenceRepo { conn }
    }

    /// Append an evidence record.
    pub fn insert(&self, e: &Evidence) -> Result<(), PicoError> {
        self.conn
            .execute(
                "INSERT INTO evidence
                 (id, scan_id, class, source_type, source_locator, subject,
                  observation, captured_at, freshness, sensitivity, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    e.id,
                    e.scan_id,
                    e.class.as_str(),
                    e.source_type,
                    e.source_locator,
                    e.subject,
                    e.observation,
                    codec::ts_to_text(e.captured_at),
                    e.freshness,
                    e.sensitivity.as_str(),
                    codec::opt_json_to_text(&e.metadata),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Load an evidence record by id.
    pub fn get(&self, id: &str) -> Result<Option<Evidence>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, scan_id, class, source_type, source_locator,
                        subject, observation, captured_at, freshness,
                        sensitivity, metadata
                 FROM evidence WHERE id = ?1",
                [id],
                row_to_evidence,
            )
            .optional()
            .map_err(db_err)
    }

    /// Count all evidence records.
    pub fn count(&self) -> Result<u64, PicoError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM evidence", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }
}

fn row_to_evidence(row: &Row<'_>) -> rusqlite::Result<Evidence> {
    Ok(Evidence {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        class: crate::domain::EvidenceClass::from_str(&row.get::<_, String>(2)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        source_type: row.get(3)?,
        source_locator: row.get(4)?,
        subject: row.get(5)?,
        observation: row.get(6)?,
        captured_at: codec::text_to_ts(&row.get::<_, String>(7)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        freshness: row.get(8)?,
        sensitivity: crate::domain::Sensitivity::from_str(&row.get::<_, String>(9)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        metadata: codec::text_to_opt_json(row.get(10)?),
    })
}

/// Repository for `Observation` records.
pub struct ObservationRepo<'a> {
    conn: &'a Connection,
}

impl<'a> ObservationRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        ObservationRepo { conn }
    }

    /// Append an observation record.
    pub fn insert(&self, o: &Observation) -> Result<(), PicoError> {
        self.conn
            .execute(
                "INSERT INTO observations
                 (id, scan_id, subject_type, subject_id, observation_type,
                  observed_at, source, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    o.id,
                    o.scan_id,
                    o.subject_type,
                    o.subject_id,
                    o.observation_type,
                    codec::ts_to_text(o.observed_at),
                    o.source,
                    codec::opt_json_to_text(&o.metadata),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Load an observation record by id.
    pub fn get(&self, id: &str) -> Result<Option<Observation>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, scan_id, subject_type, subject_id, observation_type,
                        observed_at, source, metadata
                 FROM observations WHERE id = ?1",
                [id],
                row_to_observation,
            )
            .optional()
            .map_err(db_err)
    }

    /// Count all observation records.
    pub fn count(&self) -> Result<u64, PicoError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM observations", [], |r| r.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }
}

fn row_to_observation(row: &Row<'_>) -> rusqlite::Result<Observation> {
    Ok(Observation {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        subject_type: row.get(2)?,
        subject_id: row.get(3)?,
        observation_type: row.get(4)?,
        observed_at: codec::text_to_ts(&row.get::<_, String>(5)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
        source: row.get(6)?,
        metadata: codec::text_to_opt_json(row.get(7)?),
    })
}
