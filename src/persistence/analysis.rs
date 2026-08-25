//! Persistence contracts for deterministic Sprint 008 analysis results.
//!
//! These records intentionally contain normalized provider-neutral values only.
//! The analysis layer owns their semantic construction; this module owns the
//! SQLite shape, foreign-key checks, ordering, and round-trip codecs.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::Value;

use crate::persistence::codec;
use crate::shared::PicoError;

fn db_err(error: rusqlite::Error) -> PicoError {
    PicoError::Database(error.to_string())
}

fn json_text(value: &Option<Value>) -> Option<String> {
    codec::opt_json_to_text(value)
}

fn parse_json(value: Option<String>) -> Option<Value> {
    codec::text_to_opt_json(value)
}

/// One deterministic analysis attempt for a Scan.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanAnalysisRecord {
    pub scan_id: String,
    pub analysis_version: String,
    pub status: String,
    pub overall_disposition: Option<String>,
    pub influence_path_count: u64,
    pub authority_path_count: u64,
    pub active_path_count: u64,
    pub blocked_path_count: u64,
    pub unresolved_candidate_count: u64,
    pub limit_reasons: Option<Value>,
    pub diagnostics: Option<Value>,
    pub created_at: DateTime<Utc>,
}

impl ScanAnalysisRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        if self.scan_id.trim().is_empty() || self.analysis_version.trim().is_empty() {
            return Err(PicoError::database(
                "analysis scan_id and version are required",
            ));
        }
        if !matches!(self.status.as_str(), "COMPLETE" | "LIMITED" | "FAILED") {
            return Err(PicoError::database(format!(
                "unsupported analysis status {}",
                self.status
            )));
        }
        if let Some(disposition) = self.overall_disposition.as_deref() {
            if !matches!(
                disposition,
                "ACTIVE_PRESENT" | "UNRESOLVED_PRESENT" | "BLOCKED_ONLY" | "NONE"
            ) {
                return Err(PicoError::database(format!(
                    "unsupported analysis disposition {disposition}"
                )));
            }
        }
        Ok(())
    }
}

/// A persisted ACTIVE or BLOCKED path. UNRESOLVED and NONE are represented by
/// the scan analysis summary and intentionally have no AttackPath row.
#[derive(Debug, Clone, PartialEq)]
pub struct AttackPathRecord {
    pub id: String,
    pub scan_id: String,
    pub fingerprint: String,
    pub analysis_version: String,
    pub source_resource_id: String,
    pub actor_resource_id: String,
    pub sink_resource_id: String,
    pub disposition: String,
    pub source_trust: String,
    pub influence_strength: String,
    pub capability: String,
    pub authority_resolution: String,
    pub sink_impact: String,
    pub boundary_metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

impl AttackPathRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        for (label, value) in [
            ("id", &self.id),
            ("scan_id", &self.scan_id),
            ("fingerprint", &self.fingerprint),
            ("analysis_version", &self.analysis_version),
            ("source_resource_id", &self.source_resource_id),
            ("actor_resource_id", &self.actor_resource_id),
            ("sink_resource_id", &self.sink_resource_id),
        ] {
            if value.trim().is_empty() {
                return Err(PicoError::database(format!("{label} is required")));
            }
        }
        if self.source_resource_id == self.actor_resource_id
            || self.actor_resource_id == self.sink_resource_id
            || self.source_resource_id == self.sink_resource_id
        {
            return Err(PicoError::database(
                "attack path endpoints must be distinct",
            ));
        }
        if !matches!(self.disposition.as_str(), "ACTIVE" | "BLOCKED") {
            return Err(PicoError::database(format!(
                "unsupported attack path disposition {}",
                self.disposition
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackPathEdgeRecord {
    pub attack_path_id: String,
    pub relationship_id: String,
    pub position: u32,
    pub phase: String,
    pub traversal: String,
}

impl AttackPathEdgeRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        if self.attack_path_id.trim().is_empty() || self.relationship_id.trim().is_empty() {
            return Err(PicoError::database(
                "attack path edge identifiers are required",
            ));
        }
        if !matches!(self.phase.as_str(), "INFLUENCE" | "AUTHORITY") {
            return Err(PicoError::database(format!(
                "unsupported attack path edge phase {}",
                self.phase
            )));
        }
        if !matches!(self.traversal.as_str(), "FORWARD" | "REVERSE") {
            return Err(PicoError::database(format!(
                "unsupported attack path traversal {}",
                self.traversal
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackPathEvidenceRecord {
    pub attack_path_id: String,
    pub evidence_id: String,
    pub position: u32,
    pub support_role: String,
}

impl AttackPathEvidenceRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        if self.attack_path_id.trim().is_empty() || self.evidence_id.trim().is_empty() {
            return Err(PicoError::database(
                "attack path evidence identifiers are required",
            ));
        }
        if !matches!(self.support_role.as_str(), "EDGE" | "BOUNDARY") {
            return Err(PicoError::database(format!(
                "unsupported attack path evidence role {}",
                self.support_role
            )));
        }
        Ok(())
    }
}

pub struct ScanAnalysisRepo<'a> {
    conn: &'a Connection,
}

impl<'a> ScanAnalysisRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Each analyzed scan has one summary row; rerunning replaces the summary
    /// while AttackPath rows remain append-oriented.
    pub fn upsert(&self, record: &ScanAnalysisRecord) -> Result<(), PicoError> {
        record.validate()?;
        self.conn
            .execute(
                "INSERT INTO scan_analyses
                 (scan_id, analysis_version, status, overall_disposition,
                  influence_path_count, authority_path_count, active_path_count,
                  blocked_path_count, unresolved_candidate_count, limit_reasons,
                  diagnostics, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(scan_id) DO UPDATE SET
                   analysis_version = excluded.analysis_version,
                   status = excluded.status,
                   overall_disposition = excluded.overall_disposition,
                   influence_path_count = excluded.influence_path_count,
                   authority_path_count = excluded.authority_path_count,
                   active_path_count = excluded.active_path_count,
                   blocked_path_count = excluded.blocked_path_count,
                   unresolved_candidate_count = excluded.unresolved_candidate_count,
                   limit_reasons = excluded.limit_reasons,
                   diagnostics = excluded.diagnostics,
                   created_at = excluded.created_at",
                params![
                    record.scan_id,
                    record.analysis_version,
                    record.status,
                    record.overall_disposition,
                    record.influence_path_count,
                    record.authority_path_count,
                    record.active_path_count,
                    record.blocked_path_count,
                    record.unresolved_candidate_count,
                    json_text(&record.limit_reasons),
                    json_text(&record.diagnostics),
                    codec::ts_to_text(record.created_at),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn get(&self, scan_id: &str) -> Result<Option<ScanAnalysisRecord>, PicoError> {
        self.conn
            .query_row(
                "SELECT scan_id, analysis_version, status, overall_disposition,
                        influence_path_count, authority_path_count, active_path_count,
                        blocked_path_count, unresolved_candidate_count, limit_reasons,
                        diagnostics, created_at
                 FROM scan_analyses WHERE scan_id = ?1",
                [scan_id],
                row_to_scan_analysis,
            )
            .optional()
            .map_err(db_err)
    }
}

fn row_to_scan_analysis(row: &Row<'_>) -> rusqlite::Result<ScanAnalysisRecord> {
    Ok(ScanAnalysisRecord {
        scan_id: row.get(0)?,
        analysis_version: row.get(1)?,
        status: row.get(2)?,
        overall_disposition: row.get(3)?,
        influence_path_count: row.get::<_, i64>(4)? as u64,
        authority_path_count: row.get::<_, i64>(5)? as u64,
        active_path_count: row.get::<_, i64>(6)? as u64,
        blocked_path_count: row.get::<_, i64>(7)? as u64,
        unresolved_candidate_count: row.get::<_, i64>(8)? as u64,
        limit_reasons: parse_json(row.get(9)?),
        diagnostics: parse_json(row.get(10)?),
        created_at: codec::text_to_ts(&row.get::<_, String>(11)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
    })
}

pub struct AttackPathRepo<'a> {
    conn: &'a Connection,
}

impl<'a> AttackPathRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn insert(&self, path: &AttackPathRecord) -> Result<(), PicoError> {
        path.validate()?;
        self.conn
            .execute(
                "INSERT INTO attack_paths
                 (id, scan_id, fingerprint, analysis_version, source_resource_id,
                  actor_resource_id, sink_resource_id, disposition, source_trust,
                  influence_strength, capability, authority_resolution, sink_impact,
                  boundary_metadata, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    path.id,
                    path.scan_id,
                    path.fingerprint,
                    path.analysis_version,
                    path.source_resource_id,
                    path.actor_resource_id,
                    path.sink_resource_id,
                    path.disposition,
                    path.source_trust,
                    path.influence_strength,
                    path.capability,
                    path.authority_resolution,
                    path.sink_impact,
                    json_text(&path.boundary_metadata),
                    codec::ts_to_text(path.created_at),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<AttackPathRecord>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, scan_id, fingerprint, analysis_version,
                        source_resource_id, actor_resource_id, sink_resource_id,
                        disposition, source_trust, influence_strength, capability,
                        authority_resolution, sink_impact, boundary_metadata, created_at
                 FROM attack_paths WHERE id = ?1",
                [id],
                row_to_attack_path,
            )
            .optional()
            .map_err(db_err)
    }

    pub fn list_for_scan(&self, scan_id: &str) -> Result<Vec<AttackPathRecord>, PicoError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, scan_id, fingerprint, analysis_version,
                        source_resource_id, actor_resource_id, sink_resource_id,
                        disposition, source_trust, influence_strength, capability,
                        authority_resolution, sink_impact, boundary_metadata, created_at
                 FROM attack_paths WHERE scan_id = ?1 ORDER BY fingerprint, id",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([scan_id], row_to_attack_path)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        rows
    }

    pub fn insert_edge(&self, edge: &AttackPathEdgeRecord) -> Result<(), PicoError> {
        edge.validate()?;
        self.conn
            .execute(
                "INSERT INTO attack_path_edges
                 (attack_path_id, relationship_id, position, phase, traversal)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    edge.attack_path_id,
                    edge.relationship_id,
                    edge.position,
                    edge.phase,
                    edge.traversal,
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_edges(&self, attack_path_id: &str) -> Result<Vec<AttackPathEdgeRecord>, PicoError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT attack_path_id, relationship_id, position, phase, traversal
                 FROM attack_path_edges WHERE attack_path_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([attack_path_id], row_to_attack_path_edge)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        rows
    }

    pub fn insert_evidence(&self, item: &AttackPathEvidenceRecord) -> Result<(), PicoError> {
        item.validate()?;
        self.conn
            .execute(
                "INSERT INTO attack_path_evidence
                 (attack_path_id, evidence_id, position, support_role)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    item.attack_path_id,
                    item.evidence_id,
                    item.position,
                    item.support_role
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_evidence(
        &self,
        attack_path_id: &str,
    ) -> Result<Vec<AttackPathEvidenceRecord>, PicoError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT attack_path_id, evidence_id, position, support_role
                 FROM attack_path_evidence WHERE attack_path_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([attack_path_id], row_to_attack_path_evidence)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        rows
    }
}

fn row_to_attack_path(row: &Row<'_>) -> rusqlite::Result<AttackPathRecord> {
    Ok(AttackPathRecord {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        analysis_version: row.get(3)?,
        source_resource_id: row.get(4)?,
        actor_resource_id: row.get(5)?,
        sink_resource_id: row.get(6)?,
        disposition: row.get(7)?,
        source_trust: row.get(8)?,
        influence_strength: row.get(9)?,
        capability: row.get(10)?,
        authority_resolution: row.get(11)?,
        sink_impact: row.get(12)?,
        boundary_metadata: parse_json(row.get(13)?),
        created_at: codec::text_to_ts(&row.get::<_, String>(14)?)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
    })
}

fn row_to_attack_path_edge(row: &Row<'_>) -> rusqlite::Result<AttackPathEdgeRecord> {
    Ok(AttackPathEdgeRecord {
        attack_path_id: row.get(0)?,
        relationship_id: row.get(1)?,
        position: row.get::<_, i64>(2)? as u32,
        phase: row.get(3)?,
        traversal: row.get(4)?,
    })
}

fn row_to_attack_path_evidence(row: &Row<'_>) -> rusqlite::Result<AttackPathEvidenceRecord> {
    Ok(AttackPathEvidenceRecord {
        attack_path_id: row.get(0)?,
        evidence_id: row.get(1)?,
        position: row.get::<_, i64>(2)? as u32,
        support_role: row.get(3)?,
    })
}
