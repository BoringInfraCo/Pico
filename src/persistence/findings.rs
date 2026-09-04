//! Persistence contracts for Sprint 009 Findings.
//!
//! Findings are normalized, scan-scoped projections over completed analysis.
//! This module deliberately stores identifiers and structured values only; it
//! never copies provider configuration or raw evidence observations.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde_json::{json, Value};

use crate::persistence::codec;
use crate::shared::PicoError;

fn db_err(error: rusqlite::Error) -> PicoError {
    PicoError::Database(error.to_string())
}

fn opt_json_text(value: &Option<Value>) -> Option<String> {
    codec::opt_json_to_text(value)
}

fn parse_json(value: Option<String>) -> Option<Value> {
    codec::text_to_opt_json(value)
}

fn list_json(values: &[String]) -> String {
    json!(values).to_string()
}

fn parse_string_list(row: &Row<'_>, index: usize) -> rusqlite::Result<Vec<String>> {
    let text: String = row.get(index)?;
    let value: Value = serde_json::from_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let Some(items) = value.as_array() else {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            "expected JSON array".into(),
        ));
    };
    items
        .iter()
        .map(|item| {
            item.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Text,
                    "expected JSON string array".into(),
                )
            })
        })
        .collect()
}

fn validate_nonempty(fields: &[(&str, &str)]) -> Result<(), PicoError> {
    for (name, value) in fields {
        if value.trim().is_empty() {
            return Err(PicoError::database(format!("{name} is required")));
        }
    }
    Ok(())
}

/// A scan-scoped normalized security Finding.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingRecord {
    pub id: String,
    pub scan_id: String,
    pub fingerprint: String,
    pub finding_version: String,
    pub finding_class: String,
    pub title: String,
    pub summary: String,
    pub severity: String,
    pub confidence: String,
    pub status: String,
    pub metadata: Option<Value>,
    pub created_at: DateTime<Utc>,
}

impl FindingRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        validate_nonempty(&[
            ("id", &self.id),
            ("scan_id", &self.scan_id),
            ("fingerprint", &self.fingerprint),
            ("finding_version", &self.finding_version),
            ("finding_class", &self.finding_class),
            ("title", &self.title),
            ("summary", &self.summary),
            ("severity", &self.severity),
            ("confidence", &self.confidence),
            ("status", &self.status),
        ])?;
        if self.finding_class != "UNTRUSTED_TO_PRODUCTION" {
            return Err(PicoError::database(format!(
                "unsupported finding class {}",
                self.finding_class
            )));
        }
        if !matches!(
            self.severity.as_str(),
            "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        ) {
            return Err(PicoError::database(format!(
                "unsupported finding severity {}",
                self.severity
            )));
        }
        if !matches!(self.confidence.as_str(), "LOW" | "MEDIUM" | "HIGH") {
            return Err(PicoError::database(format!(
                "unsupported finding confidence {}",
                self.confidence
            )));
        }
        if self.status != "OPEN" {
            return Err(PicoError::database(format!(
                "unsupported finding status {}",
                self.status
            )));
        }
        Ok(())
    }
}

/// Ordered reference from a Finding to an AttackPath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPathRecord {
    pub finding_id: String,
    pub attack_path_id: String,
    pub position: u32,
}

impl FindingPathRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        validate_nonempty(&[
            ("finding_id", &self.finding_id),
            ("attack_path_id", &self.attack_path_id),
        ])
    }
}

/// Ordered same-scan evidence reference supporting a Finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingEvidenceRecord {
    pub finding_id: String,
    pub evidence_id: String,
    pub position: u32,
    pub support_role: String,
}

impl FindingEvidenceRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        validate_nonempty(&[
            ("finding_id", &self.finding_id),
            ("evidence_id", &self.evidence_id),
            ("support_role", &self.support_role),
        ])
    }
}

/// Structured reason referencing exact normalized facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingReasonRecord {
    pub finding_id: String,
    pub position: u32,
    pub reason_code: String,
    pub resource_ids: Vec<String>,
    pub relationship_ids: Vec<String>,
    pub attack_path_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
}

impl FindingReasonRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        validate_nonempty(&[
            ("finding_id", &self.finding_id),
            ("reason_code", &self.reason_code),
        ])?;
        if self
            .resource_ids
            .iter()
            .chain(&self.relationship_ids)
            .chain(&self.attack_path_ids)
            .chain(&self.evidence_ids)
            .any(|value| value.trim().is_empty())
        {
            return Err(PicoError::database(
                "reason reference identifiers must be non-empty",
            ));
        }
        Ok(())
    }
}

/// Ordered remediation suggestion and its exact graph cut-point references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRemediationRecord {
    pub finding_id: String,
    pub position: u32,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub security_effect: String,
    pub cut_phase: String,
    pub target_resource_ids: Vec<String>,
    pub target_relationship_ids: Vec<String>,
}

impl FindingRemediationRecord {
    pub fn validate(&self) -> Result<(), PicoError> {
        validate_nonempty(&[
            ("finding_id", &self.finding_id),
            ("rule_id", &self.rule_id),
            ("title", &self.title),
            ("description", &self.description),
            ("security_effect", &self.security_effect),
            ("cut_phase", &self.cut_phase),
        ])?;
        if self
            .target_resource_ids
            .iter()
            .chain(&self.target_relationship_ids)
            .any(|value| value.trim().is_empty())
        {
            return Err(PicoError::database(
                "remediation target identifiers must be non-empty",
            ));
        }
        Ok(())
    }
}

/// Repository for Sprint 009 Finding records and their ordered links.
pub struct FindingRepo<'a> {
    conn: &'a Connection,
}

impl<'a> FindingRepo<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn insert(&self, finding: &FindingRecord) -> Result<(), PicoError> {
        finding.validate()?;
        self.conn
            .execute(
                "INSERT INTO findings
                 (id, scan_id, fingerprint, finding_version, finding_class, title,
                  summary, severity, confidence, status, metadata, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    finding.id,
                    finding.scan_id,
                    finding.fingerprint,
                    finding.finding_version,
                    finding.finding_class,
                    finding.title,
                    finding.summary,
                    finding.severity,
                    finding.confidence,
                    finding.status,
                    opt_json_text(&finding.metadata),
                    codec::ts_to_text(finding.created_at),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<FindingRecord>, PicoError> {
        self.conn
            .query_row(
                "SELECT id, scan_id, fingerprint, finding_version, finding_class,
                        title, summary, severity, confidence, status, metadata, created_at
                 FROM findings WHERE id = ?1",
                [id],
                row_to_finding,
            )
            .optional()
            .map_err(db_err)
    }

    pub fn list_for_scan(&self, scan_id: &str) -> Result<Vec<FindingRecord>, PicoError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, scan_id, fingerprint, finding_version, finding_class,
                        title, summary, severity, confidence, status, metadata, created_at
                 FROM findings WHERE scan_id = ?1 ORDER BY fingerprint, id",
            )
            .map_err(db_err)?;
        let result = statement
            .query_map([scan_id], row_to_finding)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        result
    }

    pub fn count_for_scan(&self, scan_id: &str) -> Result<u64, PicoError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE scan_id = ?1",
                [scan_id],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        Ok(n as u64)
    }

    pub fn insert_path(&self, path: &FindingPathRecord) -> Result<(), PicoError> {
        path.validate()?;
        self.conn
            .execute(
                "INSERT INTO finding_paths (finding_id, attack_path_id, position)
                 VALUES (?1, ?2, ?3)",
                params![path.finding_id, path.attack_path_id, path.position],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_paths(&self, finding_id: &str) -> Result<Vec<FindingPathRecord>, PicoError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT finding_id, attack_path_id, position
                 FROM finding_paths WHERE finding_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;
        let result = statement
            .query_map([finding_id], row_to_finding_path)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        result
    }

    pub fn insert_evidence(&self, evidence: &FindingEvidenceRecord) -> Result<(), PicoError> {
        evidence.validate()?;
        self.conn
            .execute(
                "INSERT INTO finding_evidence
                 (finding_id, evidence_id, position, support_role)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    evidence.finding_id,
                    evidence.evidence_id,
                    evidence.position,
                    evidence.support_role,
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_evidence(&self, finding_id: &str) -> Result<Vec<FindingEvidenceRecord>, PicoError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT finding_id, evidence_id, position, support_role
                 FROM finding_evidence WHERE finding_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;
        let result = statement
            .query_map([finding_id], row_to_finding_evidence)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        result
    }

    pub fn insert_reason(&self, reason: &FindingReasonRecord) -> Result<(), PicoError> {
        reason.validate()?;
        self.conn
            .execute(
                "INSERT INTO finding_reasons
                 (finding_id, position, reason_code, resource_ids, relationship_ids,
                  attack_path_ids, evidence_ids)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    reason.finding_id,
                    reason.position,
                    reason.reason_code,
                    list_json(&reason.resource_ids),
                    list_json(&reason.relationship_ids),
                    list_json(&reason.attack_path_ids),
                    list_json(&reason.evidence_ids),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_reasons(&self, finding_id: &str) -> Result<Vec<FindingReasonRecord>, PicoError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT finding_id, position, reason_code, resource_ids,
                        relationship_ids, attack_path_ids, evidence_ids
                 FROM finding_reasons WHERE finding_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;
        let result = statement
            .query_map([finding_id], row_to_finding_reason)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        result
    }

    pub fn insert_remediation(
        &self,
        remediation: &FindingRemediationRecord,
    ) -> Result<(), PicoError> {
        remediation.validate()?;
        self.conn
            .execute(
                "INSERT INTO finding_remediations
                 (finding_id, position, rule_id, title, description, security_effect,
                  cut_phase, target_resource_ids, target_relationship_ids)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    remediation.finding_id,
                    remediation.position,
                    remediation.rule_id,
                    remediation.title,
                    remediation.description,
                    remediation.security_effect,
                    remediation.cut_phase,
                    list_json(&remediation.target_resource_ids),
                    list_json(&remediation.target_relationship_ids),
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn list_remediations(
        &self,
        finding_id: &str,
    ) -> Result<Vec<FindingRemediationRecord>, PicoError> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT finding_id, position, rule_id, title, description,
                        security_effect, cut_phase, target_resource_ids,
                        target_relationship_ids
                 FROM finding_remediations WHERE finding_id = ?1 ORDER BY position",
            )
            .map_err(db_err)?;
        let result = statement
            .query_map([finding_id], row_to_finding_remediation)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err);
        result
    }
}

fn row_to_finding(row: &Row<'_>) -> rusqlite::Result<FindingRecord> {
    Ok(FindingRecord {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        finding_version: row.get(3)?,
        finding_class: row.get(4)?,
        title: row.get(5)?,
        summary: row.get(6)?,
        severity: row.get(7)?,
        confidence: row.get(8)?,
        status: row.get(9)?,
        metadata: parse_json(row.get(10)?),
        created_at: codec::text_to_ts(&row.get::<_, String>(11)?)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
    })
}

fn row_to_finding_path(row: &Row<'_>) -> rusqlite::Result<FindingPathRecord> {
    Ok(FindingPathRecord {
        finding_id: row.get(0)?,
        attack_path_id: row.get(1)?,
        position: row.get::<_, i64>(2)? as u32,
    })
}

fn row_to_finding_evidence(row: &Row<'_>) -> rusqlite::Result<FindingEvidenceRecord> {
    Ok(FindingEvidenceRecord {
        finding_id: row.get(0)?,
        evidence_id: row.get(1)?,
        position: row.get::<_, i64>(2)? as u32,
        support_role: row.get(3)?,
    })
}

fn row_to_finding_reason(row: &Row<'_>) -> rusqlite::Result<FindingReasonRecord> {
    Ok(FindingReasonRecord {
        finding_id: row.get(0)?,
        position: row.get::<_, i64>(1)? as u32,
        reason_code: row.get(2)?,
        resource_ids: parse_string_list(row, 3)?,
        relationship_ids: parse_string_list(row, 4)?,
        attack_path_ids: parse_string_list(row, 5)?,
        evidence_ids: parse_string_list(row, 6)?,
    })
}

fn row_to_finding_remediation(row: &Row<'_>) -> rusqlite::Result<FindingRemediationRecord> {
    Ok(FindingRemediationRecord {
        finding_id: row.get(0)?,
        position: row.get::<_, i64>(1)? as u32,
        rule_id: row.get(2)?,
        title: row.get(3)?,
        description: row.get(4)?,
        security_effect: row.get(5)?,
        cut_phase: row.get(6)?,
        target_resource_ids: parse_string_list(row, 7)?,
        target_relationship_ids: parse_string_list(row, 8)?,
    })
}
