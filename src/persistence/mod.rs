//! SQLite persistence layer.
//!
//! SQLite is Pico's canonical V0 persistent store (ARCHITECTURE.md,
//! Architecture Decision 002). This module owns the connection,
//! migrations, and repositories for the observed-domain types.

pub mod analysis;
pub mod db;
pub mod findings;
pub mod repos;

pub use analysis::{
    AttackPathEdgeRecord, AttackPathEvidenceRecord, AttackPathRecord, AttackPathRepo,
    ScanAnalysisRecord, ScanAnalysisRepo,
};
pub use db::{require_schema_version, Database, SUPPORTED_SCHEMA_VERSION};
pub use findings::{
    FindingEvidenceRecord, FindingPathRecord, FindingReasonRecord, FindingRecord,
    FindingRemediationRecord, FindingRepo,
};
pub use repos::{
    EvidenceRepo, ObservationRepo, RelationshipRepo, ResourceRepo, ScanDiagnosticsRepo, ScanRepo,
};

/// Helpers for serializing domain values to SQLite text columns.
pub mod codec {
    use chrono::{DateTime, Utc};
    use serde_json::Value;

    use crate::shared::PicoError;

    /// Encode a UTC timestamp as RFC 3339 text.
    pub fn ts_to_text(dt: DateTime<Utc>) -> String {
        dt.to_rfc3339()
    }

    /// Decode RFC 3339 text back into a UTC timestamp.
    pub fn text_to_ts(s: &str) -> Result<DateTime<Utc>, PicoError> {
        Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
    }

    /// Encode optional JSON metadata as text (None becomes NULL).
    pub fn opt_json_to_text(v: &Option<Value>) -> Option<String> {
        v.as_ref().map(Value::to_string)
    }

    /// Decode optional JSON metadata text.
    pub fn text_to_opt_json(s: Option<String>) -> Option<Value> {
        s.and_then(|t| serde_json::from_str(&t).ok())
    }
}
