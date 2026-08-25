//! The `Observation` domain type (ARCHITECTURE.md §7.1).
//!
//! An Observation records what Pico observed during a specific Scan.
//! It gives the Scan temporal context without duplicating the stable
//! Resource/Relationship objects themselves.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::DomainError;
use super::ids::new_id;
use super::{Relationship, Resource};

/// Version of the scan-scoped graph snapshot carried by new observations.
///
/// Stable Resource and Relationship rows are updated by later scans, so graph
/// projection must use the immutable, scan-specific observation payload.
pub const GRAPH_SNAPSHOT_VERSION: u64 = 1;

/// Build the safe, provider-neutral snapshot attached to a Resource
/// observation. Resource metadata has already passed the application layer's
/// secret-safety checks; this helper only wraps it in the versioned contract.
pub fn resource_snapshot_metadata(resource: &Resource) -> Value {
    serde_json::json!({
        "graph_snapshot_version": GRAPH_SNAPSHOT_VERSION,
        "subject_type": "resource",
        "resource": {
            "canonical_key": resource.canonical_key,
            "kind": resource.kind,
            "provider": resource.provider,
            "name": resource.name,
            "safe_metadata": resource.metadata,
        }
    })
}

/// Build the safe, provider-neutral snapshot attached to a Relationship
/// observation. The relationship state and endpoints are captured for the
/// scan and must not be reconstructed from the mutable stable row later.
pub fn relationship_snapshot_metadata(relationship: &Relationship) -> Value {
    serde_json::json!({
        "graph_snapshot_version": GRAPH_SNAPSHOT_VERSION,
        "subject_type": "relationship",
        "relationship": {
            "canonical_key": relationship.canonical_key,
            "from_resource_id": relationship.from_resource_id,
            "to_resource_id": relationship.to_resource_id,
            "kind": relationship.kind,
            "state": relationship.state.as_str(),
            "safe_metadata": relationship.metadata,
        }
    })
}

/// A record of what Pico observed during a Scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub id: String,
    pub scan_id: String,
    /// Kind of subject observed (e.g. `resource`, `relationship`).
    pub subject_type: String,
    /// ID of the observed subject.
    pub subject_id: String,
    /// What kind of observation this is (e.g. `present`, `absent`).
    pub observation_type: String,
    pub observed_at: DateTime<Utc>,
    /// Where the observation came from (e.g. an adapter or discovery step).
    pub source: String,
    pub metadata: Option<Value>,
}

impl Observation {
    /// Construct a new Observation, validating required fields.
    pub fn new(
        scan_id: &str,
        subject_type: &str,
        subject_id: &str,
        observation_type: &str,
        source: &str,
    ) -> Result<Self, DomainError> {
        for (label, value) in [
            ("scan_id", scan_id),
            ("subject_type", subject_type),
            ("subject_id", subject_id),
            ("observation_type", observation_type),
            ("source", source),
        ] {
            if value.trim().is_empty() {
                return Err(DomainError::InvalidValue(format!(
                    "{label} must not be empty"
                )));
            }
        }
        Ok(Observation {
            id: new_id("obs"),
            scan_id: scan_id.to_string(),
            subject_type: subject_type.to_string(),
            subject_id: subject_id.to_string(),
            observation_type: observation_type.to_string(),
            observed_at: Utc::now(),
            source: source.to_string(),
            metadata: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_observation_is_valid() {
        let obs =
            Observation::new("scan_1", "resource", "res_1", "present", "opencode_adapter").unwrap();
        assert_eq!(obs.scan_id, "scan_1");
        assert_eq!(obs.subject_type, "resource");
        assert_eq!(obs.subject_id, "res_1");
        assert_eq!(obs.observation_type, "present");
        assert_eq!(obs.source, "opencode_adapter");
        assert!(obs.id.starts_with("obs_"));
    }

    #[test]
    fn empty_fields_are_rejected() {
        assert!(Observation::new("", "resource", "res_1", "present", "src").is_err());
        assert!(Observation::new("scan_1", "", "res_1", "present", "src").is_err());
        assert!(Observation::new("scan_1", "resource", "", "present", "src").is_err());
        assert!(Observation::new("scan_1", "resource", "res_1", "", "src").is_err());
        assert!(Observation::new("scan_1", "resource", "res_1", "present", "").is_err());
    }
}
