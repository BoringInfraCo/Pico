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
