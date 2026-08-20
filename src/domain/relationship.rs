//! The `Relationship` domain type (ARCHITECTURE.md §6).
//!
//! A Relationship is a stable security-relevant connection between two
//! Resources, with a direction and a state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::DomainError;
use super::ids::new_id;

/// The evidential state of a Relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationshipState {
    Confirmed,
    Derived,
    Inferred,
    Unknown,
    Blocked,
}

impl RelationshipState {
    /// Machine-readable string form used for persistence and display.
    pub fn as_str(&self) -> &'static str {
        match self {
            RelationshipState::Confirmed => "CONFIRMED",
            RelationshipState::Derived => "DERIVED",
            RelationshipState::Inferred => "INFERRED",
            RelationshipState::Unknown => "UNKNOWN",
            RelationshipState::Blocked => "BLOCKED",
        }
    }
}

impl std::str::FromStr for RelationshipState {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CONFIRMED" => Ok(RelationshipState::Confirmed),
            "DERIVED" => Ok(RelationshipState::Derived),
            "INFERRED" => Ok(RelationshipState::Inferred),
            "UNKNOWN" => Ok(RelationshipState::Unknown),
            "BLOCKED" => Ok(RelationshipState::Blocked),
            other => Err(DomainError::InvalidValue(format!(
                "unknown relationship state: {other}"
            ))),
        }
    }
}

impl std::fmt::Display for RelationshipState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A directional security-relevant connection between two Resources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relationship {
    pub id: String,
    /// Stable identity of the relationship across scans.
    pub canonical_key: String,
    pub from_resource_id: String,
    pub to_resource_id: String,
    pub kind: String,
    pub state: RelationshipState,
    pub metadata: Option<Value>,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
}

impl Relationship {
    /// Construct a new Relationship, validating endpoints and state.
    ///
    /// A relationship must have distinct endpoints and non-empty fields.
    pub fn new(
        canonical_key: &str,
        from_resource_id: &str,
        to_resource_id: &str,
        kind: &str,
        state: RelationshipState,
    ) -> Result<Self, DomainError> {
        if from_resource_id.trim().is_empty() {
            return Err(DomainError::InvalidValue(
                "from_resource_id must not be empty".to_string(),
            ));
        }
        if to_resource_id.trim().is_empty() {
            return Err(DomainError::InvalidValue(
                "to_resource_id must not be empty".to_string(),
            ));
        }
        if from_resource_id == to_resource_id {
            return Err(DomainError::InvalidValue(
                "relationship endpoints must be distinct".to_string(),
            ));
        }
        if canonical_key.trim().is_empty() {
            return Err(DomainError::InvalidValue(
                "canonical_key must not be empty".to_string(),
            ));
        }
        if kind.trim().is_empty() {
            return Err(DomainError::InvalidValue(
                "kind must not be empty".to_string(),
            ));
        }
        let now = Utc::now();
        Ok(Relationship {
            id: new_id("rel"),
            canonical_key: canonical_key.to_string(),
            from_resource_id: from_resource_id.to_string(),
            to_resource_id: to_resource_id.to_string(),
            kind: kind.to_string(),
            state,
            metadata: None,
            first_observed_at: now,
            last_observed_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn new_relationship_is_valid() {
        let rel = Relationship::new(
            "agent:opencode:default|can_execute|shell:bash",
            "res_agent",
            "res_shell",
            "can_execute",
            RelationshipState::Confirmed,
        )
        .unwrap();
        assert_eq!(rel.from_resource_id, "res_agent");
        assert_eq!(rel.to_resource_id, "res_shell");
        assert_eq!(rel.kind, "can_execute");
        assert_eq!(rel.state, RelationshipState::Confirmed);
        assert!(rel.id.starts_with("rel_"));
    }

    #[test]
    fn self_relationship_is_rejected() {
        let err = Relationship::new(
            "self|self",
            "res_a",
            "res_a",
            "can_execute",
            RelationshipState::Confirmed,
        )
        .expect_err("self-loop must be invalid");
        assert!(matches!(err, DomainError::InvalidValue(_)));
    }

    #[test]
    fn empty_endpoints_are_rejected() {
        assert!(Relationship::new(
            "k",
            "",
            "res_shell",
            "can_execute",
            RelationshipState::Confirmed
        )
        .is_err());
        assert!(Relationship::new(
            "k",
            "res_agent",
            "   ",
            "can_execute",
            RelationshipState::Confirmed
        )
        .is_err());
        assert!(Relationship::new(
            "",
            "res_agent",
            "res_shell",
            "can_execute",
            RelationshipState::Confirmed
        )
        .is_err());
        assert!(Relationship::new(
            "k",
            "res_agent",
            "res_shell",
            "",
            RelationshipState::Confirmed
        )
        .is_err());
    }

    #[test]
    fn state_round_trips() {
        for state in [
            RelationshipState::Confirmed,
            RelationshipState::Derived,
            RelationshipState::Inferred,
            RelationshipState::Unknown,
            RelationshipState::Blocked,
        ] {
            assert_eq!(RelationshipState::from_str(state.as_str()).unwrap(), state);
        }
        assert!(RelationshipState::from_str("MAYBE").is_err());
    }
}
