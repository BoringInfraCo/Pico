//! The `Resource` domain type (ARCHITECTURE.md §5).
//!
//! A Resource is a stable normalized representation of an entity Pico
//! has discovered. Resources carry stable canonical identity so the same
//! entity is recognized across scans.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::DomainError;
use super::ids::new_id;

/// A stable normalized representation of a discovered entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    /// Stable, provider-aware identity across scans. Never contains a
    /// secret value.
    pub canonical_key: String,
    pub kind: String,
    pub provider: String,
    pub name: String,
    pub metadata: Option<Value>,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
}

impl Resource {
    /// Construct a new Resource, validating required fields.
    pub fn new(
        canonical_key: &str,
        kind: &str,
        provider: &str,
        name: &str,
    ) -> Result<Self, DomainError> {
        for (label, value) in [
            ("canonical_key", canonical_key),
            ("kind", kind),
            ("provider", provider),
            ("name", name),
        ] {
            if value.trim().is_empty() {
                return Err(DomainError::InvalidValue(format!(
                    "{label} must not be empty"
                )));
            }
        }
        let now = Utc::now();
        Ok(Resource {
            id: new_id("res"),
            canonical_key: canonical_key.to_string(),
            kind: kind.to_string(),
            provider: provider.to_string(),
            name: name.to_string(),
            metadata: None,
            first_observed_at: now,
            last_observed_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_resource_has_stable_identity() {
        let a = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
        let b = Resource::new("agent:opencode:default", "agent", "opencode", "OpenCode").unwrap();
        assert_eq!(a.canonical_key, b.canonical_key);
        assert_ne!(a.id, b.id);
        assert!(a.id.starts_with("res_"));
        assert_eq!(a.first_observed_at, a.last_observed_at);
    }

    #[test]
    fn empty_fields_are_rejected() {
        assert!(Resource::new("", "agent", "opencode", "OpenCode").is_err());
        assert!(Resource::new("agent:opencode:default", "", "opencode", "OpenCode").is_err());
        assert!(Resource::new("agent:opencode:default", "agent", "", "OpenCode").is_err());
        assert!(Resource::new("agent:opencode:default", "agent", "opencode", "").is_err());
        assert!(Resource::new("   ", "agent", "opencode", "OpenCode").is_err());
    }
}
