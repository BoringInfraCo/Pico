//! Pico domain types.
//!
//! The core observed-domain model defined by ARCHITECTURE.md:
//! Scan, Resource, Relationship, Evidence, Observation.
//!
//! This module MUST NOT depend on the CLI framework, the SQLite driver,
//! or any provider-specific code (OpenCode, GitHub, Cloudflare, MCP).

pub mod error;
pub mod evidence;
pub mod ids;
pub mod observation;
pub mod relationship;
pub mod resource;
pub mod scan;

pub use error::DomainError;
pub use evidence::{Evidence, EvidenceClass, Sensitivity};
pub use observation::{
    relationship_snapshot_metadata, resource_snapshot_metadata, Observation, GRAPH_SNAPSHOT_VERSION,
};
pub use relationship::{Relationship, RelationshipState};
pub use resource::Resource;
pub use scan::{Scan, ScanStatus, ScanTrigger};
