//! Provider-neutral in-memory Security Graph projection.
//!
//! This module consumes normalized domain objects only. It does not parse
//! OpenCode, MCP, GitHub, or Cloudflare data and it does not construct
//! InfluencePaths, AuthorityPaths, AttackPaths, or Findings.

pub mod model;
pub mod projection;
pub mod traversal;

pub use model::{
    EdgeUsability, GraphEdge, GraphEvidenceIndex, GraphNode, SecurityGraph, SecurityRole,
};
pub use projection::{project, ProjectionError, ProjectionInput, SUPPORTED_RELATIONSHIP_KINDS};
pub use traversal::{
    bounded_reachability, BoundedReachabilityResult, TraversalCompletion, TraversalDirection,
    TraversalLimits, TraversalPolicy,
};
