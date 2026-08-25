//! Provider-neutral, in-memory Security Graph model.
//!
//! The graph is a projection over normalized Pico domain objects.  It is
//! deliberately not persisted and contains no provider-specific types or
//! parsing logic.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{RelationshipState, Resource};

/// The canonical generic roles used by graph projection and later analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityRole {
    /// A source of externally controlled or untrusted content.
    Source,
    /// An autonomous actor.
    Actor,
    /// A capability available to an actor or other graph node.
    Capability,
    /// An authority-bearing credential or identity.
    Authority,
    /// A consequential destination or target.
    Sink,
    /// An approval, sandbox, or other enforcement boundary.
    Boundary,
}

impl SecurityRole {
    /// Stable canonical vocabulary spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Source => "SOURCE",
            Self::Actor => "ACTOR",
            Self::Capability => "CAPABILITY",
            Self::Authority => "AUTHORITY",
            Self::Sink => "SINK",
            Self::Boundary => "BOUNDARY",
        }
    }
}

impl std::fmt::Display for SecurityRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provider-neutral usability of a relationship edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EdgeUsability {
    /// Confirmed or derived state may be considered by a later analyzer.
    Traversable,
    /// Inferred state may be considered with an explicit later penalty.
    TraversableWithPenalty,
    /// Unknown state is retained for explanation but cannot be traversed.
    NonTraversableUnknown,
    /// Blocked state is retained for explanation but cannot be traversed.
    NonTraversableBlocked,
}

impl EdgeUsability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Traversable => "TRAVERSABLE",
            Self::TraversableWithPenalty => "TRAVERSABLE_WITH_PENALTY",
            Self::NonTraversableUnknown => "NON_TRAVERSABLE_UNKNOWN",
            Self::NonTraversableBlocked => "NON_TRAVERSABLE_BLOCKED",
        }
    }

    pub const fn from_state(state: RelationshipState) -> Self {
        match state {
            RelationshipState::Confirmed | RelationshipState::Derived => Self::Traversable,
            RelationshipState::Inferred => Self::TraversableWithPenalty,
            RelationshipState::Unknown => Self::NonTraversableUnknown,
            RelationshipState::Blocked => Self::NonTraversableBlocked,
        }
    }

    pub const fn is_traversable(self) -> bool {
        matches!(self, Self::Traversable | Self::TraversableWithPenalty)
    }
}

impl std::fmt::Display for EdgeUsability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A generic graph node corresponding to one stable Resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub resource_id: String,
    pub canonical_key: String,
    pub kind: String,
    pub provider: String,
    pub name: String,
    pub safe_metadata: Option<Value>,
    pub roles: Vec<SecurityRole>,
}

impl GraphNode {
    /// Project a normalized Resource into a provider-neutral graph node.
    pub fn from_resource(resource: &Resource) -> Self {
        let mut roles = roles_for_resource(resource);
        roles.sort();
        roles.dedup();
        Self {
            resource_id: resource.id.clone(),
            canonical_key: resource.canonical_key.clone(),
            kind: resource.kind.clone(),
            provider: resource.provider.clone(),
            name: resource.name.clone(),
            safe_metadata: resource.metadata.clone(),
            roles,
        }
    }
}

/// A generic graph edge corresponding to one normalized Relationship.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub relationship_id: String,
    pub canonical_key: String,
    pub from_resource_id: String,
    pub to_resource_id: String,
    pub kind: String,
    pub state: RelationshipState,
    pub usability: EdgeUsability,
    pub safe_metadata: Option<Value>,
    pub evidence_ids: Vec<String>,
}

impl GraphEdge {
    pub fn from_relationship(relationship: &crate::domain::Relationship) -> Self {
        Self {
            relationship_id: relationship.id.clone(),
            canonical_key: relationship.canonical_key.clone(),
            from_resource_id: relationship.from_resource_id.clone(),
            to_resource_id: relationship.to_resource_id.clone(),
            kind: relationship.kind.clone(),
            state: relationship.state,
            usability: EdgeUsability::from_state(relationship.state),
            safe_metadata: relationship.metadata.clone(),
            evidence_ids: Vec::new(),
        }
    }
}

/// Evidence indexes retained by an in-memory graph projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GraphEvidenceIndex {
    /// Evidence by its stable domain identity.
    pub by_evidence_id: BTreeMap<String, crate::domain::Evidence>,
    /// Relationship identity to exactly linked supporting evidence IDs.
    pub by_relationship_id: BTreeMap<String, Vec<String>>,
    /// Exact subject string to evidence IDs.  No fuzzy or provider matching.
    pub by_subject: BTreeMap<String, Vec<String>>,
}

impl GraphEvidenceIndex {
    pub fn evidence(&self, id: &str) -> Option<&crate::domain::Evidence> {
        self.by_evidence_id.get(id)
    }

    pub fn relationship_evidence(&self, relationship_id: &str) -> &[String] {
        self.by_relationship_id
            .get(relationship_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn subject_evidence(&self, subject: &str) -> &[String] {
        self.by_subject
            .get(subject)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// The validated, deterministic projection for exactly one scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityGraph {
    pub scan_id: String,
    pub snapshot_version: u32,
    /// Nodes ordered by canonical Resource identity.
    pub nodes: Vec<GraphNode>,
    /// Edges ordered by canonical Relationship identity.
    pub edges: Vec<GraphEdge>,
    /// Outgoing adjacency: resource ID to relationship IDs.
    pub outgoing_index: BTreeMap<String, Vec<String>>,
    /// Incoming adjacency: resource ID to relationship IDs.
    pub incoming_index: BTreeMap<String, Vec<String>>,
    pub evidence_index: GraphEvidenceIndex,
}

impl SecurityGraph {
    pub fn node(&self, resource_id: &str) -> Option<&GraphNode> {
        self.nodes
            .iter()
            .find(|node| node.resource_id == resource_id)
    }

    pub fn edge(&self, relationship_id: &str) -> Option<&GraphEdge> {
        self.edges
            .iter()
            .find(|edge| edge.relationship_id == relationship_id)
    }

    pub fn outgoing_edges(&self, resource_id: &str) -> impl Iterator<Item = &GraphEdge> {
        self.outgoing_index
            .get(resource_id)
            .into_iter()
            .flatten()
            .filter_map(|id| self.edge(id))
    }

    pub fn incoming_edges(&self, resource_id: &str) -> impl Iterator<Item = &GraphEdge> {
        self.incoming_index
            .get(resource_id)
            .into_iter()
            .flatten()
            .filter_map(|id| self.edge(id))
    }
}

fn roles_for_resource(resource: &Resource) -> Vec<SecurityRole> {
    let mut roles = Vec::new();
    match resource.kind.as_str() {
        "external_source" => roles.push(SecurityRole::Source),
        "agent" => roles.push(SecurityRole::Actor),
        "shell" | "mcp_tool" => roles.push(SecurityRole::Capability),
        "credential" => roles.push(SecurityRole::Authority),
        "approval_gate" | "sandbox" => roles.push(SecurityRole::Boundary),
        _ => {}
    }

    if resource
        .metadata
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("consequential_sink"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        roles.push(SecurityRole::Sink);
    }
    roles
}
