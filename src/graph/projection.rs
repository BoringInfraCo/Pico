//! Scan-scoped projection from normalized observed-domain state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::Value;

use crate::domain::{
    Evidence, Observation, Relationship, RelationshipState, Resource, GRAPH_SNAPSHOT_VERSION,
};

use super::model::{GraphEdge, GraphEvidenceIndex, GraphNode, SecurityGraph};

pub const SUPPORTED_RELATIONSHIP_KINDS: &[&str] = &[
    "configured_with",
    "exposes",
    "can_call",
    "can_retrieve",
    "can_read",
    "can_write",
    "can_execute",
    "can_access",
    "uses_credential",
    "authenticates_to",
    "authorizes",
    "scoped_to",
    "can_mutate",
    "can_deploy",
    "protected_by",
    "requires_approval",
    "isolated_by",
    "denied_by",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionError {
    UnknownScan(String),
    SnapshotVersion {
        expected: u32,
        actual: Option<u32>,
    },
    MissingSnapshot {
        subject_type: String,
        subject_id: String,
    },
    InvalidSnapshot(String),
    MissingResource(String),
    MissingRelationship(String),
    MissingEndpoint(String),
    UnsupportedRelationshipKind(String),
    MissingEvidence(String),
    CrossScanEvidence(String),
    UnsafeMetadata(String),
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScan(id) => write!(f, "unknown scan: {id}"),
            Self::SnapshotVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported graph snapshot version: expected {expected}, got {actual:?}"
                )
            }
            Self::MissingSnapshot {
                subject_type,
                subject_id,
            } => {
                write!(f, "missing graph snapshot for {subject_type} {subject_id}")
            }
            Self::InvalidSnapshot(msg) => write!(f, "invalid graph snapshot: {msg}"),
            Self::MissingResource(id) => {
                write!(f, "resource observation references missing resource: {id}")
            }
            Self::MissingRelationship(id) => write!(
                f,
                "relationship observation references missing relationship: {id}"
            ),
            Self::MissingEndpoint(id) => {
                write!(f, "relationship endpoint is absent from graph: {id}")
            }
            Self::UnsupportedRelationshipKind(kind) => {
                write!(f, "unsupported graph relationship kind: {kind}")
            }
            Self::MissingEvidence(key) => {
                write!(f, "relationship has no same-scan evidence: {key}")
            }
            Self::CrossScanEvidence(id) => {
                write!(f, "relationship evidence belongs to another scan: {id}")
            }
            Self::UnsafeMetadata(field) => write!(f, "unsafe graph metadata field: {field}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

pub struct ProjectionInput<'a> {
    pub scan_id: &'a str,
    pub snapshot_version: u32,
    pub resources: &'a [Resource],
    pub relationships: &'a [Relationship],
    pub observations: &'a [Observation],
    pub evidence: &'a [Evidence],
    pub relationship_evidence: &'a [(String, String)],
}

pub fn project(input: ProjectionInput<'_>) -> Result<SecurityGraph, ProjectionError> {
    if input.scan_id.trim().is_empty() {
        return Err(ProjectionError::UnknownScan(input.scan_id.to_string()));
    }
    if input.snapshot_version != GRAPH_SNAPSHOT_VERSION as u32 {
        return Err(ProjectionError::SnapshotVersion {
            expected: GRAPH_SNAPSHOT_VERSION as u32,
            actual: Some(input.snapshot_version),
        });
    }

    let resources_by_id: BTreeMap<_, _> =
        input.resources.iter().map(|r| (r.id.as_str(), r)).collect();
    let relationships_by_id: BTreeMap<_, _> = input
        .relationships
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();

    let mut node_resources: BTreeMap<String, Resource> = BTreeMap::new();
    for observation in input
        .observations
        .iter()
        .filter(|o| o.scan_id == input.scan_id && o.subject_type == "resource")
    {
        let stable = resources_by_id
            .get(observation.subject_id.as_str())
            .ok_or_else(|| ProjectionError::MissingResource(observation.subject_id.clone()))?;
        let snapshot = parse_resource_snapshot(observation)?;
        validate_safe_metadata(snapshot.metadata.as_ref())?;
        if let Some(existing) = node_resources.get(&snapshot.canonical_key) {
            if existing.id != stable.id
                || existing.kind != snapshot.kind
                || existing.provider != snapshot.provider
            {
                return Err(ProjectionError::InvalidSnapshot(format!(
                    "conflicting resource {}",
                    snapshot.canonical_key
                )));
            }
            continue;
        }
        let mut projected = (*stable).clone();
        projected.canonical_key = snapshot.canonical_key;
        projected.kind = snapshot.kind;
        projected.provider = snapshot.provider;
        projected.name = snapshot.name;
        projected.metadata = snapshot.metadata;
        node_resources.insert(projected.canonical_key.clone(), projected);
    }

    let mut relation_snapshots: BTreeMap<String, Relationship> = BTreeMap::new();
    for observation in input
        .observations
        .iter()
        .filter(|o| o.scan_id == input.scan_id && o.subject_type == "relationship")
    {
        let stable = relationships_by_id
            .get(observation.subject_id.as_str())
            .ok_or_else(|| ProjectionError::MissingRelationship(observation.subject_id.clone()))?;
        let snapshot = parse_relationship_snapshot(observation)?;
        validate_safe_metadata(snapshot.metadata.as_ref())?;
        if snapshot.id != stable.id || snapshot.canonical_key != stable.canonical_key {
            return Err(ProjectionError::InvalidSnapshot(format!(
                "conflicting relationship {}",
                snapshot.canonical_key
            )));
        }
        if !SUPPORTED_RELATIONSHIP_KINDS.contains(&snapshot.kind.as_str()) {
            return Err(ProjectionError::UnsupportedRelationshipKind(snapshot.kind));
        }
        if let Some(existing) = relation_snapshots.get(&snapshot.canonical_key) {
            if existing.state != snapshot.state || existing.metadata != snapshot.metadata {
                return Err(ProjectionError::InvalidSnapshot(format!(
                    "conflicting relationship state {}",
                    snapshot.canonical_key
                )));
            }
            continue;
        }
        relation_snapshots.insert(snapshot.canonical_key.clone(), snapshot);
    }

    let same_scan_evidence: BTreeMap<_, _> = input
        .evidence
        .iter()
        .filter(|e| e.scan_id == input.scan_id)
        .map(|e| (e.id.as_str(), e))
        .collect();
    let all_evidence: BTreeMap<_, _> = input.evidence.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut links_by_relationship: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (relationship_id, evidence_id) in input.relationship_evidence {
        let evidence = all_evidence
            .get(evidence_id.as_str())
            .ok_or_else(|| ProjectionError::MissingEvidence(evidence_id.clone()))?;
        // Stable Relationships accumulate links across scans. Historical
        // links are intentionally ignored here; only Evidence captured by
        // this graph's scan can support the projected edge.
        if evidence.scan_id != input.scan_id {
            continue;
        }
        links_by_relationship
            .entry(relationship_id.clone())
            .or_default()
            .push(evidence_id.clone());
    }
    for values in links_by_relationship.values_mut() {
        values.sort();
        values.dedup();
    }

    let node_ids: BTreeSet<_> = node_resources.values().map(|r| r.id.clone()).collect();
    let mut edges = Vec::new();
    for relationship in relation_snapshots.values() {
        if !node_ids.contains(&relationship.from_resource_id) {
            return Err(ProjectionError::MissingEndpoint(
                relationship.from_resource_id.clone(),
            ));
        }
        if !node_ids.contains(&relationship.to_resource_id) {
            return Err(ProjectionError::MissingEndpoint(
                relationship.to_resource_id.clone(),
            ));
        }
        let evidence_ids = links_by_relationship
            .get(&relationship.id)
            .cloned()
            .ok_or_else(|| ProjectionError::MissingEvidence(relationship.canonical_key.clone()))?;
        if evidence_ids.is_empty() {
            return Err(ProjectionError::MissingEvidence(
                relationship.canonical_key.clone(),
            ));
        }
        if evidence_ids
            .iter()
            .any(|id| !same_scan_evidence.contains_key(id.as_str()))
        {
            return Err(ProjectionError::CrossScanEvidence(
                relationship.canonical_key.clone(),
            ));
        }
        let mut edge = GraphEdge::from_relationship(relationship);
        edge.evidence_ids = evidence_ids;
        edges.push(edge);
    }
    edges.sort_by(|a, b| a.canonical_key.cmp(&b.canonical_key));

    let nodes: Vec<_> = node_resources
        .values()
        .map(GraphNode::from_resource)
        .collect();
    let node_id_set: BTreeSet<_> = nodes.iter().map(|n| n.resource_id.clone()).collect();
    let mut outgoing_index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut incoming_index: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for edge in &edges {
        if !node_id_set.contains(&edge.from_resource_id)
            || !node_id_set.contains(&edge.to_resource_id)
        {
            return Err(ProjectionError::MissingEndpoint(edge.canonical_key.clone()));
        }
        outgoing_index
            .entry(edge.from_resource_id.clone())
            .or_default()
            .push(edge.relationship_id.clone());
        incoming_index
            .entry(edge.to_resource_id.clone())
            .or_default()
            .push(edge.relationship_id.clone());
    }
    for values in outgoing_index.values_mut() {
        values.sort();
    }
    for values in incoming_index.values_mut() {
        values.sort();
    }

    let mut evidence_index = GraphEvidenceIndex::default();
    for evidence in same_scan_evidence.values() {
        evidence_index
            .by_evidence_id
            .insert(evidence.id.clone(), (*evidence).clone());
        evidence_index
            .by_subject
            .entry(evidence.subject.clone())
            .or_default()
            .push(evidence.id.clone());
    }
    for values in evidence_index.by_subject.values_mut() {
        values.sort();
        values.dedup();
    }
    for edge in &edges {
        evidence_index
            .by_relationship_id
            .insert(edge.relationship_id.clone(), edge.evidence_ids.clone());
    }

    Ok(SecurityGraph {
        scan_id: input.scan_id.to_string(),
        snapshot_version: input.snapshot_version,
        nodes,
        edges,
        outgoing_index,
        incoming_index,
        evidence_index,
    })
}

fn parse_resource_snapshot(observation: &Observation) -> Result<Resource, ProjectionError> {
    let value = observation
        .metadata
        .as_ref()
        .ok_or_else(|| ProjectionError::MissingSnapshot {
            subject_type: observation.subject_type.clone(),
            subject_id: observation.subject_id.clone(),
        })?;
    let root = value.as_object().ok_or_else(|| {
        ProjectionError::InvalidSnapshot("resource metadata is not an object".into())
    })?;
    if root.get("graph_snapshot_version").and_then(Value::as_u64) != Some(GRAPH_SNAPSHOT_VERSION) {
        return Err(ProjectionError::SnapshotVersion {
            expected: GRAPH_SNAPSHOT_VERSION as u32,
            actual: root
                .get("graph_snapshot_version")
                .and_then(Value::as_u64)
                .map(|v| v as u32),
        });
    }
    let resource = root
        .get("resource")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::InvalidSnapshot("missing resource snapshot".into()))?;
    let text = |key: &str| {
        resource
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| ProjectionError::InvalidSnapshot(format!("resource field {key}")))
    };
    let now = chrono::Utc::now();
    Ok(Resource {
        id: observation.subject_id.clone(),
        canonical_key: text("canonical_key")?,
        kind: text("kind")?,
        provider: text("provider")?,
        name: text("name")?,
        metadata: resource.get("safe_metadata").cloned(),
        first_observed_at: now,
        last_observed_at: now,
    })
}

fn parse_relationship_snapshot(observation: &Observation) -> Result<Relationship, ProjectionError> {
    let value = observation
        .metadata
        .as_ref()
        .ok_or_else(|| ProjectionError::MissingSnapshot {
            subject_type: observation.subject_type.clone(),
            subject_id: observation.subject_id.clone(),
        })?;
    let root = value.as_object().ok_or_else(|| {
        ProjectionError::InvalidSnapshot("relationship metadata is not an object".into())
    })?;
    if root.get("graph_snapshot_version").and_then(Value::as_u64) != Some(GRAPH_SNAPSHOT_VERSION) {
        return Err(ProjectionError::SnapshotVersion {
            expected: GRAPH_SNAPSHOT_VERSION as u32,
            actual: root
                .get("graph_snapshot_version")
                .and_then(Value::as_u64)
                .map(|v| v as u32),
        });
    }
    let relationship = root
        .get("relationship")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::InvalidSnapshot("missing relationship snapshot".into()))?;
    let text = |key: &str| {
        relationship
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| ProjectionError::InvalidSnapshot(format!("relationship field {key}")))
    };
    let state = relationship
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| ProjectionError::InvalidSnapshot("relationship state".into()))?
        .parse::<RelationshipState>()
        .map_err(|e| ProjectionError::InvalidSnapshot(e.to_string()))?;
    let now = chrono::Utc::now();
    Ok(Relationship {
        id: observation.subject_id.clone(),
        canonical_key: text("canonical_key")?,
        from_resource_id: text("from_resource_id")?,
        to_resource_id: text("to_resource_id")?,
        kind: text("kind")?,
        state,
        metadata: relationship.get("safe_metadata").cloned(),
        first_observed_at: now,
        last_observed_at: now,
    })
}

fn validate_safe_metadata(value: Option<&Value>) -> Result<(), ProjectionError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        Value::Object(fields) => {
            for (key, nested) in fields {
                let lower = key.to_ascii_lowercase();
                if lower.contains("raw")
                    || lower.contains("password")
                    || lower.contains("authorization")
                    || lower.contains("private_key")
                    || lower == "token_value"
                {
                    return Err(ProjectionError::UnsafeMetadata(key.clone()));
                }
                validate_safe_metadata(Some(nested))?;
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_safe_metadata(Some(item))?;
            }
        }
        _ => {}
    }
    Ok(())
}
