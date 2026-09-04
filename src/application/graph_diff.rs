//! Graph memory over COMPLETE observation sets (SPRINT-026.md).
//!
//! Compares resource and relationship snapshots by canonical_key.
//! Stable-row first_observed_at / last_observed_at are never product memory.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde::Serialize;
use serde_json::Value;

use crate::domain::{Observation, Relationship, Resource, Scan};
use crate::graph::{parse_relationship_snapshot, parse_resource_snapshot, validate_safe_metadata};
use crate::persistence::ObservationRepo;
use crate::shared::PicoError;

const METADATA_KEYS: &[&str] = &[
    "effective_state",
    "effective_permission",
    "scope",
    "runtime_mode",
    "boundary_kind",
    "enabled",
    "transport",
    "permission",
    "permission_pattern",
    "influence_strength",
    "trust",
    "content_class",
    "consequential_sink",
    "authority_resolution",
    "permission_state",
    "credential_status",
    "account_scope_state",
    "sink_impact",
    "unknown_reasons",
    "granted_permissions",
    "zone_scoped",
    "credential_type",
    "validity",
    "environment_reachability",
    "presence",
    "identity_precision",
];

/// One resource or relationship identity in a graph diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphSubject {
    pub canonical_key: String,
    pub kind: String,
    pub provider: Option<String>,
    pub name: Option<String>,
    pub state: Option<String>,
    pub first_seen_scan_id: String,
    pub last_seen_scan_id: String,
    pub deltas: Vec<GraphDelta>,
}

/// One allowlisted snapshot field that differed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraphDelta {
    pub field: String,
    pub from: String,
    pub to: String,
}

/// Lifecycle buckets for one subject type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct GraphSubjectDiff {
    pub unchanged: Vec<GraphSubject>,
    pub first_seen: Vec<GraphSubject>,
    pub reappeared: Vec<GraphSubject>,
    pub changed: Vec<GraphSubject>,
    pub disappeared: Vec<GraphSubject>,
}

/// Resource and relationship comparison of two COMPLETE scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct GraphDiff {
    pub resources: GraphSubjectDiff,
    pub relationships: GraphSubjectDiff,
}

struct GraphSets {
    resources: BTreeMap<String, Resource>,
    relationships: BTreeMap<String, Relationship>,
}

/// Compare observation snapshots for `from` → `to` using COMPLETE history
/// at or before `to` (newest-first `complete` list).
pub fn compare_graph(
    conn: &Connection,
    from: &Scan,
    to: &Scan,
    complete_newest_first: &[Scan],
) -> Result<GraphDiff, PicoError> {
    let window: Vec<&Scan> = complete_newest_first
        .iter()
        .skip_while(|scan| scan.id != to.id)
        .collect();
    if window.is_empty() {
        return Err(PicoError::database(format!(
            "scan {} missing from COMPLETE history",
            to.id
        )));
    }
    if !window.iter().any(|scan| scan.id == from.id) {
        return Err(PicoError::database(format!(
            "scan {} is not at or before {}",
            from.id, to.id
        )));
    }

    let mut cached: BTreeMap<String, GraphSets> = BTreeMap::new();
    for scan in &window {
        let sets = sets_for_scan(conn, &scan.id)?;
        cached.insert(scan.id.clone(), sets);
    }
    let from_sets = cached
        .get(&from.id)
        .ok_or_else(|| PicoError::database(format!("missing observation set {}", from.id)))?;
    let to_sets = cached
        .get(&to.id)
        .ok_or_else(|| PicoError::database(format!("missing observation set {}", to.id)))?;

    Ok(GraphDiff {
        resources: diff_resources(from_sets, to_sets, from, &window, &cached),
        relationships: diff_relationships(from_sets, to_sets, from, &window, &cached),
    })
}

fn sets_for_scan(conn: &Connection, scan_id: &str) -> Result<GraphSets, PicoError> {
    let observations = ObservationRepo::new(conn).list_for_scan(scan_id)?;
    let mut resources = BTreeMap::new();
    let mut relationships = BTreeMap::new();
    for observation in observations {
        match observation.subject_type.as_str() {
            "resource" => {
                let snapshot = parse_and_validate_resource(&observation)?;
                resources
                    .entry(snapshot.canonical_key.clone())
                    .or_insert(snapshot);
            }
            "relationship" => {
                let snapshot = parse_and_validate_relationship(&observation)?;
                relationships
                    .entry(snapshot.canonical_key.clone())
                    .or_insert(snapshot);
            }
            _ => {}
        }
    }
    Ok(GraphSets {
        resources,
        relationships,
    })
}

fn parse_and_validate_resource(observation: &Observation) -> Result<Resource, PicoError> {
    let snapshot = parse_resource_snapshot(observation)
        .map_err(|error| PicoError::database(error.to_string()))?;
    validate_safe_metadata(snapshot.metadata.as_ref())
        .map_err(|error| PicoError::database(error.to_string()))?;
    Ok(snapshot)
}

fn parse_and_validate_relationship(observation: &Observation) -> Result<Relationship, PicoError> {
    let snapshot = parse_relationship_snapshot(observation)
        .map_err(|error| PicoError::database(error.to_string()))?;
    validate_safe_metadata(snapshot.metadata.as_ref())
        .map_err(|error| PicoError::database(error.to_string()))?;
    Ok(snapshot)
}

fn diff_resources(
    from_sets: &GraphSets,
    to_sets: &GraphSets,
    from: &Scan,
    window: &[&Scan],
    cached: &BTreeMap<String, GraphSets>,
) -> GraphSubjectDiff {
    let mut diff = GraphSubjectDiff::default();
    for (key, resource) in &to_sets.resources {
        let (first_seen, last_seen) = seen_bounds(window, cached, key, true);
        if let Some(previous) = from_sets.resources.get(key) {
            let deltas = resource_deltas(previous, resource);
            let subject = graph_resource(resource, first_seen, last_seen, deltas);
            if subject.deltas.is_empty() {
                diff.unchanged.push(subject);
            } else {
                diff.changed.push(subject);
            }
        } else if present_before(window, cached, &from.id, key, true) {
            diff.reappeared
                .push(graph_resource(resource, first_seen, last_seen, Vec::new()));
        } else {
            diff.first_seen
                .push(graph_resource(resource, first_seen, last_seen, Vec::new()));
        }
    }
    for (key, resource) in &from_sets.resources {
        if to_sets.resources.contains_key(key) {
            continue;
        }
        let (first_seen, last_seen) = seen_bounds(window, cached, key, true);
        diff.disappeared
            .push(graph_resource(resource, first_seen, last_seen, Vec::new()));
    }
    sort_subjects(&mut diff);
    diff
}

fn diff_relationships(
    from_sets: &GraphSets,
    to_sets: &GraphSets,
    from: &Scan,
    window: &[&Scan],
    cached: &BTreeMap<String, GraphSets>,
) -> GraphSubjectDiff {
    let mut diff = GraphSubjectDiff::default();
    for (key, relationship) in &to_sets.relationships {
        let (first_seen, last_seen) = seen_bounds(window, cached, key, false);
        if let Some(previous) = from_sets.relationships.get(key) {
            let deltas = relationship_deltas(previous, relationship);
            let subject = graph_relationship(relationship, first_seen, last_seen, deltas);
            if subject.deltas.is_empty() {
                diff.unchanged.push(subject);
            } else {
                diff.changed.push(subject);
            }
        } else if present_before(window, cached, &from.id, key, false) {
            diff.reappeared.push(graph_relationship(
                relationship,
                first_seen,
                last_seen,
                Vec::new(),
            ));
        } else {
            diff.first_seen.push(graph_relationship(
                relationship,
                first_seen,
                last_seen,
                Vec::new(),
            ));
        }
    }
    for (key, relationship) in &from_sets.relationships {
        if to_sets.relationships.contains_key(key) {
            continue;
        }
        let (first_seen, last_seen) = seen_bounds(window, cached, key, false);
        diff.disappeared.push(graph_relationship(
            relationship,
            first_seen,
            last_seen,
            Vec::new(),
        ));
    }
    sort_subjects(&mut diff);
    diff
}

fn graph_resource(
    resource: &Resource,
    first_seen: String,
    last_seen: String,
    deltas: Vec<GraphDelta>,
) -> GraphSubject {
    GraphSubject {
        canonical_key: resource.canonical_key.clone(),
        kind: resource.kind.clone(),
        provider: Some(resource.provider.clone()),
        name: Some(resource.name.clone()),
        state: None,
        first_seen_scan_id: first_seen,
        last_seen_scan_id: last_seen,
        deltas,
    }
}

fn graph_relationship(
    relationship: &Relationship,
    first_seen: String,
    last_seen: String,
    deltas: Vec<GraphDelta>,
) -> GraphSubject {
    GraphSubject {
        canonical_key: relationship.canonical_key.clone(),
        kind: relationship.kind.clone(),
        provider: None,
        name: None,
        state: Some(relationship.state.as_str().to_string()),
        first_seen_scan_id: first_seen,
        last_seen_scan_id: last_seen,
        deltas,
    }
}

fn seen_bounds(
    window: &[&Scan],
    cached: &BTreeMap<String, GraphSets>,
    key: &str,
    resource: bool,
) -> (String, String) {
    let mut last_seen = None;
    let mut first_seen = None;
    for scan in window {
        if contains_key(cached, &scan.id, key, resource) {
            if last_seen.is_none() {
                last_seen = Some(scan.id.clone());
            }
            first_seen = Some(scan.id.clone());
        }
    }
    (
        first_seen.unwrap_or_else(|| key.to_string()),
        last_seen.unwrap_or_else(|| key.to_string()),
    )
}

fn present_before(
    window: &[&Scan],
    cached: &BTreeMap<String, GraphSets>,
    from_id: &str,
    key: &str,
    resource: bool,
) -> bool {
    let mut after_from = false;
    for scan in window {
        if scan.id == from_id {
            after_from = true;
            continue;
        }
        if after_from && contains_key(cached, &scan.id, key, resource) {
            return true;
        }
    }
    false
}

fn contains_key(
    cached: &BTreeMap<String, GraphSets>,
    scan_id: &str,
    key: &str,
    resource: bool,
) -> bool {
    cached.get(scan_id).is_some_and(|sets| {
        if resource {
            sets.resources.contains_key(key)
        } else {
            sets.relationships.contains_key(key)
        }
    })
}

fn resource_deltas(from: &Resource, to: &Resource) -> Vec<GraphDelta> {
    let mut deltas = Vec::new();
    push_delta(&mut deltas, "kind", &from.kind, &to.kind);
    push_delta(&mut deltas, "provider", &from.provider, &to.provider);
    push_delta(&mut deltas, "name", &from.name, &to.name);
    metadata_deltas(&mut deltas, from.metadata.as_ref(), to.metadata.as_ref());
    deltas
}

fn relationship_deltas(from: &Relationship, to: &Relationship) -> Vec<GraphDelta> {
    let mut deltas = Vec::new();
    push_delta(&mut deltas, "kind", &from.kind, &to.kind);
    push_delta(&mut deltas, "state", from.state.as_str(), to.state.as_str());
    metadata_deltas(&mut deltas, from.metadata.as_ref(), to.metadata.as_ref());
    deltas
}

fn metadata_deltas(deltas: &mut Vec<GraphDelta>, from: Option<&Value>, to: Option<&Value>) {
    for field in METADATA_KEYS {
        let left = field_text(from, field);
        let right = field_text(to, field);
        match (left, right) {
            (None, None) => {}
            (Some(from_value), Some(to_value)) if from_value == to_value => {}
            (from_value, to_value) => deltas.push(GraphDelta {
                field: (*field).to_string(),
                from: from_value.unwrap_or_else(|| "—".to_string()),
                to: to_value.unwrap_or_else(|| "—".to_string()),
            }),
        }
    }
}

fn field_text(metadata: Option<&Value>, field: &str) -> Option<String> {
    let value = metadata?.get(field)?;
    if value.is_null() {
        return None;
    }
    Some(value_text(value))
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

fn push_delta(deltas: &mut Vec<GraphDelta>, field: &str, from: &str, to: &str) {
    if from != to {
        deltas.push(GraphDelta {
            field: field.to_string(),
            from: from.to_string(),
            to: to.to_string(),
        });
    }
}

fn sort_subjects(diff: &mut GraphSubjectDiff) {
    for bucket in [
        &mut diff.unchanged,
        &mut diff.first_seen,
        &mut diff.reappeared,
        &mut diff.changed,
        &mut diff.disappeared,
    ] {
        bucket.sort_by(|left, right| left.canonical_key.cmp(&right.canonical_key));
    }
}
