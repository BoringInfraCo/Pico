//! Bounded, provider-neutral influence analysis.

use std::collections::BTreeSet;

use crate::graph::{EdgeUsability, SecurityGraph, SecurityRole};

use super::model::{
    edge_state_disposition, metadata_string, AnalysisLimits, InfluencePath, InfluenceStrength,
    PathEdgeRef, PathPhase, SegmentDisposition, SourceTrust, TraversalDirection,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfluenceAnalysis {
    pub paths: Vec<InfluencePath>,
    pub limited: bool,
    pub diagnostics: Vec<String>,
}

pub fn analyze(graph: &SecurityGraph, limits: &AnalysisLimits) -> InfluenceAnalysis {
    analyze_with_policy(graph, limits, false)
}

pub fn analyze_with_policy(
    graph: &SecurityGraph,
    limits: &AnalysisLimits,
    allow_inferred: bool,
) -> InfluenceAnalysis {
    let mut paths = Vec::new();
    let mut limited = false;
    let actors: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| node.roles.contains(&SecurityRole::Actor))
        .collect();
    for actor in actors {
        let mut context = SearchContext {
            graph,
            limits,
            allow_inferred,
            actor_id: actor.resource_id.clone(),
            edge_examinations: 0,
            paths: Vec::new(),
            limited: false,
        };
        let mut edge_path = Vec::new();
        let mut visited_nodes = BTreeSet::new();
        let mut visited_edges = BTreeSet::new();
        visited_nodes.insert(actor.resource_id.clone());
        walk(
            &mut context,
            &actor.resource_id,
            &mut edge_path,
            &mut visited_nodes,
            &mut visited_edges,
            SegmentDisposition::Active,
        );
        limited |= context.limited;
        paths.extend(context.paths);
    }
    paths.sort_by(|a, b| {
        let a_source = graph
            .node(&a.source_resource_id)
            .map(|node| node.canonical_key.as_str())
            .unwrap_or("");
        let b_source = graph
            .node(&b.source_resource_id)
            .map(|node| node.canonical_key.as_str())
            .unwrap_or("");
        a_source
            .cmp(b_source)
            .then(a.actor_resource_id.cmp(&b.actor_resource_id))
            .then(a.edges.len().cmp(&b.edges.len()))
            .then(a.evidence_ids.cmp(&b.evidence_ids))
    });
    InfluenceAnalysis {
        paths,
        limited,
        diagnostics: if limited {
            vec!["influence traversal reached an explicit analysis limit".into()]
        } else {
            Vec::new()
        },
    }
}

struct SearchContext<'a> {
    graph: &'a SecurityGraph,
    limits: &'a AnalysisLimits,
    allow_inferred: bool,
    actor_id: String,
    edge_examinations: usize,
    paths: Vec<InfluencePath>,
    limited: bool,
}

fn walk(
    context: &mut SearchContext<'_>,
    current_id: &str,
    edge_path: &mut Vec<PathEdgeRef>,
    visited_nodes: &mut BTreeSet<String>,
    visited_edges: &mut BTreeSet<String>,
    disposition: SegmentDisposition,
) {
    let Some(current) = context.graph.node(current_id) else {
        return;
    };
    if current.roles.contains(&SecurityRole::Source) {
        let mut edges = edge_path.clone();
        edges.reverse();
        for (position, edge) in edges.iter_mut().enumerate() {
            edge.position = position;
        }
        let mut evidence_ids = edges
            .iter()
            .filter_map(|edge| context.graph.edge(&edge.relationship_id))
            .flat_map(|edge| edge.evidence_ids.iter().cloned())
            .collect::<Vec<_>>();
        evidence_ids.sort();
        evidence_ids.dedup();
        let trust =
            SourceTrust::parse(metadata_string(current.safe_metadata.as_ref(), "trust").as_deref());
        let strength = InfluenceStrength::parse(
            metadata_string(current.safe_metadata.as_ref(), "influence_strength").as_deref(),
        );
        let disposition = if matches!(trust, SourceTrust::Unknown)
            || matches!(strength, InfluenceStrength::Unknown)
        {
            SegmentDisposition::Unresolved
        } else {
            disposition
        };
        context.paths.push(InfluencePath {
            source_resource_id: current.resource_id.clone(),
            actor_resource_id: context.actor_id.clone(),
            edges,
            source_trust: trust,
            influence_strength: strength,
            evidence_ids,
            disposition,
        });
        return;
    }
    if edge_path.len() >= context.limits.maximum_depth {
        context.limited = true;
        return;
    }
    if context.paths.len() >= context.limits.maximum_influence_paths_per_actor {
        context.limited = true;
        return;
    }
    let outgoing: Vec<_> = context.graph.outgoing_edges(current_id).cloned().collect();
    for edge in outgoing {
        if context.edge_examinations >= context.limits.maximum_edge_examinations {
            context.limited = true;
            return;
        }
        context.edge_examinations += 1;
        if !matches!(edge.kind.as_str(), "can_call" | "can_retrieve") {
            continue;
        }
        if edge.usability == EdgeUsability::TraversableWithPenalty && !context.allow_inferred {
            continue;
        }
        if !visited_edges.insert(edge.relationship_id.clone()) {
            continue;
        }
        let next_id = edge.to_resource_id.as_str();
        if visited_nodes.contains(next_id) {
            visited_edges.remove(&edge.relationship_id);
            continue;
        }
        let next_disposition = merge_disposition(disposition, edge_state_disposition(edge.state));
        edge_path.push(PathEdgeRef {
            relationship_id: edge.relationship_id.clone(),
            phase: PathPhase::Influence,
            traversal: TraversalDirection::Reverse,
            position: 0,
        });
        visited_nodes.insert(next_id.to_string());
        walk(
            context,
            next_id,
            edge_path,
            visited_nodes,
            visited_edges,
            next_disposition,
        );
        visited_nodes.remove(next_id);
        edge_path.pop();
        visited_edges.remove(&edge.relationship_id);
        if context.paths.len() >= context.limits.maximum_influence_paths_per_actor {
            context.limited = true;
            return;
        }
    }
}

fn merge_disposition(left: SegmentDisposition, right: SegmentDisposition) -> SegmentDisposition {
    match (left, right) {
        (SegmentDisposition::Unresolved, _) | (_, SegmentDisposition::Unresolved) => {
            SegmentDisposition::Unresolved
        }
        (SegmentDisposition::Blocked, _) | (_, SegmentDisposition::Blocked) => {
            SegmentDisposition::Blocked
        }
        _ => SegmentDisposition::Active,
    }
}
