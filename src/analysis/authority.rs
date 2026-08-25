//! Bounded, provider-neutral authority analysis.

use std::collections::BTreeSet;

use crate::graph::{EdgeUsability, SecurityGraph, SecurityRole};

use super::model::{
    edge_state_disposition, metadata_string, AnalysisLimits, AuthorityPath, AuthorityResolution,
    CapabilityClass, PathEdgeRef, PathPhase, SegmentDisposition, SinkImpact, TraversalDirection,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityAnalysis {
    pub paths: Vec<AuthorityPath>,
    pub limited: bool,
    pub diagnostics: Vec<String>,
}

pub fn analyze(graph: &SecurityGraph, limits: &AnalysisLimits) -> AuthorityAnalysis {
    analyze_with_policy(graph, limits, false)
}

pub fn analyze_with_policy(
    graph: &SecurityGraph,
    limits: &AnalysisLimits,
    allow_inferred: bool,
) -> AuthorityAnalysis {
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
            CapabilityClass::Unknown,
            AuthorityResolution::Unknown,
        );
        limited |= context.limited;
        paths.extend(context.paths);
    }
    paths.sort_by(|a, b| {
        let a_sink = graph
            .node(&a.sink_resource_id)
            .map(|node| node.canonical_key.as_str())
            .unwrap_or("");
        let b_sink = graph
            .node(&b.sink_resource_id)
            .map(|node| node.canonical_key.as_str())
            .unwrap_or("");
        a.actor_resource_id
            .cmp(&b.actor_resource_id)
            .then(a_sink.cmp(b_sink))
            .then(a.edges.len().cmp(&b.edges.len()))
            .then(a.evidence_ids.cmp(&b.evidence_ids))
    });
    AuthorityAnalysis {
        paths,
        limited,
        diagnostics: if limited {
            vec!["authority traversal reached an explicit analysis limit".into()]
        } else {
            Vec::new()
        },
    }
}

struct SearchContext<'a> {
    graph: &'a SecurityGraph,
    limits: &'a AnalysisLimits,
    allow_inferred: bool,
    edge_examinations: usize,
    paths: Vec<AuthorityPath>,
    limited: bool,
}

#[allow(clippy::too_many_arguments)]
fn walk(
    context: &mut SearchContext<'_>,
    current_id: &str,
    edge_path: &mut Vec<PathEdgeRef>,
    visited_nodes: &mut BTreeSet<String>,
    visited_edges: &mut BTreeSet<String>,
    disposition: SegmentDisposition,
    capability: CapabilityClass,
    authority_resolution: AuthorityResolution,
) {
    let Some(current) = context.graph.node(current_id) else {
        return;
    };
    if current.roles.contains(&SecurityRole::Sink)
        && edge_path.iter().any(|edge| {
            context
                .graph
                .edge(&edge.relationship_id)
                .is_some_and(|candidate| candidate.kind == "can_mutate")
        })
    {
        let mut edges = edge_path.clone();
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
        let sink_impact = SinkImpact::parse(
            metadata_string(current.safe_metadata.as_ref(), "sink_impact")
                .or_else(|| metadata_string(current.safe_metadata.as_ref(), "environment"))
                .as_deref(),
        );
        let disposition = if matches!(
            authority_resolution,
            AuthorityResolution::Unknown | AuthorityResolution::BehavioralReadOnly
        ) {
            SegmentDisposition::Unresolved
        } else {
            disposition
        };
        context.paths.push(AuthorityPath {
            actor_resource_id: edges
                .first()
                .and_then(|edge| context.graph.edge(&edge.relationship_id))
                .map(|edge| edge.from_resource_id.clone())
                .unwrap_or_default(),
            sink_resource_id: current.resource_id.clone(),
            edges,
            capability,
            authority_resolution,
            sink_impact,
            evidence_ids,
            disposition,
        });
        return;
    }
    if edge_path.len() >= context.limits.maximum_depth {
        context.limited = true;
        return;
    }
    if context.paths.len() >= context.limits.maximum_authority_paths_per_actor {
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
        if !matches!(
            edge.kind.as_str(),
            "can_execute" | "can_access" | "can_mutate"
        ) {
            continue;
        }
        if edge.usability == EdgeUsability::TraversableWithPenalty && !context.allow_inferred {
            continue;
        }
        if !visited_edges.insert(edge.relationship_id.clone()) {
            continue;
        }
        if visited_nodes.contains(&edge.to_resource_id) {
            visited_edges.remove(&edge.relationship_id);
            continue;
        }
        let next_disposition = merge_disposition(disposition, edge_state_disposition(edge.state));
        let next_capability = if edge.kind == "can_execute" {
            let node_capability = context
                .graph
                .node(&edge.to_resource_id)
                .and_then(|node| metadata_string(node.safe_metadata.as_ref(), "capability"));
            CapabilityClass::parse(
                node_capability
                    .or_else(|| metadata_string(edge.safe_metadata.as_ref(), "capability"))
                    .as_deref(),
            )
        } else {
            capability
        };
        let next_resolution = if edge.kind == "can_mutate" {
            AuthorityResolution::parse(
                metadata_string(edge.safe_metadata.as_ref(), "authority_resolution").as_deref(),
            )
        } else {
            authority_resolution
        };
        let next_disposition = if edge.kind == "can_mutate"
            && next_resolution == AuthorityResolution::Scoped
            && metadata_string(edge.safe_metadata.as_ref(), "account_scope_state").as_deref()
                != Some("IN_SCOPE")
        {
            SegmentDisposition::Unresolved
        } else {
            next_disposition
        };
        edge_path.push(PathEdgeRef {
            relationship_id: edge.relationship_id.clone(),
            phase: PathPhase::Authority,
            traversal: TraversalDirection::Forward,
            position: edge_path.len(),
        });
        visited_nodes.insert(edge.to_resource_id.clone());
        walk(
            context,
            &edge.to_resource_id,
            edge_path,
            visited_nodes,
            visited_edges,
            next_disposition,
            next_capability,
            next_resolution,
        );
        visited_nodes.remove(&edge.to_resource_id);
        edge_path.pop();
        visited_edges.remove(&edge.relationship_id);
        if context.paths.len() >= context.limits.maximum_authority_paths_per_actor {
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
