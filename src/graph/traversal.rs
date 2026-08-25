//! Small, bounded traversal primitives for future deterministic analyzers.

use std::collections::{BTreeSet, VecDeque};

use super::{EdgeUsability, SecurityGraph};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalDirection {
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalLimits {
    pub maximum_depth: usize,
    pub maximum_edge_examinations: usize,
    pub maximum_frontier_nodes: usize,
    pub maximum_reachable_nodes: usize,
}

impl Default for TraversalLimits {
    fn default() -> Self {
        Self {
            maximum_depth: 8,
            maximum_edge_examinations: 256,
            maximum_frontier_nodes: 128,
            maximum_reachable_nodes: 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalPolicy {
    pub direction: TraversalDirection,
    pub allowed_relationship_kinds: BTreeSet<String>,
    pub allow_inferred: bool,
    pub limits: TraversalLimits,
}

impl Default for TraversalPolicy {
    fn default() -> Self {
        Self {
            direction: TraversalDirection::Outgoing,
            allowed_relationship_kinds: super::SUPPORTED_RELATIONSHIP_KINDS
                .iter()
                .map(|kind| (*kind).to_string())
                .collect(),
            allow_inferred: true,
            limits: TraversalLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalCompletion {
    Complete,
    DepthLimited,
    WorkLimited,
    FrontierLimited,
    ResultLimited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedReachabilityResult {
    pub reachable_node_ids: Vec<String>,
    pub examined_edge_ids: Vec<String>,
    pub completion: TraversalCompletion,
}

pub fn bounded_reachability(
    graph: &SecurityGraph,
    start_resource_id: &str,
    policy: &TraversalPolicy,
) -> BoundedReachabilityResult {
    let mut reachable = Vec::new();
    let mut reachable_set = BTreeSet::new();
    let mut examined = Vec::new();
    let mut examined_set = BTreeSet::new();
    let mut visited_edges = BTreeSet::new();
    let mut frontier = VecDeque::new();
    let mut queued = BTreeSet::new();
    let mut completion = TraversalCompletion::Complete;

    if graph.node(start_resource_id).is_none() {
        return BoundedReachabilityResult {
            reachable_node_ids: reachable,
            examined_edge_ids: examined,
            completion,
        };
    }
    frontier.push_back((start_resource_id.to_string(), 0usize));
    queued.insert(start_resource_id.to_string());

    while let Some((node_id, depth)) = frontier.pop_front() {
        if reachable_set.insert(node_id.clone()) {
            reachable.push(node_id.clone());
            if reachable.len() >= policy.limits.maximum_reachable_nodes {
                completion = TraversalCompletion::ResultLimited;
                break;
            }
        }
        if depth >= policy.limits.maximum_depth {
            if has_candidate_edges(graph, &node_id, policy) {
                completion = TraversalCompletion::DepthLimited;
            }
            continue;
        }

        let edges: Vec<_> = match policy.direction {
            TraversalDirection::Outgoing => graph.outgoing_edges(&node_id).collect(),
            TraversalDirection::Incoming => graph.incoming_edges(&node_id).collect(),
        };
        for edge in edges {
            if examined.len() >= policy.limits.maximum_edge_examinations {
                completion = TraversalCompletion::WorkLimited;
                break;
            }
            if examined_set.insert(edge.relationship_id.clone()) {
                examined.push(edge.relationship_id.clone());
            }
            if !policy.allowed_relationship_kinds.contains(&edge.kind) {
                continue;
            }
            if edge.usability == EdgeUsability::TraversableWithPenalty && !policy.allow_inferred {
                continue;
            }
            if !edge.usability.is_traversable() {
                continue;
            }
            if !visited_edges.insert(edge.relationship_id.clone()) {
                continue;
            }
            let next = match policy.direction {
                TraversalDirection::Outgoing => edge.to_resource_id.clone(),
                TraversalDirection::Incoming => edge.from_resource_id.clone(),
            };
            if queued.contains(&next) || reachable_set.contains(&next) {
                continue;
            }
            if frontier.len() >= policy.limits.maximum_frontier_nodes {
                completion = TraversalCompletion::FrontierLimited;
                break;
            }
            queued.insert(next.clone());
            frontier.push_back((next, depth + 1));
        }
        if !matches!(completion, TraversalCompletion::Complete) {
            break;
        }
    }
    reachable.sort();
    examined.sort();
    BoundedReachabilityResult {
        reachable_node_ids: reachable,
        examined_edge_ids: examined,
        completion,
    }
}

fn has_candidate_edges(graph: &SecurityGraph, node_id: &str, policy: &TraversalPolicy) -> bool {
    match policy.direction {
        TraversalDirection::Outgoing => graph
            .outgoing_edges(node_id)
            .any(|edge| policy.allowed_relationship_kinds.contains(&edge.kind)),
        TraversalDirection::Incoming => graph
            .incoming_edges(node_id)
            .any(|edge| policy.allowed_relationship_kinds.contains(&edge.kind)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::domain::RelationshipState;

    use super::super::{GraphEdge, GraphEvidenceIndex, GraphNode, SecurityGraph};
    use super::*;

    fn edge(id: &str, from: &str, to: &str, state: RelationshipState) -> GraphEdge {
        GraphEdge {
            relationship_id: id.to_string(),
            canonical_key: format!("{from}|can_call|{to}"),
            from_resource_id: from.to_string(),
            to_resource_id: to.to_string(),
            kind: "can_call".to_string(),
            state,
            usability: EdgeUsability::from_state(state),
            safe_metadata: None,
            evidence_ids: vec![format!("ev-{id}")],
        }
    }

    fn graph(edges: Vec<GraphEdge>) -> SecurityGraph {
        let mut outgoing = BTreeMap::new();
        let mut incoming = BTreeMap::new();
        let mut ids = BTreeMap::new();
        for edge in &edges {
            ids.entry(edge.from_resource_id.clone())
                .or_insert_with(|| GraphNode {
                    resource_id: edge.from_resource_id.clone(),
                    canonical_key: edge.from_resource_id.clone(),
                    kind: "fixture".into(),
                    provider: "fixture".into(),
                    name: edge.from_resource_id.clone(),
                    safe_metadata: None,
                    roles: vec![],
                });
            ids.entry(edge.to_resource_id.clone())
                .or_insert_with(|| GraphNode {
                    resource_id: edge.to_resource_id.clone(),
                    canonical_key: edge.to_resource_id.clone(),
                    kind: "fixture".into(),
                    provider: "fixture".into(),
                    name: edge.to_resource_id.clone(),
                    safe_metadata: None,
                    roles: vec![],
                });
            outgoing
                .entry(edge.from_resource_id.clone())
                .or_insert_with(Vec::new)
                .push(edge.relationship_id.clone());
            incoming
                .entry(edge.to_resource_id.clone())
                .or_insert_with(Vec::new)
                .push(edge.relationship_id.clone());
        }
        SecurityGraph {
            scan_id: "scan-fixture".into(),
            snapshot_version: 1,
            nodes: ids.into_values().collect(),
            edges,
            outgoing_index: outgoing,
            incoming_index: incoming,
            evidence_index: GraphEvidenceIndex::default(),
        }
    }

    #[test]
    fn cycles_terminate_and_direction_is_preserved() {
        let graph = graph(vec![
            edge("ab", "a", "b", RelationshipState::Confirmed),
            edge("ba", "b", "a", RelationshipState::Confirmed),
        ]);
        let result = bounded_reachability(&graph, "a", &TraversalPolicy::default());
        assert_eq!(result.reachable_node_ids, vec!["a", "b"]);
        assert_eq!(result.completion, TraversalCompletion::Complete);
    }

    #[test]
    fn unknown_edges_remain_unreachable_and_depth_is_bounded() {
        let graph_unknown = graph(vec![
            edge("ab", "a", "b", RelationshipState::Unknown),
            edge("bc", "b", "c", RelationshipState::Confirmed),
        ]);
        let result = bounded_reachability(&graph_unknown, "a", &TraversalPolicy::default());
        assert_eq!(result.reachable_node_ids, vec!["a"]);

        let graph_depth = graph(vec![
            edge("ab", "a", "b", RelationshipState::Confirmed),
            edge("bc", "b", "c", RelationshipState::Confirmed),
        ]);
        let mut policy = TraversalPolicy::default();
        policy.limits.maximum_depth = 1;
        let result = bounded_reachability(&graph_depth, "a", &policy);
        assert_eq!(result.reachable_node_ids, vec!["a", "b"]);
        assert_eq!(result.completion, TraversalCompletion::DepthLimited);
    }
}
